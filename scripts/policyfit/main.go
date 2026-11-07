package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"github.com/nekoskin/whispera/core/tunnel"
)

const (
	traceFields        = 6
	traceStageHello    = "handshake"
	traceStageReset    = "live_reset"
	traceStageEnd      = "live_end"
	traceJointTail     = "|joint"
	traceLatencyCol    = 6
	traceSymptomCol    = 7
	traceDownCol       = 8
	traceWireCol       = 9
	traceConnectCol    = 10
	traceHelloBytesCol = 11
	traceSegmentsCol   = 12
	traceAckedCol      = 13
	traceRetransCol    = 14
	traceResetCol      = 15
	traceResetTTLCol   = 16
	traceServerTTLCol  = 17
	tracePacketsCol    = 18
	traceChainPosCol   = 19
	traceChainGapCol   = 20
	tracePresetsCol    = 21
	traceLegacyPresets = 3
	traceSymptomFrom   = string(protocol.SymptomStallVolume)
)

var localResult = strconv.Itoa(int(protocol.HandshakeLocal))

func main() {
	traces := flag.String("trace", "", "Comma-separated dial traces (dials.csv) from every device")
	stand := flag.String("stand", "", "Comma-separated dial traces from the test stand; they train and validate the net but never enter the held-out verdict or the baselines. Their live resets are skipped: the stand's proxy censor resets pooled connections it closes with unread data, which the field never shows")
	standRegimes := flag.String("stand-regimes", "", "Comma-separated regime timelines (regime,start_s,end_s) matching -stand; simulated dials then take their pcap measurements from stand dials of the same arm under the matching regime")
	out := flag.String("out", "", "Write the new weights here, only when they beat the baselines on held-out dials")
	candidate := flag.String("candidate", "", "Write the fitted weights here whatever the verdict, to inspect a net that did not pass")
	steps := flag.Int("steps", 4000, "Training steps")
	batch := flag.Int("batch", 50, "Windows averaged into each training step")
	evalEvery := flag.Int("eval", 100, "Validate every this many steps and keep the best")
	block := flag.Int("block", 100, "Consecutive dials per block for the blocked validation split")
	valEvery := flag.Int("val-every", 5, "Every this many blocks before the held-out part, one goes to validation")
	seed := flag.Int64("seed", 7, "Random seed")
	testShare := flag.Float64("test", 0.2, "Most recent share of the trace held out for the verdict")
	synthetic := flag.Int("synthetic", 3000, "Simulated censor episodes mixed into training (0 trains on the trace alone)")
	syntheticVal := flag.Int("synthetic-val", 300, "Simulated censor episodes held out for validation")
	syntheticShare := flag.Float64("synthetic-share", 0.5, "Share of each training batch drawn from the simulated episodes")
	evalEpisodes := flag.Int("eval-episodes", 200, "Simulated censor episodes the policy plays in closed loop for the report")
	fixedArm := flag.Int("fixed-arm", 4, "Arm the no-adaptation baseline keeps dialing in the closed-loop report")
	holdout := flag.String("holdout", "", "Comma-separated mechanisms left out of the simulated training episodes, to test adapting to an unseen one")
	evalOnly := flag.Bool("eval-only", false, "Only play the shipped weights against simulated censors and report, no training")
	paired := flag.Bool("paired", true, "Weight the simulated censors by the regret of the shipped policy, so training sees more of what it fails (PAIRED)")
	trainer := flag.String("trainer", "", "PyTorch script that trains the net (neural/mutate.py)")
	python := flag.String("python", "python", "Python with PyTorch installed that runs -trainer")
	stallsFrom := flag.Int64("stalls-from", 0, "Unix ms before which the -trace volume stalls are not read as live deaths: older clients flagged any stall at 12-24 KB, not only one cut inside a record")
	reliance := flag.String("reliance", "", "Comma-separated dial traces with packet columns; with -eval-only, report how much the shipped weights lean on the packets: log-loss with each dial's packets and with packets switched between dials (model reliance, Fisher, Rudin and Dominici, JMLR 2019)")
	pcaps := flag.String("pcap", "", "Comma-separated classic pcap captures (Wireshark, tcpdump); every TCP flow to -pcap-server becomes a dial for training and validation, its arm read off the ClientHello and its outcome off the packets")
	pcapServer := flag.String("pcap-server", "", "ip:port of the whispera server in the -pcap captures")
	novelty := flag.Bool("novelty", false, "Only fit the packet Gaussians of the shipped weights on the -trace and -stand dials, report how many held-out failed dials fall past their bars, and write the weights with them to -out; no training")
	holdoutRegime := flag.String("holdout-regime", "", "Comma-separated stand regimes whose dials are left out of training, validation, the simulated measurements and the packet Gaussians, then checked for how many fall past the bars as a block the net never saw")
	noveltyAlarm := flag.Float64("novelty-alarm", protocol.NoveltyFalseAlarm, "Share of failed dials under blocks the net trained on that may cross the packet distance bar; the bar is the conformal threshold over the validation dials at this level")
	flag.Parse()
	heldRegimes := map[string]bool{}
	for _, name := range strings.Split(*holdoutRegime, ",") {
		if name = strings.TrimSpace(name); name != "" {
			heldRegimes[name] = true
		}
	}
	if *evalOnly {
		loadStand(*stand, *standRegimes, heldRegimes)
		if *reliance != "" {
			reportReliance("shipped", protocol.ShippedPolicy(), relianceDocs(*reliance))
		}
		reportClosedLoop("shipped", protocol.ShippedPolicy(), *seed, *evalEpisodes, *fixedArm)
		return
	}
	if *traces == "" || *trainer == "" {
		fmt.Fprintln(os.Stderr, "policyfit: -trace and -trainer are required")
		os.Exit(2)
	}

	groups := map[string][]protocol.PolicyDial{}
	for i, path := range strings.Split(*traces, ",") {
		if err := readTrace(strings.TrimSpace(path), fmt.Sprintf("%d:", i), true, *stallsFrom, groups); err != nil {
			fmt.Fprintf(os.Stderr, "policyfit: %v\n", err)
			os.Exit(1)
		}
	}
	testCut := timeCut(groups, *testShare)
	contexts := make([]string, 0, len(groups))
	for ctx := range groups {
		contexts = append(contexts, ctx)
	}
	sort.Strings(contexts)
	var before, test [][]protocol.PolicyStep
	dials := 0
	for _, ctx := range contexts {
		g := groups[ctx]
		dials += len(g)
		var a, c []protocol.PolicyDial
		for _, d := range g {
			if d.Ms < testCut {
				a = append(a, d)
			} else {
				c = append(c, d)
			}
		}
		before = append(before, protocol.PolicySteps(a))
		test = append(test, protocol.PolicySteps(c))
	}
	train, val := protocol.PolicyBlocks(before, *block, *valEvery)
	fmt.Printf("%d trace rows in %d contexts\n", dials, len(groups))

	standGroups, heldDocs := loadStand(*stand, *standRegimes, heldRegimes)
	standContexts := make([]string, 0, len(standGroups))
	standRows := 0
	for ctx, g := range standGroups {
		standContexts = append(standContexts, ctx)
		standRows += len(g)
	}
	sort.Strings(standContexts)
	var standDocs [][]protocol.PolicyStep
	for _, ctx := range standContexts {
		standDocs = append(standDocs, protocol.PolicySteps(standGroups[ctx]))
	}
	if *pcaps != "" {
		for _, path := range strings.Split(*pcaps, ",") {
			dials, err := tunnel.PcapDials(strings.TrimSpace(path), *pcapServer)
			if err != nil {
				fmt.Fprintf(os.Stderr, "policyfit: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("%d dials read from %s\n", len(dials), path)
			standDocs = append(standDocs, protocol.PolicySteps(dials))
		}
	}
	standTrain, standVal := protocol.PolicyBlocks(standDocs, *block, *valEvery)
	if standRows > 0 {
		fmt.Printf("%d stand rows in %d contexts, training and validation only\n", standRows, len(standGroups))
	}
	if *novelty {
		seen := append(append([][]protocol.PolicyStep(nil), train...), standTrain...)
		calibration := append(append([][]protocol.PolicyStep(nil), val...), standVal...)
		fitted, err := protocol.PolicyNovelty(*python, *trainer, protocol.ShippedPolicy(), seen, calibration, *noveltyAlarm)
		if err != nil {
			fmt.Fprintf(os.Stderr, "policyfit: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("packet Gaussians of the shipped weights: %s\n", fitted.NoveltySummary())
		reportNovelty("held-out trace", fitted, test)
		if *reliance != "" {
			reportNovelty("held-out stand", fitted, relianceDocs(*reliance))
		}
		reportNovelty("held-out regimes "+*holdoutRegime, fitted, heldDocs)
		src, err := fitted.GoSource()
		if err != nil {
			fmt.Fprintf(os.Stderr, "policyfit: %v\n", err)
			os.Exit(1)
		}
		if *out != "" {
			writeWeights(*out, src)
		}
		return
	}

	held := map[string]bool{}
	for _, name := range strings.Split(*holdout, ",") {
		if name = strings.TrimSpace(name); name != "" {
			held[name] = true
		}
	}
	var weights []float64
	if *paired {
		weights = adversaryWeights(protocol.ShippedPolicy(), *seed+5, *evalEpisodes/4)
		fmt.Printf("adversary mechanism weights: %s\n", mechWeightLine(weights))
	}
	cfg := protocol.PolicyFitConfig{
		Steps: *steps, Batch: *batch, EvalEvery: *evalEvery, Seed: *seed,
		Synthetic:      simEpisodes(*seed+1, *synthetic, held, weights),
		SyntheticVal:   simEpisodes(*seed+2, *syntheticVal, held, weights),
		SyntheticShare: *syntheticShare,
		Stand:          standTrain,
		StandVal:       standVal,
		NoveltyAlpha:   *noveltyAlarm,
	}
	fitted, r, err := protocol.FitPolicy(*python, *trainer, train, val, test, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policyfit: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("best step %d of %d, blocked validation log-loss %.5f, simulated validation log-loss %.5f\n", r.BestStep, r.Steps, r.ValLoss, r.SyntheticValLoss)
	fmt.Printf("held-out log-loss of the weights shipped now: %.5f\n", r.ShippedLoss)
	reportClosedLoop("shipped", protocol.ShippedPolicy(), *seed, *evalEpisodes, *fixedArm)
	reportClosedLoop("fitted", fitted, *seed, *evalEpisodes, *fixedArm)
	fmt.Printf("held-out log-loss on %d dials: constant %.5f, per-arm rate %.5f, last outcome of the arm %.5f, net %.5f\n",
		r.TestDials, r.ConstantLoss, r.ArmRateLoss, r.LastOutcomeLoss, r.FittedLoss)
	anchors := make([]float64, 0, len(r.AnchorLoss))
	for a := range r.AnchorLoss {
		anchors = append(anchors, a)
	}
	sort.Float64s(anchors)
	for _, a := range anchors {
		fmt.Printf("online replay with anchor %g: log-loss %.5f\n", a, r.AnchorLoss[a])
	}
	fmt.Printf("anchor picked: %g\n", r.Anchor)
	fmt.Printf("check head trusts %.1f%% of held-out dials: net log-loss %.5f on them, %.5f on the rest\n", 100*r.TrustedShare, r.TrustedLoss, r.DistrustedLoss)
	fmt.Printf("held-out log-loss with the outcome check mixing the net with the arm rate and the last outcome: %.5f\n", r.CheckedLoss)
	fmt.Printf("packet Gaussians: %s\n", fitted.NoveltySummary())
	reportNovelty("held-out trace", fitted, test)
	reportNovelty("held-out regimes "+*holdoutRegime, fitted, heldDocs)
	src, err := fitted.GoSource()
	if err != nil {
		fmt.Fprintf(os.Stderr, "policyfit: %v\n", err)
		os.Exit(1)
	}
	if *candidate != "" {
		writeWeights(*candidate, src)
	}
	if !r.Better() {
		fmt.Println("verdict: keep the current weights, the net did not beat the baselines")
		return
	}
	fmt.Println("verdict: the fitted weights beat the baselines")
	if *out != "" {
		writeWeights(*out, src)
	}
}

func loadStand(stand, standRegimes string, heldRegimes map[string]bool) (map[string][]protocol.PolicyDial, [][]protocol.PolicyStep) {
	standGroups := map[string][]protocol.PolicyDial{}
	var heldDocs [][]protocol.PolicyStep
	var standRegimeFiles []string
	if standRegimes != "" {
		standRegimeFiles = strings.Split(standRegimes, ",")
	}
	bank := &measureBank{byArm: map[string][]protocol.DialMeasure{}, byPQ: map[string][]protocol.DialMeasure{}, tails: map[string][][]protocol.WirePacket{}}
	banked := 0
	if stand != "" {
		for i, path := range strings.Split(stand, ",") {
			one := map[string][]protocol.PolicyDial{}
			if err := readTrace(strings.TrimSpace(path), fmt.Sprintf("stand%d:", i), false, 0, one); err != nil {
				fmt.Fprintf(os.Stderr, "policyfit: %v\n", err)
				os.Exit(1)
			}
			var spans []standSpan
			if i < len(standRegimeFiles) {
				var err error
				if spans, err = readRegimes(strings.TrimSpace(standRegimeFiles[i])); err != nil {
					fmt.Fprintf(os.Stderr, "policyfit: %v\n", err)
					os.Exit(1)
				}
			}
			for ctx, g := range one {
				kept, held := splitRegimes(g, spans, heldRegimes)
				banked += bank.fill(kept, spans)
				standGroups[ctx] = kept
				if len(held) > 0 {
					heldDocs = append(heldDocs, protocol.PolicySteps(held))
				}
			}
		}
	}
	if banked > 0 {
		simBank = bank
		fmt.Printf("simulated dials draw their pcap measurements from %d measured stand dials\n", banked)
	}
	return standGroups, heldDocs
}

func splitRegimes(dials []protocol.PolicyDial, spans []standSpan, held map[string]bool) (kept, out []protocol.PolicyDial) {
	for _, d := range dials {
		if held[regimeAt(spans, d.Ms)] {
			out = append(out, d)
		} else {
			kept = append(kept, d)
		}
	}
	return kept, out
}

func writeWeights(path string, src []byte) {
	if err := os.WriteFile(path, src, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "policyfit: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n", path)
}

func field(fields []string, col int) string {
	if col < len(fields) {
		return fields[col]
	}
	return ""
}

func millis(fields []string, col int) time.Duration {
	ms, err := strconv.ParseInt(field(fields, col), 10, 64)
	if err != nil {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func number(fields []string, col int) int {
	n, err := strconv.Atoi(field(fields, col))
	if err != nil {
		return 0
	}
	return n
}

func traceMeasure(fields []string) protocol.DialMeasure {
	m := protocol.DialMeasure{Connect: millis(fields, traceConnectCol), Packets: protocol.ParseWirePackets(field(fields, tracePacketsCol)),
		ChainPos: number(fields, traceChainPosCol), ChainGap: millis(fields, traceChainGapCol)}
	if field(fields, traceHelloBytesCol) == "" {
		return m
	}
	m.Captured = true
	m.HelloBytes = number(fields, traceHelloBytesCol)
	m.HelloSegments = number(fields, traceSegmentsCol)
	m.HelloAcked = number(fields, traceAckedCol)
	m.Retransmits = number(fields, traceRetransCol)
	if field(fields, traceResetCol) != "" {
		m.Reset = true
		m.ResetAfter = millis(fields, traceResetCol)
		m.ResetTTL = number(fields, traceResetTTLCol)
	}
	m.ServerTTL = number(fields, traceServerTTLCol)
	return m
}

func readTrace(path, device string, liveResets bool, stallsFrom int64, groups map[string][]protocol.PolicyDial) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ",")
		if len(fields) < traceFields || !strings.HasSuffix(fields[1], traceJointTail) || fields[3] == localResult {
			continue
		}
		ms, msErr := strconv.ParseInt(fields[0], 10, 64)
		arm, armErr := strconv.Atoi(fields[2])
		if msErr != nil || armErr != nil {
			continue
		}
		recorded := traceLegacyPresets
		if v, err := strconv.Atoi(field(fields, tracePresetsCol)); err == nil {
			recorded = v
		}
		arm, known := protocol.JointArmRemap(arm, recorded, fingerprint.PresetCount())
		if !known {
			continue
		}
		dial := protocol.PolicyDial{Ms: ms, Arm: arm}
		switch fields[5] {
		case traceStageHello:
			dial.Outcome = protocol.DialHandshakeDead
			if fields[4] == "1" {
				dial.Outcome = protocol.DialAlive
			}
			dial.Wire = protocol.ParseWireVerdict(field(fields, traceWireCol))
			dial.Slow = protocol.PolicySlowness(millis(fields, traceLatencyCol), millis(fields, traceConnectCol))
			dial.Measure = traceMeasure(fields)
		case traceStageReset:
			if !liveResets {
				continue
			}
			dial.LiveDeath = true
			dial.Measure.Packets = protocol.ParseWirePackets(field(fields, tracePacketsCol))
		case traceStageEnd:
			if field(fields, traceSymptomCol) != traceSymptomFrom || ms < stallsFrom {
				continue
			}
			dial.LiveDeath = true
			dial.Measure.Packets = protocol.ParseWirePackets(field(fields, tracePacketsCol))
			dial.Measure.LiveDown = int64(number(fields, traceDownCol))
			dial.Measure.LiveFor = millis(fields, traceLatencyCol)
		default:
			continue
		}
		key := device + fields[1]
		groups[key] = append(groups[key], dial)
	}
	return sc.Err()
}

func timeCut(groups map[string][]protocol.PolicyDial, testShare float64) int64 {
	var all []int64
	for _, g := range groups {
		for _, d := range g {
			all = append(all, d.Ms)
		}
	}
	if len(all) == 0 {
		return 0
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	i := min(int(float64(len(all))*(1-testShare)), len(all)-1)
	return all[i]
}

type mechanism struct {
	name    string
	kills   func(arm int) bool
	verdict protocol.WireVerdict
	live    float64
	spares  func(arm int) bool
	slow    float64
	loss    float64
	short   bool
}

type regime struct {
	mechs []mechanism
	until int64
}

type simEnv struct {
	rng        *rand.Rand
	presets    int
	fragmented bool
	blindWire  bool
	noise      float64
	connect    time.Duration
	regimes    []regime
}

const (
	simEpisodeDials    = 300
	simNoneShare       = 0.4
	simFragmentedShare = 0.8
	simBlindShare      = 0.2
	simNoiseMax        = 0.03
	simMechsMax        = 3
	simConnectJitter   = 0.5
)

var (
	simRegimeMin   = time.Minute
	simRegimeMax   = 12 * time.Hour
	simShortMin    = 30 * time.Second
	simShortMax    = 5 * time.Minute
	simEpoch       = time.Date(2026, time.January, 5, 0, 0, 0, 0, time.UTC)
	simStartSpread = 4 * 7 * 24 * time.Hour
	simConnectLo   = 10 * time.Millisecond
	simConnectHi   = 400 * time.Millisecond
	simBurstGap    = 3 * time.Second
	simPauseMin    = 10 * time.Second
	simPauseMax    = 30 * time.Minute
)

func logUniform(rng *rand.Rand, lo, hi time.Duration) time.Duration {
	a, b := math.Log(float64(lo)), math.Log(float64(hi))
	return time.Duration(math.Exp(a + rng.Float64()*(b-a)))
}

func pick(rng *rand.Rand, verdicts ...protocol.WireVerdict) protocol.WireVerdict {
	return verdicts[rng.Intn(len(verdicts))]
}

func (e *simEnv) parts(arm int) (preset, budget int, dropPQ bool) {
	preset, budget = protocol.JointArmParts(arm, e.presets)
	return preset, budget, protocol.JointArmDropPQ(arm, e.presets)
}

func (e *simEnv) catalog() []func() mechanism {
	rng := e.rng
	handshakeKill := func() protocol.WireVerdict {
		return pick(rng, protocol.WireForgedReset, protocol.WireHelloDropped)
	}
	return []func() mechanism{
		func() mechanism {
			blocked := e.someBlockedPresets()
			return mechanism{name: "fingerprint", verdict: handshakeKill(), kills: func(arm int) bool {
				p, _, _ := e.parts(arm)
				return blocked[p]
			}}
		},
		func() mechanism {
			return mechanism{name: "bighello", verdict: handshakeKill(), kills: func(arm int) bool {
				_, _, dropPQ := e.parts(arm)
				return !dropPQ
			}}
		},
		func() mechanism {
			limit := []int{1, 2, 4}[rng.Intn(3)]
			return mechanism{name: "fragdetect", verdict: handshakeKill(), kills: func(arm int) bool {
				_, b, _ := e.parts(arm)
				return b > limit
			}}
		},
		func() mechanism {
			return mechanism{name: "statelesssni", verdict: protocol.WireForgedReset, kills: func(arm int) bool {
				_, b, _ := e.parts(arm)
				return b == 1
			}}
		},
		func() mechanism {
			return mechanism{name: "burstfreeze", verdict: protocol.WireHelloDropped, short: true, kills: func(int) bool { return true }}
		},
		func() mechanism {
			return mechanism{name: volumeFreeze, live: 0.3 + 0.7*rng.Float64(), spares: func(arm int) bool {
				return protocol.JointArmMigrates(arm, e.presets)
			}}
		},
		func() mechanism {
			return mechanism{name: "livereset", live: 0.1 + 0.5*rng.Float64()}
		},
		func() mechanism {
			return mechanism{name: "throttle", slow: 0.3 + 0.5*rng.Float64(), loss: 0.05 + 0.25*rng.Float64()}
		},
		func() mechanism {
			return mechanism{name: "ipban", verdict: protocol.WireHelloDropped, kills: func(int) bool { return true }}
		},
		func() mechanism {
			blocked := e.someBlockedPresets()
			return mechanism{name: "rstrewrite", verdict: protocol.WireCutOff, kills: func(arm int) bool {
				p, _, _ := e.parts(arm)
				return blocked[p]
			}}
		},
		func() mechanism {
			blocked := e.someBlockedPresets()
			return mechanism{name: "draincut", verdict: protocol.WireCutOff, kills: func(arm int) bool {
				p, _, _ := e.parts(arm)
				return blocked[p]
			}}
		},
		func() mechanism {
			return mechanism{name: "connlimit", live: 0.5 + 0.5*rng.Float64(), spares: func(arm int) bool {
				return !protocol.JointArmMigrates(arm, e.presets)
			}}
		},
	}
}

func pickMech(rng *rand.Rand, weights []float64, n int) int {
	if len(weights) != n {
		return rng.Intn(n)
	}
	sum := 0.0
	for _, w := range weights {
		sum += w
	}
	r, acc := rng.Float64()*sum, 0.0
	for i, w := range weights {
		if acc += w; r < acc {
			return i
		}
	}
	return n - 1
}

func newSimEnv(rng *rand.Rand, startMs, endMs int64, holdout map[string]bool, weights []float64) *simEnv {
	e := &simEnv{
		rng:        rng,
		presets:    fingerprint.PresetCount(),
		fragmented: rng.Float64() < simFragmentedShare,
		blindWire:  rng.Float64() < simBlindShare,
		noise:      simNoiseMax * rng.Float64(),
		connect:    logUniform(rng, simConnectLo, simConnectHi),
	}
	catalog := e.catalog()
	for at := startMs; at < endMs; {
		var mechs []mechanism
		short := false
		if rng.Float64() >= simNoneShare {
			for n := 1 + rng.Intn(simMechsMax); len(mechs) < n; {
				m := catalog[pickMech(rng, weights, len(catalog))]()
				if holdout[m.name] {
					continue
				}
				mechs = append(mechs, m)
				short = short || m.short
			}
		}
		span := logUniform(rng, simRegimeMin, simRegimeMax)
		if short {
			span = logUniform(rng, simShortMin, simShortMax)
		}
		at += span.Milliseconds()
		e.regimes = append(e.regimes, regime{mechs: mechs, until: at})
	}
	return e
}

func newSimEnvOne(rng *rand.Rand, startMs, endMs int64, idx int) *simEnv {
	e := &simEnv{rng: rng, presets: fingerprint.PresetCount(), fragmented: rng.Float64() < simFragmentedShare, connect: logUniform(rng, simConnectLo, simConnectHi)}
	catalog := e.catalog()
	for at := startMs; at < endMs; {
		span := logUniform(rng, simRegimeMin, simRegimeMax)
		at += span.Milliseconds()
		e.regimes = append(e.regimes, regime{mechs: []mechanism{catalog[idx]()}, until: at})
	}
	return e
}

const volumeFreeze = "volumefreeze"

var simMechNames = []string{
	"fingerprint", "bighello", "fragdetect", "statelesssni", "burstfreeze", volumeFreeze, "livereset", "throttle", "ipban", "rstrewrite", "draincut", "connlimit",
}

var simMechCount = len(simMechNames)

func mechWeightLine(w []float64) string {
	sum := 0.0
	for _, v := range w {
		sum += v
	}
	parts := make([]string, len(w))
	for i, v := range w {
		parts[i] = fmt.Sprintf("%s %.2f", simMechNames[i], v/sum)
	}
	return strings.Join(parts, ", ")
}

func adversaryWeights(f protocol.FittedPolicy, seed int64, episodes int) []float64 {
	arms := protocol.JointArmCount(fingerprint.PresetCount())
	w := make([]float64, simMechCount)
	for idx := 0; idx < simMechCount; idx++ {
		var policy, oracle, dials float64
		for i := 0; i < episodes; i++ {
			s := seed + int64(idx*7919+i)
			timesRng := rand.New(rand.NewSource(s))
			start := simStart(timesRng)
			times := simTimes(timesRng, start, simEpisodeDials)
			end := times[len(times)-1] + 1
			mk := func() *simEnv { return newSimEnvOne(rand.New(rand.NewSource(s+104729)), start, end, idx) }
			res := f.PlayEpisode(mk(), times)
			policy += float64(res.Alive)
			dials += float64(res.Dials)
			env := mk()
			for _, at := range times {
				if n, l := env.Dial(env.survivor(at, arms), at); n.Alive && !l {
					oracle++
				}
			}
		}
		if dials > 0 {
			w[idx] = math.Max((oracle-policy)/dials, 0)
		}
	}
	floor := 0.0
	for _, v := range w {
		floor += v
	}
	floor = math.Max(floor/float64(simMechCount), 0.05)
	for i := range w {
		w[i] += floor
	}
	return w
}

func (e *simEnv) regimeAt(atMs int64) regime {
	for _, r := range e.regimes {
		if atMs < r.until {
			return r
		}
	}
	return e.regimes[len(e.regimes)-1]
}

func (e *simEnv) Fragmented() bool { return e.fragmented }

func (e *simEnv) fits(arm int) bool {
	_, b, _ := e.parts(arm)
	return e.fragmented || b == 1
}

func (e *simEnv) killedBy(arm int, atMs int64) (mechanism, bool) {
	for _, m := range e.regimeAt(atMs).mechs {
		if m.kills != nil && m.kills(arm) {
			return m, true
		}
	}
	return mechanism{}, false
}

func (m mechanism) spared(arm int) bool { return m.spares != nil && m.spares(arm) }

func (e *simEnv) diesLive(arm int, atMs int64) bool {
	for _, m := range e.regimeAt(atMs).mechs {
		if m.live > 0 && !m.spared(arm) {
			return true
		}
	}
	return false
}

func (e *simEnv) Dial(arm int, atMs int64) (protocol.DialNote, bool) {
	note := protocol.DialNote{Alive: true, Slow: 0.1 * e.rng.Float64()}
	note.Measure.Connect = time.Duration(float64(e.connect) * (1 + simConnectJitter*e.rng.Float64()))
	killer := ""
	if m, killed := e.killedBy(arm, atMs); killed {
		note.Alive, note.Wire, killer = false, m.verdict, m.name
	}
	liveDeath := false
	diedOf := ""
	for _, m := range e.regimeAt(atMs).mechs {
		note.Slow += m.slow
		if !note.Alive {
			continue
		}
		if e.rng.Float64() < m.loss {
			note.Alive, note.Wire = false, protocol.WireRetransmitted
		} else if e.rng.Float64() < m.live && !m.spared(arm) {
			liveDeath = true
			diedOf = m.name
		}
	}
	if note.Alive && e.rng.Float64() < e.noise {
		note.Alive, note.Wire = false, pick(e.rng, protocol.WireHelloDropped, protocol.WireRetransmitted)
	}
	note.Slow = math.Min(note.Slow, 1)
	if e.blindWire {
		note.Wire = protocol.WireNoSignature
	} else {
		note.Measure = simBank.measure(e.rng, killer, arm, note.Alive, note.Measure.Connect)
		if liveDeath {
			note.Measure.Tail = simBank.tail(e.rng, diedOf)
		}
	}
	return note, liveDeath
}

type measureBank struct {
	byArm map[string][]protocol.DialMeasure
	byPQ  map[string][]protocol.DialMeasure
	tails map[string][][]protocol.WirePacket
}

var simBank *measureBank

const standRegimeMargin = 3 * time.Second

var (
	mechRegimes = map[string][]string{
		"bighello":     {"inline_sizecut", "inline_sizecut_rst"},
		"fingerprint":  {"fp_chrome", "fp_firefox", "fp_safari"},
		"fragdetect":   {"packets"},
		"statelesssni": {"sni"},
		"burstfreeze":  {"inline_blackhole"},
		"ipban":        {"inline_blackhole"},
		"rstrewrite":   {"fp_chrome_rewrite"},
		"draincut":     {"fp_safari_drain"},
		"connlimit":    {"conns"},
	}
	unkilledRegimes = []string{"open", "lossy", "freeze", "shape"}
)

func bankKey(regime string, class, alive bool, arm int) string {
	return fmt.Sprintf("%s|%t|%t|%d", regime, class, alive, arm)
}

func (b *measureBank) add(regime string, arm, presets int, alive bool, m protocol.DialMeasure) {
	byArm, byPQ := bankKey(regime, false, alive, protocol.JointArmHello(arm, presets)), bankKey(regime, true, alive, boolInt(protocol.JointArmDropPQ(arm, presets)))
	b.byArm[byArm] = append(b.byArm[byArm], m)
	b.byPQ[byPQ] = append(b.byPQ[byPQ], m)
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (b *measureBank) measure(rng *rand.Rand, killer string, arm int, alive bool, connect time.Duration) protocol.DialMeasure {
	unseen := protocol.DialMeasure{Connect: connect}
	if b == nil {
		return unseen
	}
	regimes := unkilledRegimes
	if killer != "" {
		regimes = mechRegimes[killer]
	}
	pq := boolInt(protocol.JointArmDropPQ(arm, fingerprint.PresetCount()))
	hello := protocol.JointArmHello(arm, fingerprint.PresetCount())
	for _, pool := range []func(string) []protocol.DialMeasure{
		func(r string) []protocol.DialMeasure { return b.byArm[bankKey(r, false, alive, hello)] },
		func(r string) []protocol.DialMeasure { return b.byPQ[bankKey(r, true, alive, pq)] },
	} {
		var found []protocol.DialMeasure
		for _, r := range regimes {
			found = append(found, pool(r)...)
		}
		if len(found) == 0 {
			continue
		}
		m := found[rng.Intn(len(found))]
		if m.Connect > 0 {
			m.ResetAfter = time.Duration(float64(m.ResetAfter) * float64(connect) / float64(m.Connect))
		}
		m.Connect = connect
		return m
	}
	return unseen
}

type standSpan struct {
	name       string
	start, end int64
}

func readRegimes(path string) ([]standSpan, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var spans []standSpan
	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		c := strings.Split(sc.Text(), ",")
		if len(c) < 3 {
			continue
		}
		start, startErr := strconv.ParseInt(c[1], 10, 64)
		end, endErr := strconv.ParseInt(c[2], 10, 64)
		if startErr != nil || endErr != nil {
			continue
		}
		margin := standRegimeMargin.Milliseconds()
		spans = append(spans, standSpan{name: c[0], start: start*1000 + margin, end: end * 1000})
	}
	return spans, sc.Err()
}

func regimeAt(spans []standSpan, ms int64) string {
	for _, s := range spans {
		if ms >= s.start && ms <= s.end {
			return s.name
		}
	}
	return ""
}

func (b *measureBank) fill(dials []protocol.PolicyDial, spans []standSpan) int {
	n := 0
	for _, d := range dials {
		regime := regimeAt(spans, d.Ms)
		if d.LiveDeath && regime != "" && len(d.Measure.Packets) > 0 {
			b.tails[regime] = append(b.tails[regime], d.Measure.Packets)
		}
		if d.LiveDeath || !d.Measure.Captured || regime == "" {
			continue
		}
		b.add(regime, d.Arm, fingerprint.PresetCount(), d.Outcome == protocol.DialAlive, d.Measure)
		n++
	}
	return n
}

func (e *simEnv) survivor(atMs int64, arms int) int {
	fallback := -1
	for arm := 0; arm < arms; arm++ {
		if _, killed := e.killedBy(arm, atMs); !e.fits(arm) || killed {
			continue
		}
		if !e.diesLive(arm, atMs) {
			return arm
		}
		if fallback < 0 {
			fallback = arm
		}
	}
	return max(fallback, 0)
}

func simStart(rng *rand.Rand) int64 {
	return simEpoch.UnixMilli() + rng.Int63n(simStartSpread.Milliseconds())
}

func simTimes(rng *rand.Rand, startMs int64, n int) []int64 {
	times := make([]int64, n)
	at := startMs
	for i := range times {
		gap := time.Duration(rng.Float64() * float64(simBurstGap))
		if rng.Intn(2) == 0 {
			gap = logUniform(rng, simPauseMin, simPauseMax)
		}
		at += max(1, gap.Milliseconds())
		times[i] = at
	}
	return times
}

type behavior func(rng *rand.Rand, fits func(int) bool, last int, lastAlive bool) int

func dirichletBehavior(rng *rand.Rand, arms int) behavior {
	weights := make([]float64, arms)
	sum := 0.0
	for i := range weights {
		weights[i] = rng.ExpFloat64()
		sum += weights[i]
	}
	point, mass := rng.Intn(arms), rng.Float64()
	for i := range weights {
		weights[i] = (1 - mass) * weights[i] / sum
	}
	weights[point] += mass
	return func(rng *rand.Rand, fits func(int) bool, _ int, _ bool) int {
		for {
			r, acc := rng.Float64(), 0.0
			for arm, w := range weights {
				acc += w
				if r < acc && fits(arm) {
					return arm
				}
			}
			if arm := rng.Intn(arms); fits(arm) {
				return arm
			}
		}
	}
}

func stickyBehavior(arms int) behavior {
	return func(rng *rand.Rand, fits func(int) bool, last int, lastAlive bool) int {
		if last >= 0 && lastAlive && fits(last) {
			return last
		}
		for {
			if arm := rng.Intn(arms); fits(arm) {
				return arm
			}
		}
	}
}

func simEpisode(rng *rand.Rand, holdout map[string]bool, weights []float64) []protocol.PolicyStep {
	arms := protocol.JointArmCount(fingerprint.PresetCount())
	start := simStart(rng)
	times := simTimes(rng, start, simEpisodeDials)
	env := newSimEnv(rng, start, times[len(times)-1]+1, holdout, weights)
	act := stickyBehavior(arms)
	if rng.Intn(2) == 0 {
		act = dirichletBehavior(rng, arms)
	}
	steps := make([]protocol.PolicyStep, 0, len(times))
	last, lastAlive := -1, false
	for _, at := range times {
		arm := act(rng, env.fits, last, lastAlive)
		note, liveDeath := env.Dial(arm, at)
		outcome := protocol.DialHandshakeDead
		switch {
		case note.Alive && liveDeath:
			outcome = protocol.DialLiveDead
		case note.Alive:
			outcome = protocol.DialAlive
		}
		steps = append(steps, protocol.PolicyStep{Arm: arm, Outcome: outcome, Wire: note.Wire, AtMs: at, Slow: note.Slow, Measure: note.Measure})
		last, lastAlive = arm, outcome == protocol.DialAlive
	}
	return steps
}

func simEpisodes(seed int64, n int, holdout map[string]bool, weights []float64) [][]protocol.PolicyStep {
	rng := rand.New(rand.NewSource(seed))
	out := make([][]protocol.PolicyStep, n)
	for i := range out {
		out[i] = simEpisode(rng, holdout, weights)
	}
	return out
}

func reportClosedLoop(name string, f protocol.FittedPolicy, seed int64, episodes, fixedArm int) {
	cl := evaluateClosedLoop(f, seed+3, episodes, fixedArm)
	fmt.Printf("closed loop on %d simulated censors, %s weights: net %.4f, oracle %.4f, fixed arm %d %.4f\n",
		episodes, name, cl.Policy, cl.Oracle, fixedArm, cl.Fixed)
}

type closedLoop struct {
	Policy, Oracle, Fixed float64
}

func evaluateClosedLoop(f protocol.FittedPolicy, seed int64, episodes, fixedArm int) closedLoop {
	arms := protocol.JointArmCount(fingerprint.PresetCount())
	var policy, oracle, fixed, dials float64
	for i := 0; i < episodes; i++ {
		episodeSeed := seed + int64(i)
		build := func() (*simEnv, []int64) {
			rng := rand.New(rand.NewSource(episodeSeed))
			start := simStart(rng)
			times := simTimes(rng, start, simEpisodeDials)
			return newSimEnv(rng, start, times[len(times)-1]+1, nil, nil), times
		}
		env, times := build()
		res := f.PlayEpisode(env, times)
		policy += float64(res.Alive)
		dials += float64(res.Dials)

		env, times = build()
		for _, at := range times {
			if note, live := env.Dial(env.survivor(at, arms), at); note.Alive && !live {
				oracle++
			}
		}
		env, times = build()
		for _, at := range times {
			arm := fixedArm
			if !env.fits(arm) {
				arm = env.survivor(at, arms)
			}
			if note, live := env.Dial(arm, at); note.Alive && !live {
				fixed++
			}
		}
	}
	return closedLoop{Policy: policy / dials, Oracle: oracle / dials, Fixed: fixed / dials}
}

func relianceDocs(paths string) [][]protocol.PolicyStep {
	groups := map[string][]protocol.PolicyDial{}
	for i, path := range strings.Split(paths, ",") {
		if err := readTrace(strings.TrimSpace(path), fmt.Sprintf("reliance%d:", i), false, 0, groups); err != nil {
			fmt.Fprintf(os.Stderr, "policyfit: %v\n", err)
			os.Exit(1)
		}
	}
	contexts := make([]string, 0, len(groups))
	for ctx := range groups {
		contexts = append(contexts, ctx)
	}
	sort.Strings(contexts)
	docs := make([][]protocol.PolicyStep, 0, len(contexts))
	for _, ctx := range contexts {
		docs = append(docs, protocol.PolicySteps(groups[ctx]))
	}
	return docs
}

func reportNovelty(name string, f protocol.FittedPolicy, docs [][]protocol.PolicyStep) {
	distances, bars := f.NoveltyDistances(docs)
	for _, outcome := range []protocol.DialOutcome{protocol.DialHandshakeDead, protocol.DialLiveDead} {
		d := distances[outcome]
		if len(d) == 0 {
			fmt.Printf("%s, outcome %d: no failed dials with packets\n", name, outcome)
			continue
		}
		sort.Float64s(d)
		novel := 0
		for _, v := range d {
			if v > bars[outcome] {
				novel++
			}
		}
		at := func(q float64) float64 { return d[int(q*float64(len(d)-1))] }
		fmt.Printf("%s, outcome %d: %d of %d past the bar %.0f; distance median %.0f, 90th percentile %.0f, max %.0f\n",
			name, outcome, novel, len(d), bars[outcome], at(0.5), at(0.9), d[len(d)-1])
	}
	fmt.Printf("%s: the dials past the bars, played in order, form %d new block patterns\n", name, f.PatternReplay(docs))
}

func reportReliance(name string, f protocol.FittedPolicy, docs [][]protocol.PolicyStep) {
	orig, switched, dials := f.PacketReliance(docs)
	fmt.Printf("%s weights on %d dials: log-loss %.5f, with packets switched between dials %.5f, model reliance on packets %.3f\n",
		name, dials, orig, switched, switched/orig)
}

func (e *simEnv) someBlockedPresets() map[int]bool {
	blocked := map[int]bool{}
	for len(blocked) == 0 || len(blocked) == e.presets {
		blocked = map[int]bool{}
		for p := 0; p < e.presets; p++ {
			if e.rng.Intn(2) == 0 {
				blocked[p] = true
			}
		}
	}
	return blocked
}

var deathRegimes = map[string][]string{volumeFreeze: {"freeze"}, "connlimit": {"conns"}}

func (b *measureBank) tail(rng *rand.Rand, killer string) []protocol.WirePacket {
	if b == nil {
		return nil
	}
	var found [][]protocol.WirePacket
	for _, r := range deathRegimes[killer] {
		found = append(found, b.tails[r]...)
	}
	if len(found) == 0 {
		return nil
	}
	return found[rng.Intn(len(found))]
}
