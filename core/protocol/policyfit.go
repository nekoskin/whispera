package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"go/format"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

type PolicyDial struct {
	Ms        int64
	Arm       int
	Outcome   DialOutcome
	Wire      WireVerdict
	Slow      float64
	Measure   DialMeasure
	LiveDeath bool
}

func PolicySteps(dials []PolicyDial) []PolicyStep {
	sorted := append([]PolicyDial(nil), dials...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Ms < sorted[j].Ms })
	var steps []PolicyStep
	for _, d := range sorted {
		if d.Arm < 0 || d.Arm >= polArms {
			continue
		}
		if d.LiveDeath {
			markLiveDeath(steps, d.Arm, d.Measure)
			continue
		}
		steps = append(steps, PolicyStep{Arm: d.Arm, Outcome: d.Outcome, Wire: d.Wire, AtMs: d.Ms, Slow: d.Slow, Measure: d.Measure})
	}
	return steps
}

func markLiveDeath(steps []PolicyStep, arm int, live DialMeasure) {
	for i := len(steps) - 1; i >= 0 && i >= len(steps)-polBlock; i-- {
		if steps[i].Arm == arm && steps[i].Outcome == DialAlive {
			steps[i].Outcome = DialLiveDead
			steps[i].Measure.LiveDown, steps[i].Measure.LiveFor, steps[i].Measure.Tail = live.LiveDown, live.LiveFor, live.Packets
			return
		}
	}
}

type PolicyFitConfig struct {
	Steps          int
	Batch          int
	EvalEvery      int
	Seed           int64
	Synthetic      [][]PolicyStep
	SyntheticVal   [][]PolicyStep
	SyntheticShare float64
	Stand          [][]PolicyStep
	StandVal       [][]PolicyStep
	NoveltyAlpha   float64
}

type PolicyFitReport struct {
	Steps            int
	BestStep         int
	ValLoss          float64
	SyntheticValLoss float64
	TestDials        int
	ConstantLoss     float64
	ArmRateLoss      float64
	LastOutcomeLoss  float64
	ShippedLoss      float64
	FittedLoss       float64
	Anchor           float64
	AnchorLoss       map[float64]float64
	TrustedShare     float64
	TrustedLoss      float64
	DistrustedLoss   float64
	CheckedLoss      float64
	StandValLoss     float64
	StandValSwitched float64
}

func (r PolicyFitReport) Better() bool {
	return r.BestStep > 0 && r.FittedLoss < r.ConstantLoss && r.FittedLoss < r.ArmRateLoss
}

type FittedPolicy struct {
	p       *polParams
	anchor  float64
	novelty polNovelty
}

func ShippedPolicy() FittedPolicy {
	return FittedPolicy{p: newPolParams(), anchor: polAnchor, novelty: shippedNovelty()}
}

func (t *polTrainer) novelty(p *polParams, fit, calibration [][]PolicyStep, alpha float64) (polNovelty, error) {
	cfg := polTrainConfigFor(polAnchor)
	cfg.NoveltyAlpha = alpha
	table := newPolPacketTable()
	req := polTrainRequest{Op: "novelty", Config: &cfg, Live: p.mats(), Docs: polDocsOf(fit, table), Calibration: polDocsOf(calibration, table)}
	req.Packets = table.rows
	reply, err := t.call(req)
	if err != nil {
		return polNovelty{}, err
	}
	if reply.Novelty == nil {
		return polNovelty{}, errors.New("the trainer sent no packet Gaussians")
	}
	return *reply.Novelty, nil
}

func PolicyNovelty(python, script string, f FittedPolicy, fit, calibration [][]PolicyStep, alpha float64) (FittedPolicy, error) {
	t := newPolTrainer(python, script)
	defer t.close()
	novelty, err := t.novelty(f.p, fit, calibration, alpha)
	if err != nil {
		return f, err
	}
	f.novelty = novelty
	return f, nil
}

func (f FittedPolicy) NoveltyDistances(docs [][]PolicyStep) (distances map[DialOutcome][]float64, bars map[DialOutcome]float64) {
	distances, bars = map[DialOutcome][]float64{}, map[DialOutcome]float64{}
	for _, d := range docs {
		for _, s := range d {
			pkts := s.Measure.Packets
			if s.Outcome == DialLiveDead {
				pkts = s.Measure.Tail
			}
			g, class, ok := f.novelty.of(s.Outcome)
			if !ok || len(pkts) == 0 {
				continue
			}
			bars[s.Outcome] = g.Bar[class]
			distances[s.Outcome] = append(distances[s.Outcome], g.distance(f.p.encodePackets(pkts), g.Mean[class]))
		}
	}
	return distances, bars
}

func (f FittedPolicy) PatternReplay(docs [][]PolicyStep) int {
	o := newOnlinePolicy()
	o.frozen, o.novelty = f.p, f.novelty
	for _, d := range docs {
		for _, s := range d {
			pkts := s.Measure.Packets
			if s.Outcome == DialLiveDead {
				pkts = s.Measure.Tail
			}
			o.NotePattern(s.Outcome, s.Wire, pkts)
		}
	}
	return o.lastPattern
}

func (f FittedPolicy) NoveltySummary() string {
	return fmt.Sprintf("dial packets per outcome %v fitted, %v calibrated, distance bars %v; death tails %v fitted, %v calibrated, bar %v",
		f.novelty.Opening.Count, f.novelty.Opening.Calibrated, f.novelty.Opening.Bar, f.novelty.Tail.Count, f.novelty.Tail.Calibrated, f.novelty.Tail.Bar)
}

var polAnchorGrid = []float64{1e-1, 1e-2, 1e-3, 1e-4}

const polExportDecimals = 1e6

func PolicyBlocks(docs [][]PolicyStep, block, every int) (train, val [][]PolicyStep) {
	for _, d := range docs {
		for start, n := 0, 0; start < len(d); start, n = start+block, n+1 {
			b := d[start:min(start+block, len(d))]
			if every > 0 && n%every == every-1 {
				val = append(val, b)
			} else {
				train = append(train, b)
			}
		}
	}
	return train, val
}

type polFitRequest struct {
	Steps          int       `json:"steps"`
	Batch          int       `json:"batch"`
	EvalEvery      int       `json:"eval_every"`
	Seed           int64     `json:"seed"`
	SyntheticShare float64   `json:"synthetic_share"`
	Anchors        []float64 `json:"anchors"`
	OnlineEvery    int       `json:"online_every"`
	Train          []polDoc  `json:"train"`
	Val            []polDoc  `json:"val"`
	Test           []polDoc  `json:"test"`
	Synthetic      []polDoc  `json:"synthetic"`
	SyntheticVal   []polDoc  `json:"synthetic_val"`
}

type polFitReply struct {
	BestStep         int                `json:"best_step"`
	ValLoss          float64            `json:"val_loss"`
	SyntheticValLoss float64            `json:"synthetic_val_loss"`
	AnchorLoss       map[string]float64 `json:"anchor_loss"`
}

func firstNonEmpty(groups ...[][]PolicyStep) []PolicyStep {
	for _, docs := range groups {
		for _, d := range docs {
			if len(d) > 0 {
				return polWindow(d, polBlock*polBlock)
			}
		}
	}
	return nil
}

func FitPolicy(python, script string, train, val, test [][]PolicyStep, cfg PolicyFitConfig) (FittedPolicy, PolicyFitReport, error) {
	t := newPolTrainer(python, script)
	defer t.close()
	trainCfg := polTrainConfigFor(polAnchor)
	probe := firstNonEmpty(test, val, train)
	table := newPolPacketTable()
	fit := &polFitRequest{
		Steps: cfg.Steps, Batch: cfg.Batch, EvalEvery: cfg.EvalEvery, Seed: cfg.Seed, SyntheticShare: cfg.SyntheticShare,
		Anchors: polAnchorGrid, OnlineEvery: polOnlineStepEvery,
		Train:     polDocsOf(append(append([][]PolicyStep(nil), train...), cfg.Stand...), table),
		Val:       polDocsOf(append(append([][]PolicyStep(nil), val...), cfg.StandVal...), table),
		Test:      polDocsOf(test, table),
		Synthetic: polDocsOf(cfg.Synthetic, table), SyntheticVal: polDocsOf(cfg.SyntheticVal, table),
	}
	probeDoc := polDocOf(probe, table)
	reply, err := t.call(polTrainRequest{Op: "fit", Config: &trainCfg, Docs: []polDoc{probeDoc}, Packets: table.rows, Fit: fit})
	if err != nil {
		return FittedPolicy{}, PolicyFitReport{}, err
	}
	best, err := polAccept(reply, probe)
	if err != nil {
		return FittedPolicy{}, PolicyFitReport{}, err
	}
	if reply.Fit == nil {
		return FittedPolicy{}, PolicyFitReport{}, fmt.Errorf("the trainer sent no fit report")
	}
	best.round(polExportDecimals)
	seen := append(append([][]PolicyStep(nil), train...), cfg.Stand...)
	calibration := append(append([][]PolicyStep(nil), val...), cfg.StandVal...)
	novelty, err := t.novelty(best, seen, calibration, cfg.NoveltyAlpha)
	if err != nil {
		return FittedPolicy{}, PolicyFitReport{}, err
	}

	report := PolicyFitReport{
		Steps:            cfg.Steps,
		BestStep:         reply.Fit.BestStep,
		ValLoss:          reply.Fit.ValLoss,
		SyntheticValLoss: reply.Fit.SyntheticValLoss,
		ConstantLoss:     constantLoss(train, test),
		ArmRateLoss:      armRateLoss(train, test),
		LastOutcomeLoss:  lastOutcomeLoss(train, test),
		AnchorLoss:       map[float64]float64{},
		Anchor:           polAnchor,
	}
	report.ShippedLoss, _ = conditionalLoss(newPolParams(), test)
	report.FittedLoss, report.TestDials = conditionalLoss(best, test)
	report.TrustedShare, report.TrustedLoss, report.DistrustedLoss = checkHeadStats(best, test)
	report.CheckedLoss = checkedReplayLoss(best, test)
	report.StandValLoss, report.StandValSwitched, _ = packetReliance(best, cfg.StandVal)
	for key, loss := range reply.Fit.AnchorLoss {
		lambda, err := strconv.ParseFloat(key, 64)
		if err != nil {
			continue
		}
		report.AnchorLoss[lambda] = loss
		if picked, ok := report.AnchorLoss[report.Anchor]; !ok || loss < picked {
			report.Anchor = lambda
		}
	}
	return FittedPolicy{p: best, anchor: report.Anchor, novelty: novelty}, report, nil
}

func (p *polParams) round(scale float64) {
	p.each(func(_ string, m [][]float64) {
		for _, row := range m {
			for j, v := range row {
				row[j] = math.Round(v*scale) / scale
			}
		}
	})
}

func conditionalLoss(p *polParams, docs [][]PolicyStep) (float64, int) {
	total, n := 0.0, 0
	for _, d := range docs {
		probs, _ := p.conditional(d)
		for i, prob := range probs {
			total += outcomeLoss(prob, d[i].Outcome == DialAlive)
			n++
		}
	}
	if n == 0 {
		return 0, 0
	}
	return total / float64(n), n
}

func checkHeadStats(p *polParams, docs [][]PolicyStep) (share, trusted, distrusted float64) {
	var nTrusted, nDistrusted, lossTrusted, lossDistrusted float64
	for _, d := range docs {
		probs, trust := p.conditional(d)
		for i := range probs {
			loss := outcomeLoss(probs[i], d[i].Outcome == DialAlive)
			if trust[i] >= polAliveBar {
				nTrusted, lossTrusted = nTrusted+1, lossTrusted+loss
			} else {
				nDistrusted, lossDistrusted = nDistrusted+1, lossDistrusted+loss
			}
		}
	}
	if n := nTrusted + nDistrusted; n > 0 {
		share = nTrusted / n
	}
	if nTrusted > 0 {
		trusted = lossTrusted / nTrusted
	}
	if nDistrusted > 0 {
		distrusted = lossDistrusted / nDistrusted
	}
	return share, trusted, distrusted
}

func checkedReplayLoss(p *polParams, docs [][]PolicyStep) float64 {
	const ctx = "replay"
	total, n := 0.0, 0
	for _, d := range docs {
		o := newOnlinePolicy()
		o.live = p
		for _, s := range d {
			at := s.AtMs
			o.now = func() time.Time { return time.UnixMilli(at) }
			alive := s.Outcome == DialAlive
			o.chain[ctx] = s.Measure.chainFeatures()
			total += outcomeLoss(o.verdictLocked(ctx, at, polArms).mixed[s.Arm], alive)
			n++
			o.checkLocked(ctx, s.Arm, alive)
			o.deaths[ctx] = rememberDeath(o.deaths[ctx], s, at)
			o.dials[ctx] = polWindow(append(o.dials[ctx], s), polBlock)
		}
	}
	if n == 0 {
		return 0
	}
	return total / float64(n)
}

func aliveRate(docs [][]PolicyStep) float64 {
	alive, n := 0.0, 0.0
	for _, d := range docs {
		for _, s := range d {
			n++
			if s.Outcome == DialAlive {
				alive++
			}
		}
	}
	return (alive + 1) / (n + 2)
}

func meanLoss(docs [][]PolicyStep, predict func(doc []PolicyStep, i int) float64) float64 {
	total, n := 0.0, 0
	for _, d := range docs {
		for i, s := range d {
			total += outcomeLoss(predict(d, i), s.Outcome == DialAlive)
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return total / float64(n)
}

func constantLoss(train, test [][]PolicyStep) float64 {
	rate := aliveRate(train)
	return meanLoss(test, func([]PolicyStep, int) float64 { return rate })
}

func armRateLoss(train, test [][]PolicyStep) float64 {
	var alive, seen [polArms]float64
	for _, d := range train {
		for _, s := range d {
			seen[s.Arm]++
			if s.Outcome == DialAlive {
				alive[s.Arm]++
			}
		}
	}
	return meanLoss(test, func(d []PolicyStep, i int) float64 {
		a := d[i].Arm
		return (alive[a] + 1) / (seen[a] + 2)
	})
}

func lastOutcomeLoss(train, test [][]PolicyStep) float64 {
	rate := aliveRate(train)
	return meanLoss(test, func(d []PolicyStep, i int) float64 {
		for j := i - 1; j >= 0; j-- {
			if d[j].Arm != d[i].Arm {
				continue
			}
			if d[j].Outcome == DialAlive {
				return rate
			}
			return 1 - rate
		}
		return rate
	})
}

func (f FittedPolicy) GoSource() ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "package protocol\n\nconst (\n")
	for _, c := range []struct {
		name string
		v    int
	}{{"polEmbd", polEmbd}, {"polHead", polHead}, {"polBlock", polBlock}, {"polLayer", len(f.p.layers)}, {"polArms", polArms}, {"polFeatDim", polFeatDim}} {
		fmt.Fprintf(&b, "\t%s = %d\n", c.name, c.v)
	}
	fmt.Fprintf(&b, "\tpolAnchor = %g\n)\n", f.anchor)
	flat := []struct {
		name string
		m    [][]float64
	}{
		{"polArm", f.p.arm}, {"polWin", f.p.win}, {"polOutcome", f.p.outcome}, {"polWire", f.p.wire}, {"polMeas", f.p.meas}, {"polPkt", f.p.pkt}, {"polPktTail", f.p.pktTail},
		{"polGapIn", f.p.gapIn}, {"polSlowIn", f.p.slowIn}, {"polGapQuery", f.p.gapQuery}, {"polChainQuery", f.p.chainQuery},
		{"polBosIn", f.p.bosIn}, {"polWpe", f.p.wpe}, {"polRecent", f.p.recent},
		{"polClockIn", f.p.clock}, {"polClockQuery", f.p.clockQuery},
		{"polCheck", f.p.check}, {"polCheckBias", f.p.checkBias},
		{"polOpeningMean", f.novelty.Opening.Mean}, {"polOpeningPrecision", f.novelty.Opening.Precision}, {"polOpeningBar", polRowOf(f.novelty.Opening.Bar)},
		{"polTailMean", f.novelty.Tail.Mean}, {"polTailPrecision", f.novelty.Tail.Precision}, {"polTailBar", polRowOf(f.novelty.Tail.Bar)},
	}
	for _, m := range flat {
		fmt.Fprintf(&b, "\nvar %s = [][]float64{\n", m.name)
		writeRows(&b, m.m, "\t")
		b.WriteString("}\n")
	}
	for i, name := range []string{"polWq", "polWk", "polWv", "polWo", "polFc1", "polFc2"} {
		fmt.Fprintf(&b, "\nvar %s = [][][]float64{\n", name)
		for l := range f.p.layers {
			b.WriteString("\t{\n")
			writeRows(&b, *f.p.layers[l].all()[i], "\t\t")
			b.WriteString("\t},\n")
		}
		b.WriteString("}\n")
	}
	for i, name := range []string{"polGRUIh", "polGRUHh", "polGRUBih", "polGRUBhh"} {
		fmt.Fprintf(&b, "\nvar %s = [][][]float64{\n", name)
		for cell := range f.p.gru {
			b.WriteString("\t{\n")
			writeRows(&b, *f.p.gru[cell].all()[i], "\t\t")
			b.WriteString("\t},\n")
		}
		b.WriteString("}\n")
	}
	return format.Source(b.Bytes())
}

func polRowOf(v []float64) [][]float64 {
	if len(v) == 0 {
		return nil
	}
	return [][]float64{v}
}

func writeRows(b *bytes.Buffer, m [][]float64, indent string) {
	for _, row := range m {
		cells := make([]string, len(row))
		for j, v := range row {
			cells[j] = fmt.Sprintf("%.6f", v)
		}
		fmt.Fprintf(b, "%s{%s},\n", indent, strings.Join(cells, ", "))
	}
}

type PolicyEnv interface {
	Fragmented() bool
	Dial(arm int, atMs int64) (note DialNote, liveDeath bool)
}

type EpisodeResult struct {
	Dials int
	Alive int
}

func (f FittedPolicy) PlayEpisode(env PolicyEnv, times []int64) EpisodeResult {
	const ctx = "episode"
	o := newOnlinePolicy()
	o.live, o.frozen, o.anchor = f.p.clone(), f.p.clone(), f.anchor
	var clock time.Time
	o.now = func() time.Time { return clock }
	fits := jointArmFits(env.Fragmented())
	var res EpisodeResult
	for _, at := range times {
		clock = time.UnixMilli(at)
		arm := o.Select(ctx, polArms, fits)
		note, liveDeath := env.Dial(arm, at)
		id := o.NoteDial(ctx, arm, note)
		if liveDeath {
			o.NoteLiveDeath(ctx, id, 0, 0, note.Measure.Tail)
		}
		res.Dials++
		if note.Alive && !liveDeath {
			res.Alive++
		}
	}
	return res
}

func (f FittedPolicy) PacketReliance(docs [][]PolicyStep) (orig, switched float64, dials int) {
	return packetReliance(f.p, docs)
}

func packetReliance(p *polParams, docs [][]PolicyStep) (orig, switched float64, dials int) {
	orig, dials = conditionalLoss(p, docs)
	moved := make([][]PolicyStep, len(docs))
	var slots []*PolicyStep
	for d, doc := range docs {
		moved[d] = append([]PolicyStep(nil), doc...)
		for i := range moved[d] {
			slots = append(slots, &moved[d][i])
		}
	}
	half := len(slots) / 2
	for i := 0; i < half; i++ {
		a, b := slots[i], slots[i+half]
		a.Measure.Packets, b.Measure.Packets = b.Measure.Packets, a.Measure.Packets
	}
	switched, _ = conditionalLoss(p, moved)
	return orig, switched, dials
}
