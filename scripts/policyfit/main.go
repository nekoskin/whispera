package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

const (
	traceFields    = 6
	traceStage     = "handshake"
	traceJointTail = "|joint"
)

var localResult = strconv.Itoa(int(protocol.HandshakeLocal))

func main() {
	traces := flag.String("trace", "", "Comma-separated dial traces (dials.csv) from every device")
	out := flag.String("out", "", "Write the new weights here, only when they beat the frozen ones")
	steps := flag.Int("steps", 20000, "Training steps")
	evalEvery := flag.Int("eval", 1000, "Validate every this many steps and keep the best")
	rehearsal := flag.Float64("rehearsal", 0.3, "Share of steps spent on the censor the frozen weights were trained on")
	seed := flag.Int64("seed", 7, "Random seed")
	gap := flag.Duration("gap", 30*time.Second, "Silence that starts a new session")
	valShare := flag.Float64("val", 0.1, "Share of the trace, by time, used to pick the best step")
	testShare := flag.Float64("test", 0.2, "Most recent share of the trace held out for the verdict")
	slack := flag.Float64("slack", 0.05, "How many more dials the fitted policy may lose on the censor, as a share")
	flag.Parse()
	if *traces == "" {
		fmt.Fprintln(os.Stderr, "policyfit: -trace is required")
		os.Exit(2)
	}

	groups := map[string][]protocol.PolicyDial{}
	for i, path := range strings.Split(*traces, ",") {
		if err := readTrace(strings.TrimSpace(path), fmt.Sprintf("%d:", i), groups); err != nil {
			fmt.Fprintf(os.Stderr, "policyfit: %v\n", err)
			os.Exit(1)
		}
	}
	trainCut, testCut := timeCuts(groups, *valShare, *testShare)
	var train, val, test [][]int
	dials := 0
	for _, g := range groups {
		dials += len(g)
		var a, b, c []protocol.PolicyDial
		for _, d := range g {
			switch {
			case d.Ms < trainCut:
				a = append(a, d)
			case d.Ms < testCut:
				b = append(b, d)
			default:
				c = append(c, d)
			}
		}
		train = append(train, protocol.PolicyDocs(a, *gap)...)
		val = append(val, protocol.PolicyDocs(b, *gap)...)
		test = append(test, protocol.PolicyDocs(c, *gap)...)
	}
	fmt.Printf("%d dials in %d contexts: %d train, %d validation, %d test sessions\n",
		dials, len(groups), len(train), len(val), len(test))

	fitted, r := protocol.FitPolicy(train, val, test, protocol.PolicyFitConfig{
		Steps: *steps, EvalEvery: *evalEvery, Rehearsal: *rehearsal, Seed: *seed,
	})
	fmt.Printf("best step %d of %d\n", r.BestStep, r.Steps)
	fmt.Printf("held-out loss on %d dials: per-arm rate %.5f, frozen %.5f, fitted %.5f\n",
		r.TestDials, r.ArmRateLoss, r.FrozenLoss, r.FittedLoss)
	modes := make([]string, 0, len(r.FrozenLost))
	for mode := range r.FrozenLost {
		modes = append(modes, mode)
	}
	sort.Strings(modes)
	for _, mode := range modes {
		fmt.Printf("censor %s: frozen lost %d, fitted lost %d of %d dials\n",
			mode, r.FrozenLost[mode], r.FittedLost[mode], r.CensorDials)
	}
	if !r.Better(*slack) {
		fmt.Println("verdict: keep the frozen weights")
		return
	}
	fmt.Println("verdict: the fitted weights are better")
	if *out == "" {
		return
	}
	src, err := fitted.GoSource()
	if err != nil {
		fmt.Fprintf(os.Stderr, "policyfit: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "policyfit: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n", *out)
}

func readTrace(path, device string, groups map[string][]protocol.PolicyDial) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ",")
		if len(fields) < traceFields || fields[5] != traceStage || !strings.HasSuffix(fields[1], traceJointTail) || fields[3] == localResult {
			continue
		}
		ms, msErr := strconv.ParseInt(fields[0], 10, 64)
		arm, armErr := strconv.Atoi(fields[2])
		if msErr != nil || armErr != nil {
			continue
		}
		key := device + fields[1]
		groups[key] = append(groups[key], protocol.PolicyDial{Ms: ms, Arm: arm, Alive: fields[4] == "1"})
	}
	return sc.Err()
}

func timeCuts(groups map[string][]protocol.PolicyDial, valShare, testShare float64) (int64, int64) {
	var all []int64
	for _, g := range groups {
		for _, d := range g {
			all = append(all, d.Ms)
		}
	}
	if len(all) == 0 {
		return 0, 0
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	at := func(share float64) int64 {
		i := int(float64(len(all)) * share)
		if i >= len(all) {
			i = len(all) - 1
		}
		return all[i]
	}
	return at(1 - valShare - testShare), at(1 - testShare)
}
