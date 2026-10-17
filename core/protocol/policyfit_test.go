package protocol

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestFrozenWeightsExportUnchanged(t *testing.T) {
	src, err := FittedPolicy{p: newPolParams()}.GoSource()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("policy_weights.go")
	if err != nil {
		t.Fatal(err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(src, want) {
		t.Fatal("exporting the frozen weights does not reproduce policy_weights.go")
	}
}

func TestPolicyDocsCutAtSilence(t *testing.T) {
	gap := 30 * time.Second
	dials := []PolicyDial{
		{Ms: 2000, Arm: 5, Alive: true},
		{Ms: 1000, Arm: 5, Alive: false},
		{Ms: 2000 + gap.Milliseconds() + 1, Arm: 9, Alive: true},
		{Ms: 3000, Arm: polArms, Alive: true},
	}
	docs := PolicyDocs(dials, gap)
	want := [][]int{
		{polBOS, polDial(5, false), polDial(5, true)},
		{polBOS, polDial(9, true)},
	}
	if len(docs) != len(want) {
		t.Fatalf("got %d docs, want %d: %v", len(docs), len(want), docs)
	}
	for i := range want {
		if !equalInts(docs[i], want[i]) {
			t.Fatalf("doc %d = %v, want %v", i, docs[i], want[i])
		}
	}
}

func TestFrozenPolicyHandlesTheCensorItWasTrainedOn(t *testing.T) {
	p := newPolParams()
	dials := censorTrials * censorLength
	for _, mode := range policyCensors {
		t.Logf("%s: frozen policy lost %d of %d dials", mode, censorLost(p, mode), dials)
	}
	if lost := censorLost(p, censorRehearsal); lost*4 > dials {
		t.Fatalf("frozen policy lost %d of %d dials on the rehearsal censor", lost, dials)
	}
}

func TestFitPolicyLearnsAnArmThatAlwaysDies(t *testing.T) {
	var train, val, test [][]int
	for i := 0; i < 60; i++ {
		doc := []int{polBOS}
		for j := 0; j < 12; j++ {
			doc = append(doc, polDial(4, false), polDial(5, true))
		}
		switch {
		case i < 40:
			train = append(train, doc)
		case i < 48:
			val = append(val, doc)
		default:
			test = append(test, doc)
		}
	}
	_, report := FitPolicy(train, val, test, PolicyFitConfig{Steps: 600, EvalEvery: 100, Seed: 1})
	if report.FittedLoss >= report.FrozenLoss {
		t.Fatalf("fitting did not help: frozen %.4f fitted %.4f", report.FrozenLoss, report.FittedLoss)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
