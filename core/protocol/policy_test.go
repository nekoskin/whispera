package protocol

import (
	"math"
	"testing"
)

// Values printed by neural/mutate.py's probe after training and export; they
// pin the Go forward pass to the trainer's own outputs.
func TestPolicyMatchesTrainer(t *testing.T) {
	cases := []struct {
		tokens []int
		want   []float64
	}{
		{tokens: []int{24, 9}, want: []float64{0.328701, 0.125146, 0.040114, 0.012062, 0.827521, 0.583620, 0.290520, 0.106846, 0.785625, 0.517054, 0.238256, 0.083725}},
		{tokens: []int{24, 2, 0, 18, 9, 13}, want: []float64{0.503433, 0.235941, 0.085971, 0.027851, 0.844591, 0.623398, 0.335191, 0.133126, 0.732601, 0.454889, 0.202663, 0.071856}},
		{tokens: []int{16, 11, 4, 23, 6, 8, 14, 0, 7, 19, 14, 0, 3, 2, 22, 15}, want: []float64{0.644277, 0.364535, 0.153756, 0.054416, 0.865497, 0.670843, 0.392287, 0.169747, 0.678302, 0.400416, 0.174589, 0.062787}},
		{tokens: []int{23, 11, 18, 11, 18, 9, 21, 10, 18, 2, 15, 5, 22, 15, 18, 14}, want: []float64{0.849176, 0.705338, 0.504386, 0.302006, 0.872440, 0.744102, 0.552826, 0.344522, 0.336080, 0.177101, 0.083829, 0.037445}},
	}
	for i, c := range cases {
		got := policyArmScores(c.tokens, polArms)
		if len(got) != len(c.want) {
			t.Fatalf("case %d: %d scores, want %d", i, len(got), len(c.want))
		}
		for a := range got {
			if math.Abs(got[a]-c.want[a]) > 1e-4 {
				t.Errorf("case %d arm %d: got %.6f, trainer says %.6f", i, a, got[a], c.want[a])
			}
		}
	}
}

func TestOnlineForwardMatchesFrozen(t *testing.T) {
	p := newPolParams()
	histories := [][]int{
		{polBOS, 9},
		{polBOS, 2, 0, 18, 9, 13},
		{16, 11, 4, 23, 6, 8, 14, 0, 7, 19, 14, 0, 3, 2, 22, 15},
	}
	for i, h := range histories {
		frozen := policyArmScores(h, polArms)
		online := p.armScores(h, polArms)
		for a := range frozen {
			if math.Abs(frozen[a]-online[a]) > 1e-9 {
				t.Errorf("case %d arm %d: online %.9f, frozen %.9f", i, a, online[a], frozen[a])
			}
		}
	}
}

func TestPolicyWindowIsBounded(t *testing.T) {
	long := make([]int, polBlock*3)
	for i := range long {
		long[i] = i % (polArms * 2)
	}
	scores := policyArmScores(long, polArms)
	if len(scores) != polArms {
		t.Fatalf("got %d scores, want %d", len(scores), polArms)
	}
	for a, s := range scores {
		if s < 0 || s > 1 || math.IsNaN(s) {
			t.Errorf("arm %d scored %.6f, which is not a probability", a, s)
		}
	}
}

func TestPolicyDialEncoding(t *testing.T) {
	for arm := 0; arm < polArms; arm++ {
		if got := polDial(arm, true); got != arm*2 {
			t.Errorf("arm %d surviving encoded as %d, want %d", arm, got, arm*2)
		}
		if got := polDial(arm, false); got != arm*2+1 {
			t.Errorf("arm %d reset encoded as %d, want %d", arm, got, arm*2+1)
		}
	}
}

func TestJointArmStaysWholeWithoutFragmentation(t *testing.T) {
	presets := polArms / len(fragmentBudgets)
	h := NewHandshakeStrategy()
	pickers := map[string]func(ctx string) int{
		"bandit": func(ctx string) int { return h.SelectJoint(ctx, presets, false) },
		"policy": func(ctx string) int {
			arm, ok := h.SelectJointPolicy(ctx, presets, false)
			if !ok {
				t.Fatal("frozen policy refused a repertoire it was built for")
			}
			return arm
		},
		"online": func(ctx string) int {
			arm, _, ok := h.SelectJointOnline(ctx, presets, false)
			if !ok {
				t.Fatal("online policy refused a repertoire it was built for")
			}
			return arm
		},
	}
	for name, pick := range pickers {
		ctx := "whole-hello|" + name
		for i := 0; i < 300; i++ {
			arm := pick(ctx)
			if _, budget := JointArmParts(arm, presets); budget != 1 {
				t.Fatalf("%s picked arm %d with a %d-record hello, but fragmentation is off and the hello always leaves whole", name, arm, budget)
			}
			alive := i%4 == 0
			result := HandshakeResetFast
			if alive {
				result = HandshakeOK
			}
			h.Observe(ctx, arm, result)
			h.NoteDial(ctx, arm, alive)
			h.NoteJointOnline(ctx, arm, alive)
		}
	}
}
