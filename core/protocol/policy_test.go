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
		{tokens: []int{24, 9}, want: []float64{0.817401, 0.290083, 0.956346, 0.947210, 0.000889, 0.931203, 0.991269, 0.933911, 0.524351, 0.253002, 0.876744, 0.995951}},
		{tokens: []int{24, 2, 0, 18, 9, 13}, want: []float64{0.951831, 0.833513, 0.000017, 0.012597, 0.996053, 0.999934, 0.029479, 0.197325, 0.945797, 0.989856, 0.000959, 0.000937}},
		{tokens: []int{16, 11, 4, 23, 6, 8, 14, 0, 7, 19, 14, 0, 3, 2, 22, 15}, want: []float64{0.999909, 0.984795, 0.000337, 0.230680, 0.393161, 0.999637, 0.072835, 0.011664, 0.951527, 0.762727, 0.028471, 0.011935}},
		{tokens: []int{23, 11, 18, 11, 18, 9, 21, 10, 18, 2, 15, 5, 22, 15, 18, 14}, want: []float64{0.770246, 0.420158, 0.326131, 0.734026, 0.214942, 0.992998, 0.892920, 0.996214, 0.809996, 0.705447, 0.479480, 0.562922}},
	}
	for i, c := range cases {
		got := policyArmScores(c.tokens)
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

func TestPolicyWindowIsBounded(t *testing.T) {
	long := make([]int, polBlock*3)
	for i := range long {
		long[i] = i % (polArms * 2)
	}
	scores := policyArmScores(long)
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
