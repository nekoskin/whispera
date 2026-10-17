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
		{tokens: []int{24, 9}, want: []float64{0.128022, 0.041479, 0.012594, 0.003745, 0.553324, 0.267464, 0.097162, 0.030745, 0.660568, 0.364517, 0.144618, 0.047467}},
		{tokens: []int{24, 2, 0, 18, 9, 13}, want: []float64{0.458268, 0.242645, 0.108211, 0.043937, 0.810193, 0.617831, 0.379761, 0.188241, 0.661640, 0.425484, 0.219049, 0.096030}},
		{tokens: []int{16, 11, 4, 23, 6, 8, 14, 0, 7, 19, 14, 0, 3, 2, 22, 15}, want: []float64{0.535011, 0.303938, 0.142155, 0.059167, 0.809392, 0.617080, 0.379489, 0.188374, 0.558627, 0.324471, 0.154179, 0.064701}},
		{tokens: []int{23, 11, 18, 11, 18, 9, 21, 10, 18, 2, 15, 5, 22, 15, 18, 14}, want: []float64{0.726149, 0.543940, 0.349157, 0.194394, 0.908446, 0.816955, 0.667498, 0.474505, 0.311967, 0.169398, 0.084026, 0.039627}},
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
			h.NoteJointOnline(ctx, arm, alive, true)
		}
	}
}
