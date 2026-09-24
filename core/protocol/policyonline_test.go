package protocol

import "testing"

// rolls hands out a fixed sequence of draws so exploration is decidable in a
// test instead of being a coin toss.
func rolls(values ...float64) func() float64 {
	i := 0
	return func() float64 {
		v := values[i%len(values)]
		i++
		return v
	}
}

func TestOnlineHoldsStillWhileSurvivalIsGood(t *testing.T) {
	o := newOnlinePolicy()
	for i := 0; i < polOnlineWindow; i++ {
		o.Note("ctx", 4, true)
	}
	// A draw of 0 would explore if the gate were open; survival is 1.0, so it
	// must not be.
	for i := 0; i < 20; i++ {
		if _, explored := o.Select("ctx", 12, anyArm, rolls(0)); explored {
			t.Fatal("explored while every dial was surviving")
		}
	}
	if o.reverts != 0 {
		t.Fatalf("reverted %d times with nothing wrong", o.reverts)
	}
}

func TestOnlineExploresOnlyWhenSurvivalDrops(t *testing.T) {
	o := newOnlinePolicy()
	for i := 0; i < polOnlineWindow; i++ {
		o.Note("ctx", 4, i%2 == 0)
	}
	if s := o.survival(); s >= polOnlineHealthy {
		t.Fatalf("survival %.2f, wanted it below the healthy mark for this test", s)
	}
	if _, explored := o.Select("ctx", 12, anyArm, rolls(0, 0.5)); !explored {
		t.Fatal("survival is down and the draw was low, but nothing was probed")
	}
	if _, explored := o.Select("ctx", 12, anyArm, rolls(0.99)); explored {
		t.Fatal("probed on a high draw, the explore rate is not being respected")
	}
}

func TestOnlineTrainsOnItsOwnDials(t *testing.T) {
	o := newOnlinePolicy()
	base := newPolParams()
	for i := 0; i < polOnlineStepEvery*3; i++ {
		o.Note("ctx", 5, true)
	}
	if o.steps == 0 {
		t.Fatal("no optimiser step after enough dials")
	}
	moved := false
	live := o.live.all()
	for x, m := range base.all() {
		for i := range m {
			for j := range m[i] {
				if live[x][i][j] != m[i][j] {
					moved = true
				}
			}
		}
	}
	if !moved {
		t.Fatal("weights are identical to the frozen base, training did nothing")
	}
}

func TestOnlineRevertsWhenSurvivalCollapses(t *testing.T) {
	o := newOnlinePolicy()
	for i := 0; i < polOnlineWindow; i++ {
		o.Note("ctx", 7, false)
	}
	if o.reverts == 0 {
		t.Fatal("survival collapsed and the trained copy was kept")
	}
	base := newPolParams().all()
	live := o.live.all()
	for x := range base {
		for i := range base[x] {
			for j := range base[x][i] {
				if live[x][i][j] != base[x][i][j] {
					t.Fatalf("after a revert the weights differ from the base at %d[%d][%d]", x, i, j)
				}
			}
		}
	}
	if o.adam.steps != 0 {
		t.Fatalf("optimiser kept %d steps of momentum across a revert", o.adam.steps)
	}
}

func TestOnlineHistoryStaysWithinTheWindow(t *testing.T) {
	o := newOnlinePolicy()
	for i := 0; i < polBlock*3; i++ {
		o.Note("ctx", i%12, true)
	}
	if got := len(o.hist["ctx"]); got > polBlock {
		t.Fatalf("history grew to %d symbols, window is %d", got, polBlock)
	}
}

func TestOnlineSelectReturnsAnArmInRange(t *testing.T) {
	o := newOnlinePolicy()
	for _, arms := range []int{1, 4, 12} {
		for i := 0; i < 50; i++ {
			arm, _ := o.Select("ctx", arms, anyArm, rolls(0, 0.999999))
			if arm < 0 || arm >= arms {
				t.Fatalf("arms %d: got arm %d", arms, arm)
			}
		}
	}
}
