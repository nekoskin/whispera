package protocol

import (
	"math"
	"math/rand"
	"os"
	"testing"
	"time"
)

const testMinute = 60_000

func testParams(rng *rand.Rand) *polParams {
	p := newPolParams()
	p.each(func(_ string, m [][]float64) {
		for _, row := range m {
			for j := range row {
				row[j] = rng.NormFloat64() * polInitStd
			}
		}
	})
	return p
}

func testTrainer(t *testing.T) (python, script string) {
	t.Helper()
	script = os.Getenv("WHISPERA_TEST_TRAINER")
	if script == "" {
		t.Skip("WHISPERA_TEST_TRAINER names the PyTorch trainer (neural/mutate.py); the bridge is untested without it")
	}
	python = os.Getenv("WHISPERA_TEST_PYTHON")
	if python == "" {
		python = "python3"
	}
	return python, script
}

func polDistance(a, b *polParams) float64 {
	sum := 0.0
	bm := b.mats()
	a.each(func(name string, m [][]float64) {
		for i := range m {
			for j := range m[i] {
				d := m[i][j] - bm[name][i][j]
				sum += d * d
			}
		}
	})
	return math.Sqrt(sum)
}

func waitTrained(t *testing.T, o *onlinePolicy) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		o.mu.Lock()
		busy, off := o.training, o.trainer == nil
		o.mu.Unlock()
		if off {
			t.Fatal("the trainer was switched off")
		}
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the trainer did not answer within a minute")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTrainerFineTunesNearTheAnchorAndSparesUnplayedArms(t *testing.T) {
	python, script := testTrainer(t)
	drift := map[float64]float64{}
	for _, anchor := range []float64{0, polAnchorGrid[0]} {
		o, clock := testOnlinePolicy(7)
		o.anchor = anchor
		o.trainer = newPolTrainer(python, script)
		before := o.live.armScores(nil, clock.UnixMilli(), polArms)
		for i := 0; i < 50*polOnlineStepEvery; i++ {
			*clock = clock.Add(time.Minute)
			o.NoteDial("c", 4, DialNote{Alive: true})
			waitTrained(t, o)
		}
		o.trainer.close()
		if o.steps == 0 || !o.tuned {
			t.Fatal("the trainer took no step")
		}
		after := o.live.armScores(o.dials["c"], clock.UnixMilli()+time.Minute.Milliseconds(), polArms)
		for a := range after {
			if a != 4 && after[a] < before[a]-0.25 {
				t.Fatalf("anchor %g: arm %d was never played but fell from %.3f to %.3f while arm 4 kept living", anchor, a, before[a], after[a])
			}
		}
		drift[anchor] = polDistance(o.live, o.frozen)
	}
	if drift[polAnchorGrid[0]] >= drift[0] {
		t.Fatalf("anchored weights drifted %.4f, unanchored %.4f", drift[polAnchorGrid[0]], drift[0])
	}
}
