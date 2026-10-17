package protocol

import (
	"math"
	"testing"
)

func TestTrainingParamsAreCopies(t *testing.T) {
	p := newPolParams()
	before := polWin[0][0]
	p.win[0][0] = before + 1
	if polWin[0][0] != before {
		t.Fatalf("training wrote through to the generated weights: %.6f became %.6f",
			before, polWin[0][0])
	}
}

func TestTrainingGradsStartEmpty(t *testing.T) {
	g := newPolGrads()
	g.each(func(name string, m [][]float64) {
		for i := range m {
			for j := range m[i] {
				if m[i][j] != 0 {
					t.Fatalf("%s[%d][%d] = %.6f, want 0", name, i, j, m[i][j])
				}
			}
		}
	})
}

func TestTrainingMatrixShapes(t *testing.T) {
	p := newPolParams()
	shapes := map[string][2]int{
		"win":     {polEmbd, polFeatDim},
		"oin":     {2, polEmbd},
		"bos_in":  {1, polEmbd},
		"wout":    {2 * polEmbd, polFeatDim},
		"oout":    {2, polEmbd},
		"bos_out": {1, polEmbd},
		"wpe":     {polBlock, polEmbd},
		"0.wq":    {polEmbd, polEmbd},
		"0.wk":    {polEmbd, polEmbd},
		"0.wv":    {polEmbd, polEmbd},
		"0.wo":    {polEmbd, polEmbd},
		"0.fc1":   {4 * polEmbd, polEmbd},
		"0.fc2":   {polEmbd, 4 * polEmbd},
	}
	seen := 0
	p.each(func(name string, m [][]float64) {
		want, ok := shapes[name]
		if !ok {
			t.Fatalf("unexpected matrix %q", name)
		}
		seen++
		if len(m) != want[0] || len(m[0]) != want[1] {
			t.Fatalf("%s is %dx%d, want %dx%d", name, len(m), len(m[0]), want[0], want[1])
		}
	})
	if seen != len(shapes) {
		t.Fatalf("walked %d matrices, want %d", seen, len(shapes))
	}
}

// Numbers printed by neural/mutate.py grad_probe on the weights this package
// carries. A trainer that runs on the client learns from its own gradients, so
// a port that drifts here degrades the model in the field with nothing to
// catch it.
//
// The tolerance is 1e-5, not tighter: the exporter writes weights to six
// decimals, so this side computes on rounded inputs and the trainer does not.
// Correctness itself is settled by finite differences below, which need no
// agreement with Python at all.
func TestTrainingBackwardMatchesTrainer(t *testing.T) {
	tokens := []int{24, 9, 2, 18, 5, 11, 0, 7}
	want := map[string][2]float64{
		"win":     {0.809897765, -0.030074290},
		"oin":     {0.690217149, -0.000284604},
		"bos_in":  {0.171205881, -0.026468821},
		"wout":    {1.448628843, -0.066752489},
		"oout":    {0.466337871, -0.053744428},
		"bos_out": {0.431800084, 0.012769759},
		"wpe":     {0.582661947, -0.026468821},
		"0.wq":    {0.039385161, 0.000012765},
		"0.wk":    {0.022233502, 0.000973297},
		"0.wv":    {1.243027305, -0.006304076},
		"0.wo":    {0.601574062, 0.003108791},
		"0.fc1":   {2.943830674, 0.000000000},
		"0.fc2":   {0.855617849, 0.000000000},
	}

	p := newPolParams()
	logits, cache := p.forward(tokens)

	targets := make([]int, len(tokens))
	copy(targets, tokens[1:])
	targets[len(targets)-1] = tokens[0]

	n := float64(len(tokens))
	dlogits := make([][]float64, len(tokens))
	for i := range logits {
		row := polSoftmax(logits[i])
		row[targets[i]] -= 1
		for j := range row {
			row[j] /= n
		}
		dlogits[i] = row
	}

	g := p.backward(cache, dlogits)
	seen := 0
	g.each(func(name string, m [][]float64) {
		ref, ok := want[name]
		if !ok {
			t.Fatalf("unexpected matrix %q", name)
		}
		seen++
		sum := 0.0
		for i := range m {
			for j := range m[i] {
				sum += m[i][j] * m[i][j]
			}
		}
		norm := math.Sqrt(sum)
		if math.Abs(norm-ref[0]) > 1e-5 {
			t.Errorf("%s: gradient norm %.9f, trainer says %.9f", name, norm, ref[0])
		}
		if math.Abs(m[0][0]-ref[1]) > 1e-5 {
			t.Errorf("%s: gradient [0][0] %.9f, trainer says %.9f", name, m[0][0], ref[1])
		}
	})
	if seen != len(want) {
		t.Fatalf("checked %d matrices, want %d", seen, len(want))
	}
}

func TestTrainingStepLowersLoss(t *testing.T) {
	p := newPolParams()
	a := newPolAdam()
	seq := []int{polBOS, 8, 9, 8, 9, 8, 9, 8, 9}

	first := polTrainStep(p, a, seq)
	for i := 0; i < 60; i++ {
		polTrainStep(p, a, seq)
	}
	last := polTrainStep(p, a, seq)

	if last >= first {
		t.Fatalf("loss went %.6f -> %.6f, training is not learning this sequence", first, last)
	}
	if a.steps != 62 {
		t.Fatalf("optimiser took %d steps, want 62", a.steps)
	}
}

func TestTrainingStepLeavesGeneratedWeightsAlone(t *testing.T) {
	before := make([]float64, len(polWin[0]))
	copy(before, polWin[0])

	p := newPolParams()
	a := newPolAdam()
	for i := 0; i < 5; i++ {
		polTrainStep(p, a, []int{polBOS, 8, 9, 4, 5})
	}

	for j := range before {
		if polWin[0][j] != before[j] {
			t.Fatalf("training moved the generated weights: win[0][%d] %.6f -> %.6f",
				j, before[j], polWin[0][j])
		}
	}
}

func TestTrainingStepIgnoresShortHistory(t *testing.T) {
	p := newPolParams()
	a := newPolAdam()
	if got := polTrainStep(p, a, []int{polBOS}); got != 0 {
		t.Fatalf("a single symbol returned loss %.6f, want 0", got)
	}
	if a.steps != 0 {
		t.Fatalf("optimiser stepped %d times on nothing to learn from", a.steps)
	}
}

// polTestLoss is the quantity dlogits is the gradient of: mean cross entropy
// over the positions.
func polTestLoss(p *polParams, tokens, targets []int) float64 {
	logits, _ := p.forward(tokens)
	total := 0.0
	for i := range logits {
		probs := polSoftmax(logits[i])
		total += -math.Log(math.Max(probs[targets[i]], 1e-300))
	}
	return total / float64(len(tokens))
}

// Settles the backward pass on its own terms: nudge a weight, watch the loss
// move, compare with the gradient. This needs no agreement with the Python
// trainer, so it separates a real porting error from the rounding the
// exporter introduces.
func TestTrainingBackwardAgainstFiniteDifferences(t *testing.T) {
	tokens := []int{24, 9, 2, 18, 5}
	targets := make([]int, len(tokens))
	copy(targets, tokens[1:])
	targets[len(targets)-1] = tokens[0]

	p := newPolParams()
	logits, cache := p.forward(tokens)
	n := float64(len(tokens))
	dlogits := make([][]float64, len(tokens))
	for i := range logits {
		row := polSoftmax(logits[i])
		row[targets[i]] -= 1
		for j := range row {
			row[j] /= n
		}
		dlogits[i] = row
	}
	g := p.backward(cache, dlogits)

	grads := map[string][][]float64{}
	g.each(func(name string, m [][]float64) { grads[name] = m })

	const eps = 1e-5
	checked, nonzero := 0, 0
	p.each(func(name string, m [][]float64) {
		want := grads[name]
		for i := 0; i < 3 && i < len(m); i++ {
			for j := 0; j < 2 && j < len(m[i]); j++ {
				orig := m[i][j]
				m[i][j] = orig + eps
				up := polTestLoss(p, tokens, targets)
				m[i][j] = orig - eps
				down := polTestLoss(p, tokens, targets)
				m[i][j] = orig

				numeric := (up - down) / (2 * eps)
				analytic := want[i][j]
				checked++
				if math.Abs(analytic) > 1e-9 {
					nonzero++
				}
				tol := 1e-4 * math.Max(1, math.Abs(analytic))
				if math.Abs(numeric-analytic) > tol {
					t.Errorf("%s[%d][%d]: gradient %.9f, finite difference %.9f",
						name, i, j, analytic, numeric)
				}
			}
		}
	})
	if checked == 0 {
		t.Fatal("no weights were checked")
	}
	if nonzero < 20 {
		t.Fatalf("only %d of %d checks had a non-zero gradient, the test is proving nothing",
			nonzero, checked)
	}
}

func TestOnlineBenchesDeadArm(t *testing.T) {
	o := newOnlinePolicy()
	roll := func() float64 { return 0.99 }
	fits := func(int) bool { return true }
	dead, _ := o.Select("c", polArms, fits, roll)
	for i := 0; i < deadArmFails; i++ {
		o.Note("c", dead, false)
	}
	for i := 0; i < 20; i++ {
		if got, _ := o.Select("c", polArms, fits, roll); got == dead {
			t.Fatalf("arm %d failed %d times in a row but was chosen again", dead, deadArmFails)
		}
	}
}

func TestOnlineReprobesBenchedArm(t *testing.T) {
	o := newOnlinePolicy()
	for i := 0; i < deadArmFails; i++ {
		o.Note("c", 0, false)
	}
	if o.alive("c", 0) {
		t.Fatal("arm 0 should be benched after consecutive failures")
	}
	for i := 0; i < deadArmDecay; i++ {
		o.Note("c", 1, true)
	}
	if !o.alive("c", 0) {
		t.Fatal("a benched arm should be re-probed after the fail count decays")
	}
}

func TestOnlineBenchesArmOnlyOnItsNetwork(t *testing.T) {
	o := newOnlinePolicy()
	for i := 0; i < deadArmFails; i++ {
		o.Note("sni|home|joint", 0, false)
	}
	if o.alive("sni|home|joint", 0) {
		t.Fatal("arm 0 should be benched on the network it failed on")
	}
	if !o.alive("sni|cafe|joint", 0) {
		t.Fatal("a failure on one network must not bench the arm on another")
	}
	for i := 0; i < deadArmDecay; i++ {
		o.Note("sni|cafe|joint", 1, true)
	}
	if o.alive("sni|home|joint", 0) {
		t.Fatal("dials on another network must not decay this network's bench")
	}
}

func TestOnlineBenchesAnArmLongerEachTimeItDiesAgain(t *testing.T) {
	o := newOnlinePolicy()
	pass := func(n int) {
		for i := 0; i < n; i++ {
			o.Note("c", 1, true)
		}
	}
	o.Note("c", 0, false)
	pass(deadArmDecay)
	if !o.alive("c", 0) {
		t.Fatal("after the first death the arm should be re-probed within one decay period")
	}
	o.Note("c", 0, false)
	pass(deadArmDecay)
	if o.alive("c", 0) {
		t.Fatal("an arm that died again on its re-probe should stay benched longer")
	}
	pass(deadArmDecay)
	if !o.alive("c", 0) {
		t.Fatal("the longer bench should still run out")
	}
	o.Note("c", 0, true)
	o.Note("c", 0, false)
	pass(deadArmDecay)
	if !o.alive("c", 0) {
		t.Fatal("a success should reset the bench to its shortest length")
	}
}
