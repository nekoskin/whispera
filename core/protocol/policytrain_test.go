package protocol

import (
	"math"
	"testing"
)

// The training pass keeps intermediate values the serving pass throws away.
// Both must still produce the same logits, or the gradient belongs to a
// different model than the one answering dials.
func TestTrainingForwardMatchesServing(t *testing.T) {
	cases := [][]int{
		{polBOS, 9},
		{polBOS, 9, 2, 18, 5, 11, 0, 7},
		{16, 11, 4, 23, 6, 8, 14, 0, 7, 19, 14, 0, 3, 2, 22, 15},
	}
	p := newPolParams()
	for _, tokens := range cases {
		want := polForward(tokens)
		got, cache := p.forward(tokens)
		if len(got) != len(want) {
			t.Fatalf("tokens %v: got %d rows, want %d", tokens, len(got), len(want))
		}
		if len(cache.xOut) != len(tokens) {
			t.Fatalf("tokens %v: cache holds %d rows, want %d", tokens, len(cache.xOut), len(tokens))
		}
		for i := range want {
			for j := range want[i] {
				if math.Abs(got[i][j]-want[i][j]) > 1e-9 {
					t.Fatalf("tokens %v: logit [%d][%d] = %.12f, serving says %.12f",
						tokens, i, j, got[i][j], want[i][j])
				}
			}
		}
	}
}

func TestTrainingParamsAreCopies(t *testing.T) {
	p := newPolParams()
	before := polWte[0][0]
	p.wte[0][0] = before + 1
	if polWte[0][0] != before {
		t.Fatalf("training wrote through to the generated weights: %.6f became %.6f",
			before, polWte[0][0])
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
		"wte":     {polVocab, polEmbd},
		"wpe":     {polBlock, polEmbd},
		"lm_head": {polVocab, polEmbd},
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
		"wte":     {2.728176131, -0.046330160},
		"wpe":     {2.728176131, 0.310129591},
		"lm_head": {2.289891425, 0.292405307},
		"0.wq":    {1.906704611, -0.022501550},
		"0.wk":    {1.439231813, 0.068719359},
		"0.wv":    {4.133409835, 0.137374502},
		"0.wo":    {3.688169921, -0.120858522},
		"0.fc1":   {5.015781977, 0.166039949},
		"0.fc2":   {3.459855529, -0.041952767},
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
	before := make([]float64, len(polWte[0]))
	copy(before, polWte[0])

	p := newPolParams()
	a := newPolAdam()
	for i := 0; i < 5; i++ {
		polTrainStep(p, a, []int{polBOS, 8, 9, 4, 5})
	}

	for j := range before {
		if polWte[0][j] != before[j] {
			t.Fatalf("training moved the generated weights: wte[0][%d] %.6f -> %.6f",
				j, before[j], polWte[0][j])
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
