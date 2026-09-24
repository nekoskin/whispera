package protocol

import (
	"math"
	"os"
	"sync"
)

// Forward pass ported from neural/fast.py, run once per dial to pick a hello
// budget. policy_test.go pins it to the trainer's own outputs.

func polRMSNorm(x []float64) []float64 {
	sum := 0.0
	for _, v := range x {
		sum += v * v
	}
	r := math.Sqrt(sum/float64(len(x)) + 1e-8)
	out := make([]float64, len(x))
	for i, v := range x {
		out[i] = v / r
	}
	return out
}

func polSoftmax(z []float64) []float64 {
	top := math.Inf(-1)
	for _, v := range z {
		if v > top {
			top = v
		}
	}
	out := make([]float64, len(z))
	sum := 0.0
	for i, v := range z {
		e := math.Exp(v - top)
		out[i] = e
		sum += e
	}
	for i := range out {
		out[i] /= sum
	}
	return out
}

func polApply(x []float64, w [][]float64) []float64 {
	out := make([]float64, len(w))
	for j, row := range w {
		sum := 0.0
		for k, v := range row {
			sum += x[k] * v
		}
		out[j] = sum
	}
	return out
}

func polForward(tokens []int) [][]float64 {
	t := len(tokens)
	x := make([][]float64, t)
	for i, tok := range tokens {
		row := make([]float64, polEmbd)
		for j := 0; j < polEmbd; j++ {
			row[j] = polWte[tok][j] + polWpe[i][j]
		}
		x[i] = polRMSNorm(row)
	}

	headDim := polEmbd / polHead
	for layer := 0; layer < polLayer; layer++ {
		q := make([][]float64, t)
		k := make([][]float64, t)
		v := make([][]float64, t)
		for i := 0; i < t; i++ {
			h := polRMSNorm(x[i])
			q[i] = polApply(h, polWq[layer])
			k[i] = polApply(h, polWk[layer])
			v[i] = polApply(h, polWv[layer])
		}

		o := make([][]float64, t)
		for i := range o {
			o[i] = make([]float64, polEmbd)
		}
		scale := math.Sqrt(float64(headDim))
		for head := 0; head < polHead; head++ {
			base := head * headDim
			for i := 0; i < t; i++ {
				scores := make([]float64, i+1)
				for u := 0; u <= i; u++ {
					dot := 0.0
					for d := 0; d < headDim; d++ {
						dot += q[i][base+d] * k[u][base+d]
					}
					scores[u] = dot / scale
				}
				a := polSoftmax(scores)
				for u := 0; u <= i; u++ {
					for d := 0; d < headDim; d++ {
						o[i][base+d] += a[u] * v[u][base+d]
					}
				}
			}
		}

		for i := 0; i < t; i++ {
			proj := polApply(o[i], polWo[layer])
			x2 := make([]float64, polEmbd)
			for j := 0; j < polEmbd; j++ {
				x2[j] = x[i][j] + proj[j]
			}
			f := polApply(polRMSNorm(x2), polFc1[layer])
			for j, val := range f {
				if val < 0 {
					f[j] = 0
				}
			}
			back := polApply(f, polFc2[layer])
			row := make([]float64, polEmbd)
			for j := 0; j < polEmbd; j++ {
				row[j] = x2[j] + back[j]
			}
			x[i] = row
		}
	}

	logits := make([][]float64, t)
	for i := 0; i < t; i++ {
		logits[i] = polApply(x[i], polLmHead)
	}
	return logits
}

func polDial(arm int, alive bool) int {
	if alive {
		return arm * 2
	}
	return arm*2 + 1
}

const polBOS = polVocab - 1

func policyArmScores(history []int) []float64 {
	if len(history) == 0 {
		history = []int{polBOS}
	}
	if len(history) > polBlock {
		history = history[len(history)-polBlock:]
	}
	logits := polForward(history)
	p := polSoftmax(logits[len(logits)-1])
	out := make([]float64, polArms)
	for a := 0; a < polArms; a++ {
		ok, reset := p[a*2], p[a*2+1]
		out[a] = ok / (ok + reset + 1e-12)
	}
	return out
}

// On by default in this build: it exists to try the model in the field, and a
// GUI client cannot set environment variables. "0" still turns either off.
func PolicyEnabled() bool { return os.Getenv("WHISPERA_POLICY") != "0" }

// JointArmEnabled hands the preset and the budget to one controller instead of
// a bandit each.
func JointArmEnabled() bool { return os.Getenv("WHISPERA_JOINT_ARM") != "0" }

// policyJointUsable guards the joint path the way policyUsable guards the
// single axis: weights trained for another arm count must not be used at all.
func policyJointUsable(presets int) bool { return JointArmCount(presets) == polArms }

// SelectJointPolicy asks the model which (preset, budget) pair to play.
func (h *HandshakeStrategy) SelectJointPolicy(ctx string, presets int, fragmented bool) (arm int, ok bool) {
	if !policyJointUsable(presets) {
		return 0, false
	}
	return h.policyArm(ctx, jointArmFits(fragmented)), true
}

// policyArm returns the model's pick for a context. A whole reconnect burst
// shares the same history until a dial reports back, so the forward pass is run
// once per history and reused for the rest.
func (h *HandshakeStrategy) policyArm(ctx string, fits func(int) bool) int {
	policyHist.mu.Lock()
	rev := policyHist.rev[ctx]
	policyHist.mu.Unlock()

	policyArmCache.mu.Lock()
	if g, ok := policyArmCache.m[ctx]; ok && g.rev == rev && fits(g.arm) {
		policyArmCache.mu.Unlock()
		return g.arm
	}
	policyArmCache.mu.Unlock()

	policyHist.mu.Lock()
	rev = policyHist.rev[ctx]
	seq := make([]int, 0, len(policyHist.m[ctx])+1)
	seq = append(seq, polBOS)
	seq = append(seq, policyHist.m[ctx]...)
	policyHist.mu.Unlock()

	best := bestFittingArm(policyArmScores(seq), fits)

	policyArmCache.mu.Lock()
	if policyArmCache.m == nil {
		policyArmCache.m = make(map[string]armGuess)
	}
	if g, ok := policyArmCache.m[ctx]; !ok || g.rev <= rev {
		policyArmCache.m[ctx] = armGuess{rev: rev, arm: best}
	}
	policyArmCache.mu.Unlock()
	return best
}

// policyUsable falls back to the bandit if the repertoire outgrew the weights.
func policyUsable() bool { return len(fragmentBudgets) == polArms }

var policyHist struct {
	mu  sync.Mutex
	m   map[string][]int
	rev map[string]uint64
}

type armGuess struct {
	rev uint64
	arm int
}

var policyArmCache struct {
	mu sync.Mutex
	m  map[string]armGuess
}

func (h *HandshakeStrategy) NoteDial(ctx string, arm int, alive bool) {
	policyHist.mu.Lock()
	defer policyHist.mu.Unlock()
	if policyHist.m == nil {
		policyHist.m = make(map[string][]int)
		policyHist.rev = make(map[string]uint64)
	}
	seq := append(policyHist.m[ctx], polDial(arm, alive))
	if len(seq) > polBlock {
		seq = seq[len(seq)-polBlock:]
	}
	policyHist.m[ctx] = seq
	policyHist.rev[ctx]++
}

func (h *HandshakeStrategy) SelectFragmentsPolicy(ctx string) (budget, arm int, ok bool) {
	if !policyUsable() {
		return 0, 0, false
	}
	arm = h.policyArm(ctx, anyArm)
	return fragmentBudgets[arm], arm, true
}

func bestFittingArm(scores []float64, fits func(int) bool) int {
	best := -1
	for a, s := range scores {
		if fits(a) && (best < 0 || s > scores[best]) {
			best = a
		}
	}
	return best
}
