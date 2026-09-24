package protocol

import (
	"math"
	mrand "math/rand"
	"os"
	"sync"
)

// Training for the dial policy on the client. The serving pass in policy.go
// answers one dial and keeps nothing; a gradient needs the intermediate values,
// so training carries its own pass that saves them.
//
// One layer only. The model in the datapath is small because the forward pass
// is paid per dial, and polLayer is 1; more layers would need the loop back.

type polParams struct {
	wte, wpe, lmHead [][]float64
	wq, wk, wv, wo   [][]float64
	fc1, fc2         [][]float64
}

type polCache struct {
	tokens []int
	x0     [][]float64
	r1     []float64
	xIn    [][]float64
	h      [][]float64
	rh     []float64
	q      [][]float64
	k      [][]float64
	v      [][]float64
	att    [][][]float64
	o      [][]float64
	x2     [][]float64
	h2     [][]float64
	rh2    []float64
	f      [][]float64
	fr     [][]float64
	xOut   [][]float64
}

func polCloneMat(m [][]float64) [][]float64 {
	out := make([][]float64, len(m))
	for i, row := range m {
		out[i] = append([]float64(nil), row...)
	}
	return out
}

func polZeroLike(m [][]float64) [][]float64 {
	out := make([][]float64, len(m))
	for i, row := range m {
		out[i] = make([]float64, len(row))
	}
	return out
}

// newPolParams copies the generated weights into buffers that can be trained.
// The generated ones stay untouched, so serving can always fall back to them.
func newPolParams() *polParams {
	return &polParams{
		wte:    polCloneMat(polWte),
		wpe:    polCloneMat(polWpe),
		lmHead: polCloneMat(polLmHead),
		wq:     polCloneMat(polWq[0]),
		wk:     polCloneMat(polWk[0]),
		wv:     polCloneMat(polWv[0]),
		wo:     polCloneMat(polWo[0]),
		fc1:    polCloneMat(polFc1[0]),
		fc2:    polCloneMat(polFc2[0]),
	}
}

func newPolGrads() *polParams {
	return &polParams{
		wte:    polZeroLike(polWte),
		wpe:    polZeroLike(polWpe),
		lmHead: polZeroLike(polLmHead),
		wq:     polZeroLike(polWq[0]),
		wk:     polZeroLike(polWk[0]),
		wv:     polZeroLike(polWv[0]),
		wo:     polZeroLike(polWo[0]),
		fc1:    polZeroLike(polFc1[0]),
		fc2:    polZeroLike(polFc2[0]),
	}
}

var polMatNames = []string{
	"wte", "wpe", "lm_head", "0.wq", "0.wk", "0.wv", "0.wo", "0.fc1", "0.fc2",
}

// all is the one place the matrices are listed, so the optimiser walks weights,
// gradients and moments in step with each other.
func (p *polParams) all() [][][]float64 {
	return [][][]float64{p.wte, p.wpe, p.lmHead, p.wq, p.wk, p.wv, p.wo, p.fc1, p.fc2}
}

func (p *polParams) each(f func(name string, m [][]float64)) {
	for i, m := range p.all() {
		f(polMatNames[i], m)
	}
}

// polNorm is RMSNorm, returning the scale it divided by: the backward pass
// needs it, and recomputing would drift.
func polNorm(x []float64) ([]float64, float64) {
	sum := 0.0
	for _, v := range x {
		sum += v * v
	}
	r := math.Sqrt(sum/float64(len(x)) + 1e-8)
	out := make([]float64, len(x))
	for i, v := range x {
		out[i] = v / r
	}
	return out, r
}

func (p *polParams) forward(tokens []int) ([][]float64, *polCache) {
	t := len(tokens)
	headDim := polEmbd / polHead
	c := &polCache{
		tokens: tokens,
		x0:     make([][]float64, t),
		r1:     make([]float64, t),
		xIn:    make([][]float64, t),
		h:      make([][]float64, t),
		rh:     make([]float64, t),
		q:      make([][]float64, t),
		k:      make([][]float64, t),
		v:      make([][]float64, t),
		att:    make([][][]float64, polHead),
		o:      make([][]float64, t),
		x2:     make([][]float64, t),
		h2:     make([][]float64, t),
		rh2:    make([]float64, t),
		f:      make([][]float64, t),
		fr:     make([][]float64, t),
		xOut:   make([][]float64, t),
	}

	for i, tok := range tokens {
		row := make([]float64, polEmbd)
		for j := 0; j < polEmbd; j++ {
			row[j] = p.wte[tok][j] + p.wpe[i][j]
		}
		c.x0[i] = row
		c.xIn[i], c.r1[i] = polNorm(row)
	}

	for i := 0; i < t; i++ {
		c.h[i], c.rh[i] = polNorm(c.xIn[i])
		c.q[i] = polApply(c.h[i], p.wq)
		c.k[i] = polApply(c.h[i], p.wk)
		c.v[i] = polApply(c.h[i], p.wv)
		c.o[i] = make([]float64, polEmbd)
	}

	scale := math.Sqrt(float64(headDim))
	for head := 0; head < polHead; head++ {
		base := head * headDim
		c.att[head] = make([][]float64, t)
		for i := 0; i < t; i++ {
			scores := make([]float64, i+1)
			for u := 0; u <= i; u++ {
				dot := 0.0
				for d := 0; d < headDim; d++ {
					dot += c.q[i][base+d] * c.k[u][base+d]
				}
				scores[u] = dot / scale
			}
			a := polSoftmax(scores)
			c.att[head][i] = a
			for u := 0; u <= i; u++ {
				for d := 0; d < headDim; d++ {
					c.o[i][base+d] += a[u] * c.v[u][base+d]
				}
			}
		}
	}

	for i := 0; i < t; i++ {
		proj := polApply(c.o[i], p.wo)
		x2 := make([]float64, polEmbd)
		for j := 0; j < polEmbd; j++ {
			x2[j] = c.xIn[i][j] + proj[j]
		}
		c.x2[i] = x2

		c.h2[i], c.rh2[i] = polNorm(x2)
		f := polApply(c.h2[i], p.fc1)
		fr := make([]float64, len(f))
		for j, val := range f {
			if val > 0 {
				fr[j] = val
			}
		}
		c.f[i] = f
		c.fr[i] = fr

		back := polApply(fr, p.fc2)
		out := make([]float64, polEmbd)
		for j := 0; j < polEmbd; j++ {
			out[j] = x2[j] + back[j]
		}
		c.xOut[i] = out
	}

	logits := make([][]float64, t)
	for i := 0; i < t; i++ {
		logits[i] = polApply(c.xOut[i], p.lmHead)
	}
	return logits, c
}

// armScores is the serving read of a trained copy: P(survive) per arm for this
// history, the same quantity policyArmScores gives for the generated weights.
func (p *polParams) armScores(history []int, arms int) []float64 {
	if len(history) == 0 {
		history = []int{polBOS}
	}
	if len(history) > polBlock {
		history = history[len(history)-polBlock:]
	}
	logits, _ := p.forward(history)
	probs := polSoftmax(logits[len(logits)-1])
	out := make([]float64, arms)
	for a := 0; a < arms; a++ {
		ok, reset := probs[a*2], probs[a*2+1]
		out[a] = ok / (ok + reset + 1e-12)
	}
	return out
}

// Learning while dialing. Three numbers decide the behavior and each is a
// trade the operator should be able to see:
//
//   - stepEvery: dials between optimiser steps. Cheap to raise, and the cost
//     is paid once per dial, not per record.
//   - floor: survival under the trained copy below which it is abandoned. The
//     frozen base is a model that was measured, so falling back is safe; the
//     trained copy has no such guarantee.
//   - explore: how often to play something other than the best arm, and only
//     while survival is already down. Exploring when nothing is wrong costs
//     the user connections for no signal.
const (
	polOnlineStepEvery = 8
	polOnlineWindow    = 32
	polOnlineFloor     = 0.5
	polOnlineHealthy   = 0.8
	polOnlineExplore   = 0.1
)

func PolicyOnlineEnabled() bool { return os.Getenv("WHISPERA_POLICY_ONLINE") != "0" }

type onlinePolicy struct {
	mu       sync.Mutex
	live     *polParams
	adam     *polAdam
	hist     map[string][]int
	outcomes []bool
	pending  int
	steps    int
	reverts  int
}

func newOnlinePolicy() *onlinePolicy {
	return &onlinePolicy{live: newPolParams(), adam: newPolAdam(), hist: map[string][]int{}}
}

func (o *onlinePolicy) survival() float64 {
	if len(o.outcomes) == 0 {
		return 1
	}
	alive := 0
	for _, ok := range o.outcomes {
		if ok {
			alive++
		}
	}
	return float64(alive) / float64(len(o.outcomes))
}

// Select answers a dial. The second result says the arm was a deliberate
// probe rather than the model's choice, so the caller can tell exploration
// from preference when reading a trace.
func (o *onlinePolicy) Select(ctx string, arms int, fits func(int) bool, roll func() float64) (int, bool) {
	if arms < 1 {
		return 0, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.survival() < polOnlineHealthy && roll() < polOnlineExplore {
		fitting := make([]int, 0, arms)
		for a := 0; a < arms; a++ {
			if fits(a) {
				fitting = append(fitting, a)
			}
		}
		pick := int(roll() * float64(len(fitting)))
		if pick >= len(fitting) {
			pick = len(fitting) - 1
		}
		return fitting[pick], true
	}

	seq := make([]int, 0, len(o.hist[ctx])+1)
	seq = append(seq, polBOS)
	seq = append(seq, o.hist[ctx]...)
	return bestFittingArm(o.live.armScores(seq, arms), fits), false
}

// Note records how a dial ended, trains on the history every so often, and
// abandons the trained copy if survival has fallen through the floor.
func (o *onlinePolicy) Note(ctx string, arm int, alive bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	seq := append(o.hist[ctx], polDial(arm, alive))
	if len(seq) > polBlock {
		seq = seq[len(seq)-polBlock:]
	}
	o.hist[ctx] = seq

	o.outcomes = append(o.outcomes, alive)
	if len(o.outcomes) > polOnlineWindow {
		o.outcomes = o.outcomes[len(o.outcomes)-polOnlineWindow:]
	}

	o.pending++
	if o.pending >= polOnlineStepEvery {
		o.pending = 0
		o.steps++
		window := make([]int, 0, len(seq)+1)
		window = append(window, polBOS)
		window = append(window, seq...)
		polTrainStep(o.live, o.adam, window)
	}

	if len(o.outcomes) >= polOnlineWindow && o.survival() < polOnlineFloor {
		o.revert()
	}
}

// revert throws the trained copy away and starts again from the weights that
// were measured offline. Training in the field can walk into a bad region and
// there is nothing in the field to tell it so.
func (o *onlinePolicy) revert() {
	o.live = newPolParams()
	o.adam = newPolAdam()
	o.outcomes = nil
	o.pending = 0
	o.reverts++
	// Logged because a run where the copy was abandoned repeatedly looks, from
	// the outside, exactly like a run where it learned something.
	traceLog.Infow("policy_online_revert", "reverts", o.reverts, "steps", o.steps)
}

var onlinePolicyOnce struct {
	once sync.Once
	p    *onlinePolicy
}

func sharedOnlinePolicy() *onlinePolicy {
	onlinePolicyOnce.once.Do(func() { onlinePolicyOnce.p = newOnlinePolicy() })
	return onlinePolicyOnce.p
}

// SelectJointOnline picks a (preset, budget) pair from a model that keeps
// learning from its own dials. Falls back to false when the weights were built
// for a different repertoire, exactly as the offline path does.
func (h *HandshakeStrategy) SelectJointOnline(ctx string, presets int, fragmented bool) (arm int, explored, ok bool) {
	if !policyJointUsable(presets) {
		return 0, false, false
	}
	a, probe := sharedOnlinePolicy().Select(ctx, JointArmCount(presets), jointArmFits(fragmented), mrand.Float64)
	return a, probe, true
}

// NoteJointOnline feeds the outcome back so the next dial is chosen on it.
func (h *HandshakeStrategy) NoteJointOnline(ctx string, arm int, alive bool) {
	sharedOnlinePolicy().Note(ctx, arm, alive)
}

// PolicyOnlineState reports what the online controller has done, for the trace.
func PolicyOnlineState() (steps, reverts int, survival float64) {
	o := sharedOnlinePolicy()
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.steps, o.reverts, o.survival()
}

// polApplyT multiplies by the same matrix the other way round. polApply reads a
// row per output; going backwards needs a row per input, and mixing the two up
// yields gradients that look plausible and are wrong.
func polApplyT(x []float64, w [][]float64) []float64 {
	out := make([]float64, len(w[0]))
	for j, row := range w {
		if x[j] == 0 {
			continue
		}
		for k, v := range row {
			out[k] += x[j] * v
		}
	}
	return out
}

// polDNorm is the gradient through RMSNorm. The scale depends on x itself, so
// there is a second term pulling along x.
func polDNorm(dy, x []float64, r float64) []float64 {
	d := float64(len(x))
	dot := 0.0
	for i := range x {
		dot += dy[i] * x[i]
	}
	out := make([]float64, len(x))
	for i := range x {
		out[i] = (dy[i] - x[i]*dot/(d*r*r)) / r
	}
	return out
}

func polOuter(dst [][]float64, left, right []float64) {
	for j, dv := range left {
		if dv == 0 {
			continue
		}
		row := dst[j]
		for k, rv := range right {
			row[k] += dv * rv
		}
	}
}

// Adam, with the trainer's constants. The trainer decays the rate over a known
// number of steps; a client has no such number, so the rate here is flat. That
// is the one place this can drift away from a good model on its own, which is
// why the caller keeps a frozen copy to fall back to.
const (
	polLearnRate = 0.01
	polBeta1     = 0.85
	polBeta2     = 0.99
	polAdamEps   = 1e-8
)

type polAdam struct {
	m, v  *polParams
	steps int
}

func newPolAdam() *polAdam { return &polAdam{m: newPolGrads(), v: newPolGrads()} }

func (a *polAdam) step(p, g *polParams) {
	a.steps++
	t := float64(a.steps)
	c1 := 1 - math.Pow(polBeta1, t)
	c2 := 1 - math.Pow(polBeta2, t)

	weights, grads, moms, vels := p.all(), g.all(), a.m.all(), a.v.all()
	for x := range weights {
		for i := range weights[x] {
			w, gr, m, v := weights[x][i], grads[x][i], moms[x][i], vels[x][i]
			for j := range w {
				m[j] = polBeta1*m[j] + (1-polBeta1)*gr[j]
				v[j] = polBeta2*v[j] + (1-polBeta2)*gr[j]*gr[j]
				w[j] -= polLearnRate * (m[j] / c1) / (math.Sqrt(v[j]/c2) + polAdamEps)
			}
		}
	}
}

// polTrainStep takes one optimiser step over a window of dial history and
// returns the loss it saw. Only outcome symbols are scored: in the joint
// encoding every symbol but the start marker is a dial that already happened,
// and scoring the start marker would spend the gradient on noise.
func polTrainStep(p *polParams, a *polAdam, seq []int) float64 {
	if len(seq) > polBlock+1 {
		seq = seq[len(seq)-polBlock-1:]
	}
	if len(seq) < 2 {
		return 0
	}
	inp, targets := seq[:len(seq)-1], seq[1:]

	logits, cache := p.forward(inp)
	dlogits := make([][]float64, len(inp))
	loss, scored := 0.0, 0
	for i := range logits {
		probs := polSoftmax(logits[i])
		if targets[i] == polBOS {
			dlogits[i] = make([]float64, polVocab)
			continue
		}
		probs[targets[i]] -= 1
		dlogits[i] = probs
		loss += -math.Log(math.Max(probs[targets[i]]+1, 1e-300))
		scored++
	}
	if scored == 0 {
		return 0
	}
	for i := range dlogits {
		for j := range dlogits[i] {
			dlogits[i][j] /= float64(scored)
		}
	}
	a.step(p, p.backward(cache, dlogits))
	return loss / float64(scored)
}

func (p *polParams) backward(c *polCache, dlogits [][]float64) *polParams {
	t := len(c.tokens)
	headDim := polEmbd / polHead
	g := newPolGrads()

	dx := make([][]float64, t)
	for i := 0; i < t; i++ {
		polOuter(g.lmHead, dlogits[i], c.xOut[i])
		dx[i] = polApplyT(dlogits[i], p.lmHead)
	}

	dx2 := make([][]float64, t)
	for i := 0; i < t; i++ {
		dfr := polApplyT(dx[i], p.fc2)
		polOuter(g.fc2, dx[i], c.fr[i])

		df := make([]float64, len(dfr))
		for k := range dfr {
			if c.f[i][k] > 0 {
				df[k] = dfr[k]
			}
		}
		polOuter(g.fc1, df, c.h2[i])
		dh2 := polApplyT(df, p.fc1)

		dn := polDNorm(dh2, c.x2[i], c.rh2[i])
		row := make([]float64, polEmbd)
		for j := 0; j < polEmbd; j++ {
			row[j] = dx[i][j] + dn[j]
		}
		dx2[i] = row
	}

	do := make([][]float64, t)
	for i := 0; i < t; i++ {
		do[i] = polApplyT(dx2[i], p.wo)
		polOuter(g.wo, dx2[i], c.o[i])
	}

	dq := make([][]float64, t)
	dk := make([][]float64, t)
	dv := make([][]float64, t)
	for i := 0; i < t; i++ {
		dq[i] = make([]float64, polEmbd)
		dk[i] = make([]float64, polEmbd)
		dv[i] = make([]float64, polEmbd)
	}

	scale := math.Sqrt(float64(headDim))
	for head := 0; head < polHead; head++ {
		base := head * headDim
		for i := 0; i < t; i++ {
			a := c.att[head][i]
			da := make([]float64, len(a))
			for u := range a {
				sum := 0.0
				for d := 0; d < headDim; d++ {
					sum += do[i][base+d] * c.v[u][base+d]
				}
				da[u] = sum
				for d := 0; d < headDim; d++ {
					dv[u][base+d] += a[u] * do[i][base+d]
				}
			}
			dot := 0.0
			for u := range a {
				dot += da[u] * a[u]
			}
			for u := range a {
				datt := a[u] * (da[u] - dot) / scale
				for d := 0; d < headDim; d++ {
					dq[i][base+d] += datt * c.k[u][base+d]
					dk[u][base+d] += datt * c.q[i][base+d]
				}
			}
		}
	}

	for i := 0; i < t; i++ {
		polOuter(g.wq, dq[i], c.h[i])
		polOuter(g.wk, dk[i], c.h[i])
		polOuter(g.wv, dv[i], c.h[i])

		dh := polApplyT(dq[i], p.wq)
		dhk := polApplyT(dk[i], p.wk)
		dhv := polApplyT(dv[i], p.wv)
		for j := 0; j < polEmbd; j++ {
			dh[j] += dhk[j] + dhv[j]
		}

		dn := polDNorm(dh, c.xIn[i], c.rh[i])
		row := make([]float64, polEmbd)
		for j := 0; j < polEmbd; j++ {
			row[j] = dx2[i][j] + dn[j]
		}

		dx0 := polDNorm(row, c.x0[i], c.r1[i])
		tok := c.tokens[i]
		for j := 0; j < polEmbd; j++ {
			g.wte[tok][j] += dx0[j]
			g.wpe[i][j] += dx0[j]
		}
	}
	return g
}
