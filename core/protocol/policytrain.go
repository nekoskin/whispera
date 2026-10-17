package protocol

import (
	"math"
	mrand "math/rand"
	"os"
	"sync"
)

type polParams struct {
	win, oin, bosIn    [][]float64
	wout, oout, bosOut [][]float64
	wpe                [][]float64
	wq, wk, wv, wo     [][]float64
	fc1, fc2           [][]float64
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
	head   [][]float64
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

func newPolParams() *polParams {
	return &polParams{
		win:    polCloneMat(polWin),
		oin:    polCloneMat(polOin),
		bosIn:  polCloneMat(polBosIn),
		wout:   polCloneMat(polWout),
		oout:   polCloneMat(polOout),
		bosOut: polCloneMat(polBosOut),
		wpe:    polCloneMat(polWpe),
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
		win:    polZeroLike(polWin),
		oin:    polZeroLike(polOin),
		bosIn:  polZeroLike(polBosIn),
		wout:   polZeroLike(polWout),
		oout:   polZeroLike(polOout),
		bosOut: polZeroLike(polBosOut),
		wpe:    polZeroLike(polWpe),
		wq:     polZeroLike(polWq[0]),
		wk:     polZeroLike(polWk[0]),
		wv:     polZeroLike(polWv[0]),
		wo:     polZeroLike(polWo[0]),
		fc1:    polZeroLike(polFc1[0]),
		fc2:    polZeroLike(polFc2[0]),
	}
}

var polMatNames = []string{
	"win", "oin", "bos_in", "wout", "oout", "bos_out",
	"wpe", "0.wq", "0.wk", "0.wv", "0.wo", "0.fc1", "0.fc2",
}

func (p *polParams) all() [][][]float64 {
	return [][][]float64{
		p.win, p.oin, p.bosIn, p.wout, p.oout, p.bosOut,
		p.wpe, p.wq, p.wk, p.wv, p.wo, p.fc1, p.fc2,
	}
}

func (p *polParams) each(f func(name string, m [][]float64)) {
	for i, m := range p.all() {
		f(polMatNames[i], m)
	}
}

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

func (p *polParams) tokenEmbed(tok int) []float64 {
	row := make([]float64, polEmbd)
	if tok == polBOS {
		copy(row, p.bosIn[0])
		return row
	}
	arm, out := tok/2, tok%2
	feat := JointArmFeatures(arm, polPresets())
	for j := 0; j < polEmbd; j++ {
		s := p.oin[out][j]
		for f := 0; f < polFeatDim; f++ {
			s += feat[f] * p.win[j][f]
		}
		row[j] = s
	}
	return row
}

func (p *polParams) candHead() [][]float64 {
	head := make([][]float64, polArms*2+1)
	for c := 0; c < polArms*2; c++ {
		arm, out := c/2, c%2
		feat := JointArmFeatures(arm, polPresets())
		row := make([]float64, polEmbd)
		woutBase := out * polEmbd
		for j := 0; j < polEmbd; j++ {
			s := p.oout[out][j]
			for f := 0; f < polFeatDim; f++ {
				s += feat[f] * p.wout[woutBase+j][f]
			}
			row[j] = s
		}
		head[c] = row
	}
	head[polBOS] = append([]float64(nil), p.bosOut[0]...)
	return head
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
		row := p.tokenEmbed(tok)
		for j := 0; j < polEmbd; j++ {
			row[j] += p.wpe[i][j]
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

	c.head = p.candHead()
	logits := make([][]float64, t)
	for i := 0; i < t; i++ {
		logits[i] = polApply(c.xOut[i], c.head)
	}
	return logits, c
}

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

const (
	polOnlineStepEvery = 8
	polOnlineWindow    = 32
	polOnlineFloor     = 0.5
	polOnlineHealthy   = 0.8
	polOnlineExplore   = 0.1
)

func PolicyOnlineEnabled() bool { return os.Getenv("WHISPERA_POLICY_ONLINE") != "0" }

type onlinePolicy struct {
	mu         sync.Mutex
	live       *polParams
	adam       *polAdam
	hist       map[string][]int
	outcomes   []bool
	pending    int
	steps      int
	reverts    int
	fails      map[string]map[int]int
	sinceDecay map[string]int
	strikes    map[string]map[int]int
	mutants    map[string][]*mutantStat
	tuned      bool
	rev        int
	saved      int
}

func newOnlinePolicy() *onlinePolicy {
	return &onlinePolicy{
		live:       newPolParams(),
		adam:       newPolAdam(),
		hist:       map[string][]int{},
		fails:      map[string]map[int]int{},
		sinceDecay: map[string]int{},
		strikes:    map[string]map[int]int{},
		mutants:    map[string][]*mutantStat{},
	}
}

const (
	deadArmFails      = 1
	deadArmDecay      = 16
	deadArmBackoffMax = 4
	deadArmWeakFails  = 3
)

func (o *onlinePolicy) alive(ctx string, a int) bool { return o.fails[ctx][a] < deadArmFails }

func (o *onlinePolicy) aliveArms(ctx string, arms int, fits func(int) bool) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for a := 0; a < arms; a++ {
		if fits(a) && o.alive(ctx, a) {
			n++
		}
	}
	return n
}

func (o *onlinePolicy) fitAlive(ctx string, fits func(int) bool, arms int) func(int) bool {
	alive := func(a int) bool { return fits(a) && o.alive(ctx, a) }
	unrelated := func(a int) bool { return alive(a) && !o.sharesPartWithDead(ctx, a) }
	for _, tier := range []func(int) bool{unrelated, alive} {
		for a := 0; a < arms; a++ {
			if tier(a) {
				return tier
			}
		}
	}
	return fits
}

func (o *onlinePolicy) sharesPartWithDead(ctx string, a int) bool {
	preset, budget := JointArmParts(a, polPresets())
	for dead, n := range o.fails[ctx] {
		if n < deadArmFails {
			continue
		}
		deadPreset, deadBudget := JointArmParts(dead, polPresets())
		if deadPreset == preset || deadBudget == budget {
			return true
		}
	}
	return false
}

func (o *onlinePolicy) noteFail(ctx string, arm int, alive, strong bool) {
	fails := o.fails[ctx]
	if fails == nil {
		fails = map[int]int{}
		o.fails[ctx] = fails
	}
	strikes := o.strikes[ctx]
	if strikes == nil {
		strikes = map[int]int{}
		o.strikes[ctx] = strikes
	}
	if alive {
		delete(fails, arm)
		delete(strikes, arm)
	} else {
		strikes[arm]++

		if strong || strikes[arm] >= deadArmWeakFails {
			fails[arm] = deadArmFails << min(strikes[arm]-1, deadArmBackoffMax)
		}
	}
	o.tickDecay(ctx)
}

func (o *onlinePolicy) tickDecay(ctx string) {
	o.sinceDecay[ctx]++
	if o.sinceDecay[ctx] < deadArmDecay {
		return
	}
	o.sinceDecay[ctx] = 0
	fails := o.fails[ctx]
	for a, n := range fails {
		if n > 1 {
			fails[a] = n - 1
		} else {
			delete(fails, a)
		}
	}
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

func (o *onlinePolicy) Select(ctx string, arms int, fits func(int) bool, roll func() float64) (int, bool) {
	if arms < 1 {
		return 0, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()

	fits = o.fitAlive(ctx, fits, arms)

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

func (o *onlinePolicy) Note(ctx string, arm int, alive, strong bool) {
	if arm < 0 || arm >= polArms {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()

	o.rev++
	o.noteFail(ctx, arm, alive, strong)

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
		o.tuned = true
		window := make([]int, 0, len(seq)+1)
		window = append(window, polBOS)
		window = append(window, seq...)
		polTrainStep(o.live, o.adam, window)
	}

	if len(o.outcomes) >= polOnlineWindow && o.survival() < polOnlineFloor {
		o.revert()
	}
}

func (o *onlinePolicy) revert() {
	o.live = newPolParams()
	o.adam = newPolAdam()
	o.tuned = false
	o.outcomes = nil
	o.pending = 0
	o.reverts++
	traceLog.Infow("online policy reverted", "reverts", o.reverts, "steps", o.steps)
}

var onlinePolicyOnce struct {
	once sync.Once
	p    *onlinePolicy
}

func sharedOnlinePolicy() *onlinePolicy {
	onlinePolicyOnce.once.Do(func() { onlinePolicyOnce.p = newOnlinePolicy() })
	return onlinePolicyOnce.p
}

func (h *HandshakeStrategy) SelectJointOnline(ctx string, presets int, fragmented bool) (arm int, explored, ok bool) {
	if !policyJointUsable(presets) {
		return 0, false, false
	}
	a, probe := sharedOnlinePolicy().Select(ctx, JointArmCount(presets), jointArmFits(fragmented), mrand.Float64)
	return a, probe, true
}

func (h *HandshakeStrategy) NoteJointOnline(ctx string, arm int, alive, strong bool) {
	sharedOnlinePolicy().Note(ctx, arm, alive, strong)
}

func (h *HandshakeStrategy) JointAliveArms(ctx string, presets int, fragmented bool) int {
	if !policyJointUsable(presets) {
		return 0
	}
	return sharedOnlinePolicy().aliveArms(ctx, JointArmCount(presets), jointArmFits(fragmented))
}

func PolicyOnlineState() (steps, reverts int, survival float64) {
	o := sharedOnlinePolicy()
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.steps, o.reverts, o.survival()
}

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
			dlogits[i] = make([]float64, polArms*2+1)
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

	nCand := polArms*2 + 1
	gHead := make([][]float64, nCand)
	gWte := make([][]float64, nCand)
	for c := 0; c < nCand; c++ {
		gHead[c] = make([]float64, polEmbd)
		gWte[c] = make([]float64, polEmbd)
	}

	dx := make([][]float64, t)
	for i := 0; i < t; i++ {
		polOuter(gHead, dlogits[i], c.xOut[i])
		dx[i] = polApplyT(dlogits[i], c.head)
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
			gWte[tok][j] += dx0[j]
			g.wpe[i][j] += dx0[j]
		}
	}

	presets := polPresets()
	for cand := 0; cand < polArms*2; cand++ {
		arm, out := cand/2, cand%2
		feat := JointArmFeatures(arm, presets)
		woutBase := out * polEmbd
		for j := 0; j < polEmbd; j++ {
			g.oin[out][j] += gWte[cand][j]
			g.oout[out][j] += gHead[cand][j]
			for f := 0; f < polFeatDim; f++ {
				g.win[j][f] += gWte[cand][j] * feat[f]
				g.wout[woutBase+j][f] += gHead[cand][j] * feat[f]
			}
		}
	}
	for j := 0; j < polEmbd; j++ {
		g.bosIn[0][j] += gWte[polBOS][j]
		g.bosOut[0][j] += gHead[polBOS][j]
	}
	return g
}
