package protocol

import (
	"math"
	"strconv"
	"time"
)

type DialOutcome int

const (
	DialAlive DialOutcome = iota
	DialHandshakeDead
	DialLiveDead
	polOutcomes
)

const (
	polGapClip     = 24 * time.Hour
	polSlowClip    = 6.0
	polRecentDims  = 5 + liveMemoryScales
	polNormEps     = 1e-8
	polHiddenScale = 4
	polClockDims   = 4
	polDay         = 24 * time.Hour
	polWeek        = 7 * polDay

	polPacketHidden = 8
	polPacketLayers = 2
	polGRUGates     = 3
	polGRUCells     = 2 * polPacketLayers
	polPacketFeat   = polGRUCells * polPacketHidden
)

func polClock(ms int64) [polClockDims]float64 {
	at := time.UnixMilli(ms).UTC()
	sinceMidnight := at.Sub(at.Truncate(polDay))
	day := float64(sinceMidnight) / float64(polDay)
	week := (float64(at.Weekday())*float64(polDay) + float64(sinceMidnight)) / float64(polWeek)
	return [polClockDims]float64{
		math.Sin(2 * math.Pi * day), math.Cos(2 * math.Pi * day),
		math.Sin(2 * math.Pi * week), math.Cos(2 * math.Pi * week),
	}
}

type PolicyStep struct {
	Arm     int         `json:"a"`
	Outcome DialOutcome `json:"o"`
	Wire    WireVerdict `json:"w,omitempty"`
	AtMs    int64       `json:"t"`
	Slow    float64     `json:"s,omitempty"`
	Measure DialMeasure `json:"m,omitzero"`
	id      uint64
}

func polGapFeature(ms int64) float64 {
	if ms <= 0 {
		return 0
	}
	d := min(time.Duration(ms)*time.Millisecond, polGapClip)
	return math.Log2(1+d.Seconds()) / math.Log2(1+polGapClip.Seconds())
}

func PolicySlowness(latency, connect time.Duration) float64 {
	if latency <= 0 || connect <= 0 {
		return 0
	}
	v := math.Log2(float64(latency) / float64(connect))
	return math.Min(math.Max(v, 0), polSlowClip) / polSlowClip
}

type polLayerParams struct {
	wq, wk, wv, wo, fc1, fc2 [][]float64
}

type polGRUParams struct {
	ih, hh, bih, bhh [][]float64
}

var polGRUMatNames = []string{"ih", "hh", "bih", "bhh"}

var polGRUDirections = []string{"f", "b"}

func polGRUMatName(cell int, name string) string {
	return "gru." + strconv.Itoa(cell/len(polGRUDirections)) + "." + polGRUDirections[cell%len(polGRUDirections)] + "." + name
}

func (g *polGRUParams) all() []*[][]float64 { return []*[][]float64{&g.ih, &g.hh, &g.bih, &g.bhh} }

type polParams struct {
	arm, win, outcome, wire, meas, pkt, pktTail [][]float64
	gapIn, slowIn, gapQuery, chainQuery         [][]float64
	bosIn, wpe, recent                          [][]float64
	clock, clockQuery                           [][]float64
	check, checkBias                            [][]float64
	layers                                      []polLayerParams
	gru                                         []polGRUParams
}

var polMatNames = []string{"arm", "win", "outcome", "wire", "meas", "pkt", "pkt_tail", "gap_in", "slow_in", "gap_query", "chain_query", "bos_in", "wpe", "recent", "clock", "clock_query", "check", "check_bias"}

var polLayerMatNames = []string{"wq", "wk", "wv", "wo", "fc1", "fc2"}

func polLayerMatName(layer int, name string) string { return strconv.Itoa(layer) + "." + name }

func (l *polLayerParams) all() []*[][]float64 {
	return []*[][]float64{&l.wq, &l.wk, &l.wv, &l.wo, &l.fc1, &l.fc2}
}

func (p *polParams) flat() []*[][]float64 {
	return []*[][]float64{
		&p.arm, &p.win, &p.outcome, &p.wire, &p.meas, &p.pkt, &p.pktTail, &p.gapIn, &p.slowIn, &p.gapQuery, &p.chainQuery, &p.bosIn, &p.wpe, &p.recent,
		&p.clock, &p.clockQuery, &p.check, &p.checkBias,
	}
}

func (p *polParams) each(f func(name string, m [][]float64)) {
	for i, m := range p.flat() {
		f(polMatNames[i], *m)
	}
	for layer := range p.layers {
		for i, m := range p.layers[layer].all() {
			f(polLayerMatName(layer, polLayerMatNames[i]), *m)
		}
	}
	for cell := range p.gru {
		for i, m := range p.gru[cell].all() {
			f(polGRUMatName(cell, polGRUMatNames[i]), *m)
		}
	}
}

func polCloneMat(m [][]float64) [][]float64 {
	out := make([][]float64, len(m))
	for i, row := range m {
		out[i] = append([]float64(nil), row...)
	}
	return out
}

func newPolParams() *polParams {
	p := &polParams{
		arm: polCloneMat(polArm), win: polCloneMat(polWin), outcome: polCloneMat(polOutcome), wire: polCloneMat(polWire),
		meas: polCloneMat(polMeas), pkt: polCloneMat(polPkt), pktTail: polCloneMat(polPktTail), gapIn: polCloneMat(polGapIn), slowIn: polCloneMat(polSlowIn), gapQuery: polCloneMat(polGapQuery), chainQuery: polCloneMat(polChainQuery),
		bosIn: polCloneMat(polBosIn), wpe: polCloneMat(polWpe), recent: polCloneMat(polRecent),
		clock: polCloneMat(polClockIn), clockQuery: polCloneMat(polClockQuery),
		check: polCloneMat(polCheck), checkBias: polCloneMat(polCheckBias),
		layers: make([]polLayerParams, polLayer),
		gru:    make([]polGRUParams, polGRUCells),
	}
	for l := range p.layers {
		p.layers[l] = polLayerParams{
			wq: polCloneMat(polWq[l]), wk: polCloneMat(polWk[l]), wv: polCloneMat(polWv[l]), wo: polCloneMat(polWo[l]),
			fc1: polCloneMat(polFc1[l]), fc2: polCloneMat(polFc2[l]),
		}
	}
	for cell := range p.gru {
		p.gru[cell] = polGRUParams{ih: polCloneMat(polGRUIh[cell]), hh: polCloneMat(polGRUHh[cell]), bih: polCloneMat(polGRUBih[cell]), bhh: polCloneMat(polGRUBhh[cell])}
	}
	return p
}

func (p *polParams) clone() *polParams {
	c := &polParams{layers: make([]polLayerParams, len(p.layers)), gru: make([]polGRUParams, len(p.gru))}
	src, dst := p.flat(), c.flat()
	for i := range src {
		*dst[i] = polCloneMat(*src[i])
	}
	for l := range p.layers {
		from, to := p.layers[l].all(), c.layers[l].all()
		for i := range from {
			*to[i] = polCloneMat(*from[i])
		}
	}
	for cell := range p.gru {
		from, to := p.gru[cell].all(), c.gru[cell].all()
		for i := range from {
			*to[i] = polCloneMat(*from[i])
		}
	}
	return c
}

func polPresets() int { return polFeatDim - armDeliveryDims }

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

func polSigmoid(z float64) float64 { return 1 / (1 + math.Exp(-z)) }

func polSoftplus(x float64) float64 { return math.Max(x, 0) + math.Log1p(math.Exp(-math.Abs(x))) }

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

func polNorm(x []float64) []float64 {
	sum := 0.0
	for _, v := range x {
		sum += v * v
	}
	r := math.Sqrt(sum/float64(len(x)) + polNormEps)
	out := make([]float64, len(x))
	for i, v := range x {
		out[i] = v / r
	}
	return out
}

func armRecency(steps []PolicyStep, arm, presets int) []float64 {
	preset, budget := JointArmParts(arm, presets)
	var hard, weak, shared, sharedLive, streak float64
	streakOpen := true
	for d := 1; d <= len(steps); d++ {
		decay := 1 - float64(d-1)/float64(deadArmDecay)
		if decay <= 0 {
			break
		}
		s := steps[len(steps)-d]
		hardFail := s.Outcome == DialLiveDead || (s.Outcome == DialHandshakeDead && s.Wire.Blocked())
		weakFail := s.Outcome == DialHandshakeDead && !s.Wire.Blocked()
		switch {
		case s.Arm == arm:
			if hardFail {
				hard += decay
			}
			if weakFail {
				weak += decay
			}
			if streakOpen && weakFail {
				streak++
			} else {
				streakOpen = false
			}
		case hardFail && sharesFailure(s, arm, preset, budget, presets):
			if s.Outcome == DialLiveDead {
				sharedLive += decay
			} else {
				shared += decay
			}
		}
	}
	return []float64{failIntensity(hard), failIntensity(weak), failIntensity(shared), failIntensity(streak), failIntensity(sharedLive)}
}

func failIntensity(sum float64) float64 { return math.Min(sum/deadArmWeakFails, 1) }

func sameLevers(a, b, presets int) bool {
	return JointArmMigrates(a, presets) == JointArmMigrates(b, presets) && JointArmShaped(a, presets) == JointArmShaped(b, presets)
}

func sharesFailure(s PolicyStep, arm, preset, budget, presets int) bool {
	if s.Outcome == DialLiveDead {
		return sameLevers(s.Arm, arm, presets)
	}
	sp, sb := JointArmParts(s.Arm, presets)
	return sp == preset || sb == budget
}

const (
	liveMemoryShortest = time.Minute
	liveMemoryLongest  = 12 * time.Hour
	liveMemoryScales   = 3
	liveMemoryHorizon  = 5
)

func liveMemoryScale(u int) time.Duration {
	ratio := float64(liveMemoryLongest) / float64(liveMemoryShortest)
	return time.Duration(float64(liveMemoryShortest) * math.Pow(ratio, float64(u)/float64(liveMemoryScales-1)))
}

func liveMemory(deaths []PolicyStep, nowMs int64, arm, presets int) []float64 {
	out := make([]float64, liveMemoryScales)
	for _, d := range deaths {
		if d.Outcome != DialLiveDead || d.AtMs > nowMs || !sameLevers(d.Arm, arm, presets) {
			continue
		}
		age := time.Duration(nowMs-d.AtMs) * time.Millisecond
		for u := range out {
			out[u] += math.Exp(-age.Seconds() / liveMemoryScale(u).Seconds())
		}
	}
	for u := range out {
		out[u] = failIntensity(out[u])
	}
	return out
}

func rememberDeath(deaths []PolicyStep, s PolicyStep, nowMs int64) []PolicyStep {
	horizon := liveMemoryHorizon * liveMemoryScale(liveMemoryScales-1).Milliseconds()
	kept := deaths[:0:0]
	for _, d := range deaths {
		if nowMs-d.AtMs < horizon {
			kept = append(kept, d)
		}
	}
	if s.Outcome == DialLiveDead && nowMs-s.AtMs < horizon {
		kept = append(kept, s)
	}
	return polWindow(kept, polBlock)
}

func armHazardInputs(steps, deaths []PolicyStep, nowMs int64, arm int) []float64 {
	return append(armRecency(steps, arm, polPresets()), liveMemory(deaths, nowMs, arm, polPresets())...)
}

func (p *polParams) recentHazard(steps, deaths []PolicyStep, nowMs int64, arm int) float64 {
	sum := 0.0
	for k, v := range armHazardInputs(steps, deaths, nowMs, arm) {
		sum += v * polSoftplus(p.recent[0][k])
	}
	return sum
}

func (p *polParams) armVec(arm int) []float64 {
	feat := JointArmFeatures(arm, polPresets())
	out := append([]float64(nil), p.arm[arm]...)
	for j := range out {
		for f := 0; f < polFeatDim; f++ {
			out[j] += feat[f] * p.win[j][f]
		}
	}
	return out
}

type polInput struct {
	bos  bool
	step PolicyStep
	gap  float64
}

func polInputs(steps []PolicyStep) []polInput {
	in := make([]polInput, 0, len(steps)+1)
	in = append(in, polInput{bos: true})
	for i, s := range steps {
		gap := 0.0
		if i > 0 {
			gap = polGapFeature(s.AtMs - steps[i-1].AtMs)
		}
		in = append(in, polInput{step: s, gap: gap})
	}
	return in
}

func (g *polGRUParams) run(seq [][]float64, backward bool) [][]float64 {
	out := make([][]float64, len(seq))
	h := make([]float64, polPacketHidden)
	for i := range seq {
		t := i
		if backward {
			t = len(seq) - 1 - i
		}
		gi, gh := polApply(seq[t], g.ih), polApply(h, g.hh)
		next := make([]float64, polPacketHidden)
		for j := range next {
			r := polSigmoid(gi[j] + g.bih[0][j] + gh[j] + g.bhh[0][j])
			z := polSigmoid(gi[polPacketHidden+j] + g.bih[0][polPacketHidden+j] + gh[polPacketHidden+j] + g.bhh[0][polPacketHidden+j])
			n := math.Tanh(gi[2*polPacketHidden+j] + g.bih[0][2*polPacketHidden+j] + r*(gh[2*polPacketHidden+j]+g.bhh[0][2*polPacketHidden+j]))
			next[j] = (1-z)*n + z*h[j]
		}
		h, out[t] = next, next
	}
	return out
}

func (p *polParams) encodePackets(pkts []WirePacket) []float64 {
	out := make([]float64, polPacketFeat)
	if len(pkts) == 0 {
		return out
	}
	seq := packetFeatures(pkts)
	for l := 0; l < polPacketLayers; l++ {
		fwd := p.gru[2*l].run(seq, false)
		bwd := p.gru[2*l+1].run(seq, true)
		copy(out[2*l*polPacketHidden:], fwd[len(seq)-1])
		copy(out[(2*l+1)*polPacketHidden:], bwd[0])
		next := make([][]float64, len(seq))
		for t := range seq {
			next[t] = append(append([]float64(nil), fwd[t]...), bwd[t]...)
		}
		seq = next
	}
	return out
}

type packetGaussians struct {
	Mean       [][]float64 `json:"mean"`
	Precision  [][]float64 `json:"precision"`
	Bar        []float64   `json:"bar"`
	Count      []float64   `json:"count"`
	Calibrated []float64   `json:"calibrated"`
}

type polNovelty struct {
	Opening packetGaussians `json:"opening"`
	Tail    packetGaussians `json:"tail"`
}

func shippedNovelty() polNovelty {
	return polNovelty{
		Opening: packetGaussians{Mean: polOpeningMean, Precision: polOpeningPrecision, Bar: polFirstRow(polOpeningBar)},
		Tail:    packetGaussians{Mean: polTailMean, Precision: polTailPrecision, Bar: polFirstRow(polTailBar)},
	}
}

func polFirstRow(m [][]float64) []float64 {
	if len(m) == 0 {
		return nil
	}
	return m[0]
}

func (n polNovelty) of(outcome DialOutcome) (packetGaussians, int, bool) {
	g, class := n.Opening, int(outcome)
	if outcome == DialLiveDead {
		g, class = n.Tail, 0
	}
	return g, class, outcome != DialAlive && g.fits(class)
}

func (g packetGaussians) fits(class int) bool {
	return class < len(g.Bar) && g.Bar[class] > 0 && class < len(g.Mean) && len(g.Precision) == polPacketFeat
}

func (g packetGaussians) distance(enc, mean []float64) float64 {
	diff := make([]float64, len(enc))
	for i := range enc {
		diff[i] = enc[i] - mean[i]
	}
	sum := 0.0
	for i, row := range g.Precision {
		sum += diff[i] * polDot(row, diff)
	}
	return sum
}

func (p *polParams) tokenEmbed(in polInput) []float64 {
	if in.bos {
		return append([]float64(nil), p.bosIn[0]...)
	}
	row := p.armVec(in.step.Arm)
	seen := in.step.Wire.feature()
	measured := in.step.Measure.features()
	packets := p.encodePackets(in.step.Measure.Packets)
	tail := p.encodePackets(in.step.Measure.Tail)
	clock := polClock(in.step.AtMs)
	for j := range row {
		row[j] += p.outcome[in.step.Outcome][j] + p.gapIn[j][0]*in.gap + p.slowIn[j][0]*in.step.Slow
		if seen >= 0 {
			row[j] += p.wire[j][seen]
		}
		for f, v := range measured {
			row[j] += p.meas[j][f] * v
		}
		for k, v := range packets {
			row[j] += p.pkt[j][k] * v
		}
		for k, v := range tail {
			row[j] += p.pktTail[j][k] * v
		}
		for k, v := range clock {
			row[j] += p.clock[j][k] * v
		}
	}
	return row
}

func (l *polLayerParams) apply(x [][]float64) [][]float64 {
	t := len(x)
	headDim := polEmbd / polHead
	q, k, v := make([][]float64, t), make([][]float64, t), make([][]float64, t)
	for i := range x {
		h := polNorm(x[i])
		q[i], k[i], v[i] = polApply(h, l.wq), polApply(h, l.wk), polApply(h, l.wv)
	}
	scale := math.Sqrt(float64(headDim))
	out := make([][]float64, t)
	for i := 0; i < t; i++ {
		o := make([]float64, polEmbd)
		for head := 0; head < polHead; head++ {
			base := head * headDim
			scores := make([]float64, i+1)
			for u := 0; u <= i; u++ {
				scores[u] = polDot(q[i][base:base+headDim], k[u][base:base+headDim]) / scale
			}
			for u, a := range polSoftmax(scores) {
				for d := 0; d < headDim; d++ {
					o[base+d] += a * v[u][base+d]
				}
			}
		}
		proj := polApply(o, l.wo)
		mid := make([]float64, polEmbd)
		for j := range mid {
			mid[j] = x[i][j] + proj[j]
		}
		hidden := polApply(polNorm(mid), l.fc1)
		for j, val := range hidden {
			hidden[j] = math.Max(val, 0)
		}
		back := polApply(hidden, l.fc2)
		for j := range mid {
			mid[j] += back[j]
		}
		out[i] = mid
	}
	return out
}

func (p *polParams) forward(inputs []polInput) [][]float64 {
	x := make([][]float64, len(inputs))
	for i, in := range inputs {
		row := p.tokenEmbed(in)
		for j := range row {
			row[j] += p.wpe[i][j]
		}
		x[i] = polNorm(row)
	}
	for l := range p.layers {
		x = p.layers[l].apply(x)
	}
	for i := range x {
		x[i] = polNorm(x[i])
	}
	return x
}

func (p *polParams) query(x []float64, gap float64, nowMs int64, chain [polChainDims]float64) []float64 {
	clock := polClock(nowMs)
	out := make([]float64, polEmbd)
	for j := range out {
		out[j] = x[j] + gap*p.gapQuery[j][0]
		for k, v := range chain {
			out[j] += p.chainQuery[j][k] * v
		}
		for k, v := range clock {
			out[j] += p.clockQuery[j][k] * v
		}
	}
	return out
}

func polDot(a, b []float64) float64 {
	s := 0.0
	for i := range a {
		s += a[i] * b[i]
	}
	return s
}

func (p *polParams) armScores(steps []PolicyStep, nowMs int64, arms int) []float64 {
	scores, _ := p.decide(steps, steps, nowMs, chainFeatures(0, 0), arms)
	return scores
}

func (p *polParams) decide(steps, deaths []PolicyStep, nowMs int64, chain [polChainDims]float64, arms int) (scores []float64, trust float64) {
	steps = polWindow(steps, polBlock-1)
	x := p.forward(polInputs(steps))
	gap := 0.0
	if len(steps) > 0 {
		gap = polGapFeature(nowMs - steps[len(steps)-1].AtMs)
	}
	q := p.query(x[len(x)-1], gap, nowMs, chain)
	scores = make([]float64, arms)
	for a := 0; a < arms; a++ {
		scores[a] = polSigmoid(polDot(q, p.armVec(a))) * math.Exp(-p.recentHazard(steps, deaths, nowMs, a))
	}
	return scores, polSigmoid(polDot(q, p.check[0]) + p.checkBias[0][0])
}

func polWindow(steps []PolicyStep, size int) []PolicyStep {
	if len(steps) > size {
		return steps[len(steps)-size:]
	}
	return steps
}

func outcomeLoss(pAlive float64, alive bool) float64 {
	q := math.Min(math.Max(pAlive, polLossFloor), 1-polLossFloor)
	if alive {
		return -math.Log(q)
	}
	return -math.Log(1 - q)
}

const polLossFloor = 1e-6

func (p *polParams) conditional(doc []PolicyStep) (probs, trust []float64) {
	probs, trust = make([]float64, len(doc)), make([]float64, len(doc))
	var deaths []PolicyStep
	for i, s := range doc {
		if i > 0 {
			deaths = rememberDeath(deaths, doc[i-1], s.AtMs)
		}
		scores, g := p.decide(doc[:i], deaths, s.AtMs, s.Measure.chainFeatures(), polArms)
		probs[i], trust[i] = scores[s.Arm], g
	}
	return probs, trust
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

func policyJointUsable(presets int) bool { return JointArmCount(presets) == polArms }
