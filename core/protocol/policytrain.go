package protocol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"math"
	"os/exec"
	"sync"
	"time"
)

const polOnlineStepEvery = 8

const (
	polLearnRate = 0.001
	polBeta1     = 0.85
	polBeta2     = 0.99
	polAdamEps   = 1e-8
	polInitStd   = 0.02
	polDropout   = 0.2
	polParityTol = 1e-9
	polServeOp   = "torchserve"

	polSelAlpha    = 0.5
	polSelLambda   = 32
	polSelCoverage = 0.9

	polRecLoss    = 0.5
	polRecBuckets = 16
	polGradClip   = 5.0
	polAuxLoss    = 1.0
	polModDrop    = 0.1

	BlockPatternLimit = 16
	NoveltyFalseAlarm = 0.05
)

const (
	expertNet = iota
	expertArmRate
	expertLastOutcome
	polExperts
)

const (
	polTrustPrior   = 0.8
	polTrustShare   = 0.05
	polTrustRetrain = 0.5
)

func polTrustStart() [polExperts]float64 {
	rest := (1 - polTrustPrior) / (polExperts - 1)
	return [polExperts]float64{polTrustPrior, rest, rest}
}

func laplace(alive, seen float64) float64 { return (alive + 1) / (seen + 2) }

func expertScores(steps []PolicyStep, arms int) (rate, last []float64) {
	alive, seen := make([]float64, arms), make([]float64, arms)
	lastAlive := make([]int, arms)
	total, totalAlive := 0.0, 0.0
	for _, s := range steps {
		if s.Arm < 0 || s.Arm >= arms {
			continue
		}
		seen[s.Arm]++
		total++
		lastAlive[s.Arm] = 0
		if s.Outcome == DialAlive {
			alive[s.Arm]++
			totalAlive++
			lastAlive[s.Arm] = 1
		}
	}
	window := laplace(totalAlive, total)
	rate, last = make([]float64, arms), make([]float64, arms)
	for a := range rate {
		rate[a] = (alive[a] + window) / (seen[a] + 1)
		last[a] = window
		if seen[a] > 0 {
			last[a] = laplace(float64(lastAlive[a]), 1)
		}
	}
	return rate, last
}

type polVerdict struct {
	mixed []float64
	net   []float64
	check float64
	trust [polExperts]float64
}

func (o *onlinePolicy) trustOf(ctx string) [polExperts]float64 {
	if w, ok := o.trust[ctx]; ok {
		return w
	}
	return polTrustStart()
}

func (o *onlinePolicy) verdictLocked(ctx string, nowMs int64, arms int) polVerdict {
	steps := o.dials[ctx]
	net, check := o.live.decide(steps, o.deaths[ctx], nowMs, o.chainOf(ctx), arms)
	w := o.trustOf(ctx)
	if w[expertNet] >= polTrustRetrain && check >= polAliveBar {
		return polVerdict{mixed: net, net: net, check: check, trust: w}
	}
	rate, last := expertScores(polWindow(steps, polBlock-1), arms)
	netWeight := w[expertNet] * check
	sum := netWeight + w[expertArmRate] + w[expertLastOutcome]
	mixed := make([]float64, arms)
	for a := range mixed {
		mixed[a] = (netWeight*net[a] + w[expertArmRate]*rate[a] + w[expertLastOutcome]*last[a]) / sum
	}
	return polVerdict{mixed: mixed, net: net, check: check, trust: w}
}

func (o *onlinePolicy) checkLocked(ctx string, arm int, alive bool) {
	steps := o.dials[ctx]
	net, _ := o.live.decide(steps, o.deaths[ctx], o.nowMs(), o.chainOf(ctx), polArms)
	rate, last := expertScores(polWindow(steps, polBlock-1), polArms)
	predicted := [polExperts]float64{net[arm], rate[arm], last[arm]}
	w := o.trustOf(ctx)
	sum := 0.0
	for e, p := range predicted {
		p = math.Min(math.Max(p, polLossFloor), 1-polLossFloor)
		if !alive {
			p = 1 - p
		}
		w[e] *= p
		sum += w[e]
	}
	prior := polTrustStart()
	for e := range w {
		w[e] = (1-polTrustShare)*w[e]/sum + polTrustShare*prior[e]
	}
	o.trust[ctx] = w
}

var polZeroInit = []string{"wire", "meas", "pkt", "pkt_tail", "chain_query", "recent", "clock", "clock_query"}

type DialNote struct {
	Alive   bool
	Strong  bool
	Wire    WireVerdict
	Slow    float64
	Measure DialMeasure
}

type onlinePolicy struct {
	mu       sync.Mutex
	live     *polParams
	frozen   *polParams
	dials    map[string][]PolicyStep
	deaths   map[string][]PolicyStep
	chain    map[string][polChainDims]float64
	pending  int
	steps    int
	tuned    bool
	nextID   uint64
	anchor   float64
	rev      int
	saved    int
	now      func() time.Time
	trainer  *polTrainer
	training bool
	trust    map[string][polExperts]float64

	novelty     polNovelty
	patterns    []BlockPattern
	lastPattern int

	speed map[string][]armSpeed
}

type armSpeed struct {
	N    int     `json:"n"`
	Mean float64 `json:"mean"`
}

func newOnlinePolicy() *onlinePolicy {
	return &onlinePolicy{
		live:    newPolParams(),
		frozen:  newPolParams(),
		dials:   map[string][]PolicyStep{},
		deaths:  map[string][]PolicyStep{},
		chain:   map[string][polChainDims]float64{},
		anchor:  polAnchor,
		now:     time.Now,
		trust:   map[string][polExperts]float64{},
		novelty: shippedNovelty(),
		speed:   map[string][]armSpeed{},
	}
}

const (
	deadArmDecay     = 16
	deadArmWeakFails = 3
	polAliveBar      = 0.5
	polLeverCost     = 0.02
	polSpeedExplore  = 0.1

	reportedFreezeSpan = 120 * time.Second
)

func leverUtility(scores []float64) []float64 {
	out := make([]float64, len(scores))
	for a, s := range scores {
		out[a] = s - polLeverCost*(indicator(JointArmMigrates(a, polPresets()))+indicator(JointArmShaped(a, polPresets())))
	}
	return out
}

func (o *onlinePolicy) aliveArms(ctx string, arms int, fits func(int) bool) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	scores := o.verdictLocked(ctx, o.nowMs(), arms).mixed
	n := 0
	for a := 0; a < arms; a++ {
		if fits(a) && scores[a] >= polAliveBar {
			n++
		}
	}
	if n == 0 && probeArm(scores, fits, o.dials[ctx]) >= 0 {
		n = 1
	}
	return n
}

func (o *onlinePolicy) anyAlive(ctx string, arms int, fits func(int) bool) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	scores := o.verdictLocked(ctx, o.nowMs(), arms).mixed
	best := bestFittingArm(scores, fits)
	return best >= 0 && scores[best] >= polAliveBar
}

func heldPreset(steps []PolicyStep, nowMs int64) (int, bool) {
	if len(steps) == 0 || steps[len(steps)-1].Outcome != DialHandshakeDead {
		return 0, false
	}
	start := steps[len(steps)-1].AtMs
	for i := len(steps) - 1; i >= 0 && steps[i].Outcome == DialHandshakeDead; i-- {
		start = steps[i].AtMs
	}
	if nowMs-start >= reportedFreezeSpan.Milliseconds() {
		return 0, false
	}
	preset, _ := JointArmParts(steps[len(steps)-1].Arm, polPresets())
	return preset, true
}

func withPreset(fits func(int) bool, preset int) func(int) bool {
	return func(a int) bool {
		p, _ := JointArmParts(a, polPresets())
		return p == preset && fits(a)
	}
}

func smallHelloFailed(steps []PolicyStep) bool {
	for _, s := range steps {
		if s.Outcome != DialAlive && JointArmDropPQ(s.Arm, polPresets()) {
			return true
		}
	}
	return false
}

func probeArm(scores []float64, fits func(int) bool, steps []PolicyStep) int {
	if smallHelloFailed(steps) {
		return -1
	}
	return bestFittingArm(leverUtility(scores), func(a int) bool { return fits(a) && JointArmDropPQ(a, polPresets()) })
}

func (o *onlinePolicy) nowMs() int64 { return o.now().UnixMilli() }

func (o *onlinePolicy) Select(ctx string, arms int, fits func(int) bool) int {
	if arms < 1 {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if steps := o.dials[ctx]; len(steps) > 0 {
		if last := steps[len(steps)-1]; last.Outcome == DialAlive && last.Arm < arms && fits(last.Arm) {
			return last.Arm
		}
	}
	scores := o.verdictLocked(ctx, o.nowMs(), arms).mixed
	utility := leverUtility(scores)
	best := bestFittingArm(utility, fits)
	if best >= 0 && scores[best] < polAliveBar {
		steps := o.dials[ctx]
		if preset, held := heldPreset(steps, o.nowMs()); held {
			if kept := bestFittingArm(utility, withPreset(fits, preset)); kept >= 0 {
				best, fits = kept, withPreset(fits, preset)
			}
		}
		if probe := probeArm(scores, fits, steps); probe >= 0 {
			return probe
		}
		return best
	}
	if best < 0 {
		return best
	}
	return o.fasterLocked(ctx, utility, fits, best)
}

func (o *onlinePolicy) fasterLocked(ctx string, utility []float64, fits func(int) bool, best int) int {
	presets := polPresets()
	preset, _ := JointArmParts(best, presets)
	speed := o.speed[ctx]
	var candidates []int
	total, norm, measured := 0, 0.0, 0
	for a := range utility {
		if p, _ := JointArmParts(a, presets); p != preset || !fits(a) || utility[a] < utility[best]-polLeverCost {
			continue
		}
		candidates = append(candidates, a)
		if a < len(speed) && speed[a].N > 0 {
			total += speed[a].N
			norm += speed[a].Mean
			measured++
		}
	}
	if len(candidates) < 2 {
		return best
	}
	unexplored := -1
	for _, a := range candidates {
		if (a >= len(speed) || speed[a].N == 0) && (unexplored < 0 || utility[a] > utility[unexplored]) {
			unexplored = a
		}
	}
	if unexplored >= 0 {
		return unexplored
	}
	if norm /= float64(measured); norm <= 0 {
		norm = 1
	}
	pick, bound := best, math.Inf(1)
	for _, a := range candidates {
		s := speed[a]
		if b := s.Mean/norm - math.Sqrt(polSpeedExplore*math.Log(float64(total))/float64(s.N)); b < bound {
			pick, bound = a, b
		}
	}
	return pick
}

func (o *onlinePolicy) NoteDial(ctx string, arm int, note DialNote) uint64 {
	if arm < 0 || arm >= polArms {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()

	o.rev++
	o.nextID++
	o.checkLocked(ctx, arm, note.Alive)
	outcome := DialHandshakeDead
	if note.Alive {
		outcome = DialAlive
	}
	step := PolicyStep{Arm: arm, Outcome: outcome, Wire: note.Wire, AtMs: o.nowMs(), Slow: note.Slow, Measure: note.Measure, id: o.nextID}
	o.dials[ctx] = polWindow(append(o.dials[ctx], step), polBlock)
	if note.Alive {
		speed := o.speed[ctx]
		if len(speed) != polArms {
			speed = make([]armSpeed, polArms)
		}
		speed[arm].N++
		speed[arm].Mean += (note.Slow - speed[arm].Mean) / float64(speed[arm].N)
		o.speed[ctx] = speed
	}

	o.pending++
	if o.pending >= polOnlineStepEvery || o.trust[ctx][expertNet] < polTrustRetrain {
		o.pending = 0
		o.trainLocked(ctx)
	}
	return o.nextID
}

func (o *onlinePolicy) NoteLiveDeath(ctx string, id uint64, down int64, lived time.Duration, tail []WirePacket) {
	o.mu.Lock()
	defer o.mu.Unlock()
	steps := o.dials[ctx]
	for i := range steps {
		if steps[i].id != id || steps[i].Outcome != DialAlive {
			continue
		}
		steps[i].Outcome = DialLiveDead
		steps[i].Measure.LiveDown, steps[i].Measure.LiveFor, steps[i].Measure.Tail = down, lived, tail
		o.deaths[ctx] = rememberDeath(o.deaths[ctx], steps[i], o.nowMs())
		o.rev++
		o.trainLocked(ctx)
		return
	}
}

type BlockPattern struct {
	ID       int         `json:"id"`
	Outcome  DialOutcome `json:"outcome"`
	Wire     WireVerdict `json:"wire"`
	Seen     int         `json:"seen"`
	FirstMs  int64       `json:"first_ms"`
	LastMs   int64       `json:"last_ms"`
	Distance float64     `json:"distance"`
	Bar      float64     `json:"bar"`
	Mean     []float64   `json:"mean,omitempty"`
}

func (b BlockPattern) view() BlockPattern {
	b.Mean = nil
	return b
}

func (o *onlinePolicy) NotePattern(outcome DialOutcome, wire WireVerdict, pkts []WirePacket) (BlockPattern, bool) {
	g, class, ok := o.novelty.of(outcome)
	if !ok || len(pkts) == 0 {
		return BlockPattern{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	enc := o.frozen.encodePackets(pkts)
	bar := g.Bar[class]
	distance := g.distance(enc, g.Mean[class])
	if distance <= bar {
		return BlockPattern{}, false
	}
	now := o.nowMs()
	o.rev++
	nearest, nearestShare := -1, 1.0
	for i, p := range o.patterns {
		if p.Outcome != outcome || len(p.Mean) != len(enc) {
			continue
		}
		if share := g.distance(enc, p.Mean) / (bar * (1 + 1/float64(p.Seen))); share <= nearestShare {
			nearest, nearestShare = i, share
		}
	}
	if nearest >= 0 {
		p := &o.patterns[nearest]
		p.Seen++
		p.LastMs = now
		for k := range p.Mean {
			p.Mean[k] += (enc[k] - p.Mean[k]) / float64(p.Seen)
		}
		return p.view(), true
	}
	o.lastPattern++
	p := BlockPattern{ID: o.lastPattern, Outcome: outcome, Wire: wire, Seen: 1, FirstMs: now, LastMs: now, Distance: distance, Bar: bar, Mean: enc}
	o.patterns = append(o.patterns, p)
	if len(o.patterns) > BlockPatternLimit {
		stale := 0
		for i, q := range o.patterns {
			if q.LastMs < o.patterns[stale].LastMs {
				stale = i
			}
		}
		o.patterns = append(o.patterns[:stale], o.patterns[stale+1:]...)
	}
	return p.view(), true
}

func NoteBlockPattern(outcome DialOutcome, wire WireVerdict, pkts []WirePacket) (BlockPattern, bool) {
	return sharedOnlinePolicy().NotePattern(outcome, wire, pkts)
}

func BlockPatterns() []BlockPattern {
	o := sharedOnlinePolicy()
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]BlockPattern, len(o.patterns))
	for i, p := range o.patterns {
		out[i] = p.view()
	}
	return out
}

func (o *onlinePolicy) trainLocked(ctx string) {
	if o.trainer == nil || o.training || len(o.dials[ctx]) == 0 {
		return
	}
	o.training = true
	go o.train(o.trainer, o.frozen, o.live.clone(), o.anchor, append([]PolicyStep(nil), o.dials[ctx]...))
}

func (o *onlinePolicy) train(t *polTrainer, frozen, live *polParams, anchor float64, window []PolicyStep) {
	next, err := t.step(frozen, live, anchor, window)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.training = false
	if err != nil {
		if o.trainer == t {
			o.trainer = nil
			stdlog.Printf("[POLICY] fine-tuning stopped, the weights stay as they are: %v", err)
		}
		t.close()
		return
	}
	o.live, o.tuned = next, true
	o.steps++
	o.rev++
}

var onlinePolicyOnce struct {
	once sync.Once
	p    *onlinePolicy
}

func sharedOnlinePolicy() *onlinePolicy {
	onlinePolicyOnce.once.Do(func() { onlinePolicyOnce.p = newOnlinePolicy() })
	return onlinePolicyOnce.p
}

func SetPolicyTrainer(python, script string) {
	if script == "" {
		return
	}
	o := sharedOnlinePolicy()
	o.mu.Lock()
	o.trainer = newPolTrainer(python, script)
	o.mu.Unlock()
	stdlog.Printf("[POLICY] fine-tuning in PyTorch: %s %s", python, script)
}

func (h *HandshakeStrategy) SelectJointOnline(ctx string, presets int, fragmented, migrate bool) (arm int, ok bool) {
	if !policyJointUsable(presets) {
		return 0, false
	}
	fits := jointArmFits(fragmented)
	if !migrate {
		fits = func(a int) bool { return jointArmFits(fragmented)(a) && !JointArmMigrates(a, presets) }
	}
	return sharedOnlinePolicy().Select(ctx, JointArmCount(presets), fits), true
}

func (h *HandshakeStrategy) NoteJointOnline(ctx string, arm int, note DialNote) uint64 {
	return sharedOnlinePolicy().NoteDial(ctx, arm, note)
}

func (h *HandshakeStrategy) NoteJointLiveDeath(ctx string, id uint64, down int64, lived time.Duration, tail []WirePacket) {
	sharedOnlinePolicy().NoteLiveDeath(ctx, id, down, lived, tail)
}

func (h *HandshakeStrategy) JointTrust(ctx string) (net, check float64) {
	o := sharedOnlinePolicy()
	o.mu.Lock()
	defer o.mu.Unlock()
	v := o.verdictLocked(ctx, o.nowMs(), polArms)
	return v.trust[expertNet], v.check
}

func (o *onlinePolicy) chainOf(ctx string) [polChainDims]float64 {
	if c, ok := o.chain[ctx]; ok {
		return c
	}
	return chainFeatures(0, 0)
}

func (h *HandshakeStrategy) SetJointChain(ctx string, pos int, gap time.Duration) {
	o := sharedOnlinePolicy()
	o.mu.Lock()
	o.chain[ctx] = chainFeatures(pos, gap)
	o.mu.Unlock()
}

func (h *HandshakeStrategy) JointPredict(ctx string, arm int) float64 {
	if arm < 0 || arm >= polArms {
		return 0
	}
	o := sharedOnlinePolicy()
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.verdictLocked(ctx, o.nowMs(), polArms).mixed[arm]
}

func (h *HandshakeStrategy) JointAnyAlive(ctx string, presets int, fragmented bool) bool {
	if !policyJointUsable(presets) {
		return true
	}
	return sharedOnlinePolicy().anyAlive(ctx, JointArmCount(presets), jointArmFits(fragmented))
}

func (h *HandshakeStrategy) JointAliveArms(ctx string, presets int, fragmented bool) int {
	if !policyJointUsable(presets) {
		return 0
	}
	return sharedOnlinePolicy().aliveArms(ctx, JointArmCount(presets), jointArmFits(fragmented))
}

type PolicyArmView struct {
	Ctx    string    `json:"ctx"`
	Picked int       `json:"picked"`
	Preset int       `json:"preset"`
	Budget int       `json:"budget"`
	DropPQ bool      `json:"drop_pq"`
	Alive  int       `json:"alive_arms"`
	Trust  float64   `json:"net_trust"`
	Check  float64   `json:"check"`
	Scores []float64 `json:"scores"`
	Net    []float64 `json:"net_scores"`
}

func PolicyScoreSnapshot() []PolicyArmView {
	o := sharedOnlinePolicy()
	o.mu.Lock()
	defer o.mu.Unlock()
	presets := polPresets()
	now := o.nowMs()
	out := make([]PolicyArmView, 0, len(o.dials))
	for ctx := range o.dials {
		v := o.verdictLocked(ctx, now, polArms)
		scores := v.mixed
		best, alive := 0, 0
		for a := range scores {
			if scores[a] > scores[best] {
				best = a
			}
			if scores[a] >= polAliveBar {
				alive++
			}
		}
		preset, budget := JointArmParts(best, presets)
		out = append(out, PolicyArmView{
			Ctx: ctx, Picked: best, Preset: preset, Budget: budget,
			DropPQ: JointArmDropPQ(best, presets), Alive: alive, Trust: v.trust[expertNet], Check: v.check, Scores: scores, Net: v.net,
		})
	}
	return out
}

type polTrainConfig struct {
	Embd         int         `json:"embd"`
	Heads        int         `json:"heads"`
	Block        int         `json:"block"`
	Layers       int         `json:"layers"`
	Arms         int         `json:"arms"`
	HiddenScale  int         `json:"hidden_scale"`
	Outcomes     int         `json:"outcomes"`
	WireDims     int         `json:"wire_dims"`
	MeasDims     int         `json:"meas_dims"`
	SelAlpha     float64     `json:"sel_alpha"`
	SelLambda    float64     `json:"sel_lambda"`
	SelCoverage  float64     `json:"sel_coverage"`
	RecentDims   int         `json:"recent_dims"`
	PacketDims   int         `json:"packet_dims"`
	PacketHid    int         `json:"packet_hidden"`
	PacketLyrs   int         `json:"packet_layers"`
	RecLoss      float64     `json:"rec_loss"`
	RecBuckets   int         `json:"rec_buckets"`
	GradClip     float64     `json:"grad_clip"`
	AuxLoss      float64     `json:"aux_loss"`
	ModDrop      float64     `json:"moddrop"`
	NoveltyAlpha float64     `json:"novelty_alpha"`
	ChainAt      int         `json:"chain_at"`
	ChainMiss    []float64   `json:"chain_missing"`
	ClockDims    int         `json:"clock_dims"`
	ChainDims    int         `json:"chain_dims"`
	ArmFeatures  [][]float64 `json:"arm_features"`
	NormEps      float64     `json:"norm_eps"`
	InitStd      float64     `json:"init_std"`
	ZeroInit     []string    `json:"zero_init"`
	Rate         float64     `json:"rate"`
	Beta1        float64     `json:"beta1"`
	Beta2        float64     `json:"beta2"`
	AdamEps      float64     `json:"adam_eps"`
	Dropout      float64     `json:"dropout"`
	Anchor       float64     `json:"anchor"`
}

func polTrainConfigFor(anchor float64) polTrainConfig {
	features := make([][]float64, polArms)
	for a := range features {
		features[a] = JointArmFeatures(a, polPresets())
	}
	return polTrainConfig{
		Embd: polEmbd, Heads: polHead, Block: polBlock, Layers: polLayer, Arms: polArms, HiddenScale: polHiddenScale,
		Outcomes: int(polOutcomes), WireDims: polWireDims, MeasDims: polMeasDims,
		SelAlpha: polSelAlpha, SelLambda: polSelLambda, SelCoverage: polSelCoverage, RecentDims: polRecentDims, ClockDims: polClockDims, ChainDims: polChainDims,
		PacketDims: polPacketDims, PacketHid: polPacketHidden, PacketLyrs: polPacketLayers,
		RecLoss: polRecLoss, RecBuckets: polRecBuckets, GradClip: polGradClip, AuxLoss: polAuxLoss,
		NoveltyAlpha: NoveltyFalseAlarm,
		ModDrop:      polModDrop, ChainAt: polMeasDims - polChainDims, ChainMiss: chainMissing(),
		ArmFeatures: features, NormEps: polNormEps, InitStd: polInitStd, ZeroInit: polZeroInit,
		Rate: polLearnRate, Beta1: polBeta1, Beta2: polBeta2, AdamEps: polAdamEps, Dropout: polDropout, Anchor: anchor,
	}
}

type polDoc struct {
	Arm     []int       `json:"arm"`
	Outcome []int       `json:"outcome"`
	Wire    []int       `json:"wire"`
	Gap     []float64   `json:"gap"`
	Slow    []float64   `json:"slow"`
	Meas    [][]float64 `json:"meas,omitempty"`
	Packets []int       `json:"packets"`
	Tail    []int       `json:"tail"`
	Chain   [][]float64 `json:"chain"`
	Recent  [][]float64 `json:"recent"`
	Clock   [][]float64 `json:"clock"`
}

func polDocOf(steps []PolicyStep, table *polPacketTable) polDoc {
	var d polDoc
	var deaths []PolicyStep
	meas := make([][]float64, len(steps))
	measured := false
	for i, s := range steps {
		gap := 0.0
		if i > 0 {
			gap = polGapFeature(s.AtMs - steps[i-1].AtMs)
		}
		f := s.Measure.features()
		measured = measured || f != [polMeasDims]float64{}
		meas[i] = f[:]
		d.Arm = append(d.Arm, s.Arm)
		d.Outcome = append(d.Outcome, int(s.Outcome))
		d.Wire = append(d.Wire, s.Wire.feature())
		d.Gap = append(d.Gap, gap)
		d.Slow = append(d.Slow, s.Slow)
		d.Packets = append(d.Packets, table.add(s.Measure.Packets))
		d.Tail = append(d.Tail, table.add(s.Measure.Tail))
		chain := s.Measure.chainFeatures()
		d.Chain = append(d.Chain, chain[:])
		if i > 0 {
			deaths = rememberDeath(deaths, steps[i-1], s.AtMs)
		}
		d.Recent = append(d.Recent, armHazardInputs(steps[max(0, i-(polBlock-1)):i], deaths, s.AtMs, s.Arm))
		clock := polClock(s.AtMs)
		d.Clock = append(d.Clock, clock[:])
	}
	if measured {
		d.Meas = meas
	}
	return d
}

type polPacketTable struct {
	index map[string]int
	rows  [][][]float64
}

func newPolPacketTable() *polPacketTable {
	return &polPacketTable{index: map[string]int{"": 0}, rows: [][][]float64{{}}}
}

func (t *polPacketTable) add(pkts []WirePacket) int {
	key := EncodeWirePackets(pkts)
	if i, ok := t.index[key]; ok {
		return i
	}
	t.index[key] = len(t.rows)
	t.rows = append(t.rows, packetFeatures(pkts))
	return len(t.rows) - 1
}

func polDocsOf(docs [][]PolicyStep, table *polPacketTable) []polDoc {
	out := make([]polDoc, 0, len(docs))
	for _, d := range docs {
		if len(d) > 0 {
			out = append(out, polDocOf(d, table))
		}
	}
	return out
}

func (p *polParams) mats() map[string][][]float64 {
	out := map[string][][]float64{}
	p.each(func(name string, m [][]float64) { out[name] = m })
	return out
}

type polTrainRequest struct {
	Op          string                 `json:"op"`
	Config      *polTrainConfig        `json:"config,omitempty"`
	Frozen      map[string][][]float64 `json:"frozen,omitempty"`
	Live        map[string][][]float64 `json:"live,omitempty"`
	Docs        []polDoc               `json:"docs,omitempty"`
	Packets     [][][]float64          `json:"packets,omitempty"`
	Fit         *polFitRequest         `json:"fit,omitempty"`
	Calibration []polDoc               `json:"calibration,omitempty"`
}

type polTrainReply struct {
	Error   string                 `json:"error,omitempty"`
	Params  map[string][][]float64 `json:"params,omitempty"`
	Probe   []float64              `json:"probe,omitempty"`
	Check   []float64              `json:"check,omitempty"`
	Fit     *polFitReply           `json:"fit,omitempty"`
	Novelty *polNovelty            `json:"novelty,omitempty"`
}

type polTrainer struct {
	mu      sync.Mutex
	python  string
	script  string
	cmd     *exec.Cmd
	stop    context.CancelFunc
	send    *json.Encoder
	replies *bufio.Reader
	ready   bool
}

func newPolTrainer(python, script string) *polTrainer {
	return &polTrainer{python: python, script: script}
}

func (t *polTrainer) start() error {
	ctx, stop := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, t.python, t.script, polServeOp)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		stop()
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stop()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		stop()
		return err
	}
	if err := cmd.Start(); err != nil {
		stop()
		return fmt.Errorf("start %s: %w", t.python, err)
	}
	go forwardTrainerLog(stderr)
	t.cmd, t.stop, t.send, t.replies = cmd, stop, json.NewEncoder(stdin), bufio.NewReader(stdout)
	return nil
}

func forwardTrainerLog(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		stdlog.Printf("[POLICY] trainer: %s", sc.Text())
	}
}

func (t *polTrainer) call(req polTrainRequest) (polTrainReply, error) {
	if t.cmd == nil {
		if err := t.start(); err != nil {
			return polTrainReply{}, err
		}
	}
	if err := t.send.Encode(req); err != nil {
		return polTrainReply{}, fmt.Errorf("trainer stopped reading: %w", err)
	}
	line, err := t.replies.ReadBytes('\n')
	if err != nil {
		return polTrainReply{}, fmt.Errorf("trainer exited: %w", err)
	}
	var reply polTrainReply
	if err := json.Unmarshal(line, &reply); err != nil {
		return polTrainReply{}, fmt.Errorf("trainer reply: %w", err)
	}
	if reply.Error != "" {
		return reply, errors.New(reply.Error)
	}
	return reply, nil
}

func (t *polTrainer) step(frozen, live *polParams, anchor float64, window []PolicyStep) (*polParams, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ready {
		cfg := polTrainConfigFor(anchor)
		if _, err := t.call(polTrainRequest{Op: "init", Config: &cfg, Frozen: frozen.mats(), Live: live.mats()}); err != nil {
			return nil, err
		}
		t.ready = true
	}
	table := newPolPacketTable()
	doc := polDocOf(window, table)
	reply, err := t.call(polTrainRequest{Op: "step", Docs: []polDoc{doc}, Packets: table.rows})
	if err != nil {
		return nil, err
	}
	return polAccept(reply, window)
}

func (t *polTrainer) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cmd != nil {
		t.stop()
		t.cmd.Wait()
	}
	t.cmd, t.stop, t.ready = nil, nil, false
}

func polAccept(reply polTrainReply, doc []PolicyStep) (*polParams, error) {
	p, ok := polParamsFrom(reply.Params)
	if !ok {
		return nil, errors.New("the trainer sent weights of another shape")
	}
	probs, trust := p.conditional(doc)
	if len(probs) != len(reply.Probe) || len(trust) != len(reply.Check) {
		return nil, fmt.Errorf("the trainer scored %d dials and checked %d of %d", len(reply.Probe), len(reply.Check), len(probs))
	}
	for i := range probs {
		if math.Abs(probs[i]-reply.Probe[i]) > polParityTol || math.Abs(trust[i]-reply.Check[i]) > polParityTol {
			return nil, fmt.Errorf("the trainer and the client disagree on dial %d: %.9f/%.9f vs %.9f/%.9f", i, reply.Probe[i], reply.Check[i], probs[i], trust[i])
		}
	}
	return p, nil
}

func chainMissing() []float64 {
	missing := chainFeatures(0, 0)
	return missing[:]
}
