package protocol

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

func testOnlinePolicy(seed int64) (*onlinePolicy, *time.Time) {
	o := newOnlinePolicy()
	o.live = testParams(rand.New(rand.NewSource(seed)))
	o.frozen = o.live.clone()
	clock := time.Unix(1_800_000_000, 0)
	o.now = func() time.Time { return clock }
	return o, &clock
}

func TestOnlineLiveDeathTurnsTheDialDead(t *testing.T) {
	o, _ := testOnlinePolicy(2)
	const down, lived = 16 << 10, 3 * time.Second
	id := o.NoteDial("c", 3, DialNote{Alive: true})
	o.NoteDial("c", 5, DialNote{Alive: true})
	o.NoteLiveDeath("c", id, down, lived, nil)
	if got := o.dials["c"][0]; got.Outcome != DialLiveDead || got.Measure.LiveDown != down || got.Measure.LiveFor != lived {
		t.Fatalf("a dial frozen after its handshake is %+v, want a live death with what got through", got)
	}
	if got := o.dials["c"][1].Outcome; got != DialAlive {
		t.Fatalf("the other dial became %v", got)
	}
	rev := o.rev
	o.NoteLiveDeath("c", id, down, lived, nil)
	if o.dials["c"][0].Outcome != DialLiveDead || o.rev != rev {
		t.Fatal("the same live death was counted twice")
	}
}

func TestOnlineReportsNoArmsUnderASilentFreeze(t *testing.T) {
	const pathRTT = 80 * time.Millisecond
	o := newOnlinePolicy()
	ctx := "sni|home|joint"
	fits := jointArmFits(true)
	start := o.aliveArms(ctx, polArms, fits)
	for i := 0; i < polBlock; i++ {
		arm := o.Select(ctx, polArms, fits)
		o.NoteDial(ctx, arm, DialNote{Alive: false, Wire: WireHelloDropped, Slow: PolicySlowness(FastRotateHandshakeTimeout, pathRTT), Measure: DialMeasure{Connect: pathRTT}})
	}
	if n := o.aliveArms(ctx, polArms, fits); n != 0 {
		t.Fatalf("after a silent freeze the policy still trusts %d of the %d arms it started with", n, start)
	}
}

func TestLiveDeathIsRememberedPastTheDialWindow(t *testing.T) {
	o := newOnlinePolicy()
	now := time.Now()
	o.now = func() time.Time { return now }
	const ctx = "c"
	plain := 0
	migrate := plain
	for a := 0; a < polArms; a++ {
		if JointArmMigrates(a, polPresets()) && !JointArmShaped(a, polPresets()) {
			migrate = a
			break
		}
	}
	id := o.NoteDial(ctx, plain, DialNote{Alive: true})
	o.NoteLiveDeath(ctx, id, 16<<10, 5*time.Second, nil)
	for i := 0; i < 2*polBlock; i++ {
		now = now.Add(time.Second)
		o.NoteDial(ctx, migrate, DialNote{Alive: true})
	}
	memory := armHazardInputs(o.dials[ctx], o.deaths[ctx], o.nowMs(), plain)[polRecentDims-liveMemoryScales:]
	if memory[0] == 0 || memory[liveMemoryScales-1] == 0 {
		t.Fatalf("a connection that froze half a minute ago is forgotten once it leaves the dial window: %v", memory)
	}
	if other := armHazardInputs(o.dials[ctx], o.deaths[ctx], o.nowMs(), migrate)[polRecentDims-liveMemoryScales:]; other[0] != 0 {
		t.Fatalf("a freeze on plain connections is held against migrating ones: %v", other)
	}
}

func TestSilentFreezeKeepsTheFingerprintForTheReportedSpan(t *testing.T) {
	const pathRTT = 80 * time.Millisecond
	o := newOnlinePolicy()
	now := time.Now()
	o.now = func() time.Time { return now }
	ctx := "sni|home|joint"
	fits := jointArmFits(true)
	for i := 0; i < polBlock; i++ {
		o.NoteDial(ctx, o.Select(ctx, polArms, fits), DialNote{Alive: false, Wire: WireHelloDropped, Slow: PolicySlowness(FastRotateHandshakeTimeout, pathRTT), Measure: DialMeasure{Connect: pathRTT}})
		now = now.Add(time.Second)
	}
	if o.anyAlive(ctx, polArms, fits) {
		t.Skip("the policy still sees a live arm, nothing to hold")
	}
	steps := o.dials[ctx]
	want, _ := JointArmParts(steps[len(steps)-1].Arm, polPresets())
	if got, _ := JointArmParts(o.Select(ctx, polArms, fits), polPresets()); got != want {
		t.Fatalf("with no live arm the policy changed the fingerprint from preset %d to %d inside the reported freeze", want, got)
	}
	if _, held := heldPreset(steps, now.Add(reportedFreezeSpan).UnixMilli()); held {
		t.Fatal("the fingerprint is still held after the reported freeze span")
	}
}

func TestNewBlockPatternIsLearnedOnce(t *testing.T) {
	o := newOnlinePolicy()
	rng := rand.New(rand.NewSource(3))
	known := testPackets(rng, false)
	injected := append(testPackets(rng, false), WirePacket{Inbound: true, Flags: WireRST | WireACK, TTL: 3, Gap: time.Millisecond})
	identity := make([][]float64, polPacketFeat)
	for i := range identity {
		identity[i] = make([]float64, polPacketFeat)
		identity[i][i] = 1
	}
	knownMean, injectedEnc := o.frozen.encodePackets(known), o.frozen.encodePackets(injected)
	g := packetGaussians{Mean: make([][]float64, polOutcomes), Precision: identity, Bar: make([]float64, polOutcomes)}
	for c := range g.Mean {
		g.Mean[c] = knownMean
	}
	g.Bar[DialHandshakeDead] = g.distance(injectedEnc, knownMean) / 2
	o.novelty.Opening = g

	if _, novel := o.NotePattern(DialHandshakeDead, WireHelloDropped, known); novel {
		t.Fatal("a block the net trained on was reported as a new pattern")
	}
	first, novel := o.NotePattern(DialHandshakeDead, WireForgedReset, injected)
	if !novel || first.Seen != 1 {
		t.Fatalf("a block unlike any trained one was not reported as new: %+v", first)
	}
	again, novel := o.NotePattern(DialHandshakeDead, WireForgedReset, injected)
	if !novel || again.ID != first.ID || again.Seen != 2 {
		t.Fatalf("the same new block came back as %+v, want pattern #%d seen twice", again, first.ID)
	}
	if _, novel := o.NotePattern(DialAlive, WireNoSignature, injected); novel {
		t.Fatal("a dial that got through was reported as a block")
	}
}

func TestOnlineProbesASmallHelloBeforeGivingUp(t *testing.T) {
	presets := polPresets()
	all := func(int) bool { return true }
	doubt := make([]float64, polArms)
	for a := range doubt {
		doubt[a] = polAliveBar / 2
	}
	bigHello := 4
	cut := []PolicyStep{{Arm: bigHello, Outcome: DialHandshakeDead}, {Arm: bigHello, Outcome: DialHandshakeDead}}
	probe := probeArm(doubt, all, cut)
	if probe < 0 || !JointArmDropPQ(probe, presets) {
		t.Fatalf("two cut big hellos and no arm above the bar: probed arm %d, want a small hello first", probe)
	}
	if again := probeArm(doubt, all, append(cut, PolicyStep{Arm: probe, Outcome: DialHandshakeDead})); again >= 0 {
		t.Fatalf("the small hello died too, yet arm %d was probed again instead of giving up", again)
	}
}

func TestOnlineTurnsALeverOnOnlyForAClearGain(t *testing.T) {
	presets := polPresets()
	plain := 4
	migrating := plain + jointBlock(presets)*armPQStates
	scores := make([]float64, polArms)
	scores[plain], scores[migrating] = 0.9, 0.9+polLeverCost/2
	if got := bestFittingArm(leverUtility(scores), func(int) bool { return true }); got != plain {
		t.Fatalf("a lever that adds less than its cost was chosen: arm %d", got)
	}
	scores[migrating] = 0.9 + 2*polLeverCost
	if got := bestFittingArm(leverUtility(scores), func(int) bool { return true }); got != migrating || !JointArmMigrates(got, presets) {
		t.Fatalf("a lever that clearly saves the dial was not chosen: arm %d", got)
	}
}

func TestOnlineCheckStopsTrustingAWrongNet(t *testing.T) {
	o, clock := testOnlinePolicy(9)
	for _, p := range []*polParams{o.live, o.frozen} {
		for k := range p.recent[0] {
			p.recent[0][k] = math.Inf(-1)
		}
	}
	const ctx = "c"
	start := o.trustOf(ctx)[expertNet]
	for i := 0; i < polBlock; i++ {
		*clock = clock.Add(time.Minute)
		o.NoteDial(ctx, 4, DialNote{Wire: WireHelloDropped})
	}
	if got := o.trustOf(ctx)[expertNet]; got >= polTrustRetrain {
		t.Fatalf("the net kept guessing ~0.5 for an arm that died %d times running, yet its trust only went %.3f -> %.3f", polBlock, start, got)
	}
	if mixed := o.verdictLocked(ctx, clock.UnixMilli(), polArms).mixed[4]; mixed >= polAliveBar {
		t.Fatalf("decisions still rate the dead arm %.3f after the check stopped trusting the net", mixed)
	}
}

func TestOnlineRecencyLeavesAForgedResetArm(t *testing.T) {
	o := newOnlinePolicy()
	fits := func(int) bool { return true }
	before := o.live.armScores(o.dials["c"], o.nowMs(), polArms)
	arm := bestFittingArm(before, fits)
	o.NoteDial("c", arm, DialNote{Wire: WireForgedReset})
	after := o.live.armScores(o.dials["c"], o.nowMs(), polArms)
	if after[arm] >= before[arm] {
		t.Fatalf("a forged reset did not lower arm %d: %.3f -> %.3f", arm, before[arm], after[arm])
	}
	if bestFittingArm(after, fits) == arm {
		t.Fatalf("the policy kept picking arm %d after the wire proved its reset forged", arm)
	}
}

func TestOnlineKeepsAWorkingArmAndLeavesItOnceItFails(t *testing.T) {
	o := newOnlinePolicy()
	fits := func(int) bool { return true }
	arm := o.Select("c", polArms, fits)
	for i := 0; i < polBlock; i++ {
		o.NoteDial("c", arm, DialNote{Alive: true})
		if got := o.Select("c", polArms, fits); got != arm {
			t.Fatalf("dial %d on arm %d worked, yet the next dial moved to arm %d", i+1, arm, got)
		}
	}
	o.NoteDial("c", arm, DialNote{Wire: WireForgedReset})
	if got := o.Select("c", polArms, fits); got == arm {
		t.Fatalf("arm %d drew a forged reset, yet the next dial stayed on it", arm)
	}
}

func TestJointArmStaysWholeWithoutFragmentation(t *testing.T) {
	h := NewHandshakeStrategy()
	presets := polPresets()
	ctx := "whole-hello"
	for i := 0; i < 300; i++ {
		arm, ok := h.SelectJointOnline(ctx, presets, false, true)
		if !ok {
			t.Fatal("online policy refused a repertoire it was built for")
		}
		if _, budget := JointArmParts(arm, presets); budget != 1 {
			t.Fatalf("picked arm %d with a %d-record hello, but fragmentation is off", arm, budget)
		}
		h.NoteJointOnline(ctx, arm, DialNote{Alive: i%4 == 0})
	}
}

func TestOnlineSettlesOnTheFasterOfEquallySafeArms(t *testing.T) {
	o := newOnlinePolicy()
	presets := polPresets()
	arm := func(records int) int {
		a, ok := JointArmFor(0, records, false, presets)
		if !ok {
			t.Fatalf("no arm with a %d-record hello", records)
		}
		return a
	}
	whole, split, riskier := arm(1), arm(8), arm(2)
	utility := make([]float64, polArms)
	utility[whole], utility[split], utility[riskier] = 0.95, 0.95, 0.95-2*polLeverCost
	speed := make([]armSpeed, polArms)
	speed[whole], speed[split], speed[riskier] = armSpeed{N: 30, Mean: 0.2}, armSpeed{N: 30, Mean: 0.6}, armSpeed{N: 30, Mean: 0.05}
	o.speed["c"] = speed
	fits := func(a int) bool { return a == whole || a == split || a == riskier }
	if got := o.fasterLocked("c", utility, fits, split); got != whole {
		t.Fatalf("two arms survive alike and one handshakes faster, yet arm %d was kept instead of %d", got, whole)
	}
}
