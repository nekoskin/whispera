package protocol

import (
	"bytes"
	"math/rand"
	"os"
	"testing"
	"time"
)

func TestPolicyStepsMarkALiveDeathOnItsDial(t *testing.T) {
	steps := PolicySteps([]PolicyDial{
		{Ms: 30, Arm: 2, Outcome: DialAlive},
		{Ms: 10, Arm: 2, Outcome: DialAlive},
		{Ms: 20, Arm: 5, Outcome: DialAlive},
		{Ms: 35, Arm: 2, LiveDeath: true, Measure: DialMeasure{LiveDown: 16 << 10}},
		{Ms: 40, Arm: polArms, Outcome: DialAlive},
	})
	if len(steps) != 3 {
		t.Fatalf("%d steps, want 3", len(steps))
	}
	if steps[0].AtMs != 10 || steps[1].AtMs != 20 || steps[2].AtMs != 30 {
		t.Fatalf("steps out of time order: %+v", steps)
	}
	if steps[2].Outcome != DialLiveDead || steps[2].Measure.LiveDown != 16<<10 || steps[0].Outcome != DialAlive {
		t.Fatalf("the live death and what got through should land on the latest dial of arm 2: %+v", steps)
	}
}

func fitTestDocs(rng *rand.Rand, docs, dials int) [][]PolicyStep {
	out := make([][]PolicyStep, docs)
	for d := range out {
		frozenFor := 0
		at := int64(0)
		for i := 0; i < dials; i++ {
			if frozenFor == 0 && rng.Float64() < 0.03 {
				frozenFor = 8 + rng.Intn(12)
			}
			arm := rng.Intn(polArms)
			outcome := DialAlive
			if frozenFor > 0 {
				frozenFor--
				outcome = DialHandshakeDead
			} else if JointArmDropPQ(arm, polPresets()) == (rng.Float64() < 0.1) {
				outcome = DialHandshakeDead
			}
			at += int64(1+rng.Intn(5)) * testMinute
			out[d] = append(out[d], PolicyStep{Arm: arm, Outcome: outcome, AtMs: at, Measure: DialMeasure{Packets: testPackets(rng, outcome == DialAlive),
				ChainPos: 1 + rng.Intn(4), ChainGap: time.Duration(rng.Intn(800)) * time.Millisecond, Tail: testTail(rng)}})
		}
	}
	return out
}

func TestFitPolicyThroughTheTrainerBeatsTheBaselines(t *testing.T) {
	python, script := testTrainer(t)
	rng := rand.New(rand.NewSource(12))
	train, val, test := fitTestDocs(rng, 6, 400), fitTestDocs(rng, 2, 400), fitTestDocs(rng, 2, 400)
	fitted, r, err := FitPolicy(python, script, train, val, test, PolicyFitConfig{Steps: 1000, Batch: 16, EvalEvery: 50, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Better() {
		t.Fatalf("net %.4f vs constant %.4f and per-arm rate %.4f", r.FittedLoss, r.ConstantLoss, r.ArmRateLoss)
	}
	found := false
	for _, a := range polAnchorGrid {
		found = found || a == r.Anchor
	}
	if !found || fitted.anchor != r.Anchor {
		t.Fatalf("anchor %g is not from the grid %v", r.Anchor, polAnchorGrid)
	}
	if _, err := fitted.GoSource(); err != nil {
		t.Fatal(err)
	}
}

func TestShippedWeightsAreWhatTheExporterWrites(t *testing.T) {
	src, err := ShippedPolicy().GoSource()
	if err != nil {
		t.Fatal(err)
	}
	shipped, err := os.ReadFile("policy_weights.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.ReplaceAll(shipped, []byte("\r\n"), []byte("\n")), src) {
		t.Fatal("policy_weights.go differs from what policyfit would export for the same weights; regenerate it with scripts/policyfit")
	}
}

func testPackets(rng *rand.Rand, answered bool) []WirePacket {
	pkts := []WirePacket{
		{Flags: WireSYN, TTL: 64, Window: 64240, MSS: 1460, WScale: 7, Options: WireOptWScale | WireOptSACK | WireOptTimestamps},
		{Inbound: true, Flags: WireSYN | WireACK, TTL: 52, Window: 65160, Gap: time.Duration(20+rng.Intn(80)) * time.Millisecond},
		{Flags: WireACK, TTL: 64, Window: 502},
		{Size: 517 + rng.Intn(1300), Flags: WireACK | WirePSH, TTL: 64, Window: 502, Record: 22, RecLen: 512 + rng.Intn(1300), Records: 1, Hello: 1},
	}
	if !answered {
		for i := 0; i < 1+rng.Intn(4); i++ {
			pkts = append(pkts, WirePacket{Size: pkts[3].Size, Flags: WireACK | WirePSH, TTL: 64, Window: 502, Gap: time.Second << i, SeqGap: -int64(pkts[3].Size)})
		}
		return pkts
	}
	return append(pkts,
		WirePacket{Inbound: true, Size: 1400, Flags: WireACK, TTL: 52, Window: 501, Record: 22, RecLen: 122, Gap: time.Duration(20+rng.Intn(80)) * time.Millisecond},
		WirePacket{Inbound: true, Size: 900 + rng.Intn(500), Flags: WireACK | WirePSH, TTL: 52, Window: 501, Record: 23, RecLen: 2300},
		WirePacket{Size: 80, Flags: WireACK | WirePSH, TTL: 64, Window: 501, Record: 20, RecLen: 1})
}

func TestTracePacketsRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	want := testPackets(rng, false)
	got := ParseWirePackets(EncodeWirePackets(want))
	if len(got) != len(want) {
		t.Fatalf("%d packets read back, %d written", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("packet %d read back as %+v, written as %+v", i, got[i], want[i])
		}
	}
	if ParseWirePackets("o:1:2") != nil || ParseWirePackets("x:1:0:0:0:0:0:0") != nil {
		t.Fatal("a malformed packet column was read as packets")
	}
}

func testTail(rng *rand.Rand) []WirePacket {
	if rng.Intn(5) != 0 {
		return nil
	}
	return testPackets(rng, rng.Intn(2) == 0)
}

func TestOldTraceArmsKeepWhatTheyWereAfterPresetsAreAdded(t *testing.T) {
	const before, after = 3, 5
	seen := map[int]bool{}
	for arm := 0; arm < JointArmCount(before); arm++ {
		now, ok := JointArmRemap(arm, before, after)
		if !ok || now >= JointArmCount(after) || seen[now] {
			t.Fatalf("arm %d of %d presets maps to %d (ok %v), not to its own arm among %d", arm, before, now, ok, JointArmCount(after))
		}
		seen[now] = true
		p0, b0 := JointArmParts(arm, before)
		p1, b1 := JointArmParts(now, after)
		if p0 != p1 || b0 != b1 || JointArmDropPQ(arm, before) != JointArmDropPQ(now, after) ||
			JointArmMigrates(arm, before) != JointArmMigrates(now, after) || JointArmShaped(arm, before) != JointArmShaped(now, after) {
			t.Fatalf("arm %d changed what it plays when %d presets became %d (now arm %d)", arm, before, after, now)
		}
	}
}
