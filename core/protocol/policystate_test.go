package protocol

import (
	"encoding/json"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func tunedOnlinePolicy(t *testing.T) *onlinePolicy {
	t.Helper()
	o, _ := testOnlinePolicy(11)
	o.frozen, o.live, o.tuned = newPolParams(), testParams(rand.New(rand.NewSource(11))), true
	measured := DialMeasure{Captured: true, HelloBytes: 517, HelloSegments: 1, HelloAcked: 517, ServerTTL: 50, Connect: 70 * time.Millisecond}
	for i := 0; i < polOnlineStepEvery*3; i++ {
		o.NoteDial("sni|home|joint", i%3, DialNote{Alive: i%3 != 0, Wire: WireVerdict(i % int(wireVerdictCount)), Slow: 0.25, Measure: measured})
	}
	o.NoteDial("sni|cafe|joint", 4, DialNote{Strong: true})
	return o
}

func writeSnapshot(t *testing.T, path string, snap onlinePolicySnapshot) {
	t.Helper()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func stripIDs(dials map[string][]PolicyStep) map[string][]PolicyStep {
	out := map[string][]PolicyStep{}
	for ctx, steps := range dials {
		for _, s := range steps {
			s.id = 0
			out[ctx] = append(out[ctx], s)
		}
	}
	return out
}

func TestOnlinePolicySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-online.json")
	before := tunedOnlinePolicy(t)
	if err := before.save(path); err != nil {
		t.Fatal(err)
	}
	after := newOnlinePolicy()
	if err := after.load(path); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.live.mats(), after.live.mats()) {
		t.Fatal("tuned weights did not come back")
	}
	if !reflect.DeepEqual(before.trust, after.trust) {
		t.Fatalf("the outcome check's trust did not come back: %v vs %v", before.trust, after.trust)
	}
	if !reflect.DeepEqual(stripIDs(before.dials), stripIDs(after.dials)) {
		t.Fatalf("dials differ:\n%v\n%v", before.dials, after.dials)
	}
}

func TestOnlinePolicyDropsWeightsTunedFromOtherFrozen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-online.json")
	snap := tunedOnlinePolicy(t).snapshot()
	snap.Frozen = "retrained"
	writeSnapshot(t, path, snap)
	after := newOnlinePolicy()
	if err := after.load(path); err != nil {
		t.Fatal(err)
	}
	if after.tuned || !reflect.DeepEqual(after.live.mats(), newPolParams().mats()) {
		t.Fatal("weights tuned from other frozen weights were kept")
	}
	if len(after.dials["sni|home|joint"]) == 0 {
		t.Fatal("the dial history is not tied to the weights and should be kept")
	}
}

func TestOnlinePolicyRejectsMalformedSteps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-online.json")
	snap := tunedOnlinePolicy(t).snapshot()
	snap.Dials = map[string][]PolicyStep{"bad": {
		{Arm: -1}, {Arm: polArms}, {Arm: 1, Outcome: polOutcomes}, {Arm: 1, Wire: wireVerdictCount},
		{Arm: 1, Slow: math.NaN()}, {Arm: 1, Slow: 2}, {Arm: 1, Measure: DialMeasure{HelloBytes: -1}},
	}}
	data, err := json.Marshal(snap)
	if err != nil {
		data = []byte(`{"dials":{"bad":[{"a":-1},{"a":24},{"a":1,"o":3},{"a":1,"w":5},{"a":1,"s":2}]}}`)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	after := newOnlinePolicy()
	if err := after.load(path); err != nil {
		t.Fatal(err)
	}
	if got := after.dials["bad"]; len(got) != 0 {
		t.Fatalf("malformed steps were restored: %v", got)
	}
}

func TestOnlinePolicyMigratesTokenHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-online.json")
	writeSnapshot(t, path, onlinePolicySnapshot{Presets: presetIdentities(), History: map[string][]int{"c": {2 * 5, 2*7 + 1}}})
	after := newOnlinePolicy()
	if err := after.load(path); err != nil {
		t.Fatal(err)
	}
	want := []PolicyStep{{Arm: 5, Outcome: DialAlive}, {Arm: 7, Outcome: DialHandshakeDead}}
	if got := after.dials["c"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("old token history became %v, want %v", got, want)
	}
}
