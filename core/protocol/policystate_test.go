package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func trainedOnlinePolicy(t *testing.T) *onlinePolicy {
	t.Helper()
	o := newOnlinePolicy()
	for i := 0; i < polOnlineStepEvery*3; i++ {
		o.Note("sni|home|joint", i%3, i%3 != 0, true)
	}
	o.Note("sni|cafe|joint", 4, false, true)
	if !o.tuned {
		t.Fatal("policy should have taken a training step")
	}
	return o
}

func TestOnlinePolicySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-online.json")
	before := trainedOnlinePolicy(t)
	if err := before.save(path); err != nil {
		t.Fatal(err)
	}

	after := newOnlinePolicy()
	if err := after.load(path); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.live.all(), after.live.all()) {
		t.Fatal("tuned weights did not come back")
	}
	if !reflect.DeepEqual(before.hist, after.hist) {
		t.Fatalf("history differs: %v vs %v", before.hist, after.hist)
	}
	if after.alive("sni|cafe|joint", 4) {
		t.Fatal("an arm benched before the restart should stay benched")
	}
	if !reflect.DeepEqual(before.strikes, after.strikes) {
		t.Fatalf("strikes differ: %v vs %v", before.strikes, after.strikes)
	}
	seq := append([]int{polBOS}, after.hist["sni|home|joint"]...)
	if !reflect.DeepEqual(before.live.armScores(seq, polArms), after.live.armScores(seq, polArms)) {
		t.Fatal("restored policy scores arms differently")
	}
}

func TestOnlinePolicyDropsWeightsTunedFromOtherFrozen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-online.json")
	o := trainedOnlinePolicy(t)
	snap := o.snapshot()
	snap.Frozen = "retrained"
	writeSnapshot(t, path, snap)

	after := newOnlinePolicy()
	if err := after.load(path); err != nil {
		t.Fatal(err)
	}
	if after.tuned || !reflect.DeepEqual(after.live.all(), newPolParams().all()) {
		t.Fatal("weights tuned on top of other frozen weights must be dropped")
	}
	if len(after.hist["sni|home|joint"]) == 0 || after.alive("sni|cafe|joint", 4) {
		t.Fatal("history and benched arms do not depend on the weights and should be kept")
	}
}

func TestOnlinePolicyRejectsMalformedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-online.json")
	snap := trainedOnlinePolicy(t).snapshot()
	snap.Params["win"] = snap.Params["win"][:1]
	snap.History["bad"] = []int{0, polBOS, 3}
	snap.Fails["bad"] = map[int]int{polArms + 5: 2}
	writeSnapshot(t, path, snap)

	after := newOnlinePolicy()
	if err := after.load(path); err != nil {
		t.Fatal(err)
	}
	if after.tuned {
		t.Fatal("weights of the wrong shape must be dropped")
	}
	if _, ok := after.hist["bad"]; ok {
		t.Fatal("history with tokens out of range must be dropped")
	}
	if _, ok := after.fails["bad"]; ok {
		t.Fatal("fails for arms out of range must be dropped")
	}
}

func TestOnlinePolicySkipsUnchangedSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-online.json")
	o := trainedOnlinePolicy(t)
	if err := o.save(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := o.save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("nothing changed, so nothing should have been written")
	}
	o.Note("sni|home|joint", 1, true, true)
	if err := o.save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("a new dial should be saved")
	}
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
