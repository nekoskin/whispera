package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"sync"

	"github.com/nekoskin/whispera/core/protocol/fingerprint"
)

type onlinePolicySnapshot struct {
	Frozen  string                         `json:"frozen"`
	Presets []string                       `json:"presets,omitempty"`
	Params  map[string][][]float64         `json:"params,omitempty"`
	Dials   map[string][]PolicyStep        `json:"dials,omitempty"`
	Deaths  map[string][]PolicyStep        `json:"deaths,omitempty"`
	History map[string][]int               `json:"history,omitempty"`
	Trust   map[string][polExperts]float64 `json:"trust,omitempty"`
	Steps   int                            `json:"steps"`

	Patterns    []BlockPattern `json:"patterns,omitempty"`
	LastPattern int            `json:"last_pattern,omitempty"`

	Speed map[string][]armSpeed `json:"speed,omitempty"`
}

var polFrozenOnce struct {
	once sync.Once
	sum  string
}

func polFrozenFingerprint() string {
	polFrozenOnce.once.Do(func() {
		h := sha256.New()
		var buf [8]byte
		newPolParams().each(func(name string, m [][]float64) {
			h.Write([]byte(name))
			for _, row := range m {
				binary.LittleEndian.PutUint64(buf[:], uint64(len(row)))
				h.Write(buf[:])
				for _, v := range row {
					binary.LittleEndian.PutUint64(buf[:], math.Float64bits(v))
					h.Write(buf[:])
				}
			}
		})
		polFrozenOnce.sum = hex.EncodeToString(h.Sum(nil))
	})
	return polFrozenOnce.sum
}

func presetIdentities() []string {
	ids := make([]string, fingerprint.PresetCount())
	for i := range ids {
		id := fingerprint.PresetAt(i)
		ids[i] = id.Str()
	}
	return ids
}

func changedPresets(saved []string) map[int]bool {
	changed := map[int]bool{}
	for i, id := range presetIdentities() {
		if i >= len(saved) || saved[i] != id {
			changed[i] = true
		}
	}
	return changed
}

func (o *onlinePolicy) snapshot() onlinePolicySnapshot {
	snap := onlinePolicySnapshot{
		Frozen:  polFrozenFingerprint(),
		Presets: presetIdentities(),
		Dials:   o.dials,
		Deaths:  o.deaths,
		Trust:   o.trust,
		Steps:   o.steps,

		Patterns:    o.patterns,
		LastPattern: o.lastPattern,

		Speed: o.speed,
	}
	if o.tuned {
		snap.Params = map[string][][]float64{}
		o.live.each(func(name string, m [][]float64) { snap.Params[name] = m })
	}
	return snap
}

func (o *onlinePolicy) restore(snap onlinePolicySnapshot) {
	changed := changedPresets(snap.Presets)
	armKept := func(arm int) bool {
		preset, _ := JointArmParts(arm, fingerprint.PresetCount())
		return !changed[preset]
	}
	if live, ok := polParamsFrom(snap.Params); ok && snap.Frozen == polFrozenFingerprint() && len(changed) == 0 {
		o.live = live
		o.tuned = true
	}
	dials := snap.Dials
	if len(dials) == 0 {
		dials = polStepsFromHistory(snap.History)
	}
	saved := len(snap.Presets)
	for ctx, steps := range dials {
		if kept := polValidSteps(remapSteps(steps, saved), armKept); len(kept) > 0 {
			o.dials[ctx] = kept
		}
	}
	for ctx, deaths := range snap.Deaths {
		if kept := polValidSteps(remapSteps(deaths, saved), armKept); len(kept) > 0 {
			o.deaths[ctx] = kept
		}
	}
	for ctx, w := range snap.Trust {
		if validTrust(w) {
			o.trust[ctx] = w
		}
	}
	o.steps = snap.Steps
	for ctx, speed := range snap.Speed {
		if len(speed) != JointArmCount(saved) {
			continue
		}
		kept := make([]armSpeed, polArms)
		for arm, s := range speed {
			if now, ok := JointArmRemap(arm, saved, fingerprint.PresetCount()); ok && now < polArms && armKept(now) && s.N > 0 && !math.IsNaN(s.Mean) {
				kept[now] = s
			}
		}
		o.speed[ctx] = kept
	}
	if snap.Frozen == polFrozenFingerprint() {
		for _, p := range snap.Patterns {
			if len(p.Mean) == polPacketFeat {
				o.patterns = append(o.patterns, p)
			}
		}
		o.lastPattern = snap.LastPattern
	}
}

func validTrust(w [polExperts]float64) bool {
	sum := 0.0
	for _, v := range w {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return false
		}
		sum += v
	}
	return sum > 0
}

func polStepsFromHistory(history map[string][]int) map[string][]PolicyStep {
	out := map[string][]PolicyStep{}
	for ctx, tokens := range history {
		steps := make([]PolicyStep, 0, len(tokens))
		for _, tok := range tokens {
			outcome := DialAlive
			if tok%2 == 1 {
				outcome = DialHandshakeDead
			}
			steps = append(steps, PolicyStep{Arm: tok / 2, Outcome: outcome})
		}
		out[ctx] = steps
	}
	return out
}

func remapSteps(steps []PolicyStep, saved int) []PolicyStep {
	if saved == 0 || saved == fingerprint.PresetCount() {
		return steps
	}
	out := make([]PolicyStep, 0, len(steps))
	for _, s := range steps {
		if arm, ok := JointArmRemap(s.Arm, saved, fingerprint.PresetCount()); ok {
			s.Arm = arm
			out = append(out, s)
		}
	}
	return out
}

func polValidSteps(steps []PolicyStep, keep func(arm int) bool) []PolicyStep {
	var kept []PolicyStep
	for _, s := range polWindow(steps, polBlock) {
		if s.Arm < 0 || s.Arm >= polArms || s.Outcome < 0 || s.Outcome >= polOutcomes || !s.Wire.valid() ||
			math.IsNaN(s.Slow) || s.Slow < 0 || s.Slow > 1 || !s.Measure.valid() || !keep(s.Arm) {
			continue
		}
		kept = append(kept, s)
	}
	return kept
}

func polParamsFrom(mats map[string][][]float64) (*polParams, bool) {
	if len(mats) == 0 {
		return nil, false
	}
	live := newPolParams()
	ok := true
	live.each(func(name string, m [][]float64) {
		src, found := mats[name]
		if !found || len(src) != len(m) {
			ok = false
			return
		}
		for i := range m {
			if len(src[i]) != len(m[i]) {
				ok = false
				return
			}
			for _, v := range src[i] {
				if math.IsNaN(v) || math.IsInf(v, 0) {
					ok = false
					return
				}
			}
		}
	})
	if !ok {
		return nil, false
	}
	live.each(func(name string, m [][]float64) {
		for i := range m {
			copy(m[i], mats[name][i])
		}
	})
	return live, true
}

func (o *onlinePolicy) save(path string) error {
	o.mu.Lock()
	if o.rev == o.saved {
		o.mu.Unlock()
		return nil
	}
	rev := o.rev
	data, err := json.Marshal(o.snapshot())
	o.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	o.mu.Lock()
	o.saved = rev
	o.mu.Unlock()
	return nil
}

func (o *onlinePolicy) load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var snap onlinePolicySnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	o.mu.Lock()
	o.restore(snap)
	o.saved = o.rev
	o.mu.Unlock()
	return nil
}

func SaveOnlinePolicy(path string) error { return sharedOnlinePolicy().save(path) }

func LoadOnlinePolicy(path string) error { return sharedOnlinePolicy().load(path) }
