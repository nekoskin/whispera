package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"sync"
)

type onlinePolicySnapshot struct {
	Frozen   string                   `json:"frozen"`
	Params   map[string][][]float64   `json:"params,omitempty"`
	History  map[string][]int         `json:"history"`
	Fails    map[string]map[int]int   `json:"fails"`
	Strikes  map[string]map[int]int   `json:"strikes"`
	Mutants  map[string][]*mutantStat `json:"mutants,omitempty"`
	Decay    map[string]int           `json:"decay"`
	Outcomes []bool                   `json:"outcomes"`
	Steps    int                      `json:"steps"`
	Reverts  int                      `json:"reverts"`
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

func (o *onlinePolicy) snapshot() onlinePolicySnapshot {
	snap := onlinePolicySnapshot{
		Frozen:   polFrozenFingerprint(),
		History:  o.hist,
		Fails:    o.fails,
		Strikes:  o.strikes,
		Mutants:  o.mutants,
		Decay:    o.sinceDecay,
		Outcomes: o.outcomes,
		Steps:    o.steps,
		Reverts:  o.reverts,
	}
	if o.tuned {
		snap.Params = map[string][][]float64{}
		o.live.each(func(name string, m [][]float64) { snap.Params[name] = m })
	}
	return snap
}

func (o *onlinePolicy) restore(snap onlinePolicySnapshot) {
	if live, ok := polParamsFrom(snap.Params); ok && snap.Frozen == polFrozenFingerprint() {
		o.live = live
		o.adam = newPolAdam()
		o.tuned = true
	}
	for ctx, seq := range snap.History {
		if seq = polValidHistory(seq); len(seq) > 0 {
			o.hist[ctx] = seq
		}
	}
	restoreArmCounts(o.fails, snap.Fails)
	restoreArmCounts(o.strikes, snap.Strikes)
	restoreMutants(o.mutants, snap.Mutants)
	for ctx, n := range snap.Decay {
		if n > 0 && n < deadArmDecay {
			o.sinceDecay[ctx] = n
		}
	}
	if len(snap.Outcomes) > polOnlineWindow {
		snap.Outcomes = snap.Outcomes[len(snap.Outcomes)-polOnlineWindow:]
	}
	o.outcomes = snap.Outcomes
	o.steps = snap.Steps
	o.reverts = snap.Reverts
}

func restoreArmCounts(dst, src map[string]map[int]int) {
	for ctx, counts := range src {
		kept := map[int]int{}
		for arm, n := range counts {
			if arm >= 0 && arm < polArms && n > 0 {
				kept[arm] = n
			}
		}
		if len(kept) > 0 {
			dst[ctx] = kept
		}
	}
}

func restoreMutants(dst, src map[string][]*mutantStat) {
	for ctx, stats := range src {
		var kept []*mutantStat
		for _, s := range stats {
			if s == nil || len(s.Hello) != hex.EncodedLen(mutantHelloBytes) || s.Records < 1 || s.Records > mutantMaxRecords ||
				s.Alive < 0 || s.Alive > s.Total || s.Streak < 0 {
				continue
			}
			kept = append(kept, s)
		}
		if len(kept) > 0 {
			dst[ctx] = kept
		}
	}
}

func polValidHistory(seq []int) []int {
	if len(seq) > polBlock {
		seq = seq[len(seq)-polBlock:]
	}
	for _, tok := range seq {
		if tok < 0 || tok >= polArms*2 {
			return nil
		}
	}
	return seq
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
