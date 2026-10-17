package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"sort"

	utls "github.com/refraction-networking/utls"

	"github.com/nekoskin/whispera/core/protocol/fingerprint"
)

const (
	mutantExplore    = 0.1
	mutantMaxRecords = 8
	mutantHelloBytes = 8
	mutantShrink     = 0.5
)

type Mutant struct {
	Hello   string
	Records int
}

func (m Mutant) String() string { return fmt.Sprintf("%s/r%d", m.Hello, m.Records) }

type mutantStat struct {
	Mutant
	Alive  int
	Total  int
	Streak int
}

func (s *mutantStat) rate() float64 { return float64(s.Alive+1) / float64(s.Total+2) }

func mutantPopCap() int { return 2 * fingerprint.CollectedCapacity() }

func mutantHelloID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:mutantHelloBytes])
}

func mutantPool() map[string][]byte {
	pool := map[string][]byte{}
	for i := 0; i < fingerprint.PoolSize(); i++ {
		if _, raw, _ := fingerprint.RawAt(i); len(raw) > 0 {
			pool[mutantHelloID(raw)] = raw
		}
	}
	return pool
}

func (o *onlinePolicy) selectMutant(ctx string, pool []string, maxRecords int, roll func() float64) (Mutant, bool) {
	if len(pool) == 0 {
		return Mutant{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()

	inPool := make(map[string]bool, len(pool))
	for _, id := range pool {
		inPool[id] = true
	}
	tried := map[string]bool{}
	var best, parent *mutantStat
	for _, s := range o.mutants[ctx] {
		if !inPool[s.Hello] {
			continue
		}
		tried[s.Hello] = true
		if parent == nil || s.rate() > parent.rate() {
			parent = s
		}
		if s.Streak == 0 && s.Total > 0 && (best == nil || s.rate() > best.rate()) {
			best = s
		}
	}
	if best != nil && roll() >= mutantExplore {
		return clampRecords(best.Mutant, maxRecords), true
	}

	records := 1
	if best != nil {
		records = best.Records
	}
	var fresh []string
	for _, id := range pool {
		if !tried[id] {
			fresh = append(fresh, id)
		}
	}
	if len(fresh) > 0 {
		return clampRecords(Mutant{Hello: fresh[pickIndex(roll(), len(fresh))], Records: records}, maxRecords), true
	}
	child := parent.Mutant
	if roll() < mutantShrink {
		child.Records--
	} else {
		child.Records++
	}
	return clampRecords(child, maxRecords), true
}

func pickIndex(r float64, n int) int {
	i := int(r * float64(n))
	if i >= n {
		i = n - 1
	}
	return i
}

func clampRecords(m Mutant, maxRecords int) Mutant {
	m.Records = clampInt(m.Records, 1, maxRecords)
	return m
}

func (o *onlinePolicy) noteMutant(ctx string, m Mutant, alive bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rev++
	o.tickDecay(ctx)

	stats := o.mutants[ctx]
	var s *mutantStat
	for _, e := range stats {
		if e.Mutant == m {
			s = e
			break
		}
	}
	if s == nil {
		s = &mutantStat{Mutant: m}
		stats = append(stats, s)
	}
	s.Total++
	if alive {
		s.Alive++
		s.Streak = 0
	} else {
		s.Streak++
	}
	if limit := mutantPopCap(); len(stats) > limit {
		sort.SliceStable(stats, func(i, j int) bool { return stats[i].rate() > stats[j].rate() })
		stats = stats[:limit]
	}
	o.mutants[ctx] = stats
}

func (h *HandshakeStrategy) ApplyMutant(ctx string, fragmented bool, c *ClientConfig) (Mutant, bool) {
	pool := mutantPool()
	ids := make([]string, 0, len(pool))
	for id := range pool {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	maxRecords := 1
	if fragmented {
		maxRecords = mutantMaxRecords
	}
	m, ok := sharedOnlinePolicy().selectMutant(ctx, ids, maxRecords, mrand.Float64)
	if !ok {
		return Mutant{}, false
	}
	c.HelloID, c.HelloRaw = utls.HelloCustom, pool[m.Hello]
	return m, true
}

func (h *HandshakeStrategy) NoteMutant(ctx string, m Mutant, alive bool) {
	sharedOnlinePolicy().noteMutant(ctx, m, alive)
}

func (o *onlinePolicy) mutantPreferred(ctx string, roll func() float64) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	seq := o.hist[ctx]
	if len(seq) == 0 {
		return false
	}
	if last := seq[len(seq)-1]; last == polDial(last/2, true) {
		return false
	}
	for _, s := range o.mutants[ctx] {
		if s.Streak == 0 && s.Alive > 0 {
			return roll() >= mutantExplore
		}
	}
	return false
}

func (h *HandshakeStrategy) MutantPreferred(ctx string) bool {
	return sharedOnlinePolicy().mutantPreferred(ctx, mrand.Float64)
}
