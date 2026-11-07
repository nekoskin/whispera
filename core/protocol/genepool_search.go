//go:build stand

package protocol

import (
	"math/rand"
	"sort"
	"sync"
	"time"
)

type geneStat struct {
	gene  Gene
	alive int
	total int
}

func (e *geneStat) rate() float64 { return float64(e.alive+1) / float64(e.total+2) }

const (
	geneScrambleModes = 4
	genePopCap        = 24
	geneExplore       = 0.2
	geneCross         = 0.3
	geneMaxRecords    = 12
	geneMaxPause      = 20
)

// Candidate phantom TTLs the search draws from; 0 is off. A useful value lands
// between the inspector's hop and the server, so it is calibrated per path.
var genePhantomTTLs = []int{0, 2, 3, 4, 5, 8}

type GenePool struct {
	mu     sync.Mutex
	idents int
	pop    []*geneStat
	rng    *rand.Rand
}

func NewGenePool(idents int) *GenePool {
	if idents < 1 {
		idents = 1
	}
	s := &GenePool{idents: idents, rng: rand.New(rand.NewSource(time.Now().UnixNano()))}
	for i := 0; i < idents; i++ {
		for _, r := range []int{1, 2, 4, 8} {
			s.pop = append(s.pop, &geneStat{gene: Gene{Ident: i, Records: r, PauseMs: 0}})
		}
	}
	return s
}

func (s *GenePool) Select() Gene {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.pop {
		if e.total == 0 {
			return e.gene
		}
	}
	if s.rng.Float64() < geneExplore {
		child := s.breed()
		if s.find(child) == nil && len(s.pop) < genePopCap*2 {
			s.pop = append(s.pop, &geneStat{gene: child})
		}
		return child
	}
	return s.best().gene
}

func (s *GenePool) Observe(g Gene, alive bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.find(g)
	if e == nil {
		e = &geneStat{gene: g}
		s.pop = append(s.pop, e)
	}
	e.total++
	if alive {
		e.alive++
	}
	s.prune()
}

func (s *GenePool) best() *geneStat {
	best := s.pop[0]
	for _, e := range s.pop[1:] {
		if e.rate() > best.rate() || (e.rate() == best.rate() && e.total > best.total) {
			best = e
		}
	}
	return best
}

func (s *GenePool) find(g Gene) *geneStat {
	for _, e := range s.pop {
		if e.gene == g {
			return e
		}
	}
	return nil
}

func (s *GenePool) breed() Gene {
	if len(s.pop) >= 2 && s.rng.Float64() < geneCross {
		a := s.pop[s.rng.Intn(len(s.pop))].gene
		b := s.pop[s.rng.Intn(len(s.pop))].gene
		return s.mutate(Gene{Ident: a.Ident, Records: b.Records, PauseMs: b.PauseMs, Scramble: a.Scramble, PhantomTTL: b.PhantomTTL})
	}
	return s.mutate(s.pop[s.rng.Intn(len(s.pop))].gene)
}

func (s *GenePool) mutate(g Gene) Gene {
	switch s.rng.Intn(5) {
	case 0:
		if s.idents > 1 {
			g.Ident = (g.Ident + 1 + s.rng.Intn(s.idents-1)) % s.idents
		}
	case 1:
		g.Records = min(max(g.Records+s.rng.Intn(3)-1, 1), geneMaxRecords)
	case 2:
		g.PauseMs = min(max(g.PauseMs+s.rng.Intn(5)-2, 0), geneMaxPause)
	case 3:
		g.Scramble = s.rng.Intn(geneScrambleModes)
	default:
		g.PhantomTTL = genePhantomTTLs[s.rng.Intn(len(genePhantomTTLs))]
	}
	return g
}

func (s *GenePool) prune() {
	if len(s.pop) <= genePopCap {
		return
	}
	sort.Slice(s.pop, func(i, j int) bool { return s.pop[i].rate() > s.pop[j].rate() })
	s.pop = s.pop[:genePopCap]
}
