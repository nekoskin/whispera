package protocol

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"sync"
	"time"
)

func ShapeSearchEnabled() bool { return os.Getenv("WHISPERA_SHAPE_SEARCH") == "1" }

type HelloShape struct {
	Records int
	PauseMs int
}

func (s HelloShape) String() string { return fmt.Sprintf("r%d/p%dms", s.Records, s.PauseMs) }

type shapeStat struct {
	shape HelloShape
	alive int
	total int
}

func (e *shapeStat) rate() float64 { return float64(e.alive+1) / float64(e.total+2) }

const (
	shapePopCap     = 16
	shapeExplore    = 0.2
	shapeMaxRecords = 12
	shapeMaxPause   = 20
)

type ShapeSearch struct {
	mu  sync.Mutex
	pop []*shapeStat
	rng *rand.Rand
}

func NewShapeSearch() *ShapeSearch {
	s := &ShapeSearch{rng: rand.New(rand.NewSource(time.Now().UnixNano()))}
	for _, r := range []int{1, 2, 3, 4, 6, 8} {
		for _, p := range []int{0, 3} {
			s.pop = append(s.pop, &shapeStat{shape: HelloShape{r, p}})
		}
	}
	return s
}

func (s *ShapeSearch) Select() HelloShape {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.pop {
		if e.total == 0 {
			return e.shape
		}
	}
	if s.rng.Float64() < shapeExplore {
		child := s.mutate(s.pop[s.rng.Intn(len(s.pop))].shape)
		if s.find(child) == nil && len(s.pop) < shapePopCap*2 {
			s.pop = append(s.pop, &shapeStat{shape: child})
		}
		return child
	}
	return s.best().shape
}

func (s *ShapeSearch) Observe(sh HelloShape, alive bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.find(sh)
	if e == nil {
		e = &shapeStat{shape: sh}
		s.pop = append(s.pop, e)
	}
	e.total++
	if alive {
		e.alive++
	}
	s.prune()
}

func (s *ShapeSearch) Best() (HelloShape, float64, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.best()
	return e.shape, e.rate(), e.total
}

func (s *ShapeSearch) best() *shapeStat {
	best := s.pop[0]
	for _, e := range s.pop[1:] {
		if e.rate() > best.rate() || (e.rate() == best.rate() && e.total > best.total) {
			best = e
		}
	}
	return best
}

func (s *ShapeSearch) find(sh HelloShape) *shapeStat {
	for _, e := range s.pop {
		if e.shape == sh {
			return e
		}
	}
	return nil
}

func (s *ShapeSearch) mutate(sh HelloShape) HelloShape {
	if s.rng.Intn(2) == 0 {
		sh.Records = clampInt(sh.Records+s.rng.Intn(3)-1, 1, shapeMaxRecords)
	} else {
		sh.PauseMs = clampInt(sh.PauseMs+s.rng.Intn(5)-2, 0, shapeMaxPause)
	}
	return sh
}

func (s *ShapeSearch) prune() {
	if len(s.pop) <= shapePopCap {
		return
	}
	sort.Slice(s.pop, func(i, j int) bool { return s.pop[i].rate() > s.pop[j].rate() })
	s.pop = s.pop[:shapePopCap]
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
