package protocol

import "testing"

func TestShapeSearchConvergesToTheSurvivingShape(t *testing.T) {
	s := NewShapeSearch()

	for i := 0; i < 4000; i++ {
		sh := s.Select()
		s.Observe(sh, sh.Records == 3)
	}

	best, rate, trials := s.Best()
	if best.Records != 3 {
		t.Fatalf("best shape %v, want records 3 (rate %.2f, %d trials)", best, rate, trials)
	}
	if rate < 0.8 {
		t.Fatalf("winner rate %.2f too low to trust", rate)
	}
}

func TestShapeSearchExploresBeyondTheSeedGrid(t *testing.T) {
	s := NewShapeSearch()
	seeded := map[HelloShape]bool{}
	for _, e := range s.pop {
		seeded[e.shape] = true
	}
	beyond := false
	for i := 0; i < 3000 && !beyond; i++ {
		sh := s.Select()
		if !seeded[sh] {
			beyond = true
		}
		s.Observe(sh, sh.Records == 5)
	}
	if !beyond {
		t.Fatal("search never tried a shape outside the seed grid")
	}
}
