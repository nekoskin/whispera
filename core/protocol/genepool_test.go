//go:build stand

package protocol

import "testing"

func TestGenePoolMutationKeepsIdentInRange(t *testing.T) {
	const idents = 3
	p := NewGenePool(idents)
	for i := 0; i < 5000; i++ {
		g := p.mutate(Gene{Ident: p.rng.Intn(idents), Records: 4, PauseMs: 3})
		if g.Ident < 0 || g.Ident >= idents {
			t.Fatalf("ident %d out of [0,%d)", g.Ident, idents)
		}
		if g.Records < 1 || g.Records > geneMaxRecords {
			t.Fatalf("records %d out of range", g.Records)
		}
		if g.PauseMs < 0 || g.PauseMs > geneMaxPause {
			t.Fatalf("pause %d out of range", g.PauseMs)
		}
	}
}

func TestGenePoolCrossoverTakesIdentFromReplicatedParent(t *testing.T) {
	p := NewGenePool(4)
	for i := 0; i < 5000; i++ {
		child := p.breed()
		if child.Ident < 0 || child.Ident >= p.idents {
			t.Fatalf("bred ident %d is not a replicated pool index", child.Ident)
		}
	}
}

func TestGenePoolConvergesToTheLiveGene(t *testing.T) {
	p := NewGenePool(3)
	winner := Gene{Ident: 1, Records: 4, PauseMs: 0}
	for i := 0; i < 2000; i++ {
		g := p.Select()
		p.Observe(g, g == winner)
	}
	best, rate, total := p.Best()
	if best != winner {
		t.Fatalf("best gene %v, want %v (rate %.2f, n %d)", best, winner, rate, total)
	}
}

func TestGenePoolPruneRespectsCap(t *testing.T) {
	p := NewGenePool(4)
	for i := 0; i < 3000; i++ {
		g := p.Select()
		p.Observe(g, i%2 == 0)
	}
	if len(p.pop) > genePopCap {
		t.Fatalf("population %d exceeds cap %d after prune", len(p.pop), genePopCap)
	}
}

func TestGenePoolSingleIdentStaysZero(t *testing.T) {
	p := NewGenePool(1)
	for i := 0; i < 1000; i++ {
		if g := p.mutate(Gene{Ident: 0, Records: 4, PauseMs: 3}); g.Ident != 0 {
			t.Fatalf("ident drifted to %d with a single replicated source", g.Ident)
		}
	}
}
