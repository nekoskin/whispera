package protocol

import (
	"testing"
)

// restoreChunk puts the knob back, since it is process-wide and a test that
// leaves it set would change the datapath of every test that follows.
func restoreChunk(t *testing.T) {
	t.Helper()
	min, max := Shape.Chunk()
	t.Cleanup(func() {
		if err := Shape.SetChunk(min, max); err != nil {
			t.Errorf("restoring the chunk range: %v", err)
		}
	})
}

func TestChunkLenFillsTheRecordWhenOff(t *testing.T) {
	restoreChunk(t)
	if err := Shape.SetChunk(0, 0); err != nil {
		t.Fatal(err)
	}
	for _, left := range []int{1, 100, framedMaxData, framedMaxData * 3} {
		if got := chunkLen(left); got != left {
			t.Errorf("with the knob off, chunkLen(%d) = %d, want the lot", left, got)
		}
	}
}

func TestChunkLenStaysInRange(t *testing.T) {
	restoreChunk(t)
	if err := Shape.SetChunk(200, 1200); err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for i := 0; i < 500; i++ {
		got := chunkLen(framedMaxData)
		if got < 200 || got > 1200 {
			t.Fatalf("chunkLen gave %d, outside 200..1200", got)
		}
		seen[got] = true
	}
	if len(seen) < 50 {
		t.Errorf("only %d distinct lengths in 500 draws: the stream would still look like a constant", len(seen))
	}
}

func TestChunkLenNeverExceedsWhatIsLeft(t *testing.T) {
	restoreChunk(t)
	if err := Shape.SetChunk(500, 4000); err != nil {
		t.Fatal(err)
	}
	for _, left := range []int{1, 7, 499, 500} {
		if got := chunkLen(left); got != left {
			t.Errorf("chunkLen(%d) = %d, want exactly what is left", left, got)
		}
	}
}

func TestSetChunkRejectsNonsense(t *testing.T) {
	restoreChunk(t)
	for _, c := range []struct{ min, max int }{
		{-1, 100},
		{100, -1},
		{900, 100},
		{0, framedMaxData + 1},
	} {
		if err := Shape.SetChunk(c.min, c.max); err == nil {
			t.Errorf("SetChunk(%d, %d) was accepted", c.min, c.max)
		}
	}
}
