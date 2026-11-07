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
