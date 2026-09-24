package protocol

import (
	"math"
	"testing"
)

func TestShapedChunkFollowsTheMeasuredDistribution(t *testing.T) {
	const draws = 200000
	counts := make([]int, len(chunkShape))
	for i := 0; i < draws; i++ {
		n := shapedChunk(framedMaxData)
		wire := n + chunkWireOverhead
		for j, c := range chunkShape {
			if wire >= c.lo && wire < c.hi || (j == len(chunkShape)-1 && wire >= c.lo) {
				counts[j]++
				break
			}
		}
	}
	total := 0.0
	for _, c := range chunkShape {
		total += c.w
	}
	for j, c := range chunkShape {
		want := c.w / total * 100
		got := float64(counts[j]) / draws * 100
		if math.Abs(got-want) > 1.5 {
			t.Errorf("class %d-%dB: got %.1f%%, want %.1f%%", c.lo, c.hi, got, want)
		}
	}
}

func TestShapedChunkNeverExceedsWhatIsLeft(t *testing.T) {
	for _, left := range []int{1, 9, 100, 1000} {
		for i := 0; i < 2000; i++ {
			if n := shapedChunk(left); n > left {
				t.Fatalf("shapedChunk(%d) returned %d", left, n)
			}
		}
	}
}

func TestShapedChunkStaysWithinTheFrame(t *testing.T) {
	for i := 0; i < 20000; i++ {
		n := shapedChunk(framedMaxData)
		if n < 1 || n > framedMaxData {
			t.Fatalf("shapedChunk gave %d, outside 1..%d", n, framedMaxData)
		}
	}
}
