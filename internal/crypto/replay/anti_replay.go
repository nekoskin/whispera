package replay

import "sync"

// SlidingWindow implements a 64-size anti-replay window for 32-bit sequence numbers.
type SlidingWindow struct {
	mu   sync.Mutex
	max  uint32
	mask uint64
}

func NewSlidingWindow() *SlidingWindow {
	return &SlidingWindow{}
}

// CheckAndMark returns true if seq is accepted (not replayed and not too old), and marks it as seen.
func (w *SlidingWindow) CheckAndMark(seq uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if seq > w.max {
		shift := uint64(seq - w.max)
		if shift >= 64 {
			w.mask = 0
		} else {
			w.mask = (w.mask << shift)
		}
		w.mask |= 1
		w.max = seq
		return true
	}

	// too old
	if w.max-seq >= 64 {
		return false
	}
	offset := uint64(w.max - seq)
	if (w.mask>>offset)&1 == 1 {
		return false
	}
	w.mask |= (1 << offset)
	return true
}
