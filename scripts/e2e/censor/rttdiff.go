package main

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

type rttWatch struct {
	mu        sync.Mutex
	firstUp   time.Time
	firstDown time.Time
	pendingUp time.Time
	gaps      []time.Duration
}

func rttEnabled() bool { return os.Getenv("CENSOR_RTTDIFF") == "1" }

func (w *rttWatch) feedUp(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.firstUp.IsZero() {
		w.firstUp = now
	}
	if w.pendingUp.IsZero() {
		w.pendingUp = now
	}
}

func (w *rttWatch) feedDown(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.firstDown.IsZero() {
		w.firstDown = now
		return
	}
	if !w.pendingUp.IsZero() {
		w.gaps = append(w.gaps, now.Sub(w.pendingUp))
		w.pendingUp = time.Time{}
	}
}

func (w *rttWatch) report() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	hs := w.firstDown.Sub(w.firstUp)
	if w.firstUp.IsZero() || w.firstDown.IsZero() || len(w.gaps) == 0 {
		return fmt.Sprintf("handshakeRTT=%.1fms rounds=%d (no data round-trips)", ms(hs), len(w.gaps))
	}
	sorted := append([]time.Duration(nil), w.gaps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	med := sorted[len(sorted)/2]
	app := sorted[0]
	diff := app - hs
	return fmt.Sprintf("handshakeRTT=%.1fms appRTT(min)=%.1fms appRTT(med)=%.1fms rounds=%d RTTdiff=%.1fms",
		ms(hs), ms(app), ms(med), len(w.gaps), ms(diff))
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }
