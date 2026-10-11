package main

import (
	"fmt"
	"sync"
	"time"
)

type tlsRec struct {
	typ  byte
	size int
}

type tlsScanner struct {
	buf []byte
}

func (s *tlsScanner) push(b []byte) []tlsRec {
	s.buf = append(s.buf, b...)
	var out []tlsRec
	for len(s.buf) >= 5 {
		n := int(s.buf[3])<<8 | int(s.buf[4])
		if len(s.buf) < 5+n {
			break
		}
		out = append(out, tlsRec{typ: s.buf[0], size: n})
		s.buf = s.buf[5+n:]
	}
	return out
}

const (
	appData      = 0x17
	flightWindow = 40
	innerHelloLo = 400
	certBurstMin = 1200
	splitRunMin  = 2
	minRounds    = 2
)

type direction uint8

const (
	dirUp direction = iota
	dirDown
)

type flight struct {
	dir   direction
	bytes int
	recs  int
	at    time.Time
}

type hsWatch struct {
	mu      sync.Mutex
	up      tlsScanner
	down    tlsScanner
	seen    int
	flights []flight
}

func newHSWatch() *hsWatch { return &hsWatch{} }

func (w *hsWatch) record(dir direction, size int) {
	if w.seen >= flightWindow {
		return
	}
	w.seen++
	now := time.Now()
	if n := len(w.flights); n > 0 && w.flights[n-1].dir == dir {
		w.flights[n-1].bytes += size
		w.flights[n-1].recs++
		return
	}
	w.flights = append(w.flights, flight{dir: dir, bytes: size, recs: 1, at: now})
}

func (w *hsWatch) feedUp(b []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range w.up.push(b) {
		if r.typ == appData {
			w.record(dirUp, r.size)
		}
	}
}

func (w *hsWatch) feedDown(b []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range w.down.push(b) {
		if r.typ == appData {
			w.record(dirDown, r.size)
		}
	}
}

func (w *hsWatch) rounds() int {
	if len(w.flights) == 0 {
		return 0
	}
	return len(w.flights) - 1
}

func (w *hsWatch) handshakeLocked() (request flight, burst flight, ok bool) {
	if w.rounds() < minRounds {
		return
	}
	for i := 0; i+1 < len(w.flights); i++ {
		f := w.flights[i]
		if f.dir != dirUp || f.bytes < innerHelloLo {
			continue
		}
		answer := w.flights[i+1]
		if answer.dir != dirDown || answer.bytes < certBurstMin || answer.at.Before(f.at) {
			continue
		}
		return f, answer, true
	}
	return
}

func (w *hsWatch) encapsulatedLocked() bool {
	req, _, ok := w.handshakeLocked()
	return ok && req.recs < splitRunMin
}

func (w *hsWatch) splitLocked() bool {
	req, _, ok := w.handshakeLocked()
	return ok && req.recs >= splitRunMin
}

func (w *hsWatch) report() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	req, burst, ok := w.handshakeLocked()
	gap := 0.0
	reqBytes, reqRecs, burstBytes := 0, 0, 0
	if ok {
		gap = burst.at.Sub(req.at).Seconds() * 1000
		reqBytes, reqRecs, burstBytes = req.bytes, req.recs, burst.bytes
	}
	return fmt.Sprintf("rounds=%d hello=%d/%drec burst=%d gapMs=%.1f split=%v encap=%v flights=%v",
		w.rounds(), reqBytes, reqRecs, burstBytes, gap, w.splitLocked(), w.encapsulatedLocked(), w.shape())
}

func (w *hsWatch) shape() []string {
	out := make([]string, len(w.flights))
	for i, f := range w.flights {
		sign := "+"
		if f.dir == dirDown {
			sign = "-"
		}
		out[i] = fmt.Sprintf("%s%d", sign, f.bytes)
	}
	return out
}
