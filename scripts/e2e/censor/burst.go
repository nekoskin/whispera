package main

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const modeBurst = "burst"

const (
	burstDefaultCount    = 3
	burstDefaultWindow   = 50 * time.Millisecond
	burstDefaultFreeze   = 120 * time.Second
	burstDefaultEscalate = 600 * time.Second
)

type burstJudge struct {
	mu       sync.Mutex
	count    int
	window   time.Duration
	freeze   time.Duration
	escalate time.Duration
	held     map[string]bool
	seen     map[string][]time.Time
	until    map[string]time.Time
	fp       map[string]string
}

var bursts = newBurstJudge()

func newBurstJudge() *burstJudge {
	return &burstJudge{
		count:    burstDefaultCount,
		window:   burstDefaultWindow,
		freeze:   burstDefaultFreeze,
		escalate: burstDefaultEscalate,
		held:     map[string]bool{},
		seen:     map[string][]time.Time{},
		until:    map[string]time.Time{},
		fp:       map[string]string{},
	}
}

func (b *burstJudge) load() {
	if n, err := strconv.Atoi(os.Getenv("CENSOR_BURST_COUNT")); err == nil && n > 1 {
		b.count = n
	}
	if d, err := time.ParseDuration(os.Getenv("CENSOR_BURST_WINDOW")); err == nil && d > 0 {
		b.window = d
	}
	if d, err := time.ParseDuration(os.Getenv("CENSOR_BURST_FREEZE")); err == nil && d > 0 {
		b.freeze = d
	}
	if d, err := time.ParseDuration(os.Getenv("CENSOR_BURST_ESCALATE")); err == nil && d > 0 {
		b.escalate = d
	}
	for _, name := range strings.Split(os.Getenv("CENSOR_BURST_FP"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			b.held[name] = true
		}
	}
	log.Printf("BURST %d hellos within %s freeze for %s, %s if the fingerprint changes meanwhile",
		b.count, b.window, b.freeze, b.escalate)
}

func (b *burstJudge) admit(c net.Conn, fp string, now time.Time) (bool, string) {
	ip := clientIP(c)
	b.mu.Lock()
	defer b.mu.Unlock()

	recent := b.seen[ip][:0]
	for _, t := range b.seen[ip] {
		if now.Sub(t) < b.window {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	b.seen[ip] = recent
	burst := len(recent) >= b.count && (len(b.held) == 0 || b.held[fp])

	if until, frozen := b.until[ip]; frozen && now.Before(until) {
		switch {
		case fp != b.fp[ip]:
			was := b.fp[ip]
			b.until[ip] = now.Add(b.escalate)
			b.fp[ip] = fp
			return false, "fingerprint " + fp + " while frozen on " + was + ", frozen for " + b.escalate.String()
		case burst && now.Add(b.freeze).After(until):
			b.until[ip] = now.Add(b.freeze)
			return false, "another burst while frozen, frozen for " + b.freeze.String() + " again"
		}
		return false, "frozen for another " + until.Sub(now).Round(time.Second).String()
	}
	if burst {
		b.until[ip] = now.Add(b.freeze)
		b.fp[ip] = fp
		return false, strconv.Itoa(len(recent)) + " hellos within " + b.window.String() + ", frozen for " + b.freeze.String()
	}
	return true, ""
}
