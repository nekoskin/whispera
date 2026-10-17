package tunnel

import (
	"context"
	stdlog "log"
	"sync"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

const (
	freezeDistinctArms = 3
	freezeWindow       = 5 * time.Second
	maxConcurrentDials = 2
	dialGap            = 150 * time.Millisecond
)

var freezeHold = 125 * time.Second

type freezeMark struct {
	arm int
	at  time.Time
}

type freezeNet struct {
	slots   chan struct{}
	lastAt  time.Time
	recent  []freezeMark
	until   time.Time
	noticed bool
}

type freezeGate struct {
	mu   sync.Mutex
	nets map[string]*freezeNet
	now  func() time.Time
}

func newFreezeGate() *freezeGate {
	return &freezeGate{nets: map[string]*freezeNet{}, now: time.Now}
}

var sharedFreeze = newFreezeGate()

func (g *freezeGate) net(key string) *freezeNet {
	n := g.nets[key]
	if n == nil {
		n = &freezeNet{slots: make(chan struct{}, maxConcurrentDials)}
		g.nets[key] = n
	}
	return n
}

func (g *freezeGate) admit(ctx context.Context, key string) (func(), error) {
	g.mu.Lock()
	n := g.net(key)
	g.mu.Unlock()

	for {
		g.mu.Lock()
		wait := n.until.Sub(g.now())
		g.mu.Unlock()
		if wait <= 0 {
			break
		}
		if wait > freezeHold {
			wait = freezeHold
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}

	select {
	case n.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	g.mu.Lock()
	gap := dialGap - g.now().Sub(n.lastAt)
	if gap < 0 {
		gap = 0
	}
	n.lastAt = g.now().Add(gap)
	g.mu.Unlock()
	if gap > 0 {
		t := time.NewTimer(gap)
		select {
		case <-ctx.Done():
			t.Stop()
			<-n.slots
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	return func() { <-n.slots }, nil
}

func (g *freezeGate) silent(key string, arm int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := g.net(key)
	now := g.now()
	if now.Before(n.until) {
		return true
	}

	kept := n.recent[:0]
	seen := map[int]bool{}
	for _, m := range n.recent {
		if now.Sub(m.at) < freezeWindow {
			kept = append(kept, m)
			seen[m.arm] = true
		}
	}
	kept = append(kept, freezeMark{arm: arm, at: now})
	seen[arm] = true
	n.recent = kept
	if len(seen) < freezeDistinctArms {
		return false
	}
	n.until = now.Add(freezeHold)
	n.recent = n.recent[:0]
	if !n.noticed {
		n.noticed = true
		stdlog.Printf("[INFO] network %s looks frozen: %d arms went quiet within %s, holding new handshakes for %s",
			key, len(seen), freezeWindow, freezeHold)
	}
	return true
}

func (g *freezeGate) ok(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := g.net(key)
	n.recent = n.recent[:0]
	n.until = time.Time{}
	n.noticed = false
}

func freezeSilent(result protocol.HandshakeResult) bool {
	return result == protocol.HandshakeIncomplete
}
