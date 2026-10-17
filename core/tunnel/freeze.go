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
)

var freezeHold = 125 * time.Second

type freezeMark struct {
	arm int
	at  time.Time
}

type freezeNet struct {
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
		n = &freezeNet{}
		g.nets[key] = n
	}
	return n
}

func (g *freezeGate) waitOutFreeze(ctx context.Context, key string) error {
	for {
		g.mu.Lock()
		wait := g.net(key).until.Sub(g.now())
		g.mu.Unlock()
		if wait <= 0 {
			return nil
		}
		if wait > freezeHold {
			wait = freezeHold
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
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
