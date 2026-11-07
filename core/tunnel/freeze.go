package tunnel

import (
	"context"
	"errors"
	stdlog "log"
	"sync"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

const (
	helloChainGap         = 400 * time.Millisecond
	helloChainSlack       = 100 * time.Millisecond
	helloChainTracked     = 16
	helloChainSafe        = 3
	helloLimitRelaxChains = 8
	helloLimitRelaxMax    = 128
)

var errHelloNoRoom = errors.New("whispera: no room for another hello to the server right now")

type chainGuardKey struct{}

type chainGuard int

const (
	chainHold chainGuard = iota + 1
	chainOverflow
)

func withChainGuard(ctx context.Context, guard chainGuard) context.Context {
	return context.WithValue(ctx, chainGuardKey{}, guard)
}

func chainGuarded(ctx context.Context) bool {
	_, guarded := ctx.Value(chainGuardKey{}).(chainGuard)
	return guarded
}

type helloChain struct {
	marks   []*helloMark
	counted bool
}

func (c *helloChain) passed() int {
	n := 0
	for _, m := range c.marks {
		if m.settled && m.ok {
			n++
		}
	}
	return n
}

type helloMark struct {
	chain   *helloChain
	seq     uint64
	pos     int
	gap     time.Duration
	settled bool
	ok      bool
	done    chan struct{}
}

type helloNet struct {
	chain       *helloChain
	seq         uint64
	run         int
	last        time.Time
	limit       int
	cleanChains int
	relaxChains int
	suspect     *helloMark
	lastFailed  bool
	single      chan struct{}
}

type helloGate struct {
	mu   sync.Mutex
	nets map[string]*helloNet
	now  func() time.Time
}

func newHelloGate() *helloGate {
	return &helloGate{nets: map[string]*helloNet{}, now: time.Now}
}

var sharedHellos = newHelloGate()

func (g *helloGate) net(key string) *helloNet {
	n := g.nets[key]
	if n == nil {
		n = &helloNet{single: make(chan struct{}, 1)}
		g.nets[key] = n
	}
	return n
}

func (g *helloGate) admit(ctx context.Context, key string, anyAlive func() bool) (func(), error) {
	g.mu.Lock()
	n := g.net(key)
	dead := n.lastFailed
	g.mu.Unlock()
	if !dead || anyAlive() {
		return func() {}, nil
	}
	select {
	case n.single <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	g.mu.Lock()
	dead = n.lastFailed
	g.mu.Unlock()
	if !dead || anyAlive() {
		<-n.single
		return func() {}, nil
	}
	return func() { <-n.single }, nil
}

func (g *helloGate) start(ctx context.Context, key string) (*helloMark, error) {
	guard, _ := ctx.Value(chainGuardKey{}).(chainGuard)
	for {
		g.mu.Lock()
		n := g.net(key)
		now := g.now()
		breakAt := n.last.Add(helloChainGap + helloChainSlack)
		pos, gap := n.next(now)
		if pos == 1 {
			n.chain, n.run = &helloChain{}, 0
		}
		limit := n.limit
		if guard != 0 && (limit == 0 || limit > helloChainSafe) {
			limit = helloChainSafe
		}
		paced := n.lastFailed && n.limit == 0 && pos > 1
		capacity := !paced && (limit == 0 || len(n.chain.marks) < limit)
		var inFlight *helloMark
		if guard != 0 && pos > 1 && len(n.chain.marks) > 0 {
			if prev := n.chain.marks[len(n.chain.marks)-1]; !prev.settled {
				inFlight = prev
			}
		}
		if capacity && inFlight == nil {
			n.run++
			n.seq++
			mark := &helloMark{chain: n.chain, seq: n.seq, pos: pos, gap: gap, done: make(chan struct{})}
			if len(n.chain.marks) < helloChainTracked {
				n.chain.marks = append(n.chain.marks, mark)
			}
			n.last = now
			g.mu.Unlock()
			return mark, nil
		}
		g.mu.Unlock()
		if guard == chainOverflow {
			return nil, errHelloNoRoom
		}
		if capacity {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-inFlight.done:
			}
			continue
		}
		t := time.NewTimer(breakAt.Sub(now))
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

func (n *helloNet) next(now time.Time) (pos int, gap time.Duration) {
	if !n.last.IsZero() {
		gap = now.Sub(n.last)
	}
	if n.chain == nil || !now.Before(n.last.Add(helloChainGap+helloChainSlack)) {
		return 1, gap
	}
	return n.run + 1, gap
}

func (g *helloGate) limited(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.net(key).limit > 0
}

func (g *helloGate) sent(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := g.net(key)
	if now := g.now(); now.After(n.last) {
		n.last = now
	}
}

func (n *helloNet) noteCleanChain(key string, chain *helloChain) {
	if n.limit == 0 || chain.counted || chain.passed() < len(chain.marks) {
		return
	}
	chain.counted = true
	if n.cleanChains++; n.cleanChains < n.relaxChains {
		return
	}
	n.cleanChains = 0
	if n.limit++; n.limit <= helloChainSafe {
		stdlog.Printf("[INFO] %s passed %d chains without a freeze, trying chains of %d hellos", key, n.relaxChains, n.limit)
		return
	}
	n.limit = 0
	stdlog.Printf("[INFO] %s passed %d chains without a freeze, hello chains are no longer capped", key, n.relaxChains)
}

func nextRelaxChains(current int) int {
	if current == 0 {
		return helloLimitRelaxChains
	}
	return min(2*current, helloLimitRelaxMax)
}

func (g *helloGate) failed(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.net(key).lastFailed
}

func (g *helloGate) settle(key string, mark *helloMark, result protocol.HandshakeResult, connectFailed bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := g.net(key)
	switch {
	case result == protocol.HandshakeOK:
		n.lastFailed = false
	case connectFailed || result != protocol.HandshakeLocal:
		n.lastFailed = true
	}
	if mark == nil {
		return
	}
	if !mark.settled {
		mark.settled = true
		close(mark.done)
	}
	mark.ok = result == protocol.HandshakeOK
	if result != protocol.HandshakeIncomplete {
		if mark.ok && n.suspect != nil && mark.seq > n.suspect.seq {
			n.suspect = nil
		}
		if mark.ok {
			n.noteCleanChain(key, mark.chain)
		}
		return
	}
	if n.suspect == nil {
		if mark.chain.passed() > 0 {
			n.suspect = mark
		}
		return
	}
	if mark.seq <= n.suspect.seq {
		return
	}
	limit := n.suspect.chain.passed()
	n.suspect = nil
	if n.limit == 0 || limit < n.limit {
		n.relaxChains = nextRelaxChains(n.relaxChains)
		n.limit, n.cleanChains = limit, 0
		stdlog.Printf("[INFO] %s drops hellos past %d in a chain spaced under %s, keeping chains to %d until %d chains pass",
			key, limit, helloChainGap, limit, n.relaxChains)
	}
}
