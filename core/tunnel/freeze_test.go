package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

func startHellos(t *testing.T, g *helloGate, key string, n int) []*helloMark {
	t.Helper()
	marks := make([]*helloMark, n)
	for i := range marks {
		m, err := g.start(context.Background(), key)
		if err != nil {
			t.Fatalf("hello %d of a chain was held: %v", i+1, err)
		}
		marks[i] = m
	}
	return marks
}

func held(g *helloGate, key string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := g.start(ctx, key)
	return err != nil
}

func TestHelloChainIsCappedOnlyAfterAConfirmedFreeze(t *testing.T) {
	g := newHelloGate()
	now := time.Now()
	g.now = func() time.Time { return now }

	marks := startHellos(t, g, "net", 5)
	for _, i := range []int{0, 2, 3} {
		g.settle("net", marks[i], protocol.HandshakeOK, false)
	}
	g.settle("net", marks[1], protocol.HandshakeIncomplete, false)
	if g.net("net").limit != 0 {
		t.Fatal("a single silent hello is not yet a freeze")
	}
	g.settle("net", marks[4], protocol.HandshakeIncomplete, false)
	if got := g.net("net").limit; got != 3 {
		t.Fatalf("the censor let 3 hellos of the chain through, whatever order they arrived in, chains should be kept to 3, got %d", got)
	}

	now = now.Add(helloChainGap + helloChainSlack)
	startHellos(t, g, "net", 3)
	if !held(g, "net") {
		t.Fatal("the 4th hello of a quick chain went out after the network showed it freezes on it")
	}
	now = now.Add(helloChainGap)
	g.sent("net")
	now = now.Add(helloChainSlack)
	if !held(g, "net") {
		t.Fatal("a chain was taken as broken while its last hello had only just left")
	}
	now = now.Add(helloChainGap)
	if held(g, "net") {
		t.Fatal("a hello after a break in the chain was held")
	}
	if held(g, "cafe") {
		t.Fatal("a chain cap learned on one network held another")
	}
}

func TestFailingNetworkSendsNoHelloInsideTheChainGap(t *testing.T) {
	g := newHelloGate()
	now := time.Now()
	g.now = func() time.Time { return now }
	m := startHellos(t, g, "net", 1)[0]
	g.settle("net", m, protocol.HandshakeResetFast, false)
	if !held(g, "net") {
		t.Fatal("a hello went out right behind a failed one, chaining hellos into the censor's count")
	}
	now = now.Add(helloChainGap + helloChainSlack)
	if held(g, "net") {
		t.Fatal("a hello after the chain gap was held")
	}
}

func TestLostHelloFollowedByASuccessDoesNotCapChains(t *testing.T) {
	g := newHelloGate()
	now := time.Now()
	g.now = func() time.Time { return now }
	chain := func(results ...protocol.HandshakeResult) {
		for i, m := range startHellos(t, g, "net", len(results)) {
			g.settle("net", m, results[i], false)
		}
		now = now.Add(helloChainGap + helloChainSlack)
	}
	chain(protocol.HandshakeOK, protocol.HandshakeIncomplete)
	chain(protocol.HandshakeOK)
	chain(protocol.HandshakeOK, protocol.HandshakeIncomplete)
	if got := g.net("net").limit; got != 0 {
		t.Fatalf("hellos lost one at a time between working chains capped chains to %d", got)
	}
}

func TestDeadNetworkDialsOneAtATimeUntilOneWorks(t *testing.T) {
	g := newHelloGate()
	noneAlive := func() bool { return false }
	admitted := func() (func(), bool) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		release, err := g.admit(ctx, "net", noneAlive)
		return release, err == nil
	}

	if _, ok := admitted(); !ok {
		t.Fatal("a dial was held before any handshake failed")
	}
	m := startHellos(t, g, "net", 1)[0]
	g.settle("net", m, protocol.HandshakeIncomplete, false)

	release, ok := admitted()
	if !ok {
		t.Fatal("no dial at all was let through on a dead network")
	}
	if _, ok := admitted(); ok {
		t.Fatal("two handshakes ran at once on a network with no live arm")
	}
	release()

	m = startHellos(t, g, "net", 1)[0]
	g.settle("net", m, protocol.HandshakeOK, false)
	first, ok := admitted()
	if !ok {
		t.Fatal("a working handshake did not lift the one-at-a-time rule")
	}
	defer first()
	if _, ok := admitted(); !ok {
		t.Fatal("dials still ran one at a time after a handshake worked")
	}
}

func TestHelloChainPositionCountsTheRunAndResetsAfterABreak(t *testing.T) {
	g := newHelloGate()
	now := time.Now()
	g.now = func() time.Time { return now }
	for want := 1; want <= 3; want++ {
		m := startHellos(t, g, "net", 1)[0]
		if m.pos != want {
			t.Fatalf("hello %d of a quick run marked as %d", want, m.pos)
		}
		now = now.Add(helloChainGap / 4)
	}
	now = now.Add(helloChainGap + helloChainSlack)
	m := startHellos(t, g, "net", 1)[0]
	if m.pos != 1 || m.gap < helloChainGap+helloChainSlack {
		t.Fatalf("after a break the next hello should start a chain, got position %d after %s", m.pos, m.gap)
	}
}

func TestGuardedChainStopsAtTheSafeCountAndOverflowsOrHolds(t *testing.T) {
	g := newHelloGate()
	now := time.Now()
	g.now = func() time.Time { return now }
	overflow := withChainGuard(context.Background(), chainOverflow)
	if !chainGuarded(overflow) || chainGuarded(context.Background()) {
		t.Fatal("a guarded dial is not told apart from a free one, so migrate arms that need a handshake per few KB stay on offer under the chain cap")
	}
	for i := 1; i <= helloChainSafe; i++ {
		m, err := g.start(overflow, "net")
		if err != nil {
			t.Fatalf("hello %d of a chain was refused below the safe count: %v", i, err)
		}
		g.settle("net", m, protocol.HandshakeOK, false)
	}
	if _, err := g.start(overflow, "net"); !errors.Is(err, errHelloNoRoom) {
		t.Fatalf("a flow that may overflow got hello %d of a quick chain instead of being sent to stream-mux: %v", helloChainSafe+1, err)
	}
	hold, cancel := context.WithTimeout(withChainGuard(context.Background(), chainHold), 50*time.Millisecond)
	defer cancel()
	if _, err := g.start(hold, "net"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a stream-mux transport hello joined a full chain instead of waiting for it to break: %v", err)
	}
	if held(g, "net") {
		t.Fatal("an unguarded hello was capped before the network showed any freeze")
	}
	now = now.Add(helloChainGap + helloChainSlack)
	if _, err := g.start(overflow, "net"); err != nil {
		t.Fatalf("a flow overflowed after the chain broke: %v", err)
	}
}

func TestGuardedHelloWaitsForThePreviousOneToSettle(t *testing.T) {
	g := newHelloGate()
	now := time.Now()
	g.now = func() time.Time { return now }
	first, err := g.start(withChainGuard(context.Background(), chainOverflow), "net")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.start(withChainGuard(context.Background(), chainOverflow), "net"); !errors.Is(err, errHelloNoRoom) {
		t.Fatalf("a second hello went out while the first of the chain was still in flight: %v", err)
	}
	got := make(chan error, 1)
	go func() {
		_, err := g.start(withChainGuard(context.Background(), chainHold), "net")
		got <- err
	}()
	select {
	case err := <-got:
		t.Fatalf("a held hello went out before the previous one settled: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	g.settle("net", first, protocol.HandshakeOK, false)
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("the held hello failed once the previous one settled: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("the held hello did not go out when the previous one settled")
	}
}

func TestLearnedChainLimitRelaxesAfterCleanChains(t *testing.T) {
	g := newHelloGate()
	now := time.Now()
	g.now = func() time.Time { return now }
	learn := func() {
		marks := startHellos(t, g, "net", 3)
		g.settle("net", marks[0], protocol.HandshakeOK, false)
		g.settle("net", marks[1], protocol.HandshakeIncomplete, false)
		g.settle("net", marks[2], protocol.HandshakeIncomplete, false)
		now = now.Add(helloChainGap + helloChainSlack)
	}
	cleanChains := func(length, count int) {
		for range count {
			for _, m := range startHellos(t, g, "net", length) {
				g.settle("net", m, protocol.HandshakeOK, false)
			}
			now = now.Add(helloChainGap + helloChainSlack)
		}
	}
	learn()
	if got := g.net("net").limit; got != 1 {
		t.Fatalf("the freeze should have capped chains to 1, got %d", got)
	}
	cleanChains(1, helloLimitRelaxChains-1)
	if got := g.net("net").limit; got != 1 {
		t.Fatalf("the cap moved to %d before %d clean chains passed", got, helloLimitRelaxChains)
	}
	cleanChains(1, 1)
	if got := g.net("net").limit; got != 2 {
		t.Fatalf("%d clean chains did not let the next chain be one hello longer, cap is %d", helloLimitRelaxChains, got)
	}
	cleanChains(1, helloLimitRelaxChains)
	if got := g.net("net").limit; got != 3 {
		t.Fatalf("clean chains shorter than the cap did not relax it, cap is %d", got)
	}
	cleanChains(3, helloLimitRelaxChains)
	if g.limited("net") {
		t.Fatalf("chains stayed capped at %d after the censor stopped freezing", g.net("net").limit)
	}
	learn()
	if got := g.net("net").relaxChains; got != 2*helloLimitRelaxChains {
		t.Fatalf("a freeze after the cap was lifted should double the clean chains needed next time, got %d", got)
	}
}

func TestArmSpecificSilenceInAMixedChainDoesNotCapChains(t *testing.T) {
	g := newHelloGate()
	marks := startHellos(t, g, "net", 6)
	results := []protocol.HandshakeResult{
		protocol.HandshakeOK, protocol.HandshakeIncomplete, protocol.HandshakeOK,
		protocol.HandshakeIncomplete, protocol.HandshakeOK, protocol.HandshakeIncomplete,
	}
	order := []int{0, 2, 4, 1, 3, 5}
	for _, i := range order[:3] {
		g.settle("net", marks[i], results[i], false)
	}
	g.settle("net", marks[1], results[1], false)
	g.settle("net", marks[3], protocol.HandshakeIncomplete, false)
	if got := g.net("net").limit; got != 3 {
		t.Fatalf("hellos started after the first silent one all went silent too, chains should be capped at the 3 that passed, got %d", got)
	}

	g = newHelloGate()
	marks = startHellos(t, g, "net", 4)
	g.settle("net", marks[0], protocol.HandshakeOK, false)
	g.settle("net", marks[1], protocol.HandshakeIncomplete, false)
	g.settle("net", marks[2], protocol.HandshakeOK, false)
	g.settle("net", marks[3], protocol.HandshakeIncomplete, false)
	if got := g.net("net").limit; got != 0 {
		t.Fatalf("a hello started after the silent one still passed, so the silence belongs to an arm, yet chains were capped to %d", got)
	}
}
