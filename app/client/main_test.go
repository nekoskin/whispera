package client

import (
	"errors"
	"net"

	"syscall"
	"testing"
	"time"

	"github.com/nekoskin/whispera/core/config"
)

func TestPickServerAddressTCP(t *testing.T) {
	cfg := &config.ClientConfig{ServerTCP: "tcp.example.com", Server: "fallback.example.com"}
	if got := pickServerAddress(cfg, "tcp"); got != "tcp.example.com" {
		t.Errorf("pickServerAddress() = %q, want %q", got, "tcp.example.com")
	}
}

func TestReviveBacksOffAfterFailure(t *testing.T) {
	p := &tunnelPool{}
	done, _ := p.beginRevive()
	p.endRevive(done, false, true)
	if _, mine := p.beginRevive(); mine {
		t.Fatal("revive must back off after a failed restart")
	}
	if p.fails != 1 {
		t.Fatalf("fails = %d, want 1", p.fails)
	}
}

func TestConcurrentReviveWaitsForTheOneInFlight(t *testing.T) {
	p := &tunnelPool{}
	done, mine := p.beginRevive()
	if !mine {
		t.Fatal("first caller must own the attempt")
	}

	second, mine := p.beginRevive()
	if mine {
		t.Fatal("a second caller must not start its own restart")
	}
	if second != done {
		t.Fatal("the second caller must wait on the attempt already running, not fail immediately")
	}

	waited := make(chan struct{})
	go func() {
		<-second
		close(waited)
	}()
	p.endRevive(done, true, true)

	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("waiting callers must be released when the attempt finishes")
	}
}

func TestNetworkDown(t *testing.T) {
	if !networkDown(&net.OpError{Op: "dial", Err: syscall.ENETUNREACH}) {
		t.Fatal("ENETUNREACH must be treated as a dead network, not as a dead tunnel")
	}
	if networkDown(errors.New("whispera: utls handshake: EOF")) {
		t.Fatal("a handshake failure must still trigger revive")
	}
}
