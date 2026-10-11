package tunnel

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestCircuitBreakerTripsAtThreshold(t *testing.T) {
	cb := newCircuitBreaker(3, time.Hour)
	cb.Fail()
	cb.Fail()
	if !cb.Allow() {
		t.Fatal("breaker must stay closed below the threshold")
	}
	cb.Fail()
	if cb.Allow() {
		t.Fatal("breaker must open once the threshold is reached")
	}
}

func TestCircuitBreakerHalfOpensThenCloses(t *testing.T) {
	cb := newCircuitBreaker(1, 10*time.Millisecond)
	cb.Fail()
	if cb.Allow() {
		t.Fatal("breaker must be open right after tripping")
	}
	time.Sleep(20 * time.Millisecond)
	if !cb.Allow() {
		t.Fatal("breaker must half-open once the reset window passes")
	}
	cb.Success()
	if !cb.Allow() {
		t.Fatal("breaker must close after a success")
	}
}

func TestIsConnectErrorMatchesDialOnly(t *testing.T) {
	dialErr := &net.OpError{Op: "dial", Net: "tcp4", Err: errors.New("i/o timeout")}
	if !isConnectError(dialErr) {
		t.Fatal("a dial OpError is a connect error")
	}
	if !isConnectError(fmt.Errorf("direct dial: %w", dialErr)) {
		t.Fatal("a wrapped dial OpError is still a connect error")
	}
	if isConnectError(errors.New("whispera: utls handshake: tls: handshake failure")) {
		t.Fatal("a handshake error is not a connect error")
	}
	readErr := &net.OpError{Op: "read", Net: "tcp4", Err: errors.New("i/o timeout")}
	if isConnectError(readErr) {
		t.Fatal("a read OpError is not a connect error")
	}
}
