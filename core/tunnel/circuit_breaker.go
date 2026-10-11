package tunnel

import (
	"sync"
	"time"
)

const (
	cbThreshold = 5
	cbResetTime = 30 * time.Second

	flowCBThreshold = 3
	flowCBResetTime = 3 * time.Second
)

type cbState string

const (
	cbClosed   cbState = "closed"
	cbOpen     cbState = "open"
	cbHalfOpen cbState = "half-open"
)

type circuitBreaker struct {
	mu          sync.Mutex
	failures    int
	lastFailure time.Time
	state       cbState
	threshold   int
	resetTime   time.Duration
}

func newCircuitBreaker(threshold int, resetTime time.Duration) *circuitBreaker {
	return &circuitBreaker{state: cbClosed, threshold: threshold, resetTime: resetTime}
}

func (cb *circuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case cbOpen:
		if time.Since(cb.lastFailure) > cb.resetTime {
			cb.state = cbHalfOpen
			return true
		}
		return false
	default:
		return true
	}
}

func (cb *circuitBreaker) Fail() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailure = time.Now()
	if cb.state == cbHalfOpen || cb.failures >= cb.threshold {
		cb.state = cbOpen
	}
}

func (cb *circuitBreaker) Success() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = cbClosed
}

func (cb *circuitBreaker) Failures() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.failures
}
