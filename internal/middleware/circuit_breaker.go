package middleware

import (
	"context"
	"errors"
	"sync"
	"time"

	"whispera/core/router"
)

// State состояние circuit breaker
type State int

const (
	StateClosed State = iota
	StateOpen
	StateHalfOpen
)

// CircuitBreakerMiddleware реализует паттерн Circuit Breaker
type CircuitBreakerMiddleware struct {
	mu           sync.RWMutex
	state        State
	failures     int
	threshold    int
	resetTimeout time.Duration
	lastFailure  time.Time
}

// NewCircuitBreakerMiddleware создает новый CircuitBreakerMiddleware
func NewCircuitBreakerMiddleware(threshold int, resetTimeout time.Duration) *CircuitBreakerMiddleware {
	return &CircuitBreakerMiddleware{
		threshold:    threshold,
		resetTimeout: resetTimeout,
		state:        StateClosed,
	}
}

// Process реализует интерфейс Middleware
func (m *CircuitBreakerMiddleware) Process(ctx context.Context, req *router.Request, next router.Handler) (*router.Response, error) {
	m.mu.Lock()
	if m.state == StateOpen {
		if time.Since(m.lastFailure) > m.resetTimeout {
			m.state = StateHalfOpen
		} else {
			m.mu.Unlock()
			return &router.Response{
				StatusCode: 503,
				Error:      errors.New("service unavailable (circuit open)"),
			}, nil
		}
	}
	m.mu.Unlock()

	resp, err := next.Handle(ctx, req)

	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil || (resp != nil && resp.StatusCode >= 500) {
		m.failures++
		if m.failures >= m.threshold {
			m.state = StateOpen
			m.lastFailure = time.Now()
		}
	} else if m.state == StateHalfOpen {
		m.state = StateClosed
		m.failures = 0
	} else {
		m.failures = 0
	}

	return resp, err
}

// Name возвращает имя middleware
func (m *CircuitBreakerMiddleware) Name() string {
	return "circuit_breaker"
}

// Priority возвращает приоритет
func (m *CircuitBreakerMiddleware) Priority() int {
	return 100 // Низкий приоритет? Нет, высокий, чтобы быстро отказать
	// Вернем 5, очень высокий
}
