// Package base provides base implementations for common module patterns
package base

import (
	"context"
	"sync"
	"time"

	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

// Module provides a base implementation of interfaces.Module
// Embed this in your module implementations to get common functionality
type Module struct {
	mu           sync.RWMutex
	name         string
	version      string
	deps         []string
	ctx          context.Context
	cancel       context.CancelFunc
	running      bool
	healthy      bool
	healthMsg    string
	eventBus     events.EventBus
	lastActivity time.Time
}

// NewModule creates a new base module
func NewModule(name, version string, deps []string) *Module {
	return &Module{
		name:         name,
		version:      version,
		deps:         deps,
		healthy:      true,
		healthMsg:    "initialized",
		lastActivity: time.Now(),
	}
}

// Name returns the module name
func (m *Module) Name() string {
	return m.name
}

// Version returns the module version
func (m *Module) Version() string {
	return m.version
}

// Dependencies returns the list of module dependencies
func (m *Module) Dependencies() []string {
	return m.deps
}

// Init initializes the module with configuration
func (m *Module) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ctx, m.cancel = context.WithCancel(ctx)
	m.healthMsg = "initialized"
	return nil
}

// Start starts the module
func (m *Module) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.running = true
	m.healthy = true
	m.healthMsg = "running"
	m.lastActivity = time.Now()
	return nil
}

// Stop stops the module
func (m *Module) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancel != nil {
		m.cancel()
	}
	m.running = false
	m.healthMsg = "stopped"
	return nil
}

// HealthCheck returns the current health status
func (m *Module) HealthCheck() interfaces.HealthStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return interfaces.HealthStatus{
		Healthy:     m.healthy,
		Message:     m.healthMsg,
		LastChecked: time.Now(),
		Details: map[string]interface{}{
			"running":       m.running,
			"last_activity": m.lastActivity,
		},
	}
}

// IsRunning returns true if the module is running
func (m *Module) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// Context returns the module context
func (m *Module) Context() context.Context {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ctx
}

// SetHealthy sets the health status
func (m *Module) SetHealthy(healthy bool, msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy = healthy
	m.healthMsg = msg
}

// SetEventBus sets the event bus for the module
func (m *Module) SetEventBus(bus events.EventBus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventBus = bus
}

// EventBus returns the event bus
func (m *Module) EventBus() events.EventBus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.eventBus
}

// PublishEvent publishes an event
func (m *Module) PublishEvent(eventType string, data interface{}) {
	m.mu.RLock()
	bus := m.eventBus
	m.mu.RUnlock()

	if bus != nil {
		bus.PublishAsync(events.NewEvent(eventType, m.name, data))
	}
}

// UpdateActivity updates the last activity timestamp
func (m *Module) UpdateActivity() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastActivity = time.Now()
}

// LastActivity returns the last activity timestamp
func (m *Module) LastActivity() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastActivity
}

// WorkerPool manages a pool of goroutines for concurrent work
type WorkerPool struct {
	workers  int
	workChan chan func()
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.Mutex
	started  bool
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workers int, queueSize int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		workers:  workers,
		workChan: make(chan func(), queueSize),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start starts the worker pool
func (wp *WorkerPool) Start() {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if wp.started {
		return
	}
	wp.started = true

	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

// worker processes work items
func (wp *WorkerPool) worker() {
	defer wp.wg.Done()
	for {
		select {
		case <-wp.ctx.Done():
			return
		case work, ok := <-wp.workChan:
			if !ok {
				return
			}
			work()
		}
	}
}

// Submit submits work to the pool
func (wp *WorkerPool) Submit(work func()) bool {
	select {
	case wp.workChan <- work:
		return true
	case <-wp.ctx.Done():
		return false
	}
}

// SubmitAsync submits work asynchronously (blocking if queue is full)
func (wp *WorkerPool) SubmitAsync(work func()) {
	select {
	case wp.workChan <- work:
	case <-wp.ctx.Done():
	}
}

// TrySubmit submits work asynchronously, returning false immediately if queue is full
func (wp *WorkerPool) TrySubmit(work func()) bool {
	select {
	case wp.workChan <- work:
		return true
	default:
		return false
	}
}

// Stop stops the worker pool
func (wp *WorkerPool) Stop() {
	wp.mu.Lock()
	if !wp.started {
		wp.mu.Unlock()
		return
	}
	wp.mu.Unlock()

	wp.cancel()
	close(wp.workChan)
	wp.wg.Wait()
}

// RateLimiter provides rate limiting functionality
type RateLimiter struct {
	mu        sync.Mutex
	rate      float64
	burst     int
	tokens    float64
	lastCheck time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		rate:      rate,
		burst:     burst,
		tokens:    float64(burst),
		lastCheck: time.Now(),
	}
}

// Allow checks if an action is allowed under the rate limit
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastCheck).Seconds()
	rl.lastCheck = now

	// Add tokens based on elapsed time
	rl.tokens += elapsed * rl.rate
	if rl.tokens > float64(rl.burst) {
		rl.tokens = float64(rl.burst)
	}

	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}
	return false
}

// SetRate updates the rate limit
func (rl *RateLimiter) SetRate(rate float64, burst int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.rate = rate
	rl.burst = burst
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	mu            sync.Mutex
	failures      int
	threshold     int
	timeout       time.Duration
	state         CircuitState
	lastFailure   time.Time
	onStateChange func(CircuitState)
}

// CircuitState represents the state of the circuit breaker
type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold: threshold,
		timeout:   timeout,
		state:     CircuitClosed,
	}
}

// Execute executes a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(fn func() error) error {
	cb.mu.Lock()

	switch cb.state {
	case CircuitOpen:
		if time.Since(cb.lastFailure) > cb.timeout {
			cb.setState(CircuitHalfOpen)
		} else {
			cb.mu.Unlock()
			return ErrCircuitOpen
		}
	case CircuitHalfOpen:
		// Allow one request through
	}
	cb.mu.Unlock()

	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		cb.lastFailure = time.Now()
		if cb.failures >= cb.threshold {
			cb.setState(CircuitOpen)
		}
		return err
	}

	// Success - reset
	cb.failures = 0
	if cb.state == CircuitHalfOpen {
		cb.setState(CircuitClosed)
	}
	return nil
}

// setState changes the circuit state
func (cb *CircuitBreaker) setState(state CircuitState) {
	if cb.state != state {
		cb.state = state
		if cb.onStateChange != nil {
			cb.onStateChange(state)
		}
	}
}

// State returns the current circuit state
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// OnStateChange sets a callback for state changes
func (cb *CircuitBreaker) OnStateChange(fn func(CircuitState)) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.onStateChange = fn
}

// ErrCircuitOpen is returned when the circuit is open
var ErrCircuitOpen = &CircuitError{Message: "circuit breaker is open"}

// CircuitError represents a circuit breaker error
type CircuitError struct {
	Message string
}

func (e *CircuitError) Error() string {
	return e.Message
}

// Metrics provides simple internal metrics
type Metrics struct {
	mu       sync.RWMutex
	counters map[string]int64
	gauges   map[string]float64
}

// NewMetrics creates a new metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		counters: make(map[string]int64),
		gauges:   make(map[string]float64),
	}
}

// Increment increments a counter
func (m *Metrics) Increment(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[name]++
}

// Add adds a value to a counter
func (m *Metrics) Add(name string, value int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[name] += value
}

// SetGauge sets a gauge value
func (m *Metrics) SetGauge(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gauges[name] = value
}

// GetCounter gets a counter value
func (m *Metrics) GetCounter(name string) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.counters[name]
}

// GetGauge gets a gauge value
func (m *Metrics) GetGauge(name string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.gauges[name]
}

// Snapshot returns a copy of all metrics
func (m *Metrics) Snapshot() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]interface{})
	for k, v := range m.counters {
		result["counter."+k] = v
	}
	for k, v := range m.gauges {
		result["gauge."+k] = v
	}
	return result
}
