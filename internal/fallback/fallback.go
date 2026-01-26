// Package fallback provides automatic transport fallback when primary is blocked
package fallback

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/interfaces"
)

// Config holds fallback configuration
type Config struct {
	// Transports ordered by priority (first = highest)
	TransportPriority []interfaces.TransportType
	// RetryDelay between fallback attempts
	RetryDelay time.Duration
	// MaxRetries per transport before moving to next
	MaxRetries int
	// BlockDetectionTimeout for detecting if transport is blocked
	BlockDetectionTimeout time.Duration
	// CooldownPeriod before retrying a blocked transport
	CooldownPeriod time.Duration
}

// DefaultConfig returns default fallback configuration
func DefaultConfig() *Config {
	return &Config{
		TransportPriority: []interfaces.TransportType{
			interfaces.TransportH2C,
			interfaces.TransportWebSocket,
			interfaces.TransportXHTTP,
			interfaces.TransportTCP,
			interfaces.TransportQUIC,
			interfaces.TransportUDP,
		},
		RetryDelay:            500 * time.Millisecond,
		MaxRetries:            3,
		BlockDetectionTimeout: 5 * time.Second,
		CooldownPeriod:        5 * time.Minute,
	}
}

// TransportDialer interface for transport dial operations
type TransportDialer interface {
	Dial(ctx context.Context, addr string) (net.Conn, error)
	Type() interfaces.TransportType
}

// Manager handles automatic transport fallback
type Manager struct {
	config     *Config
	transports map[interfaces.TransportType]TransportDialer
	mu         sync.RWMutex

	// Blocked transports with cooldown
	blocked   map[interfaces.TransportType]time.Time
	blockedMu sync.RWMutex

	// Current active transport
	current interfaces.TransportType

	// Stats
	fallbackCount uint64
	successCount  uint64
	failureCount  uint64
}

// New creates a new fallback manager
func New(cfg *Config) *Manager {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	m := &Manager{
		config:     cfg,
		transports: make(map[interfaces.TransportType]TransportDialer),
		blocked:    make(map[interfaces.TransportType]time.Time),
	}

	// Set initial current to first priority
	if len(cfg.TransportPriority) > 0 {
		m.current = cfg.TransportPriority[0]
	}

	return m
}

// RegisterTransport registers a transport for fallback
func (m *Manager) RegisterTransport(t TransportDialer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transports[t.Type()] = t
}

// Dial attempts to dial using fallback strategy
func (m *Manager) Dial(ctx context.Context, addr string) (net.Conn, error) {
	m.mu.RLock()
	transports := m.transports
	priority := m.config.TransportPriority
	m.mu.RUnlock()

	if len(transports) == 0 {
		return nil, errors.New("no transports registered")
	}

	var lastErr error

	// Try transports in priority order
	for _, tType := range priority {
		// Skip if transport not registered
		transport, ok := transports[tType]
		if !ok {
			continue
		}

		// Skip if transport is blocked and in cooldown
		if m.isBlocked(tType) {
			continue
		}

		// Try this transport with retries
		conn, err := m.tryTransport(ctx, transport, addr)
		if err == nil {
			m.setActive(tType)
			atomic.AddUint64(&m.successCount, 1)
			return conn, nil
		}

		lastErr = err
		atomic.AddUint64(&m.failureCount, 1)

		// Mark as potentially blocked
		if m.shouldMarkBlocked(err) {
			m.markBlocked(tType)
			atomic.AddUint64(&m.fallbackCount, 1)
		}
	}

	return nil, fmt.Errorf("all transports failed, last error: %w", lastErr)
}

// tryTransport attempts to dial with retries
func (m *Manager) tryTransport(ctx context.Context, t TransportDialer, addr string) (net.Conn, error) {
	var lastErr error

	for i := 0; i < m.config.MaxRetries; i++ {
		// Create timeout context for this attempt
		dialCtx, cancel := context.WithTimeout(ctx, m.config.BlockDetectionTimeout)

		conn, err := t.Dial(dialCtx, addr)
		cancel()

		if err == nil {
			return conn, nil
		}

		lastErr = err

		// Check if context was cancelled (not timeout)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// Wait before retry
		if i < m.config.MaxRetries-1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(m.config.RetryDelay):
			}
		}
	}

	return nil, lastErr
}

// isBlocked checks if transport is currently blocked
func (m *Manager) isBlocked(t interfaces.TransportType) bool {
	m.blockedMu.RLock()
	blockedTime, blocked := m.blocked[t]
	m.blockedMu.RUnlock()

	if !blocked {
		return false
	}

	// Check if cooldown has passed
	if time.Since(blockedTime) > m.config.CooldownPeriod {
		m.blockedMu.Lock()
		delete(m.blocked, t)
		m.blockedMu.Unlock()
		return false
	}

	return true
}

// markBlocked marks a transport as blocked
func (m *Manager) markBlocked(t interfaces.TransportType) {
	m.blockedMu.Lock()
	m.blocked[t] = time.Now()
	m.blockedMu.Unlock()
}

// shouldMarkBlocked determines if error indicates blocking
func (m *Manager) shouldMarkBlocked(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Common blocking indicators
	blockIndicators := []string{
		"connection reset",
		"connection refused",
		"tls: handshake failure",
		"tls: protocol version",
		"i/o timeout",
		"network is unreachable",
		"no route to host",
		"connection timed out",
	}

	for _, indicator := range blockIndicators {
		if contains(errStr, indicator) {
			return true
		}
	}

	return false
}

// setActive sets the current active transport
func (m *Manager) setActive(t interfaces.TransportType) {
	m.mu.Lock()
	m.current = t
	m.mu.Unlock()
}

// GetActive returns the current active transport type
func (m *Manager) GetActive() interfaces.TransportType {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// GetBlockedTransports returns list of currently blocked transports
func (m *Manager) GetBlockedTransports() []interfaces.TransportType {
	m.blockedMu.RLock()
	defer m.blockedMu.RUnlock()

	result := make([]interfaces.TransportType, 0, len(m.blocked))
	for t := range m.blocked {
		result = append(result, t)
	}
	return result
}

// UnblockAll clears all blocked transports
func (m *Manager) UnblockAll() {
	m.blockedMu.Lock()
	m.blocked = make(map[interfaces.TransportType]time.Time)
	m.blockedMu.Unlock()
}

// Stats returns fallback statistics
func (m *Manager) Stats() (fallbacks, successes, failures uint64) {
	return atomic.LoadUint64(&m.fallbackCount),
		atomic.LoadUint64(&m.successCount),
		atomic.LoadUint64(&m.failureCount)
}

// helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsLower(s, substr))
}

func containsLower(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalFoldSlice(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalFoldSlice(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
