package xhttp

import (
	"crypto/ed25519"
	"fmt"
	"net"
	"sync"
	"time"

	metr "whispera/internal/metrics"
	"whispera/internal/obfuscation"
)

// ClientConfig represents XHTTP client configuration
// XHTTP is an obfuscation layer, NOT a transport protocol
// It uses two-layer obfuscation:
// 1. HTTP/2 frame obfuscation (primary - makes traffic look like HTTP/2)
// 2. Marionette obfuscation (mandatory additional layer - browser fingerprinting)
// According to Xray-core specification, XHTTP does NOT create TCP/TLS connections
type ClientConfig struct {
	PublicKey  ed25519.PublicKey
	ShortID    []byte
	ServerName string

	// Marionette integration (MANDATORY for XHTTP)
	ObfuscationManager *obfuscation.IntegrationManager // Required - must not be nil
}

// ClientConnPool manages XHTTP client-side connection pooling with shortID tracking
type ClientConnPool struct {
	config        *ClientConfig
	conns         map[string]*PooledConn // Indexed by shortID (hex)
	connsMutex    sync.RWMutex
	maxPoolSize   int
	connTimeout   time.Duration
	http2PoolSize int

	// Metrics
	poolStats sync.Map // map[string]int64 - stats per shortID
}

// PooledConn wraps a connection with pool management metadata
type PooledConn struct {
	Conn         net.Conn
	CreatedAt    time.Time
	LastUsed     time.Time
	BytesRead    int64
	BytesWritten int64
	mu           sync.RWMutex
	shortID      string
}

// NewClientConfig creates a new XHTTP client config
// obfuscationManager is MANDATORY - XHTTP requires Marionette obfuscation
// Returns error if obfuscationManager is nil
func NewClientConfig(
	publicKey ed25519.PublicKey,
	shortID []byte,
	serverName string,
	obfuscationManager *obfuscation.IntegrationManager,
) (*ClientConfig, error) {
	// Validate that Marionette is provided (mandatory)
	if obfuscationManager == nil {
		return nil, ErrMarionetteRequired
	}

	return &ClientConfig{
		PublicKey:          publicKey,
		ShortID:            shortID,
		ServerName:         serverName,
		ObfuscationManager: obfuscationManager,
	}, nil
}

// NewClientConnPool creates a new connection pool for XHTTP client
func NewClientConnPool(config *ClientConfig, maxPoolSize int, connTimeout time.Duration) *ClientConnPool {
	pool := &ClientConnPool{
		config:        config,
		conns:         make(map[string]*PooledConn),
		maxPoolSize:   maxPoolSize,
		connTimeout:   connTimeout,
		http2PoolSize: 10, // Max HTTP/2 streams per connection
	}

	// Start cleanup goroutine
	go pool.cleanupExpiredConns()

	return pool
}

// cleanupExpiredConns removes stale connections from pool
func (p *ClientConnPool) cleanupExpiredConns() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.connsMutex.Lock()
		now := time.Now()
		var toRemove []string

		for shortID, poolConn := range p.conns {
			poolConn.mu.RLock()
			lastUsed := poolConn.LastUsed
			poolConn.mu.RUnlock()

			if now.Sub(lastUsed) > p.connTimeout {
				toRemove = append(toRemove, shortID)
				poolConn.Conn.Close()
			}
		}

		for _, shortID := range toRemove {
			delete(p.conns, shortID)
		}

		p.connsMutex.Unlock()
	}
}

// GetConn retrieves or creates a connection for a given shortID
func (p *ClientConnPool) GetConn(shortID string) (net.Conn, error) {
	p.connsMutex.RLock()

	if poolConn, exists := p.conns[shortID]; exists {
		poolConn.mu.Lock()
		poolConn.LastUsed = time.Now()
		poolConn.mu.Unlock()

		p.connsMutex.RUnlock()

		// Try to use existing connection
		// In real implementation, would test connection health first
		return poolConn.Conn, nil
	}

	p.connsMutex.RUnlock()

	// Connection doesn't exist or pool is empty - need to create new one
	// In real implementation, would establish TCP/TLS to server here
	// For now, return error (caller would establish connection)
	return nil, fmt.Errorf("no connection for shortID %s", shortID)
}

// ReturnConn returns a connection to the pool after use
func (p *ClientConnPool) ReturnConn(shortID string, conn net.Conn) error {
	p.connsMutex.Lock()
	defer p.connsMutex.Unlock()

	// Check if we already have this connection
	if poolConn, exists := p.conns[shortID]; exists {
		// Update usage stats
		poolConn.mu.Lock()
		poolConn.LastUsed = time.Now()
		poolConn.mu.Unlock()
		return nil
	}

	// Add new connection to pool if under limit
	if len(p.conns) < p.maxPoolSize {
		poolConn := &PooledConn{
			Conn:      conn,
			CreatedAt: time.Now(),
			LastUsed:  time.Now(),
			shortID:   shortID,
		}
		p.conns[shortID] = poolConn
		return nil
	}

	// Pool is full - close connection
	conn.Close()
	return fmt.Errorf("pool is full")
}

// WrapConn wraps an existing connection with XHTTP obfuscation layer
// XHTTP does NOT create TCP/TLS connections - it works as an obfuscation layer
// over existing connections, according to Xray-core specification
// XHTTP uses two-layer obfuscation: HTTP/2 frames (primary) + Marionette (mandatory)
func (c *ClientConfig) WrapConn(conn net.Conn) (net.Conn, error) {
	// Validate that Marionette is provided (mandatory)
	if c.ObfuscationManager == nil {
		return nil, ErrMarionetteRequired
	}

	// Wrap existing connection with two-layer obfuscation:
	// 1. HTTP/2 frame obfuscation (primary - makes traffic look like HTTP/2)
	// 2. Marionette obfuscation (mandatory additional layer)
	wrapped := &ObfuscatedConn{
		Conn:               conn,
		ObfuscationManager: c.ObfuscationManager,
		Direction:          "outbound",
		http2Obf:           NewHTTP2Obfuscator(),
	}

	// Record metrics
	metr.XHTTPStreamsCreated.Inc()

	return wrapped, nil
}

// GetStats returns pool statistics for a given shortID
func (p *ClientConnPool) GetStats(shortID string) map[string]interface{} {
	p.connsMutex.RLock()
	poolConn, exists := p.conns[shortID]
	p.connsMutex.RUnlock()

	if !exists {
		return nil
	}

	poolConn.mu.RLock()
	defer poolConn.mu.RUnlock()

	return map[string]interface{}{
		"bytes_read":    poolConn.BytesRead,
		"bytes_written": poolConn.BytesWritten,
		"created_at":    poolConn.CreatedAt,
		"last_used":     poolConn.LastUsed,
		"age":           time.Since(poolConn.CreatedAt).Seconds(),
	}
}

// PoolStats returns overall pool statistics
func (p *ClientConnPool) PoolStats() map[string]interface{} {
	p.connsMutex.RLock()
	poolSize := len(p.conns)
	p.connsMutex.RUnlock()

	return map[string]interface{}{
		"pool_size":     poolSize,
		"max_pool_size": p.maxPoolSize,
		"utilization":   float64(poolSize) / float64(p.maxPoolSize),
	}
}

// ObfuscatedConn is defined in server.go and shared between client and server
// ErrMarionetteRequired is defined in server.go
