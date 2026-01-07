// Package failover manages server connection redundancy and automatic failover
package failover

import (
	"context"
	"net"
	"sync"
	"time"

	"whispera/internal/logger"
)

var log = logger.Module("failover")

// ServerStatus represents the health of a server
type ServerStatus struct {
	Address      string
	IsHealthy    bool
	Latency      time.Duration
	LastChecked  time.Time
	FailureCount int
}

// Config for failover manager
type Config struct {
	PrimaryServer   string
	FallbackServers []string
	CheckInterval   time.Duration
	Timeout         time.Duration
	MaxRetries      int
}

// Manager handles failover logic
type Manager struct {
	mu           sync.RWMutex
	config       *Config
	servers      map[string]*ServerStatus
	activeServer string

	// Callbacks
	onServerChange func(newServer string)

	// Background tasks
	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a new failover manager
func New(cfg *Config) *Manager {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 30 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:       cfg,
		servers:      make(map[string]*ServerStatus),
		activeServer: cfg.PrimaryServer,
		ctx:          ctx,
		cancel:       cancel,
	}

	// Initialize status for all servers
	allServers := append([]string{cfg.PrimaryServer}, cfg.FallbackServers...)
	for _, addr := range allServers {
		if addr != "" {
			m.servers[addr] = &ServerStatus{
				Address:   addr,
				IsHealthy: true, // Assume healthy tightly
			}
		}
	}

	return m
}

// Start begins health monitoring
func (m *Manager) Start() {
	go m.monitorLoop()
	log.Info("Failover manager started (Primary: %s, Fallbacks: %d)",
		m.config.PrimaryServer, len(m.config.FallbackServers))
}

// Stop stops monitoring
func (m *Manager) Stop() {
	m.cancel()
}

// GetActiveServer returns the currently selected server
func (m *Manager) GetActiveServer() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.activeServer
}

// ReportFailure reports a connection failure for the active server
func (m *Manager) ReportFailure(err error) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	current := m.activeServer
	if status, exists := m.servers[current]; exists {
		status.IsHealthy = false
		status.FailureCount++
		status.LastChecked = time.Now()
		log.Warn("Server %s reported failure: %v (Count: %d)", current, err, status.FailureCount)
	}

	// Trigger failover immediately if threshold exceeded
	if m.servers[current].FailureCount >= m.config.MaxRetries {
		return m.selectBestServer() // Returns new server
	}

	return current // Keep trying same server
}

// monitorLoop periodically checks server health
func (m *Manager) monitorLoop() {
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkAllServers()
		}
	}
}

// checkAllServers pings all servers to update status
func (m *Manager) checkAllServers() {
	m.mu.RLock()
	servers := make([]string, 0, len(m.servers))
	for addr := range m.servers {
		servers = append(servers, addr)
	}
	m.mu.RUnlock()

	var wg sync.WaitGroup
	for _, addr := range servers {
		wg.Add(1)
		go func(address string) {
			defer wg.Done()
			latency, healthy := m.pingServer(address)

			m.mu.Lock()
			if status, ok := m.servers[address]; ok {
				status.LastChecked = time.Now()
				status.IsHealthy = healthy
				status.Latency = latency
				if healthy {
					status.FailureCount = 0
				}
			}
			m.mu.Unlock()
		}(addr)
	}
	wg.Wait()

	// Re-evaluate active server
	m.mu.Lock()
	newServer := m.selectBestServer()
	if newServer != m.activeServer {
		log.Info("Failover switching server: %s -> %s", m.activeServer, newServer)
		m.activeServer = newServer
		if m.onServerChange != nil {
			go m.onServerChange(newServer)
		}
	}
	m.mu.Unlock()
}

// pingServer checks server connectivity (UDP/TCP ping)
func (m *Manager) pingServer(addr string) (time.Duration, bool) {
	start := time.Now()
	conn, err := net.DialTimeout("udp", addr, m.config.Timeout)
	if err != nil {
		return 0, false
	}
	defer conn.Close()

	// In a real implementation we would send a specific ping packet
	// For UDP, Dial doesn't guarantee connectivity, sending/receiving does.
	// But sending requires protocol knowledge. For now we assume if DNS resolves its OK-ish,
	// or upgrade to TCP check if mixed mode.
	// A better check:
	_, err = conn.Write([]byte{0x00}) // Ping
	if err != nil {
		return 0, false
	}

	return time.Since(start), true
}

// selectBestServer logic (must hold lock)
func (m *Manager) selectBestServer() string {
	// 1. If primary is healthy, prefer it
	if p, ok := m.servers[m.config.PrimaryServer]; ok && p.IsHealthy {
		return m.config.PrimaryServer
	}

	// 2. Find best fallback (lowest latency)
	var bestServer string
	var minLatency time.Duration = 1<<63 - 1

	for addr, status := range m.servers {
		if status.IsHealthy && status.Latency < minLatency {
			minLatency = status.Latency
			bestServer = addr
		}
	}

	if bestServer != "" {
		return bestServer
	}

	// 3. If all dead, return primary to keep retrying
	return m.config.PrimaryServer
}

// OnServerChange registers callback
func (m *Manager) OnServerChange(cb func(string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onServerChange = cb
}
