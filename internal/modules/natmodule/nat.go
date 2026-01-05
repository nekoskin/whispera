// Package natmodule provides Network Address Translation module for VPN
package natmodule

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

const (
	ModuleName    = "nat.manager"
	ModuleVersion = "1.0.0"

	DefaultMappingTimeout = 5 * time.Minute
)

// Config holds NAT configuration
type Config struct {
	Enabled        bool          // Enable NAT
	PortRangeStart int           // Start of external port range
	PortRangeEnd   int           // End of external port range
	MappingTimeout time.Duration // Timeout for dynamic mappings
}

// DefaultConfig returns default NAT configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:        true,
		PortRangeStart: 10000,
		PortRangeEnd:   60000,
		MappingTimeout: DefaultMappingTimeout,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.PortRangeStart < 1 || c.PortRangeStart > 65535 {
		c.PortRangeStart = 10000
	}
	if c.PortRangeEnd < c.PortRangeStart || c.PortRangeEnd > 65535 {
		c.PortRangeEnd = 60000
	}
	if c.MappingTimeout <= 0 {
		c.MappingTimeout = DefaultMappingTimeout
	}
	return nil
}

// Mapping represents a NAT mapping
type Mapping struct {
	InternalIP   net.IP
	InternalPort int
	ExternalPort int
	Protocol     string
	CreatedAt    time.Time
	LastUsed     time.Time
}

// Manager implements Network Address Translation
type Manager struct {
	*base.Module
	config *Config

	// Mappings: Protocol -> ExternalPort -> Mapping
	mappings   map[string]map[int]*Mapping
	mappingsMu sync.RWMutex

	// Stats
	activeMappings int64
	totalMappings  int64
	translations   int64
	errors         int64
}

// New creates a new NAT manager
func New(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	m := &Manager{
		Module:   base.NewModule(ModuleName, ModuleVersion, nil),
		config:   cfg,
		mappings: make(map[string]map[int]*Mapping),
	}

	return m, nil
}

// Init initializes the NAT manager
func (m *Manager) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := m.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if natCfg, ok := cfg.(*Config); ok {
		m.config = natCfg
	}

	return nil
}

// Start starts the NAT manager
func (m *Manager) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}

	// Start cleanup loop
	go m.cleanupLoop()

	m.SetHealthy(true, "NAT manager running")
	m.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"enabled":    m.config.Enabled,
		"port_range": fmt.Sprintf("%d-%d", m.config.PortRangeStart, m.config.PortRangeEnd),
	})

	return nil
}

// Stop stops the NAT manager
func (m *Manager) Stop() error {
	m.PublishEvent(events.EventTypeModuleStopped, nil)
	return m.Module.Stop()
}

// AddMapping adds a NAT mapping
func (m *Manager) AddMapping(internalIP net.IP, internalPort int, protocol string) (int, error) {
	if !m.config.Enabled {
		return 0, fmt.Errorf("NAT disabled")
	}

	m.mappingsMu.Lock()
	defer m.mappingsMu.Unlock()

	// Ensure protocol map exists
	if _, ok := m.mappings[protocol]; !ok {
		m.mappings[protocol] = make(map[int]*Mapping)
	}

	// Check if already exists (simplified: usually we check 5-tuple, but here we do port mapping)
	for _, mapping := range m.mappings[protocol] {
		if mapping.InternalIP.Equal(internalIP) && mapping.InternalPort == internalPort {
			mapping.LastUsed = time.Now()
			return mapping.ExternalPort, nil
		}
	}

	// Allocate new port
	externalPort, err := m.allocatePort(protocol)
	if err != nil {
		return 0, err
	}

	mapping := &Mapping{
		InternalIP:   internalIP,
		InternalPort: internalPort,
		ExternalPort: externalPort,
		Protocol:     protocol,
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
	}

	m.mappings[protocol][externalPort] = mapping
	atomic.AddInt64(&m.activeMappings, 1)
	atomic.AddInt64(&m.totalMappings, 1)

	return externalPort, nil
}

// RemoveMapping removes a NAT mapping
func (m *Manager) RemoveMapping(externalPort int, protocol string) error {
	m.mappingsMu.Lock()
	defer m.mappingsMu.Unlock()

	if protos, ok := m.mappings[protocol]; ok {
		if _, exists := protos[externalPort]; exists {
			delete(protos, externalPort)
			atomic.AddInt64(&m.activeMappings, -1)
			return nil
		}
	}

	return fmt.Errorf("mapping not found")
}

// GetMapping gets a NAT mapping
func (m *Manager) GetMapping(externalPort int, protocol string) (net.IP, int, bool) {
	m.mappingsMu.RLock()
	defer m.mappingsMu.RUnlock()

	if protos, ok := m.mappings[protocol]; ok {
		if mapping, exists := protos[externalPort]; exists {
			mapping.LastUsed = time.Now() // Update activity
			return mapping.InternalIP, mapping.InternalPort, true
		}
	}

	return nil, 0, false
}

// Translate translates an address (simulated for now)
func (m *Manager) Translate(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, protocol string) (net.IP, int) {
	atomic.AddInt64(&m.translations, 1)
	// In a full implementation, this would modify packet headers or return transparent proxy addr
	// For now, we mainly manage mappings.

	// Example reversed logic: if dst matches one of our external ports, return internal addr
	m.mappingsMu.RLock()
	defer m.mappingsMu.RUnlock()

	if protos, ok := m.mappings[protocol]; ok {
		if mapping, exists := protos[dstPort]; exists {
			return mapping.InternalIP, mapping.InternalPort
		}
	}

	// No translation needed/found
	return dstIP, dstPort
}

// allocatePort finds a free external port
func (m *Manager) allocatePort(protocol string) (int, error) {
	// Simple linear search for now. In high-load, use a bitmap or free list.
	protos, ok := m.mappings[protocol]
	if !ok {
		return m.config.PortRangeStart, nil
	}

	for port := m.config.PortRangeStart; port <= m.config.PortRangeEnd; port++ {
		if _, used := protos[port]; !used {
			return port, nil
		}
	}

	return 0, fmt.Errorf("no free ports in range")
}

// cleanupLoop removes expired mappings
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for m.IsRunning() {
		select {
		case <-m.Context().Done():
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

// cleanup removes expired mappings
func (m *Manager) cleanup() {
	m.mappingsMu.Lock()
	defer m.mappingsMu.Unlock()

	timeout := m.config.MappingTimeout
	now := time.Now()

	for proto, ports := range m.mappings {
		for port, mapping := range ports {
			if now.Sub(mapping.LastUsed) > timeout {
				delete(ports, port)
				atomic.AddInt64(&m.activeMappings, -1)
			}
		}
		if len(ports) == 0 {
			delete(m.mappings, proto)
		}
	}
}

// HealthCheck returns health status
func (m *Manager) HealthCheck() interfaces.HealthStatus {
	status := m.Module.HealthCheck()

	status.Details["active_mappings"] = atomic.LoadInt64(&m.activeMappings)
	status.Details["total_mappings"] = atomic.LoadInt64(&m.totalMappings)
	status.Details["translations"] = atomic.LoadInt64(&m.translations)
	status.Details["errors"] = atomic.LoadInt64(&m.errors)

	return status
}

// Factory creates NAT manager modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
