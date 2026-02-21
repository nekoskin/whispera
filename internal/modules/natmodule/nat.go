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

type Config struct {
	Enabled        bool
	PortRangeStart int
	PortRangeEnd   int
	MappingTimeout time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		Enabled:        true,
		PortRangeStart: 10000,
		PortRangeEnd:   60000,
		MappingTimeout: DefaultMappingTimeout,
	}
}

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

type Mapping struct {
	InternalIP   net.IP
	InternalPort int
	ExternalPort int
	Protocol     string
	CreatedAt    time.Time
	LastUsed     time.Time
}

type Manager struct {
	*base.Module
	config *Config
	mappings   map[string]map[int]*Mapping
	mappingsMu sync.RWMutex

	// Stats
	activeMappings int64
	totalMappings  int64
	translations   int64
	errors         int64
}

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

func (m *Manager) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := m.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if natCfg, ok := cfg.(*Config); ok {
		m.config = natCfg
	}

	return nil
}

func (m *Manager) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}

	go m.cleanupLoop()

	m.SetHealthy(true, "NAT manager running")
	m.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"enabled":    m.config.Enabled,
		"port_range": fmt.Sprintf("%d-%d", m.config.PortRangeStart, m.config.PortRangeEnd),
	})

	return nil
}

func (m *Manager) Stop() error {
	m.PublishEvent(events.EventTypeModuleStopped, nil)
	return m.Module.Stop()
}

func (m *Manager) AddMapping(internalIP net.IP, internalPort int, protocol string) (int, error) {
	if !m.config.Enabled {
		return 0, fmt.Errorf("NAT disabled")
	}

	m.mappingsMu.Lock()
	defer m.mappingsMu.Unlock()

	if _, ok := m.mappings[protocol]; !ok {
		m.mappings[protocol] = make(map[int]*Mapping)
	}
	for _, mapping := range m.mappings[protocol] {
		if mapping.InternalIP.Equal(internalIP) && mapping.InternalPort == internalPort {
			mapping.LastUsed = time.Now()
			return mapping.ExternalPort, nil
		}
	}

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

func (m *Manager) Translate(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, protocol string) (net.IP, int) {
	atomic.AddInt64(&m.translations, 1)

	m.mappingsMu.RLock()
	defer m.mappingsMu.RUnlock()

	if protos, ok := m.mappings[protocol]; ok {
		if mapping, exists := protos[dstPort]; exists {
			return mapping.InternalIP, mapping.InternalPort
		}
	}

	return dstIP, dstPort
}

func (m *Manager) allocatePort(protocol string) (int, error) {
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

func (m *Manager) HealthCheck() interfaces.HealthStatus {
	status := m.Module.HealthCheck()

	status.Details["active_mappings"] = atomic.LoadInt64(&m.activeMappings)
	status.Details["total_mappings"] = atomic.LoadInt64(&m.totalMappings)
	status.Details["translations"] = atomic.LoadInt64(&m.translations)
	status.Details["errors"] = atomic.LoadInt64(&m.errors)

	return status
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
