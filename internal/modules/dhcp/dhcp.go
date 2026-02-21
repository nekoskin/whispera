package dhcp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/logger"
)

const (
	ModuleName    = "dhcp.manager"
	ModuleVersion = "1.0.0"
)

type Config struct {
	Enabled       bool          `json:"enabled" yaml:"enabled"`
	SubnetCIDR    string        `json:"subnet_cidr" yaml:"subnet_cidr"`       
	LeaseTime     time.Duration `json:"lease_time" yaml:"lease_time"`         
	DNSServers    []string      `json:"dns_servers" yaml:"dns_servers"`       
	Gateway       string        `json:"gateway" yaml:"gateway"`               
	DomainSuffix  string        `json:"domain_suffix" yaml:"domain_suffix"`   
	PushRoutes    []string      `json:"push_routes" yaml:"push_routes"`       
	FullTunneling bool          `json:"full_tunneling" yaml:"full_tunneling"` 
}

func DefaultConfig() *Config {
	return &Config{
		Enabled:       true,
		SubnetCIDR:    "10.8.0.0/24",
		LeaseTime:     24 * time.Hour,
		DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
		Gateway:       "10.8.0.1",
		PushRoutes:    []string{},
		FullTunneling: true,
	}
}

func (c *Config) Validate() error {
	if c.SubnetCIDR == "" {
		c.SubnetCIDR = "10.8.0.0/24"
	}

	_, _, err := net.ParseCIDR(c.SubnetCIDR)
	if err != nil {
		return fmt.Errorf("invalid subnet CIDR: %w", err)
	}

	if c.LeaseTime <= 0 {
		c.LeaseTime = 24 * time.Hour
	}

	if len(c.DNSServers) == 0 {
		c.DNSServers = []string{"8.8.8.8", "8.8.4.4"}
	}

	return nil
}

type Lease struct {
	IP          net.IP                 `json:"ip"`
	ClientID    string                 `json:"client_id"`
	SessionID   uint32                 `json:"session_id,omitempty"`
	Hostname    string                 `json:"hostname,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	LastRenewed time.Time              `json:"last_renewed"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func (l *Lease) IsExpired() bool {
	return time.Now().After(l.ExpiresAt)
}
func (l *Lease) TimeRemaining() time.Duration {
	remaining := time.Until(l.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

type ClientParams struct {
	AssignedIP   net.IP   `json:"assigned_ip"`
	SubnetMask   net.IP   `json:"subnet_mask"`
	Gateway      net.IP   `json:"gateway"`
	DNSServers   []net.IP `json:"dns_servers"`
	DomainSuffix string   `json:"domain_suffix,omitempty"`
	Routes       []Route  `json:"routes,omitempty"`
	LeaseTime    int64    `json:"lease_time_seconds"`
}

type Route struct {
	Network string `json:"network"`
	Gateway string `json:"gateway,omitempty"`
}

type Manager struct {
	*base.Module
	config *Config

	pool *IPPool

	leasesMu sync.RWMutex
	leases   map[string]*Lease

	clientToIP map[string]string

	gateway    net.IP
	dnsServers []net.IP
	subnetMask net.IP

	log *logger.Logger
}

func New(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	pool, err := NewIPPool(cfg.SubnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to create IP pool: %w", err)
	}
	gateway := net.ParseIP(cfg.Gateway)
	if gateway == nil {
		gateway = pool.Gateway()
	}

	pool.Reserve(gateway)

	var dnsServers []net.IP
	for _, dns := range cfg.DNSServers {
		if ip := net.ParseIP(dns); ip != nil {
			dnsServers = append(dnsServers, ip)
		}
	}

	m := &Manager{
		Module:     base.NewModule(ModuleName, ModuleVersion, nil),
		config:     cfg,
		pool:       pool,
		leases:     make(map[string]*Lease),
		clientToIP: make(map[string]string),
		gateway:    gateway,
		dnsServers: dnsServers,
		subnetMask: pool.SubnetMask(),
		log:        logger.Module("dhcp"),
	}

	return m, nil
}

func (m *Manager) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := m.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if dhcpCfg, ok := cfg.(*Config); ok {
		m.config = dhcpCfg
	}

	return nil
}

func (m *Manager) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}

	if !m.config.Enabled {
		m.SetHealthy(true, "DHCP disabled")
		return nil
	}

	go m.leaseCleanupLoop()

	m.SetHealthy(true, "DHCP manager running")
	m.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"subnet":     m.config.SubnetCIDR,
		"pool_size":  m.pool.AvailableCount(),
		"lease_time": m.config.LeaseTime.String(),
	})

	m.log.Info("DHCP manager started: subnet=%s available=%d",
		m.config.SubnetCIDR, m.pool.AvailableCount())

	return nil
}

func (m *Manager) Stop() error {
	m.PublishEvent(events.EventTypeModuleStopped, nil)
	m.log.Info("DHCP manager stopped")
	return m.Module.Stop()
}

func (m *Manager) AllocateIP(clientID string) (*Lease, error) {
	if !m.config.Enabled {
		return nil, fmt.Errorf("DHCP disabled")
	}

	m.leasesMu.Lock()
	defer m.leasesMu.Unlock()

	if existingIP, ok := m.clientToIP[clientID]; ok {
		if lease, ok := m.leases[existingIP]; ok {
			lease.LastRenewed = time.Now()
			lease.ExpiresAt = time.Now().Add(m.config.LeaseTime)
			m.log.Info("Renewed lease for client %s: IP=%s", clientID, lease.IP)
			return lease, nil
		}
	}

	ip, err := m.pool.Allocate()
	if err != nil {
		m.log.Error("Failed to allocate IP for client %s: %v", clientID, err)
		return nil, err
	}

	now := time.Now()
	lease := &Lease{
		IP:          ip,
		ClientID:    clientID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(m.config.LeaseTime),
		LastRenewed: now,
		Metadata:    make(map[string]interface{}),
	}

	ipStr := ip.String()
	m.leases[ipStr] = lease
	m.clientToIP[clientID] = ipStr

	m.log.Info("Allocated IP %s to client %s (lease: %s)", ip, clientID, m.config.LeaseTime)

	return lease, nil
}

func (m *Manager) ReleaseIP(ip net.IP) error {
	m.leasesMu.Lock()
	defer m.leasesMu.Unlock()

	ipStr := ip.String()
	lease, ok := m.leases[ipStr]
	if !ok {
		return fmt.Errorf("no lease found for IP %s", ipStr)
	}

	delete(m.leases, ipStr)
	delete(m.clientToIP, lease.ClientID)

	m.pool.Release(ip)

	m.log.Info("Released IP %s from client %s", ip, lease.ClientID)

	return nil
}

func (m *Manager) ReleaseByClient(clientID string) error {
	m.leasesMu.Lock()
	defer m.leasesMu.Unlock()

	ipStr, ok := m.clientToIP[clientID]
	if !ok {
		return fmt.Errorf("no lease found for client %s", clientID)
	}

	lease := m.leases[ipStr]
	if lease != nil {
		m.pool.Release(lease.IP)
	}

	delete(m.leases, ipStr)
	delete(m.clientToIP, clientID)

	m.log.Info("Released IP %s from client %s", ipStr, clientID)

	return nil
}

func (m *Manager) RenewLease(ip net.IP) error {
	m.leasesMu.Lock()
	defer m.leasesMu.Unlock()

	ipStr := ip.String()
	lease, ok := m.leases[ipStr]
	if !ok {
		return fmt.Errorf("no lease found for IP %s", ipStr)
	}

	lease.LastRenewed = time.Now()
	lease.ExpiresAt = time.Now().Add(m.config.LeaseTime)

	m.log.Debug("Renewed lease for IP %s (new expiry: %s)", ip, lease.ExpiresAt)

	return nil
}

func (m *Manager) GetClientParams(clientID string) (*ClientParams, error) {
	m.leasesMu.RLock()
	defer m.leasesMu.RUnlock()

	ipStr, ok := m.clientToIP[clientID]
	if !ok {
		return nil, fmt.Errorf("no lease found for client %s", clientID)
	}

	lease := m.leases[ipStr]
	if lease == nil {
		return nil, fmt.Errorf("lease data missing for client %s", clientID)
	}

	params := &ClientParams{
		AssignedIP:   lease.IP,
		SubnetMask:   m.subnetMask,
		Gateway:      m.gateway,
		DNSServers:   m.dnsServers,
		DomainSuffix: m.config.DomainSuffix,
		LeaseTime:    int64(m.config.LeaseTime.Seconds()),
	}

	if m.config.FullTunneling {
		params.Routes = []Route{{Network: "0.0.0.0/0"}}
	} else {
		for _, r := range m.config.PushRoutes {
			params.Routes = append(params.Routes, Route{Network: r})
		}
	}

	return params, nil
}

func (m *Manager) GetLease(ip net.IP) *Lease {
	m.leasesMu.RLock()
	defer m.leasesMu.RUnlock()

	if lease, ok := m.leases[ip.String()]; ok {
		copy := *lease
		return &copy
	}
	return nil
}

func (m *Manager) GetLeaseByClient(clientID string) *Lease {
	m.leasesMu.RLock()
	defer m.leasesMu.RUnlock()

	if ipStr, ok := m.clientToIP[clientID]; ok {
		if lease, ok := m.leases[ipStr]; ok {
			copy := *lease
			return &copy
		}
	}
	return nil
}

func (m *Manager) GetAllLeases() []*Lease {
	m.leasesMu.RLock()
	defer m.leasesMu.RUnlock()

	result := make([]*Lease, 0, len(m.leases))
	for _, lease := range m.leases {
		copy := *lease
		result = append(result, &copy)
	}
	return result
}

func (m *Manager) GetStats() map[string]interface{} {
	m.leasesMu.RLock()
	defer m.leasesMu.RUnlock()

	return map[string]interface{}{
		"enabled":        m.config.Enabled,
		"subnet":         m.config.SubnetCIDR,
		"total_ips":      m.pool.TotalCount(),
		"available_ips":  m.pool.AvailableCount(),
		"used_ips":       m.pool.UsedCount(),
		"active_leases":  len(m.leases),
		"lease_time":     m.config.LeaseTime.String(),
		"dns_servers":    m.config.DNSServers,
		"full_tunneling": m.config.FullTunneling,
	}
}

func (m *Manager) leaseCleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for m.IsRunning() {
		select {
		case <-m.Context().Done():
			return
		case <-ticker.C:
			m.cleanupExpiredLeases()
		}
	}
}

func (m *Manager) cleanupExpiredLeases() {
	m.leasesMu.Lock()
	defer m.leasesMu.Unlock()

	var expiredCount int
	for ipStr, lease := range m.leases {
		if lease.IsExpired() {
			m.pool.Release(lease.IP)
			delete(m.leases, ipStr)
			delete(m.clientToIP, lease.ClientID)
			expiredCount++
			m.log.Info("Expired lease for client %s (IP=%s)", lease.ClientID, ipStr)
		}
	}

	if expiredCount > 0 {
		m.log.Info("Cleaned up %d expired leases", expiredCount)
	}
}

func (m *Manager) HealthCheck() interfaces.HealthStatus {
	status := m.Module.HealthCheck()

	m.leasesMu.RLock()
	status.Details["active_leases"] = len(m.leases)
	status.Details["available_ips"] = m.pool.AvailableCount()
	status.Details["used_ips"] = m.pool.UsedCount()
	m.leasesMu.RUnlock()

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
