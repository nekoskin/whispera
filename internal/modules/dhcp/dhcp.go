// Package dhcp provides DHCP-like IP pool management for VPN clients
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

// Config holds DHCP configuration
type Config struct {
	Enabled       bool          `json:"enabled" yaml:"enabled"`
	SubnetCIDR    string        `json:"subnet_cidr" yaml:"subnet_cidr"`       // e.g., "10.8.0.0/24"
	LeaseTime     time.Duration `json:"lease_time" yaml:"lease_time"`         // Default 24h
	DNSServers    []string      `json:"dns_servers" yaml:"dns_servers"`       // DNS servers to push
	Gateway       string        `json:"gateway" yaml:"gateway"`               // Gateway IP (usually .1)
	DomainSuffix  string        `json:"domain_suffix" yaml:"domain_suffix"`   // e.g., "vpn.local"
	PushRoutes    []string      `json:"push_routes" yaml:"push_routes"`       // Routes to push
	FullTunneling bool          `json:"full_tunneling" yaml:"full_tunneling"` // Route all traffic
}

// DefaultConfig returns default DHCP configuration
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

// Validate validates the configuration
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

// Lease represents an IP lease for a client
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

// IsExpired checks if the lease has expired
func (l *Lease) IsExpired() bool {
	return time.Now().After(l.ExpiresAt)
}

// TimeRemaining returns time remaining on lease
func (l *Lease) TimeRemaining() time.Duration {
	remaining := time.Until(l.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ClientParams holds network parameters to push to client
type ClientParams struct {
	AssignedIP   net.IP   `json:"assigned_ip"`
	SubnetMask   net.IP   `json:"subnet_mask"`
	Gateway      net.IP   `json:"gateway"`
	DNSServers   []net.IP `json:"dns_servers"`
	DomainSuffix string   `json:"domain_suffix,omitempty"`
	Routes       []Route  `json:"routes,omitempty"`
	LeaseTime    int64    `json:"lease_time_seconds"`
}

// Route represents a route to push to client
type Route struct {
	Network string `json:"network"` // CIDR notation
	Gateway string `json:"gateway,omitempty"`
}

// Manager implements DHCP-like IP pool management
type Manager struct {
	*base.Module
	config *Config

	// IP pool
	pool *IPPool

	// Active leases: IP string -> Lease
	leasesMu sync.RWMutex
	leases   map[string]*Lease

	// Client to IP mapping
	clientToIP map[string]string

	// Parsed config values
	gateway    net.IP
	dnsServers []net.IP
	subnetMask net.IP

	log *logger.Logger
}

// New creates a new DHCP manager
func New(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Create IP pool
	pool, err := NewIPPool(cfg.SubnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to create IP pool: %w", err)
	}

	// Parse gateway
	gateway := net.ParseIP(cfg.Gateway)
	if gateway == nil {
		// Default to first usable IP + 1
		gateway = pool.Gateway()
	}

	// Reserve gateway
	pool.Reserve(gateway)

	// Parse DNS servers
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

// Init initializes the DHCP manager
func (m *Manager) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := m.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if dhcpCfg, ok := cfg.(*Config); ok {
		m.config = dhcpCfg
	}

	return nil
}

// Start starts the DHCP manager
func (m *Manager) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}

	if !m.config.Enabled {
		m.SetHealthy(true, "DHCP disabled")
		return nil
	}

	// Start lease cleanup goroutine
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

// Stop stops the DHCP manager
func (m *Manager) Stop() error {
	m.PublishEvent(events.EventTypeModuleStopped, nil)
	m.log.Info("DHCP manager stopped")
	return m.Module.Stop()
}

// AllocateIP allocates an IP address for a client
func (m *Manager) AllocateIP(clientID string) (*Lease, error) {
	if !m.config.Enabled {
		return nil, fmt.Errorf("DHCP disabled")
	}

	m.leasesMu.Lock()
	defer m.leasesMu.Unlock()

	// Check if client already has a lease
	if existingIP, ok := m.clientToIP[clientID]; ok {
		if lease, ok := m.leases[existingIP]; ok {
			// Renew existing lease
			lease.LastRenewed = time.Now()
			lease.ExpiresAt = time.Now().Add(m.config.LeaseTime)
			m.log.Info("Renewed lease for client %s: IP=%s", clientID, lease.IP)
			return lease, nil
		}
	}

	// Allocate new IP
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

// ReleaseIP releases an IP address
func (m *Manager) ReleaseIP(ip net.IP) error {
	m.leasesMu.Lock()
	defer m.leasesMu.Unlock()

	ipStr := ip.String()
	lease, ok := m.leases[ipStr]
	if !ok {
		return fmt.Errorf("no lease found for IP %s", ipStr)
	}

	// Remove from maps
	delete(m.leases, ipStr)
	delete(m.clientToIP, lease.ClientID)

	// Return to pool
	m.pool.Release(ip)

	m.log.Info("Released IP %s from client %s", ip, lease.ClientID)

	return nil
}

// ReleaseByClient releases IP by client ID
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

// RenewLease renews a lease
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

// GetClientParams returns network parameters for a client
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

	// Add routes
	if m.config.FullTunneling {
		params.Routes = []Route{{Network: "0.0.0.0/0"}}
	} else {
		for _, r := range m.config.PushRoutes {
			params.Routes = append(params.Routes, Route{Network: r})
		}
	}

	return params, nil
}

// GetLease returns a lease by IP
func (m *Manager) GetLease(ip net.IP) *Lease {
	m.leasesMu.RLock()
	defer m.leasesMu.RUnlock()

	if lease, ok := m.leases[ip.String()]; ok {
		copy := *lease
		return &copy
	}
	return nil
}

// GetLeaseByClient returns a lease by client ID
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

// GetAllLeases returns all active leases
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

// GetStats returns DHCP statistics
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

// leaseCleanupLoop periodically cleans up expired leases
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

// cleanupExpiredLeases removes expired leases
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

// HealthCheck returns health status
func (m *Manager) HealthCheck() interfaces.HealthStatus {
	status := m.Module.HealthCheck()

	m.leasesMu.RLock()
	status.Details["active_leases"] = len(m.leases)
	status.Details["available_ips"] = m.pool.AvailableCount()
	status.Details["used_ips"] = m.pool.UsedCount()
	m.leasesMu.RUnlock()

	return status
}

// Factory creates DHCP manager modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
