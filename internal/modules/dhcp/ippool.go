// Package dhcp provides DHCP-like IP pool management for VPN clients
package dhcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// IPPool manages a pool of IP addresses
type IPPool struct {
	mu sync.Mutex

	// Network configuration
	network   *net.IPNet
	networkIP net.IP
	broadcast net.IP

	// IP tracking
	usedIPs     map[string]bool // IPs currently in use
	reservedIPs map[string]bool // Reserved IPs (gateway, broadcast, etc.)

	// Allocation cursor (for round-robin)
	nextIP uint32

	// Pool bounds
	firstIP uint32
	lastIP  uint32
}

// NewIPPool creates a new IP pool from a CIDR notation
func NewIPPool(cidr string) (*IPPool, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	// Get network address
	networkIP := ip.Mask(network.Mask)

	// Calculate broadcast address
	broadcast := make(net.IP, len(networkIP))
	for i := range networkIP {
		broadcast[i] = networkIP[i] | ^network.Mask[i]
	}

	// Convert to uint32 for easier manipulation
	networkUint := ipToUint32(networkIP)
	broadcastUint := ipToUint32(broadcast)

	// First usable IP is network + 1, last is broadcast - 1
	firstIP := networkUint + 1
	lastIP := broadcastUint - 1

	if firstIP >= lastIP {
		return nil, fmt.Errorf("subnet too small for IP pool")
	}

	pool := &IPPool{
		network:     network,
		networkIP:   networkIP,
		broadcast:   broadcast,
		usedIPs:     make(map[string]bool),
		reservedIPs: make(map[string]bool),
		firstIP:     firstIP,
		lastIP:      lastIP,
		nextIP:      firstIP,
	}

	// Reserve network and broadcast addresses
	pool.reservedIPs[networkIP.String()] = true
	pool.reservedIPs[broadcast.String()] = true

	return pool, nil
}

// Allocate allocates the next available IP address
func (p *IPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try to find an available IP starting from nextIP
	startIP := p.nextIP
	for {
		ip := uint32ToIP(p.nextIP)
		ipStr := ip.String()

		// Check if available
		if !p.usedIPs[ipStr] && !p.reservedIPs[ipStr] {
			p.usedIPs[ipStr] = true
			p.nextIP = p.wrapIP(p.nextIP + 1)
			return ip, nil
		}

		// Move to next
		p.nextIP = p.wrapIP(p.nextIP + 1)

		// If we've wrapped around, no IPs available
		if p.nextIP == startIP {
			return nil, fmt.Errorf("no available IPs in pool")
		}
	}
}

// AllocateSpecific tries to allocate a specific IP address
func (p *IPPool) AllocateSpecific(ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ipStr := ip.String()

	// Check if in range
	ipUint := ipToUint32(ip)
	if ipUint < p.firstIP || ipUint > p.lastIP {
		return fmt.Errorf("IP %s is not in pool range", ipStr)
	}

	// Check if available
	if p.usedIPs[ipStr] {
		return fmt.Errorf("IP %s is already in use", ipStr)
	}
	if p.reservedIPs[ipStr] {
		return fmt.Errorf("IP %s is reserved", ipStr)
	}

	p.usedIPs[ipStr] = true
	return nil
}

// Release releases an IP address back to the pool
func (p *IPPool) Release(ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ipStr := ip.String()

	if !p.usedIPs[ipStr] {
		return fmt.Errorf("IP %s is not in use", ipStr)
	}

	delete(p.usedIPs, ipStr)
	return nil
}

// Reserve reserves an IP address (cannot be allocated)
func (p *IPPool) Reserve(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.reservedIPs[ip.String()] = true
}

// Unreserve removes a reservation
func (p *IPPool) Unreserve(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.reservedIPs, ip.String())
}

// IsAvailable checks if an IP is available
func (p *IPPool) IsAvailable(ip net.IP) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	ipStr := ip.String()
	return !p.usedIPs[ipStr] && !p.reservedIPs[ipStr]
}

// IsInRange checks if an IP is in the pool range
func (p *IPPool) IsInRange(ip net.IP) bool {
	ipUint := ipToUint32(ip)
	return ipUint >= p.firstIP && ipUint <= p.lastIP
}

// AvailableCount returns the number of available IPs
func (p *IPPool) AvailableCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	total := int(p.lastIP - p.firstIP + 1)
	used := len(p.usedIPs)
	reserved := len(p.reservedIPs)

	available := total - used - reserved
	if available < 0 {
		available = 0
	}
	return available
}

// UsedCount returns the number of IPs currently in use
func (p *IPPool) UsedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.usedIPs)
}

// TotalCount returns the total number of usable IPs
func (p *IPPool) TotalCount() int {
	return int(p.lastIP - p.firstIP + 1)
}

// Gateway returns the default gateway IP (first usable IP)
func (p *IPPool) Gateway() net.IP {
	return uint32ToIP(p.firstIP)
}

// SubnetMask returns the subnet mask as IP
func (p *IPPool) SubnetMask() net.IP {
	ones, bits := p.network.Mask.Size()
	mask := net.CIDRMask(ones, bits)
	// Convert IPMask to IP
	return net.IP(mask)
}

// Network returns the network address
func (p *IPPool) Network() *net.IPNet {
	return p.network
}

// GetUsedIPs returns a list of all used IPs
func (p *IPPool) GetUsedIPs() []net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := make([]net.IP, 0, len(p.usedIPs))
	for ipStr := range p.usedIPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			result = append(result, ip)
		}
	}
	return result
}

// GetReservedIPs returns a list of all reserved IPs
func (p *IPPool) GetReservedIPs() []net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := make([]net.IP, 0, len(p.reservedIPs))
	for ipStr := range p.reservedIPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			result = append(result, ip)
		}
	}
	return result
}

// wrapIP wraps the IP when it exceeds the range
func (p *IPPool) wrapIP(ip uint32) uint32 {
	if ip > p.lastIP {
		return p.firstIP
	}
	return ip
}

// ipToUint32 converts an IPv4 address to uint32
func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

// uint32ToIP converts uint32 to an IPv4 address
func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
