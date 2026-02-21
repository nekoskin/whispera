package dhcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

type IPPool struct {
	mu sync.Mutex

	network   *net.IPNet
	networkIP net.IP
	broadcast net.IP

	usedIPs     map[string]bool
	reservedIPs map[string]bool

	nextIP uint32

	firstIP uint32
	lastIP  uint32
}

func NewIPPool(cidr string) (*IPPool, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	networkIP := ip.Mask(network.Mask)

	broadcast := make(net.IP, len(networkIP))
	for i := range networkIP {
		broadcast[i] = networkIP[i] | ^network.Mask[i]
	}

	networkUint := ipToUint32(networkIP)
	broadcastUint := ipToUint32(broadcast)
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

	pool.reservedIPs[networkIP.String()] = true
	pool.reservedIPs[broadcast.String()] = true

	return pool, nil
}

func (p *IPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	startIP := p.nextIP
	for {
		ip := uint32ToIP(p.nextIP)
		ipStr := ip.String()

		if !p.usedIPs[ipStr] && !p.reservedIPs[ipStr] {
			p.usedIPs[ipStr] = true
			p.nextIP = p.wrapIP(p.nextIP + 1)
			return ip, nil
		}
		p.nextIP = p.wrapIP(p.nextIP + 1)

		if p.nextIP == startIP {
			return nil, fmt.Errorf("no available IPs in pool")
		}
	}
}

func (p *IPPool) AllocateSpecific(ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ipStr := ip.String()

	ipUint := ipToUint32(ip)
	if ipUint < p.firstIP || ipUint > p.lastIP {
		return fmt.Errorf("IP %s is not in pool range", ipStr)
	}

	if p.usedIPs[ipStr] {
		return fmt.Errorf("IP %s is already in use", ipStr)
	}
	if p.reservedIPs[ipStr] {
		return fmt.Errorf("IP %s is reserved", ipStr)
	}

	p.usedIPs[ipStr] = true
	return nil
}

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

func (p *IPPool) Reserve(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.reservedIPs[ip.String()] = true
}

func (p *IPPool) Unreserve(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.reservedIPs, ip.String())
}

func (p *IPPool) IsAvailable(ip net.IP) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	ipStr := ip.String()
	return !p.usedIPs[ipStr] && !p.reservedIPs[ipStr]
}

func (p *IPPool) IsInRange(ip net.IP) bool {
	ipUint := ipToUint32(ip)
	return ipUint >= p.firstIP && ipUint <= p.lastIP
}

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

func (p *IPPool) UsedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.usedIPs)
}

func (p *IPPool) TotalCount() int {
	return int(p.lastIP - p.firstIP + 1)
}
func (p *IPPool) Gateway() net.IP {
	return uint32ToIP(p.firstIP)
}

func (p *IPPool) SubnetMask() net.IP {
	ones, bits := p.network.Mask.Size()
	mask := net.CIDRMask(ones, bits)
	return net.IP(mask)
}
func (p *IPPool) Network() *net.IPNet {
	return p.network
}
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

func (p *IPPool) wrapIP(ip uint32) uint32 {
	if ip > p.lastIP {
		return p.firstIP
	}
	return ip
}

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
