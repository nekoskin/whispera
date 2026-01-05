// Package dns provides DNS resolution with DoH/DoT support
package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ResolverType defines the type of DNS resolver
type ResolverType string

const (
	ResolverTypeSystem ResolverType = "system" // System resolver
	ResolverTypeUDP    ResolverType = "udp"    // Plain UDP DNS
	ResolverTypeDoH    ResolverType = "doh"    // DNS over HTTPS
	ResolverTypeDoT    ResolverType = "dot"    // DNS over TLS
)

// Config holds resolver configuration
type Config struct {
	Type      ResolverType
	Servers   []string // DNS server addresses
	Timeout   time.Duration
	CacheSize int
	CacheTTL  time.Duration
	// DoH specific
	DoHPath string // Usually "/dns-query"
	// DoT specific
	DoTPort    int    // Usually 853
	ServerName string // For TLS SNI
}

// DefaultConfig returns default DNS configuration
func DefaultConfig() *Config {
	return &Config{
		Type:      ResolverTypeDoH,
		Servers:   []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"},
		Timeout:   5 * time.Second,
		CacheSize: 10000,
		CacheTTL:  5 * time.Minute,
		DoHPath:   "/dns-query",
		DoTPort:   853,
	}
}

// CacheEntry represents a cached DNS record
type CacheEntry struct {
	IPs       []net.IP
	ExpiresAt time.Time
}

// Resolver handles DNS resolution
type Resolver struct {
	config  *Config
	cache   map[string]*CacheEntry
	cacheMu sync.RWMutex
	client  *http.Client

	// Stats
	queries   uint64
	cacheHits uint64
	cacheMiss uint64
}

// NewResolver creates a new DNS resolver
func NewResolver(cfg *Config) *Resolver {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	r := &Resolver{
		config: cfg,
		cache:  make(map[string]*CacheEntry),
		client: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					ServerName: cfg.ServerName,
				},
			},
		},
	}

	// Start cache cleanup
	go r.cacheCleanup()

	return r
}

// Resolve resolves a hostname to IP addresses
func (r *Resolver) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	atomic.AddUint64(&r.queries, 1)

	// Check if already IP
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	// Check cache
	if ips := r.getFromCache(host); ips != nil {
		atomic.AddUint64(&r.cacheHits, 1)
		return ips, nil
	}
	atomic.AddUint64(&r.cacheMiss, 1)

	// Resolve based on type
	var ips []net.IP
	var err error

	switch r.config.Type {
	case ResolverTypeSystem:
		ips, err = r.resolveSystem(ctx, host)
	case ResolverTypeUDP:
		ips, err = r.resolveUDP(ctx, host)
	case ResolverTypeDoH:
		ips, err = r.resolveDoH(ctx, host)
	case ResolverTypeDoT:
		ips, err = r.resolveDoT(ctx, host)
	default:
		ips, err = r.resolveSystem(ctx, host)
	}

	if err != nil {
		return nil, err
	}

	// Cache result
	r.putToCache(host, ips)

	return ips, nil
}

// resolveSystem uses system DNS
func (r *Resolver) resolveSystem(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, len(addrs))
	for i, addr := range addrs {
		ips[i] = addr.IP
	}
	return ips, nil
}

// resolveUDP uses plain UDP DNS
func (r *Resolver) resolveUDP(ctx context.Context, host string) ([]net.IP, error) {
	if len(r.config.Servers) == 0 {
		return nil, errors.New("no DNS servers configured")
	}

	// Build DNS query
	query := buildDNSQuery(host, 1) // Type A

	server := r.config.Servers[0]
	if !strings.Contains(server, ":") {
		server += ":53"
	}

	conn, err := net.DialTimeout("udp", server, r.config.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(r.config.Timeout))

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	return parseDNSResponse(response[:n])
}

// resolveDoH uses DNS over HTTPS
func (r *Resolver) resolveDoH(ctx context.Context, host string) ([]net.IP, error) {
	if len(r.config.Servers) == 0 {
		return nil, errors.New("no DoH servers configured")
	}

	query := buildDNSQuery(host, 1) // Type A

	for _, server := range r.config.Servers {
		ips, err := r.doHQuery(ctx, server, query)
		if err == nil {
			return ips, nil
		}
	}

	return nil, errors.New("all DoH servers failed")
}

func (r *Resolver) doHQuery(ctx context.Context, server string, query []byte) ([]net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", server, strings.NewReader(string(query)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseDNSResponse(body)
}

// resolveDoT uses DNS over TLS
func (r *Resolver) resolveDoT(ctx context.Context, host string) ([]net.IP, error) {
	if len(r.config.Servers) == 0 {
		return nil, errors.New("no DoT servers configured")
	}

	query := buildDNSQuery(host, 1) // Type A

	for _, server := range r.config.Servers {
		ips, err := r.doTQuery(ctx, server, query)
		if err == nil {
			return ips, nil
		}
	}

	return nil, errors.New("all DoT servers failed")
}

func (r *Resolver) doTQuery(ctx context.Context, server string, query []byte) ([]net.IP, error) {
	// Strip protocol prefix if present
	server = strings.TrimPrefix(server, "tls://")

	port := r.config.DoTPort
	if port == 0 {
		port = 853
	}
	if !strings.Contains(server, ":") {
		server = fmt.Sprintf("%s:%d", server, port)
	}

	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName: r.config.ServerName,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(r.config.Timeout))

	// DNS over TLS uses length-prefixed messages
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(query)))

	if _, err := conn.Write(lenBuf); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	// Read response length
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(lenBuf)

	// Read response
	response := make([]byte, respLen)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}

	return parseDNSResponse(response)
}

// getFromCache retrieves cached entry
func (r *Resolver) getFromCache(host string) []net.IP {
	r.cacheMu.RLock()
	entry, ok := r.cache[strings.ToLower(host)]
	r.cacheMu.RUnlock()

	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil
	}
	return entry.IPs
}

// putToCache stores entry in cache
func (r *Resolver) putToCache(host string, ips []net.IP) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	// Enforce cache size limit
	if len(r.cache) >= r.config.CacheSize {
		// Remove oldest entry
		var oldestKey string
		var oldestTime time.Time
		for k, v := range r.cache {
			if oldestKey == "" || v.ExpiresAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.ExpiresAt
			}
		}
		delete(r.cache, oldestKey)
	}

	r.cache[strings.ToLower(host)] = &CacheEntry{
		IPs:       ips,
		ExpiresAt: time.Now().Add(r.config.CacheTTL),
	}
}

// cacheCleanup periodically removes expired entries
func (r *Resolver) cacheCleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		r.cacheMu.Lock()
		now := time.Now()
		for k, v := range r.cache {
			if now.After(v.ExpiresAt) {
				delete(r.cache, k)
			}
		}
		r.cacheMu.Unlock()
	}
}

// Stats returns resolver statistics
func (r *Resolver) Stats() (queries, hits, misses uint64) {
	return atomic.LoadUint64(&r.queries),
		atomic.LoadUint64(&r.cacheHits),
		atomic.LoadUint64(&r.cacheMiss)
}

// ClearCache clears the DNS cache
func (r *Resolver) ClearCache() {
	r.cacheMu.Lock()
	r.cache = make(map[string]*CacheEntry)
	r.cacheMu.Unlock()
}

// buildDNSQuery builds a simple DNS query
func buildDNSQuery(host string, qtype uint16) []byte {
	// Simple DNS query builder
	buf := make([]byte, 0, 512)

	// Header
	buf = append(buf, 0xAB, 0xCD) // Transaction ID
	buf = append(buf, 0x01, 0x00) // Flags: standard query
	buf = append(buf, 0x00, 0x01) // Questions: 1
	buf = append(buf, 0x00, 0x00) // Answer RRs: 0
	buf = append(buf, 0x00, 0x00) // Authority RRs: 0
	buf = append(buf, 0x00, 0x00) // Additional RRs: 0

	// Question
	parts := strings.Split(host, ".")
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00) // End of name

	// Type and Class
	buf = append(buf, byte(qtype>>8), byte(qtype)) // Type A
	buf = append(buf, 0x00, 0x01)                  // Class IN

	return buf
}

// parseDNSResponse parses DNS response and extracts IPs
func parseDNSResponse(response []byte) ([]net.IP, error) {
	if len(response) < 12 {
		return nil, errors.New("response too short")
	}

	// Check response code
	rcode := response[3] & 0x0F
	if rcode != 0 {
		return nil, fmt.Errorf("DNS error code: %d", rcode)
	}

	// Get answer count
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return nil, errors.New("no answers in response")
	}

	// Skip header and question section
	offset := 12

	// Skip question
	for offset < len(response) && response[offset] != 0 {
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
			break
		}
		offset += int(response[offset]) + 1
	}
	if offset < len(response) && response[offset] == 0 {
		offset++
	}
	offset += 4 // Type and Class

	// Parse answers
	var ips []net.IP
	for i := 0; i < int(ancount) && offset < len(response); i++ {
		// Skip name (may be compressed)
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}

		if offset+10 > len(response) {
			break
		}

		// Parse record
		rtype := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8 // Type, Class, TTL
		rdlength := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2

		if offset+int(rdlength) > len(response) {
			break
		}

		// Type A (IPv4)
		if rtype == 1 && rdlength == 4 {
			ip := net.IP(response[offset : offset+4])
			ips = append(ips, ip)
		}
		// Type AAAA (IPv6)
		if rtype == 28 && rdlength == 16 {
			ip := net.IP(response[offset : offset+16])
			ips = append(ips, ip)
		}

		offset += int(rdlength)
	}

	if len(ips) == 0 {
		return nil, errors.New("no IP addresses found")
	}

	return ips, nil
}
