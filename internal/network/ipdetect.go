// Package network provides network utilities for Whispera
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IPDetector detects the server's external IP address
type IPDetector struct {
	mu         sync.RWMutex
	cachedIP   string
	lastCheck  time.Time
	cacheTTL   time.Duration
	httpClient *http.Client
}

// IPDetectConfig holds configuration for IP detection
type IPDetectConfig struct {
	CacheTTL       time.Duration // How long to cache the IP
	RequestTimeout time.Duration // Timeout for external service requests
	PreferIPv4     bool          // Prefer IPv4 over IPv6
}

// DefaultIPDetectConfig returns default configuration
func DefaultIPDetectConfig() *IPDetectConfig {
	return &IPDetectConfig{
		CacheTTL:       5 * time.Minute,
		RequestTimeout: 10 * time.Second,
		PreferIPv4:     true,
	}
}

// NewIPDetector creates a new IP detector
func NewIPDetector(cfg *IPDetectConfig) *IPDetector {
	if cfg == nil {
		cfg = DefaultIPDetectConfig()
	}

	return &IPDetector{
		cacheTTL: cfg.CacheTTL,
		httpClient: &http.Client{
			Timeout: cfg.RequestTimeout,
		},
	}
}

// externalIPService represents a service for detecting external IP
type externalIPService struct {
	URL       string
	ParseFunc func(body []byte) (string, error)
}

// services ordered by reliability and speed
var ipServices = []externalIPService{
	{
		URL: "https://api.ipify.org?format=json",
		ParseFunc: func(body []byte) (string, error) {
			var result struct {
				IP string `json:"ip"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				return "", err
			}
			return result.IP, nil
		},
	},
	{
		URL: "https://ifconfig.me/ip",
		ParseFunc: func(body []byte) (string, error) {
			return strings.TrimSpace(string(body)), nil
		},
	},
	{
		URL: "https://icanhazip.com",
		ParseFunc: func(body []byte) (string, error) {
			return strings.TrimSpace(string(body)), nil
		},
	},
	{
		URL: "https://api.my-ip.io/ip",
		ParseFunc: func(body []byte) (string, error) {
			return strings.TrimSpace(string(body)), nil
		},
	},
	{
		URL: "https://checkip.amazonaws.com",
		ParseFunc: func(body []byte) (string, error) {
			return strings.TrimSpace(string(body)), nil
		},
	},
}

// DetectExternalIP detects the server's external IP address
// It tries multiple services and falls back to local detection if all fail
func (d *IPDetector) DetectExternalIP(ctx context.Context) (string, error) {
	// Check cache first
	d.mu.RLock()
	if d.cachedIP != "" && time.Since(d.lastCheck) < d.cacheTTL {
		ip := d.cachedIP
		d.mu.RUnlock()
		return ip, nil
	}
	d.mu.RUnlock()

	// Try external services
	ip, err := d.detectFromExternalServices(ctx)
	if err == nil && ip != "" {
		d.cacheIP(ip)
		return ip, nil
	}

	// Fallback to local interface detection
	ip, err = d.detectFromLocalInterfaces()
	if err == nil && ip != "" {
		d.cacheIP(ip)
		return ip, nil
	}

	// Return cached IP if available (even if stale)
	d.mu.RLock()
	if d.cachedIP != "" {
		ip := d.cachedIP
		d.mu.RUnlock()
		return ip, nil
	}
	d.mu.RUnlock()

	return "", fmt.Errorf("failed to detect external IP: %w", err)
}

// detectFromExternalServices tries to get IP from external services
func (d *IPDetector) detectFromExternalServices(ctx context.Context) (string, error) {
	var lastErr error

	for _, service := range ipServices {
		ip, err := d.queryService(ctx, service)
		if err != nil {
			lastErr = err
			continue
		}

		// Validate IP
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			return ip, nil
		}
	}

	return "", fmt.Errorf("all external services failed: %v", lastErr)
}

// queryService queries a single IP detection service
func (d *IPDetector) queryService(ctx context.Context, service externalIPService) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", service.URL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Whispera/1.0")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024)) // Limit to 1KB
	if err != nil {
		return "", err
	}

	return service.ParseFunc(body)
}

// detectFromLocalInterfaces tries to detect external-facing IP from local interfaces
func (d *IPDetector) detectFromLocalInterfaces() (string, error) {
	// Try to connect to a public DNS server to find the outbound interface
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 3*time.Second)
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP.String(), nil
	}

	// Fallback: iterate through interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Skip loopback and link-local
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			// Prefer non-private IPs
			if !isPrivateIP(ip) {
				return ip.String(), nil
			}
		}
	}

	// Last resort: return first private IP found
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no suitable interface found")
}

// cacheIP stores the detected IP in cache
func (d *IPDetector) cacheIP(ip string) {
	d.mu.Lock()
	d.cachedIP = ip
	d.lastCheck = time.Now()
	d.mu.Unlock()
}

// GetCachedIP returns the cached IP without checking external services
func (d *IPDetector) GetCachedIP() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cachedIP
}

// InvalidateCache clears the cached IP
func (d *IPDetector) InvalidateCache() {
	d.mu.Lock()
	d.cachedIP = ""
	d.lastCheck = time.Time{}
	d.mu.Unlock()
}

// isPrivateIP checks if an IP is in a private range
func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 100.64.0.0/10 (CGNAT)
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}
	return false
}

// Global IP detector instance
var globalDetector *IPDetector
var globalDetectorOnce sync.Once

// GetGlobalDetector returns the global IP detector instance
func GetGlobalDetector() *IPDetector {
	globalDetectorOnce.Do(func() {
		globalDetector = NewIPDetector(nil)
	})
	return globalDetector
}

// DetectServerIP is a convenience function to detect server's external IP
func DetectServerIP(ctx context.Context) (string, error) {
	return GetGlobalDetector().DetectExternalIP(ctx)
}

// GetServerInfo returns comprehensive server network information
func GetServerInfo(ctx context.Context) (*ServerInfo, error) {
	detector := GetGlobalDetector()

	externalIP, err := detector.DetectExternalIP(ctx)
	if err != nil {
		// Use placeholder if detection fails
		externalIP = "unknown"
	}

	info := &ServerInfo{
		ExternalIP: externalIP,
		Hostname:   getHostname(),
		Interfaces: getInterfaceInfo(),
		DetectedAt: time.Now(),
	}

	return info, nil
}

// ServerInfo holds comprehensive server network information
type ServerInfo struct {
	ExternalIP string          `json:"external_ip"`
	Hostname   string          `json:"hostname"`
	Interfaces []InterfaceInfo `json:"interfaces"`
	DetectedAt time.Time       `json:"detected_at"`
}

// InterfaceInfo holds information about a network interface
type InterfaceInfo struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	IsUp      bool     `json:"is_up"`
}

// getHostname returns the system hostname
func getHostname() string {
	// Placeholder - will be implemented with os.Hostname()
	return "whispera-server"
}

// getInterfaceInfo returns information about all network interfaces
func getInterfaceInfo() []InterfaceInfo {
	var result []InterfaceInfo

	interfaces, err := net.Interfaces()
	if err != nil {
		return result
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		info := InterfaceInfo{
			Name: iface.Name,
			IsUp: iface.Flags&net.FlagUp != 0,
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			info.Addresses = append(info.Addresses, addr.String())
		}

		if len(info.Addresses) > 0 {
			result = append(result, info)
		}
	}

	return result
}
