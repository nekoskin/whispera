//go:build darwin

// Package killswitch provides macOS implementation using pf (packet filter)
package killswitch

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
)

const (
	pfConfPath = "/tmp/whispera_killswitch.conf"
	anchorName = "whispera_killswitch"
)

// DarwinKillSwitch implements kill switch using macOS pf
type DarwinKillSwitch struct {
	mu          sync.Mutex
	rulesActive bool
}

// NewPlatformImpl creates macOS-specific implementation
func NewPlatformImpl() (Platform, error) {
	return &DarwinKillSwitch{}, nil
}

// Name returns platform name
func (d *DarwinKillSwitch) Name() string {
	return "darwin"
}

// IsSupported checks if pf is available
func (d *DarwinKillSwitch) IsSupported() bool {
	// Check if pfctl is available
	cmd := exec.Command("pfctl", "-s", "info")
	err := cmd.Run()
	return err == nil
}

// Enable activates kill switch rules
func (d *DarwinKillSwitch) Enable(vpnServerIP net.IP, vpnPort int, allowLAN, allowDNS bool, allowedIPs []net.IP) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Build pf rules
	var rules strings.Builder

	// Allow loopback
	rules.WriteString("pass quick on lo0 all\n")

	// Allow VPN server
	vpnIP := vpnServerIP.String()
	rules.WriteString(fmt.Sprintf("pass out quick to %s\n", vpnIP))
	rules.WriteString(fmt.Sprintf("pass in quick from %s\n", vpnIP))

	// Allow LAN if enabled
	if allowLAN {
		lanRanges := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
		for _, cidr := range lanRanges {
			rules.WriteString(fmt.Sprintf("pass quick to %s\n", cidr))
			rules.WriteString(fmt.Sprintf("pass quick from %s\n", cidr))
		}
	}

	// Allow DNS if enabled
	if allowDNS {
		rules.WriteString("pass out quick proto udp to any port 53\n")
		rules.WriteString("pass out quick proto tcp to any port 53\n")
	}

	// Allow additional IPs
	for _, ip := range allowedIPs {
		rules.WriteString(fmt.Sprintf("pass quick to %s\n", ip.String()))
		rules.WriteString(fmt.Sprintf("pass quick from %s\n", ip.String()))
	}

	// Allow TUN interfaces
	rules.WriteString("pass quick on utun0 all\n")
	rules.WriteString("pass quick on utun1 all\n")
	rules.WriteString("pass quick on utun2 all\n")

	// Block everything else
	rules.WriteString("block drop all\n")

	// Write rules to temp file
	if err := os.WriteFile(pfConfPath, []byte(rules.String()), 0600); err != nil {
		return fmt.Errorf("failed to write pf rules: %w", err)
	}

	// Load anchor
	if err := d.runPfctl("-a", anchorName, "-f", pfConfPath); err != nil {
		return fmt.Errorf("failed to load pf rules: %w", err)
	}

	// Enable pf if not already enabled
	d.runPfctl("-e") // Ignore error if already enabled

	d.rulesActive = true
	log.Info("macOS pf kill switch rules activated")
	return nil
}

// Disable removes kill switch rules
func (d *DarwinKillSwitch) Disable() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Flush anchor rules
	d.runPfctl("-a", anchorName, "-F", "all")

	// Remove temp file
	os.Remove(pfConfPath)

	d.rulesActive = false
	log.Info("macOS pf kill switch rules removed")
	return nil
}

// IsActive returns true if rules are active
func (d *DarwinKillSwitch) IsActive() (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rulesActive, nil
}

// Cleanup removes all kill switch rules
func (d *DarwinKillSwitch) Cleanup() error {
	return d.Disable()
}

// runPfctl executes pfctl command
func (d *DarwinKillSwitch) runPfctl(args ...string) error {
	cmd := exec.Command("pfctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl failed: %v, output: %s", err, string(output))
	}
	return nil
}
