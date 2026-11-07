package split_tunnel

import (
	"testing"
)

func mixedManager() *SplitTunnelManager {
	stm := NewSplitTunnelManager()
	stm.config.Enabled = true
	stm.byCountry = false
	stm.rules = []SplitTunnelRule{
		{Type: "domain", Value: "example.com", Action: "direct", Enabled: true},
		{Type: "domain", Value: "*.cdn.net", Action: "tunnel", Enabled: true},
		{Type: "domain-exact", Value: "exact.host", Action: "direct", Enabled: true},
		{Type: "domain-keyword", Value: "tracker", Action: "tunnel", Enabled: true},
		{Type: "ip", Value: "10.0.0.0/8", Action: "direct", Enabled: true},
		{Type: "ip", Value: "10.1.0.0/16", Action: "tunnel", Enabled: true},
		{Type: "ip", Value: "192.168.1.1", Action: "direct", Enabled: true},
		{Type: "domain", Value: "disabled.example", Action: "direct", Enabled: false},
	}
	stm.recompileLocked()
	return stm
}

func TestBypassByHostname(t *testing.T) {
	stm := mixedManager()
	cases := map[string]bool{
		"example.com":      true,
		"www.example.com":  true,
		"notexample.com":   false,
		"a.b.cdn.net":      false,
		"cdn.net":          false,
		"exact.host":       true,
		"sub.exact.host":   false,
		"ads.tracker.io":   false,
		"disabled.example": false,
		"nothing.here":     false,
	}
	for host, want := range cases {
		if got := stm.ShouldBypassByHostname(host); got != want {
			t.Errorf("host %q = %v, want %v", host, got, want)
		}
	}
}

func TestBypassByIPPrefersHigherPriorityRule(t *testing.T) {
	stm := mixedManager()
	cases := map[string]bool{
		"10.0.0.1":    true,
		"10.1.2.3":    true,
		"10.2.0.1":    true,
		"192.168.1.1": true,
		"192.168.1.2": false,
		"8.8.8.8":     false,
	}
	for ip, want := range cases {
		if got := stm.ShouldBypassByIP(ip); got != want {
			t.Errorf("ip %s = %v, want %v", ip, got, want)
		}
	}
}
