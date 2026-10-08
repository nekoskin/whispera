package socks5

import (
	"net"
	"testing"
)

func TestBypassRouteTunnelsForeignDialAddress(t *testing.T) {
	m, _ := New(&Config{
		BypassDecision:   func(string, uint16) (bool, bool) { return true, true },
		BypassAddrDirect: func(net.IP) bool { return false },
	})
	if direct, _ := m.bypassRoute("203.0.113.9", 443); direct {
		t.Fatal("a country verdict whose dial address is foreign must stay on the tunnel")
	}
}

func TestBypassRouteDirectForDomesticDialAddress(t *testing.T) {
	m, _ := New(&Config{
		BypassDecision:   func(string, uint16) (bool, bool) { return true, true },
		BypassAddrDirect: func(net.IP) bool { return true },
	})
	direct, ip := m.bypassRoute("77.88.8.8", 443)
	if !direct || ip == nil {
		t.Fatal("a country verdict whose dial address is domestic must go direct to that address")
	}
}

func TestBypassRouteHonorsExplicitRule(t *testing.T) {
	rechecked := false
	m, _ := New(&Config{
		BypassDecision:   func(string, uint16) (bool, bool) { return true, false },
		BypassAddrDirect: func(net.IP) bool { rechecked = true; return false },
	})
	direct, ip := m.bypassRoute("example.com", 443)
	if !direct || ip != nil {
		t.Fatal("an explicit rule must go direct and resolve the address at dial time")
	}
	if rechecked {
		t.Fatal("an explicit rule must not be re-checked against the country list")
	}
}
