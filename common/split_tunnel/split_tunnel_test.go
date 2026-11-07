package split_tunnel

import (
	"context"

	"errors"
	"fmt"
	"net"

	"strings"
	"testing"
)

func (stm *SplitTunnelManager) ShouldBypassByHostname(hostname string) bool {
	snap := stm.snap.Load()
	if snap == nil || !snap.enabled {
		return false
	}
	return stm.bypassHost(snap, hostname)
}

func (c *verdictCache) len() int {
	total := 0
	for i := range c.shards {
		c.shards[i].mu.RLock()
		total += len(c.shards[i].m)
		c.shards[i].mu.RUnlock()
	}
	return total
}

func TestUserRuleOverridesLowerPriority(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)

	stm.AddRule(&SplitTunnelRule{
		Type: "domain", Value: "vk.com", Action: "direct", Enabled: true, Priority: 10,
	})
	stm.AddRule(&SplitTunnelRule{
		Type: "domain", Value: "vk.com", Action: "tunnel", Enabled: true, Priority: 90,
	})

	if stm.ShouldBypassByHostname("vk.com") {
		t.Fatal("higher priority rule must win regardless of insertion order")
	}
}

func TestLocalNetworksBypass(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.CreateDefaultRules()
	stm.SetEnabled(true)

	for _, ip := range []string{"192.168.1.5", "10.1.2.3", "127.0.0.1"} {
		if !stm.ShouldBypassByIP(ip) {
			t.Fatalf("local address %s must bypass the tunnel", ip)
		}
	}
	if stm.ShouldBypassByIP("8.8.8.8") {
		t.Fatal("public address must not bypass by default")
	}
}

func geoWith(t *testing.T, cidrs ...string) *GeoIPSet {
	t.Helper()
	g := NewGeoIPSet()
	ranges, err := parseGeoIP(strings.NewReader(strings.Join(cidrs, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	g.ranges.Store(&ranges)
	return g
}

func TestBypassByCountryUsesResolvedAddress(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	stm.SetGeoIP(geoWith(t, "176.114.122.0/24"))

	calls := 0
	setResolvers(stm, func(host string) []net.IP {
		calls++
		switch host {
		case "avito.ru":
			return []net.IP{net.ParseIP("176.114.122.24")}
		default:
			return []net.IP{net.ParseIP("1.1.1.1")}
		}
	})

	if !stm.ShouldBypassByHostname("avito.ru") {
		t.Fatal("host resolving inside the country list must go direct")
	}
	if stm.ShouldBypassByHostname("example.com") {
		t.Fatal("host outside the list must stay in the tunnel")
	}

	stm.ShouldBypassByHostname("avito.ru")
	if calls != 2 {
		t.Fatalf("verdict must be cached, got %d lookups for 3 requests", calls)
	}
}

func TestBypassByCountryTunnelsOnResolveFailure(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	stm.SetGeoIP(geoWith(t, "176.114.122.0/24"))
	setResolvers(stm, func(host string) []net.IP {
		return nil
	})

	if stm.ShouldBypassByHostname("avito.ru") {
		t.Fatal("an unresolvable host must stay in the tunnel, not leak out in the clear")
	}
}

func TestBypassByCountryCoversIPv6(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	stm.SetGeoIP(geoWith(t, "2a02:6b8::/32", "176.114.122.0/24"))
	setResolvers(stm, func(host string) []net.IP {
		return []net.IP{net.ParseIP("2a02:6b8:23::225")}
	})

	if !stm.ShouldBypassByHostname("yandex.ru") {
		t.Fatal("a host reachable only over IPv6 must still match the country list")
	}
	if !stm.ShouldBypassByIP("2a02:6b8:23::225") {
		t.Fatal("IPv6 literal must match the country list")
	}
	if stm.ShouldBypassByIP("2606:4700::1111") {
		t.Fatal("foreign IPv6 must stay in the tunnel")
	}
	if !stm.ShouldBypassByIP("176.114.122.24") {
		t.Fatal("IPv4 must keep working alongside IPv6")
	}
}

func TestVerdictCacheStaysBounded(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	stm.SetGeoIP(geoWith(t, "176.114.122.0/24"))
	setResolvers(stm, func(host string) []net.IP {
		return []net.IP{net.ParseIP("8.8.8.8")}
	})

	for i := 0; i < verdictMax*2; i++ {
		stm.ShouldBypassByHostname(fmt.Sprintf("host%d.example.com", i))
	}

	n := stm.verdicts.len()
	if n > verdictMax {
		t.Fatalf("verdict cache grew to %d entries, it must not accumulate without bound", n)
	}
}

func TestAppRuleForcesTunnelOverGeoIP(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	stm.CreateDefaultRules()
	stm.SetGeoIP(geoWith(t, "176.114.122.0/24"))
	setResolvers(stm, func(host string) []net.IP {
		if host == "avito.ru" {
			return []net.IP{net.ParseIP("176.114.122.24")}
		}
		return []net.IP{net.ParseIP("1.1.1.1")}
	})

	if !stm.ShouldBypassByHostname("avito.ru") {
		t.Fatal("without a rule the country list decides")
	}

	if err := stm.LoadAppRules(`[
		{"kind":"domain-suffix","suffix":"avito.ru","action":"PROXY"},
		{"kind":"domain-keyword","keyword":"tracker","action":"PROXY"},
		{"kind":"domain-exact","domain":"vk.com","action":"DIRECT"},
		{"kind":"ip-cidr","cidr":"5.255.255.0/24","action":"DIRECT"},
		{"kind":"domain-suffix","suffix":"ads.example","action":"REJECT"}
	]`); err != nil {
		t.Fatal(err)
	}

	if stm.ShouldBypassByHostname("avito.ru") {
		t.Fatal("an explicit tunnel rule must beat the country list")
	}
	if stm.ShouldBypassByHostname("my.tracker.ru") {
		t.Fatal("keyword rule must apply")
	}
	if !stm.ShouldBypassByHostname("vk.com") {
		t.Fatal("exact rule must apply")
	}
	if stm.ShouldBypassByHostname("sub.vk.com") {
		t.Fatal("exact rule must not match subdomains")
	}
	if !stm.ShouldBypassByIP("5.255.255.10") {
		t.Fatal("ip-cidr rule must apply")
	}
}

// setResolvers wires both resolvers from one answer table: on a live client the
// name has just been looked up for the application, so the cache holds it and
// the verdict costs nothing. The network resolver is what the background
// learning uses when it does not.
func setResolvers(stm *SplitTunnelManager, fn func(host string) []net.IP) {
	stm.SetResolver(func(ctx context.Context, host string) ([]net.IP, error) {
		ips := fn(host)
		if len(ips) == 0 {
			return nil, errors.New("no such host")
		}
		return ips, nil
	})
	stm.SetCachedResolver(func(host string) ([]net.IP, bool) {
		ips := fn(host)
		return ips, len(ips) > 0
	})
}
