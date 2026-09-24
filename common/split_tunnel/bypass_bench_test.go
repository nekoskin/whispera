package split_tunnel

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func benchManager(n int, kind string) *SplitTunnelManager {
	stm := NewSplitTunnelManager()
	stm.config.Enabled = true
	stm.byCountry = false
	rules := make([]SplitTunnelRule, 0, n)
	for i := 0; i < n; i++ {
		switch kind {
		case "domain":
			rules = append(rules, SplitTunnelRule{
				Type: "domain", Value: fmt.Sprintf("site%d.example.com", i),
				Action: "direct", Enabled: true,
			})
		case "ip":
			rules = append(rules, SplitTunnelRule{
				Type: "ip", Value: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				Action: "direct", Enabled: true,
			})
		}
	}
	stm.rules = rules
	stm.recompileLocked()
	return stm
}

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

func TestRulesAreDeduplicated(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.config.Enabled = true
	stm.byCountry = false

	dup := []SplitTunnelRule{
		{Type: "domain", Value: "example.com", Action: "direct", Enabled: true},
		{Type: "domain", Value: "*.example.com", Action: "tunnel", Enabled: true},
		{Type: "domain", Value: "EXAMPLE.com", Action: "tunnel", Enabled: true},
		{Type: "ip", Value: "10.0.0.0/8", Action: "direct", Enabled: true},
		{Type: "ip", Value: "10.0.0.0/8", Action: "tunnel", Enabled: true},
	}
	for round := 0; round < 3; round++ {
		stm.rules = append(stm.rules, dup...)
		stm.recompileLocked()
	}

	if len(stm.rules) != 2 {
		t.Fatalf("rules after three rounds = %d, want 2", len(stm.rules))
	}
	if !stm.ShouldBypassByHostname("example.com") {
		t.Error("first rule must win for example.com")
	}
	if !stm.ShouldBypassByIP("10.0.0.1") {
		t.Error("first rule must win for 10.0.0.1")
	}
}

func TestDisabledManagerBypassesNothing(t *testing.T) {
	stm := mixedManager()
	stm.SetEnabled(false)
	if stm.ShouldBypassByHostname("example.com") || stm.ShouldBypassByIP("10.0.0.1") {
		t.Error("a disabled manager must not bypass")
	}
	stm.SetEnabled(true)
	if !stm.ShouldBypassByHostname("example.com") {
		t.Error("re-enabling must restore the rules")
	}
}

func BenchmarkBypassByHostname(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		stm := benchManager(n, "domain")
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				stm.ShouldBypassByHostname("unmatched.host.invalid")
			}
		})
	}
}

func BenchmarkBypassByIP(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		stm := benchManager(n, "ip")
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				stm.ShouldBypassByIP("203.0.113.7")
			}
		})
	}
}

func BenchmarkBypassParallel(b *testing.B) {
	stm := benchManager(100, "domain")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			stm.ShouldBypassByHostname("unmatched.host.invalid")
		}
	})
}

func BenchmarkRebuild(b *testing.B) {
	for _, n := range []int{100, 1000} {
		stm := benchManager(n, "ip")
		b.Run(fmt.Sprintf("ip-rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				stm.publishLocked()
			}
		})
	}
}

const largeRuleSet = 26000

func BenchmarkLargeLookup(b *testing.B) {
	for _, kind := range []string{"domain", "ip"} {
		stm := benchManager(largeRuleSet, kind)
		b.Run(kind, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if kind == "domain" {
					stm.ShouldBypassByHostname("unmatched.host.invalid")
				} else {
					stm.ShouldBypassByIP("203.0.113.7")
				}
			}
		})
	}
}

func BenchmarkLargeRebuild(b *testing.B) {
	for _, kind := range []string{"domain", "ip"} {
		stm := benchManager(largeRuleSet, kind)
		b.Run(kind, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				stm.publishLocked()
			}
		})
	}
}

func benchCountryManager() *SplitTunnelManager {
	stm := benchManager(100, "domain")
	stm.byCountry = true
	g := NewGeoIPSet()
	var list strings.Builder
	for i := 0; i < 2000; i++ {
		list.WriteString(fmt.Sprintf("%d.%d.0.0/16", 100+i/256, i%256))
		list.WriteByte(10)
	}
	if _, err := g.load(strings.NewReader(list.String())); err != nil {
		panic(err)
	}
	stm.geo = g
	stm.verdicts.put("unmatched.host.invalid", verdict{bypass: false, expires: time.Now().Add(time.Hour)})
	stm.recompileLocked()
	return stm
}

func BenchmarkCountryVerdict(b *testing.B) {
	stm := benchCountryManager()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		stm.ShouldBypassByHostname("unmatched.host.invalid")
	}
}

func BenchmarkCountryVerdictParallel(b *testing.B) {
	stm := benchCountryManager()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			stm.ShouldBypassByHostname("unmatched.host.invalid")
		}
	})
}

func BenchmarkGeoContainsParallel(b *testing.B) {
	stm := benchCountryManager()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			stm.ShouldBypassByIP("203.0.113.7")
		}
	})
}

func BenchmarkCountryLearnParallel(b *testing.B) {
	stm := benchCountryManager()
	stm.verdicts.reset()
	stm.cached = func(string) ([]net.IP, bool) {
		return []net.IP{net.ParseIP("203.0.113.7")}, true
	}
	var n int64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			host := "h" + strconv.FormatInt(atomic.AddInt64(&n, 1), 10) + ".invalid"
			stm.ShouldBypassByHostname(host)
		}
	})
}

func BenchmarkShouldBypassEntryParallel(b *testing.B) {
	stm := benchCountryManager()
	b.Run("hostname", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				stm.ShouldBypass("unmatched.host.invalid", 443)
			}
		})
	})
	b.Run("ip", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				stm.ShouldBypass("203.0.113.7", 443)
			}
		})
	})
}
