package split_tunnel

import (
	"fmt"
	"strings"
	"testing"
)

// oldHostnameMatch is the matcher this package used before the index: a linear
// scan, first enabled rule that matches wins. It exists only so the new path
// can be held against it.
func oldHostnameMatch(rules []SplitTunnelRule, hostname string) (bypass bool, matched bool) {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		value := strings.ToLower(rule.Value)
		var hit bool
		switch rule.Type {
		case "domain":
			pattern := strings.TrimPrefix(value, "*.")
			hit = hostname == pattern || strings.HasSuffix(hostname, "."+pattern)
		case "domain-exact":
			hit = hostname == value
		case "domain-keyword":
			hit = strings.Contains(hostname, value)
		}
		if hit {
			return rule.Action == "direct", true
		}
	}
	return false, false
}

func TestNewHostnameMatchAgreesWithOld(t *testing.T) {
	values := []string{"example.com", "*.example.com", "EXAMPLE.com", "com", "shop", "sub.example.com"}
	types := []string{"domain", "domain-exact", "domain-keyword"}
	actions := []string{"direct", "tunnel"}

	hosts := []string{
		"example.com", "www.example.com", "sub.example.com", "a.b.sub.example.com",
		"notexample.com", "example.com.evil.net", "EXAMPLE.COM", "example.com.",
		"shop.example.com", "myshop.net", "com", "x.com", "nothing.here", "",
	}

	var rules []SplitTunnelRule
	for i, v := range values {
		for j, ty := range types {
			rules = append(rules, SplitTunnelRule{
				Type: ty, Value: v, Action: actions[(i+j)%2], Enabled: true,
			})
		}
	}

	for n := 1; n <= len(rules); n++ {
		subset := rules[:n]
		stm := NewSplitTunnelManager()
		stm.config.Enabled = true
		stm.byCountry = false
		stm.rules = append([]SplitTunnelRule(nil), subset...)
		sortRulesByPriority(stm.rules)
		stm.recompileLocked()

		for _, h := range hosts {
			wantBypass, wantMatched := oldHostnameMatch(subset, h)
			got := stm.ShouldBypassByHostname(h)
			want := wantBypass && wantMatched
			if got != want {
				t.Errorf("rules=%d host=%q: new=%v old=%v (matched=%v)\n  first rules: %s",
					n, h, got, want, wantMatched, describe(subset))
				return
			}
		}
	}
}

func describe(rules []SplitTunnelRule) string {
	var b strings.Builder
	for i, r := range rules {
		if i > 3 {
			fmt.Fprintf(&b, " …(+%d)", len(rules)-i)
			break
		}
		fmt.Fprintf(&b, " [%s %s→%s]", r.Type, r.Value, r.Action)
	}
	return b.String()
}
