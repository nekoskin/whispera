package split_tunnel

import (
	"net"
	"testing"
)

func TestCountryVerdictIgnoresDialAddress(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	geo := geoWith(t, "176.114.122.0/24")
	stm.SetGeoIP(geo)

	setResolvers(stm, func(host string) []net.IP {
		if host == "dual.test" {
			return []net.IP{net.ParseIP("176.114.122.24")}
		}
		return nil
	})

	if !stm.ShouldBypassByHostname("dual.test") {
		t.Fatal("verdict must be direct — the resolved address sits in the country list")
	}

	dialIP := net.ParseIP("203.0.113.9")
	if geo.Contains(dialIP) {
		t.Fatal("precondition: the dial address must be outside the country list")
	}

	if !stm.ShouldBypassByHostname("dual.test") {
		t.Fatal("cached verdict must stay direct regardless of the dial address")
	}
}
