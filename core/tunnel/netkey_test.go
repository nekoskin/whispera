package tunnel

import (
	"net"
	"testing"
)

func TestHashNetworkIsShortAndStable(t *testing.T) {
	a, b := hashNetwork("wifi:gw=192.168.1.1"), hashNetwork("wifi:gw=192.168.1.1")
	if a != b {
		t.Fatalf("same network hashed differently: %q vs %q", a, b)
	}
	if len(a) != networkKeyBytes*2 {
		t.Fatalf("key %q should be %d hex chars", a, networkKeyBytes*2)
	}
	if hashNetwork("wifi:gw=192.168.0.1") == a {
		t.Fatal("different networks share a key")
	}
	if hashNetwork("") != "" {
		t.Fatal("an unknown network should have no key")
	}
}

func TestLocalPrefixMasksHostBits(t *testing.T) {
	cases := map[string]string{
		"192.168.1.57":         "192.168.1.0/24",
		"10.0.0.9":             "10.0.0.0/24",
		"2a02:6b8:1:2:3:4:5:6": "2a02:6b8:1:2::/64",
	}
	for ip, want := range cases {
		if got := localPrefix(net.ParseIP(ip)).String(); got != want {
			t.Errorf("localPrefix(%s) = %s, want %s", ip, got, want)
		}
	}
}

func TestArmContextKeepsLegacyShapeWithoutNetwork(t *testing.T) {
	if got := armContext("ya.ru", "", "joint"); got != "ya.ru|joint" {
		t.Fatalf("got %q", got)
	}
	if got := armContext("ya.ru", "a1b2c3d4", "joint"); got != "ya.ru|a1b2c3d4|joint" {
		t.Fatalf("got %q", got)
	}
}

func TestPlatformNetworkOverridesRoute(t *testing.T) {
	defer SetNetwork("")
	const server = "127.0.0.1:443"
	route := networkKey(t.Context(), server)
	if route == "" {
		t.Fatal("loopback route should give a key")
	}
	SetNetwork("mobile:25001")
	if got := networkKey(t.Context(), server); got != hashNetwork("mobile:25001") {
		t.Fatalf("platform network ignored: %q", got)
	}
	SetNetwork("")
	if got := networkKey(t.Context(), server); got != route {
		t.Fatalf("clearing the platform network should fall back to the route key, got %q", got)
	}
}
