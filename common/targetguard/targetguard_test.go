package targetguard

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
)

func TestBlocksAddressClasses(t *testing.T) {
	guard, err := New([]string{ClassLoopback, ClassUnspecified, ClassPrivate, ClassLinkLocal})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := map[string]bool{
		"127.0.0.1":        true,
		"::1":              true,
		"0.0.0.0":          true,
		"::":               true,
		"10.1.2.3":         true,
		"172.16.5.5":       true,
		"192.168.1.1":      true,
		"fd00::1":          true,
		"169.254.169.254":  true,
		"fe80::1%eth0":     true,
		"::ffff:127.0.0.1": true,
		"8.8.8.8":          false,
		"2a00:1450::1":     false,
		"100.64.1.1":       false,
	}
	for text, want := range cases {
		if got := guard.Blocks(netip.MustParseAddr(text)); got != want {
			t.Errorf("Blocks(%s) = %v, want %v", text, got, want)
		}
	}
}

func TestBlocksConfiguredNetwork(t *testing.T) {
	guard, err := New([]string{" 100.64.0.0/10 "})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := map[string]bool{
		"100.64.1.1":         true,
		"::ffff:100.127.0.1": true,
		"10.0.0.1":           false,
		"127.0.0.1":          false,
	}
	for text, want := range cases {
		if got := guard.Blocks(netip.MustParseAddr(text)); got != want {
			t.Errorf("Blocks(%s) = %v, want %v", text, got, want)
		}
	}
}

func TestRejectsUnknownEntry(t *testing.T) {
	if _, err := New([]string{"lan"}); err == nil {
		t.Fatal("an entry that is neither a class nor a CIDR must be rejected")
	}
}

func TestEmptyPolicyBlocksNothing(t *testing.T) {
	guard, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	loopback := netip.MustParseAddr("127.0.0.1")
	if guard.Blocks(loopback) {
		t.Error("an empty list must not block anything")
	}
	var unset *Guard
	if unset.Blocks(loopback) {
		t.Error("an unset guard must not block anything")
	}
}

func TestDialerRefusesBlockedTarget(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	guard, err := New([]string{ClassLoopback})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, target := range []struct{ network, addr string }{
		{"tcp", ln.Addr().String()},
		{"tcp", net.JoinHostPort("localhost", port)},
		{"udp", net.JoinHostPort("127.0.0.1", port)},
	} {
		conn, err := guard.Dialer().DialContext(t.Context(), target.network, target.addr)
		if err == nil {
			_ = conn.Close()
			t.Errorf("%s %s: dial went through", target.network, target.addr)
			continue
		}
		if !errors.Is(err, ErrBlocked) {
			t.Errorf("%s %s: err = %v, want ErrBlocked", target.network, target.addr, err)
		}
	}

	var unset *Guard
	conn, err := unset.Dialer().DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("an unset guard must dial normally: %v", err)
	}
	_ = conn.Close()
}
