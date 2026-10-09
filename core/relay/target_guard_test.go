package relay

import (
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/nekoskin/whispera/common/targetguard"
)

func dialThroughRelay(s *Server, network, host string, port uint16) error {
	ips := s.routeIPs(host)
	dialer, tag, blocked := s.resolveProxyDialer(network, host, port, ips)
	if blocked {
		return errors.New("router blocked the target")
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	conn, err := s.dialProxyTarget(tag, network, target, host, port, dialer, ips)
	if err == nil {
		_ = conn.Close()
	}
	return err
}

func TestRelayRefusesBlockedTargets(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	guard, err := targetguard.New([]string{targetguard.ClassLoopback})
	if err != nil {
		t.Fatalf("targetguard.New: %v", err)
	}
	guarded, err := New(&Config{EnableTCP: true, EnableUDP: true, TargetGuard: guard})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, target := range []struct {
		network string
		host    string
	}{
		{"tcp", "127.0.0.1"},
		{"tcp", "localhost"},
		{"udp", "127.0.0.1"},
	} {
		err := dialThroughRelay(guarded, target.network, target.host, port)
		if !errors.Is(err, targetguard.ErrBlocked) {
			t.Errorf("%s %s: err = %v, want ErrBlocked", target.network, target.host, err)
		}
	}

	open, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := dialThroughRelay(open, "tcp", "127.0.0.1", port); err != nil {
		t.Fatalf("without a policy the relay must reach the target: %v", err)
	}
}
