package config

import (
	"testing"
)

func TestFillRestoresZeroedFields(t *testing.T) {
	c := *DefaultServerConfig()
	c.Server.ListenAddr = ""
	c.Server.MTU = 0
	c.Server.Workers = 0
	c.Session.MaxSessions = 0

	if err := c.fill(); err != nil {
		t.Fatalf("fill on a zeroed config: %v", err)
	}

	d := DefaultServerConfig()
	if c.Server.ListenAddr != d.Server.ListenAddr {
		t.Errorf("listen_addr = %q, want %q", c.Server.ListenAddr, d.Server.ListenAddr)
	}
	if c.Server.MTU != d.Server.MTU {
		t.Errorf("mtu = %d, want %d", c.Server.MTU, d.Server.MTU)
	}
	if c.Server.Workers != d.Server.Workers {
		t.Errorf("workers = %d, want %d", c.Server.Workers, d.Server.Workers)
	}
	if c.Session.MaxSessions != d.Session.MaxSessions {
		t.Errorf("max_sessions = %d, want %d", c.Session.MaxSessions, d.Session.MaxSessions)
	}
}
