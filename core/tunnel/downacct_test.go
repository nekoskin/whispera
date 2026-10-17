package tunnel

import (
	"net"
	"testing"
)

func TestDecoyLeaveConnCarriesAcctAcrossReuse(t *testing.T) {
	a, _ := net.Pipe()
	defer a.Close()
	first := newDecoyLeaveConn(a)
	if first.acct == nil {
		t.Fatal("a fresh connection should get a downstream account")
	}
	first.acct.down.Store(9000)
	reused := newDecoyLeaveConn(first)
	if reused.acct != first.acct {
		t.Fatal("wrapping a pooled connection should carry its account forward, not reset it")
	}
	if reused.acct.down.Load() != 9000 {
		t.Fatalf("carried-forward total = %d, want 9000", reused.acct.down.Load())
	}
}

func TestDownstreamCapRetiresAHotConnection(t *testing.T) {
	a, _ := net.Pipe()
	defer a.Close()
	d := newDecoyLeaveConn(a)
	if d.acct.down.Add(downstreamCapBytes-1) >= downstreamCapBytes {
		t.Fatal("under the cap the connection should still be reusable")
	}
	if d.acct.down.Add(1) < downstreamCapBytes {
		t.Fatal("at the cap the connection should be retired")
	}
}
