package tunnel

import (
	"net"
	"testing"
)

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
