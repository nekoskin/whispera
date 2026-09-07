package tunnel

import (
	"net"
	"testing"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

func TestParkedConnectionGetsFiller(t *testing.T) {
	if err := protocol.Shape.SetFiller(0, 50, 64, 128); err != nil {
		t.Fatalf("set filler: %v", err)
	}
	defer func() { _ = protocol.Shape.SetFiller(0, 0, 0, 0) }()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	var s idleSet
	s.put(a)

	got := make(chan int, 4)
	go func() {
		buf := make([]byte, 4096)
		n, err := b.Read(buf)
		if err != nil {
			return
		}
		got <- n
	}()

	select {
	case n := <-got:
		if n < 7+64 {
			t.Fatalf("filler record too small: %d", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no filler on a parked connection")
	}
}
