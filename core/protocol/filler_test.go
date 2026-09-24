package protocol

import (
	"net"
	"runtime"
	"testing"
	"time"
)

func TestFillerRecordsAreSkippedByReader(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	writer := NewFramedConn(a, NewShapeBudget())
	reader := NewFramedConn(b, NewShapeBudget())

	go func() {
		if err := writer.writeFiller(64); err != nil {
			t.Errorf("write filler: %v", err)
		}
		if _, err := writer.Write([]byte("payload")); err != nil {
			t.Errorf("write payload: %v", err)
		}
	}()

	buf := make([]byte, 32)
	reader.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("read after filler: %v", err)
	}
	if got := string(buf[:n]); got != "payload" {
		t.Fatalf("got %q, want %q", got, "payload")
	}
}

func TestFillerRunsOnlyWhileIdle(t *testing.T) {
	if err := Shape.SetFiller(20, 10, 32, 64); err != nil {
		t.Fatalf("set filler: %v", err)
	}
	defer func() { _ = Shape.SetFiller(0, 0, 0, 0) }()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	writer := NewFramedConn(a, NewShapeBudget())
	defer writer.stopFiller()

	got := make(chan int, 8)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := b.Read(buf)
			if err != nil {
				return
			}
			got <- n
		}
	}()

	select {
	case n := <-got:
		if n < 32+7 {
			t.Fatalf("filler record too small: %d bytes", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no filler record while idle")
	}
}

func TestFillerOffByDefault(t *testing.T) {
	idle, interval, min, max := Shape.Filler()
	if interval != 0 || idle != 0 || min != 0 || max != 0 {
		t.Fatalf("filler must be off by default, got idle=%d interval=%d min=%d max=%d",
			idle, interval, min, max)
	}
}

func TestFillerStartsNoGoroutineWhenOff(t *testing.T) {
	if err := Shape.SetFiller(0, 0, 0, 0); err != nil {
		t.Fatalf("reset filler: %v", err)
	}
	runtime.GC()
	before := runtime.NumGoroutine()

	conns := make([]*FramedConn, 0, 64)
	for i := 0; i < 64; i++ {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		conns = append(conns, NewFramedConn(a, NewShapeBudget()))
	}
	time.Sleep(50 * time.Millisecond)

	if grew := runtime.NumGoroutine() - before; grew > 4 {
		t.Fatalf("filler is off, yet %d goroutines appeared for %d connections", grew, len(conns))
	}
}
