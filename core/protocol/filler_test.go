package protocol

import (
	"net"

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
