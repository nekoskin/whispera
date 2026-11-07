package protocol

import (
	"bytes"

	"testing"
)

func TestDenialRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	const msg = "IP limit exceeded; you will have to wait until someone disconnects."
	WriteDenial(&buf, msg)

	got, ok := ParseDenial(buf.Bytes())
	if !ok {
		t.Fatal("a written denial must parse back")
	}
	if got != msg {
		t.Fatalf("got %q, want %q", got, msg)
	}
}
