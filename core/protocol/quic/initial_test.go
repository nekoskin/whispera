package quic

import (
	"bytes"
	"testing"
)

func TestQUICCamoProbeGarbageRejected(t *testing.T) {
	garbage := bytes.Repeat([]byte{0xAA}, 1200)
	if _, err := parseQUICInitialClientHello(garbage); err == nil {
		t.Fatal("expected error parsing garbage as quic initial")
	}
}
