package quic

import (
	"encoding/binary"
	"testing"
	"time"
)

func fecPacket(seq uint32, payload []byte) []byte {
	p := make([]byte, 9+len(payload))
	p[0] = markerFEC
	binary.BigEndian.PutUint32(p[1:5], seq)
	binary.BigEndian.PutUint16(p[7:9], uint16(len(payload)))
	copy(p[9:], payload)
	return p
}

func TestSweepIdleDoesNotSignal(t *testing.T) {
	r := newRTFECReceiver()
	select {
	case <-r.pending:
		t.Fatal("an empty receiver signals, the loop would spin for nothing")
	default:
	}
	if r.sweep(func([]byte) {}) {
		t.Fatal("sweep on an empty receiver reports work left")
	}
}

func TestSweepSignalsOnFirstBlock(t *testing.T) {
	r := newRTFECReceiver()
	r.ingest(fecPacket(0, []byte("x")))
	select {
	case <-r.pending:
	case <-time.After(time.Second):
		t.Fatal("an arriving block did not wake the loop")
	}
	if !r.sweep(func([]byte) {}) {
		t.Fatal("an incomplete block must leave work behind")
	}
}
