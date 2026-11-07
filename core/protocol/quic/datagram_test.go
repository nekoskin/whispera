package quic

import (
	"bytes"
	"fmt"

	"testing"
)

func TestRTAddrRoundTrip(t *testing.T) {
	cases := []struct {
		host string
		port uint16
	}{
		{"203.0.113.7", 51820},
		{"2001:db8::1", 443},
		{"game.example.com", 27015},
	}
	for _, c := range cases {
		enc := encodeAddr(c.host, c.port)
		host, port, rest, ok := decodeAddr(append(enc, 0xAA, 0xBB))
		if !ok {
			t.Fatalf("decode failed for %s:%d", c.host, c.port)
		}
		if host != c.host || port != c.port {
			t.Fatalf("got %s:%d, want %s:%d", host, port, c.host, c.port)
		}
		if !bytes.Equal(rest, []byte{0xAA, 0xBB}) {
			t.Fatalf("rest mismatch: %v", rest)
		}
	}
}

func TestRTFECRecoversFullBlockWithLosses(t *testing.T) {
	sender := newRTFECSender()
	receiver := newRTFECReceiver()

	payloads := make([][]byte, fecK)
	for i := range payloads {
		payloads[i] = []byte(fmt.Sprintf("payload-%02d-game-datagram", i))
	}

	var allPkts [][]byte
	for _, p := range payloads {
		allPkts = append(allPkts, sender.encode(p)...)
	}
	if len(allPkts) != fecK+fecM {
		t.Fatalf("got %d packets, want %d", len(allPkts), fecK+fecM)
	}

	dropped := map[int]bool{1: true, 3: true, fecK: true, fecK + 1: true}
	if len(dropped) != fecM {
		t.Fatalf("test setup: dropped %d, want %d", len(dropped), fecM)
	}

	for i, pkt := range allPkts {
		if dropped[i] {
			continue
		}
		receiver.ingest(pkt)
	}

	var delivered [][]byte
	receiver.deliverBlock(0, func(p []byte) {
		delivered = append(delivered, append([]byte{}, p...))
	})

	if len(delivered) != fecK {
		t.Fatalf("recovered %d payloads, want %d", len(delivered), fecK)
	}
	for i, p := range delivered {
		if !bytes.Equal(p, payloads[i]) {
			t.Fatalf("payload %d mismatch: got %q want %q", i, p, payloads[i])
		}
	}
}
