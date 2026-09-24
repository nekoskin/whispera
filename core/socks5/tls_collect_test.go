package socks5

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestCollectPeekTransparent(t *testing.T) {
	var got []byte
	CollectHook = func(b []byte) { got = b }
	defer func() { CollectHook = nil }()
	lastCollect.Store(0)

	body := make([]byte, 50)
	body[0] = 0x01
	rec := append([]byte{0x16, 0x03, 0x01, 0x00, byte(len(body))}, body...)

	r := &collectPeekReader{Reader: bytes.NewReader(rec)}
	out := make([]byte, len(rec))
	n, err := io.ReadFull(r, out)
	if err != nil || n != len(rec) || !bytes.Equal(out, rec) {
		t.Fatalf("data not passed through unchanged: n=%d err=%v", n, err)
	}
	if len(got) != 5+len(body) {
		t.Fatalf("hook not called with full record, got %d", len(got))
	}
}

func TestCollectPeekNonTLS(t *testing.T) {
	called := false
	CollectHook = func(b []byte) { called = true }
	defer func() { CollectHook = nil }()
	lastCollect.Store(0)

	plain := []byte("GET / HTTP/1.1\r\n\r\n")
	r := &collectPeekReader{Reader: bytes.NewReader(plain)}
	out, _ := io.ReadAll(r)
	if !bytes.Equal(out, plain) {
		t.Fatalf("non-TLS data altered")
	}
	if called {
		t.Fatalf("hook fired on non-TLS data")
	}
}

func TestIsBitTorrentDetectsHandshake(t *testing.T) {
	hs := append([]byte{0x13}, []byte("BitTorrent protocol")...)
	hs = append(hs, make([]byte, 48)...)
	if !isBitTorrent(hs) {
		t.Fatal("a real handshake was not detected")
	}
	if isBitTorrent([]byte{0x16, 0x03, 0x01, 0x00}) {
		t.Fatal("a TLS hello was misdetected as torrent")
	}
	if isBitTorrent([]byte("short")) {
		t.Fatal("a short prefix was misdetected")
	}
}

func TestFakeIPRangeMatchesFakeIPFilter(t *testing.T) {
	for _, s := range []string{"198.18.0.1", "198.18.255.255", "198.19.0.1", "198.19.255.255"} {
		if !fakeIP(net.ParseIP(s)) {
			t.Fatalf("%s should be inside the fake-ip range", s)
		}
	}
	for _, s := range []string{"198.17.255.255", "198.20.0.0", "8.8.8.8", "176.114.120.6"} {
		if fakeIP(net.ParseIP(s)) {
			t.Fatalf("%s should be outside the fake-ip range", s)
		}
	}
}
