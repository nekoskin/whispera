package main

// The point of JA4 over JA3: it sorts the cipher and extension lists, so the
// per-connection extension shuffling that gives a browser a fresh JA3 every
// time leaves JA4 unchanged. These tests build a hello, reorder its
// extensions, and confirm JA3 moves while JA4 holds.

import "testing"

// helloWithExtOrder builds a ClientHello whose extensions appear in the given
// order, so a test can shuffle them.
func helloWithExtOrder(order []int) []byte {
	ext := map[int][]byte{
		0x0000: {0x00, 0x00, 0x00, 0x00}, // SNI (empty for brevity)
		0x000a: {0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d},
		0x000b: {0x00, 0x0b, 0x00, 0x02, 0x01, 0x00},
		0x000d: {0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03},
		0x0010: {0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32}, // ALPN h2
		0x002b: {0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04},             // supported_versions 1.3
	}
	var exts []byte
	for _, t := range order {
		exts = append(exts, ext[t]...)
	}

	var hs []byte
	hs = append(hs, 0x03, 0x03)
	hs = append(hs, make([]byte, 32)...)
	hs = append(hs, 0x00)
	ciphers := []byte{0x13, 0x01, 0x13, 0x02}
	hs = append(hs, byte(len(ciphers)>>8), byte(len(ciphers)))
	hs = append(hs, ciphers...)
	hs = append(hs, 0x01, 0x00)
	hs = append(hs, byte(len(exts)>>8), byte(len(exts)))
	hs = append(hs, exts...)

	body := append([]byte{0x01, byte(len(hs) >> 16), byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return append([]byte{0x16, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}, body...)
}

func TestJA4SurvivesExtensionShuffle(t *testing.T) {
	a := helloWithExtOrder([]int{0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b})
	b := helloWithExtOrder([]int{0x002b, 0x0010, 0x000d, 0x000b, 0x000a, 0x0000})

	h4a, ok1 := ja4(a)
	h4b, ok2 := ja4(b)
	if !ok1 || !ok2 {
		t.Fatal("ja4 failed to parse")
	}
	if h4a != h4b {
		t.Fatalf("JA4 changed under a shuffle: %s vs %s", h4a, h4b)
	}

	// And confirm the premise: JA3 does move, so the shuffle is real.
	h3a, _ := ja3(a)
	h3b, _ := ja3(b)
	if h3a == h3b {
		t.Fatal("JA3 did not change under the shuffle — the test proves nothing")
	}
}

func TestJA4Shape(t *testing.T) {
	h, ok := ja4(helloWithExtOrder([]int{0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b}))
	if !ok {
		t.Fatal("ja4 failed to parse")
	}
	// t + version(2) + sni(1) + ciphers(2) + exts(2) + alpn(2) = 10, then _b_c
	if len(h) != 10+1+12+1+12 {
		t.Fatalf("JA4 %q has wrong length %d", h, len(h))
	}
	if h[0] != 't' {
		t.Fatalf("JA4 %q should start with t (TLS over TCP)", h)
	}
	if h[1:3] != "13" {
		t.Fatalf("JA4 %q should show version 13 from supported_versions", h)
	}
	if h[3] != 'd' {
		t.Fatalf("JA4 %q: SNI extension is present, want 'd', got %c", h, h[3])
	}
}
