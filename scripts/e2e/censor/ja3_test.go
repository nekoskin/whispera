package main

import "testing"

// A minimal but well-formed ClientHello record, built so the test can flip one
// GREASE cipher on and off and confirm the hash ignores it. Layout: record
// header, handshake header, legacy version, 32-byte random, empty session id,
// cipher suites, one null compression, then a supported_groups and an
// ec_point_formats extension.
func sampleHello(greaseCipher bool) []byte {
	ciphers := []byte{0x13, 0x01, 0x13, 0x02} // TLS_AES_128/256_GCM_SHA
	if greaseCipher {
		ciphers = append([]byte{0x0a, 0x0a}, ciphers...) // a GREASE value
	}

	var hs []byte
	hs = append(hs, 0x03, 0x03)          // legacy version
	hs = append(hs, make([]byte, 32)...) // random
	hs = append(hs, 0x00)                // session id length 0
	hs = append(hs, byte(len(ciphers)>>8), byte(len(ciphers)))
	hs = append(hs, ciphers...)
	hs = append(hs, 0x01, 0x00) // compression: 1 method, null

	// supported_groups: x25519 (0x001d)
	groups := []byte{0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d}
	// ec_point_formats: uncompressed (0x00)
	formats := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}
	exts := append(append([]byte{}, groups...), formats...)
	hs = append(hs, byte(len(exts)>>8), byte(len(exts)))
	hs = append(hs, exts...)

	body := append([]byte{0x01, byte(len(hs) >> 16), byte(len(hs) >> 8), byte(len(hs))}, hs...)
	rec := append([]byte{0x16, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}, body...)
	return rec
}

func TestJA3IsDeterministic(t *testing.T) {
	h1, ok1 := ja3(sampleHello(false))
	h2, ok2 := ja3(sampleHello(false))
	if !ok1 || !ok2 {
		t.Fatal("ja3 failed to parse a well-formed hello")
	}
	if h1 != h2 {
		t.Fatalf("same hello gave two hashes: %s vs %s", h1, h2)
	}
	if len(h1) != 32 {
		t.Fatalf("hash is %d chars, want 32 (md5 hex)", len(h1))
	}
}

func TestJA3IgnoresGREASE(t *testing.T) {
	plain, ok1 := ja3(sampleHello(false))
	greased, ok2 := ja3(sampleHello(true))
	if !ok1 || !ok2 {
		t.Fatal("ja3 failed to parse")
	}
	if plain != greased {
		t.Fatalf("a GREASE cipher changed the hash: %s vs %s", plain, greased)
	}
}

func TestJA3RejectsNonHello(t *testing.T) {
	if _, ok := ja3([]byte{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5}); ok {
		t.Fatal("ja3 accepted a non-handshake record")
	}
}
