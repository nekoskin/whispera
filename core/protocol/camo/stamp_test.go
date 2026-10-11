package camo

import "testing"

func TestStampCarriesClientTimeAndIgnoresServerClock(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	keyShare := make([]byte, 32)
	for i := range keyShare {
		keyShare[i] = byte(0x40 + i)
	}
	clientTime := int64(1_700_000_000)

	marker := sealStamp(key, keyShare, clientTime)

	got, ok := openStamp(key, keyShare, marker[:])
	if !ok {
		t.Fatal("openStamp rejected a freshly sealed stamp")
	}
	if got != clientTime {
		t.Fatalf("recovered time %d, want %d", got, clientTime)
	}

	// The whole point: the server accepts the stamp whatever its own clock says.
	for _, serverClock := range []int64{clientTime, clientTime + 7200, clientTime - 86400, 0} {
		if !MarkerMatchesKey(key, marker[:], keyShare, serverClock) {
			t.Fatalf("stamp rejected at server clock %d — the clock must not matter", serverClock)
		}
	}

	wrongKey := make([]byte, 32)
	if _, ok := openStamp(wrongKey, keyShare, marker[:]); ok {
		t.Fatal("openStamp accepted the wrong key")
	}

	tampered := append([]byte(nil), marker[:]...)
	tampered[0] ^= 0xff
	if _, ok := openStamp(key, keyShare, tampered); ok {
		t.Fatal("openStamp accepted a tampered time byte")
	}
}

func TestWriteRandomStampRoundTrips(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*3 + 1)
	}
	keyShare := make([]byte, 32)
	for i := range keyShare {
		keyShare[i] = byte(i)
	}
	var sel [SelectorSize]byte
	for i := range sel {
		sel[i] = byte(0xA0 + i)
	}

	random := make([]byte, 32)
	if !WriteRandomStamp(random, sel, key, keyShare, 1_700_000_123) {
		t.Fatal("WriteRandomStamp refused a 32-byte random")
	}

	gotSel, marker, ok := SplitRandom(random)
	if !ok {
		t.Fatal("SplitRandom failed")
	}
	if gotSel != sel {
		t.Fatal("selector did not survive the round trip")
	}
	if !MarkerMatchesKey(key, marker, keyShare, 0) {
		t.Fatal("marker written by WriteRandomStamp was not accepted at an arbitrary server clock")
	}
}
