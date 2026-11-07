package camo

import "testing"

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
