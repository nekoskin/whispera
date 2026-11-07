package camo

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

func WriteRandom(random []byte, sel [SelectorSize]byte, key []byte, window int64, keyShare []byte) bool {
	if len(random) != 32 {
		return false
	}
	marker := markerFor(key, window, keyShare)
	copy(random[:SelectorSize], sel[:])
	copy(random[SelectorSize:], marker[:])
	return true
}

func newEph(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("эфемерный ключ: %v", err)
	}
	return k
}

func TestSelectorRoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	srv, err := ServerKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("ключ сервера: %v", err)
	}

	psk := make([]byte, 32)
	rand.Read(psk)
	eph := newEph(t)

	sel, err := BuildSelector(psk, eph, srv.PublicKey())
	if err != nil {
		t.Fatalf("BuildSelector: %v", err)
	}
	got, err := OpenSelector(sel, srv, eph.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("OpenSelector: %v", err)
	}
	if got != UserTag(psk) {
		t.Fatalf("сервер не восстановил метку пользователя")
	}
}

func TestMarkerToleratesWindowDrift(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	key := DeriveKey(psk)
	keyShare := make([]byte, 32)
	rand.Read(keyShare)

	now := time.Now().Unix()
	random := make([]byte, 32)
	var sel [SelectorSize]byte
	WriteRandom(random, sel, key, now/WindowSeconds, keyShare)
	_, marker, _ := SplitRandom(random)

	if !MarkerMatchesKey(key, marker, keyShare, now+WindowSeconds) {
		t.Fatal("маркер должен приниматься в соседнем окне вперёд")
	}
	if !MarkerMatchesKey(key, marker, keyShare, now-WindowSeconds) {
		t.Fatal("маркер должен приниматься в соседнем окне назад")
	}
	if MarkerMatchesKey(key, marker, keyShare, now+5*WindowSeconds) {
		t.Fatal("маркер не должен приниматься далеко за окном")
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random: %v", err)
	}
	return b
}

const unixEpochWindow int64 = 0

func TestMarkerWithoutTimeIsRefused(t *testing.T) {
	key, keyShare := randomBytes(t, 32), randomBytes(t, 32)
	random := make([]byte, 32)
	var sel [SelectorSize]byte
	if !WriteRandom(random, sel, key, unixEpochWindow, keyShare) {
		t.Fatal("write random failed")
	}
	_, marker, _ := SplitRandom(random)
	if MarkerMatchesKey(key, marker, keyShare, time.Now().Unix()) {
		t.Fatal("a marker carrying no time was accepted, so a recorded hello replays forever")
	}
}

func TestFullMarkerWithoutTimeIsRefused(t *testing.T) {
	key, keyShare := randomBytes(t, 32), randomBytes(t, 32)
	marker := markerForWindow(key, unixEpochWindow, keyShare)
	if MarkerMatches([][]byte{key}, marker[:], keyShare, time.Now().Unix()) {
		t.Fatal("a full marker carrying no time was accepted")
	}
}
