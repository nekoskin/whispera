package camo

import "testing"

const testReplayTTLSec = 60

func TestReplayGuardRefusesASecondSighting(t *testing.T) {
	g := NewReplayGuard(testReplayTTLSec)
	random := randomBytes(t, 32)
	if !g.FirstSighting(random, "", 100) {
		t.Fatal("a fresh hello was refused")
	}
	if g.FirstSighting(random, "", 101) {
		t.Fatal("the same hello was accepted twice")
	}
}

func TestReplayGuardLetsTheSameSenderRetransmit(t *testing.T) {
	g := NewReplayGuard(testReplayTTLSec)
	random := randomBytes(t, 32)
	client, prober := "198.51.100.7:51000", "203.0.113.9:40000"
	if !g.FirstSighting(random, client, 100) {
		t.Fatal("a fresh hello was refused")
	}
	if !g.FirstSighting(random, client, 101) {
		t.Fatal("the client's own retransmission was refused")
	}
	if g.FirstSighting(random, prober, 102) {
		t.Fatal("the hello replayed from another address was accepted")
	}
}

func TestReplayGuardForgetsAfterItsTTL(t *testing.T) {
	g := NewReplayGuard(testReplayTTLSec)
	random := randomBytes(t, 32)
	g.FirstSighting(random, "", 100)
	later := int64(100 + testReplayTTLSec)
	g.Sweep(later)
	if !g.FirstSighting(random, "", later) {
		t.Fatal("a sighting older than the TTL still blocks the hello")
	}
}

func TestReplayGuardRefusesMalformedRandom(t *testing.T) {
	g := NewReplayGuard(testReplayTTLSec)
	if g.FirstSighting(randomBytes(t, 16), "", 100) {
		t.Fatal("a 16-byte random was accepted")
	}
}
