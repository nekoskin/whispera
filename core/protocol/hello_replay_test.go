package protocol

import (
	"crypto/rand"
	"testing"
)

func TestServerRefusesARepeatedHello(t *testing.T) {
	cfg := &ServerConfig{}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("random: %v", err)
	}
	if !cfg.firstHelloSighting(random, "") {
		t.Fatal("the first hello was refused")
	}
	if cfg.firstHelloSighting(random, "") {
		t.Fatal("a repeated hello was accepted")
	}
}
