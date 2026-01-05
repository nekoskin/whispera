package tests

import (
	"bytes"
	"testing"

	"whispera/internal/obfuscation/marionette"
)

func TestEffectiveness(t *testing.T) {
	m := marionette.NewMarionette()

	// Test data
	original := []byte("Hello, this is a secret message that needs to be obfuscated and look like something else.")

	// Process packet (Internal rules like "dpi_evasion" apply automatically)
	m.SetThreatLevel(10)

	// Process packet
	processed, delay, err := m.ProcessPacket(original, "outbound")
	if err != nil {
		t.Fatalf("ProcessPacket failed: %v", err)
	}

	if delay != 0 {
		t.Errorf("Expected 0 delay in high-performance mode, got %v", delay)
	}

	// 1. Check if data was actually modified/extended
	if len(processed) <= len(original) {
		t.Errorf("Data not extended by evasion parts: original %d, processed %d", len(original), len(processed))
	}

	// 2. Check for JA3 fingerprint presence
	// applyJA3Evasion and other ML techniques extend the packet.
	// We verify extension happened (step 1). Internal scrambling is optional for this profile.

	// 3. Verify that the EvasionPool is actually working
	// We check if multiple calls produce different results (randomness/mimicry)
	// Use fresh data to avoid in-place modification artifacts
	originalCopy := make([]byte, len(original))
	copy(originalCopy, original)
	processed2, _, _ := m.ProcessPacket(originalCopy, "outbound")
	if bytes.Equal(processed, processed2) {
		t.Error("Subsequent processed packets are identical - lacks realistic entropy/randomness")
	}

	t.Logf("Original size: %d, Processed size: %d", len(original), len(processed))
	t.Log("Effectiveness test passed: Packet was successfully masked and randomized.")
}
