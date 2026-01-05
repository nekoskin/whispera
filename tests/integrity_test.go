package tests

import (
	"bytes"
	"testing"
	"whispera/internal/obfuscation"
	"whispera/internal/obfuscation/fte"
)

func TestPayloadIntegrity(t *testing.T) {
	// Original payload
	original := []byte("THIS_IS_A_SECRET_PAYLOAD_THAT_MUST_NOT_BE_CORRUPTED_OR_TRUNCATED_BY_OBFUSCATION_LAYERS")

	t.Run("MarionetteIntegrity", func(t *testing.T) {
		m := obfuscation.NewMarionetteAdapter()

		// Process packet
		processed, _, err := m.ProcessPacket(original, "outbound")
		if err != nil {
			t.Fatalf("Marionette ProcessPacket failed: %v", err)
		}

		// Integrity Check: Processed data MUST contain the original data at the beginning
		// (since we append padding, but never overwrite or truncate)
		if !bytes.HasPrefix(processed, original) {
			t.Errorf("Marionette corrupted or truncated the payload.\nExpected prefix: %s\nGot: %x", original, processed)
		}
	})

	t.Run("FTEIntegrity", func(t *testing.T) {
		f := fte.NewFTE()

		// Process packet with FTE
		processed, _, err := f.ProcessPacket(original, "outbound")
		if err != nil {
			t.Fatalf("FTE ProcessPacket failed: %v", err)
		}

		// Integrity Check: FTE MUST contain the original data at the beginning
		if !bytes.HasPrefix(processed, original) {
			t.Errorf("FTE corrupted or truncated the payload.\nExpected prefix: %s\nGot: %x", original, processed)
		}
	})
}
