package util

import (
	"log"
)

// SafeClose safely closes a resource and logs any errors.
// This function is designed to be used in defer statements to ensure
// resource cleanup while properly handling errors.
func SafeClose(name string, closeFunc func() error) {
	if closeFunc == nil {
		return
	}
	if err := closeFunc(); err != nil {
		log.Printf("[SafeClose] Error closing %s: %v", name, err)
	}
}
