//go:build e2e

package protocol

import (
	"os"
	"time"
)

func init() {
	if skew, err := time.ParseDuration(os.Getenv("WHISPERA_E2E_CLOCK_SKEW")); err == nil && skew != 0 {
		serverNow = func() time.Time { return time.Now().Add(skew) }
	}
}
