package protocol

import (
	rtdebug "runtime/debug"

	"testing"
)

func TestH2BuffersFitMemoryLimit(t *testing.T) {
	lim := rtdebug.SetMemoryLimit(-1)
	perConn, perStream := h2Buffers()

	if perStream > perConn {
		t.Fatalf("per-stream %d exceeds per-connection %d", perStream, perConn)
	}
	if lim > 0 && lim < 1<<62 && int64(perConn) > lim {
		t.Fatalf("per-connection buffer %d exceeds the process memory limit %d", perConn, lim)
	}
}
