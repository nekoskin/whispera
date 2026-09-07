package socks5

import (
	"io"
	"sync/atomic"
	"time"
)

var CollectHook func([]byte)

var lastCollect atomic.Int64

type collectPeekReader struct {
	io.Reader
	done bool
}

func (h *collectPeekReader) Read(p []byte) (int, error) {
	r, err := h.Reader.Read(p)
	if !h.done && r > 0 {
		h.done = true
		maybeCollect(p[:r])
	}
	return r, err
}

func maybeCollect(b []byte) {
	if CollectHook == nil || len(b) < 6 || b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x01 {
		return
	}
	recLen := int(b[3])<<8 | int(b[4])
	if recLen <= 0 || 5+recLen > len(b) {
		return
	}
	now := time.Now().UnixNano()
	last := lastCollect.Load()
	if now-last < int64(30*time.Second) {
		return
	}
	if !lastCollect.CompareAndSwap(last, now) {
		return
	}
	rec := make([]byte, 5+recLen)
	copy(rec, b[:5+recLen])
	CollectHook(rec)
}
