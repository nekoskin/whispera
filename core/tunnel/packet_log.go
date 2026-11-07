package tunnel

import (
	"io"
	stdlog "log"
	"sync"
	"time"
)

const (
	packetLinesPerSecond = 50
	packetLogWindow      = time.Second
)

type lineLimiter struct {
	perWindow int
	window    time.Time
	used      int
	dropped   int
}

func (l *lineLimiter) allow(now time.Time) (bool, int) {
	carried := 0
	if now.Sub(l.window) >= packetLogWindow {
		carried = l.dropped
		l.window, l.used, l.dropped = now, 0, 0
	}
	if l.used >= l.perWindow {
		l.dropped++
		return false, carried
	}
	l.used++
	return true, carried
}

var packetLog = struct {
	mu      sync.Mutex
	out     *stdlog.Logger
	limiter lineLimiter
}{limiter: lineLimiter{perWindow: packetLinesPerSecond}}

func SetPacketLog(w io.Writer) {
	packetLog.mu.Lock()
	packetLog.out = stdlog.New(w, "", stdlog.LstdFlags)
	packetLog.mu.Unlock()
}

func writePacketLine(line string) {
	packetLog.mu.Lock()
	defer packetLog.mu.Unlock()
	out := packetLog.out
	if out == nil {
		out = stdlog.Default()
	}
	ok, dropped := packetLog.limiter.allow(time.Now())
	if dropped > 0 {
		out.Printf("[PCAP] %d packets not logged in the last %s, the limit is %d", dropped, packetLogWindow, packetLinesPerSecond)
	}
	if ok {
		out.Printf("[PCAP] %s", line)
	}
}
