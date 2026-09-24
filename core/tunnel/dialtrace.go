package tunnel

import (
	"bytes"
	"fmt"
	stdlog "log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

// One line per dial for the trainer, off unless WHISPERA_DIAL_TRACE names a
// file. The ring buffer behind logger.Snapshot drops a line's fields and the
// client's /logs refuses when logging to a file, so neither carries this.
const (
	dialTraceDefaultMB  = 4
	dialTraceCheckEvery = 64 << 10
	dialTraceHeader     = "ms,ctx,arm,result,alive,stage"
)

var dialTrace struct {
	once    sync.Once
	mu      sync.Mutex
	file    *os.File
	path    string
	keep    int64
	written int
}

func dialTraceKeepBytes() int64 {
	mb := dialTraceDefaultMB
	if v := os.Getenv("WHISPERA_DIAL_TRACE_MB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			mb = n
		} else {
			log.Warn("dial trace: %q is not a size in megabytes, keeping %d", v, mb)
		}
	}
	return int64(mb) << 20
}

// defaultDialTracePath puts the trace next to the client's own config, so a
// GUI build with no console still collects it and the file can be handed over
// as it is. "off" in the env turns the whole thing off.
func defaultDialTracePath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	dir = filepath.Join(dir, "whispera")
	if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
		return ""
	}
	return filepath.Join(dir, "dials.csv")
}

func dialTraceFile() *os.File {
	dialTrace.once.Do(func() {
		path := os.Getenv("WHISPERA_DIAL_TRACE")
		switch path {
		case "off":
			return
		case "":
			path = defaultDialTracePath()
		}
		if path == "" {
			return
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			log.Warn("dial trace disabled, cannot open %s: %v", path, err)
			return
		}
		if info, statErr := f.Stat(); statErr == nil && info.Size() == 0 {
			fmt.Fprintln(f, dialTraceHeader)
		}
		dialTrace.file = f
		dialTrace.path = path
		dialTrace.keep = dialTraceKeepBytes()
	})
	return dialTrace.file
}

// Only a handshake stage judges the arm. A later reset is the censor changing
// its rule under a live tunnel, or the peer leaving, not the arm's fault.
const (
	dialStageHandshake = "handshake"
	dialStageLiveOK    = "live_ok"
	dialStageLiveReset = "live_reset"
)

func recordDial(ctx string, arm int, result protocol.HandshakeResult, stage string) {
	alive := 0
	if result == protocol.HandshakeOK {
		alive = 1
	}

	// Written through the standard logger, the way the socks5 module writes the
	// lines a user actually sees: the zap level starts at Error and only
	// WHISPERA_LOG_LEVEL moves it, which a GUI build cannot set, and lowering it
	// globally would turn on Info for every module at once.
	stdlog.Printf("[INFO] dial_trace %d,%s,%d,%d,%d,%s",
		time.Now().UnixMilli(), ctx, arm, int(result), alive, stage)

	f := dialTraceFile()
	if f == nil {
		return
	}
	dialTrace.mu.Lock()
	defer dialTrace.mu.Unlock()
	n, err := fmt.Fprintf(f, "%d,%s,%d,%d,%d,%s\n", time.Now().UnixMilli(), ctx, arm, int(result), alive, stage)
	if err != nil {
		log.Warn("dial trace write failed: %v", err)
		return
	}
	dialTrace.written += n
	if dialTrace.written >= dialTraceCheckEvery {
		dialTrace.written = 0
		if trimErr := trimDialTrace(dialTrace.path, dialTrace.keep); trimErr != nil {
			log.Warn("dial trace trim failed: %v", trimErr)
		}
	}
}

// trimDialTrace keeps the tail once the file outgrows its allowance and rewrites
// the header, since the parser skips the first line.
func trimDialTrace(path string, keep int64) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Size() <= keep {
		return nil
	}

	src, err := os.Open(path)
	if err != nil {
		return err
	}
	from := fi.Size() - keep
	buf := make([]byte, fi.Size()-from)
	n, _ := src.ReadAt(buf, from)
	src.Close()
	if n == 0 {
		return nil
	}
	buf = buf[:n]
	if i := bytes.IndexByte(buf, '\n'); i >= 0 {
		buf = buf[i+1:]
	}

	out, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	if err := out.Truncate(0); err != nil {
		return err
	}
	if _, err := out.WriteString(dialTraceHeader + "\n"); err != nil {
		return err
	}
	_, err = out.Write(buf)
	return err
}
