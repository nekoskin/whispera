package client

import (
	"bytes"
	"io"
	stdlog "log"
	"net"
	"os"
	"strings"
	"sync"

	logger "github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/core/config"
)

func pickServerAddress(cfg *config.ClientConfig, transport string) string {
	switch transport {
	case "tcp", "tls":
		if cfg.ServerTCP != "" {
			return cfg.ServerTCP
		}
	case "ws", "websocket":
		if cfg.ServerWS != "" {
			return cfg.ServerWS
		}
		if cfg.ServerTCP != "" {
			return cfg.ServerTCP
		}
	}
	if cfg.Server != "" {
		return cfg.Server
	}
	return cfg.ServerTCP
}

func mlDefaultDataDir() string {
	if exe, err := os.Executable(); err == nil {
		exeDir := strings.TrimSuffix(exe, "/"+strings.Split(exe, "/")[len(strings.Split(exe, "/"))-1])
		if fi, err := os.Stat(exeDir + "/data/api_token"); err == nil && !fi.IsDir() {
			return exeDir + "/data"
		}
	}
	switch {
	case strings.EqualFold(os.Getenv("OS"), "Windows_NT") || os.PathSeparator == '\\':
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return appdata + `\Whispera`
		}
	default:
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return xdg + "/whispera"
		}
		if home, err := os.UserHomeDir(); err == nil {
			return home + "/.config/whispera"
		}
	}
	return "data"
}

const (
	logKeepBytes  = 20 << 20
	logCheckEvery = 64 << 10

	logLinesDesktop = 5000
	logLinesMobile  = 2000
)

// A phone has less to spare, so it keeps a shorter tail.
func logMaxLines() int {
	if mobileMode {
		return logLinesMobile
	}
	return logLinesDesktop
}

type trimmingLog struct {
	mu      sync.Mutex
	f       *os.File
	path    string
	written int
}

var (
	currentLog   *trimmingLog
	currentLogMu sync.Mutex
)

func openTrimmingLog(path string) (*trimmingLog, error) {
	currentLogMu.Lock()
	defer currentLogMu.Unlock()

	if currentLog != nil {
		if err := currentLog.reopen(path); err != nil {
			return nil, err
		}
		return currentLog, nil
	}

	t, err := newTrimmingLog(path)
	if err != nil {
		return nil, err
	}
	currentLog = t
	return t, nil
}

func (t *trimmingLog) reopen(path string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.path == path {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	t.f.Close()
	t.f, t.path = f, path
	return nil
}

func newTrimmingLog(path string) (*trimmingLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	t := &trimmingLog{f: f, path: path}
	t.trimLocked()
	return t, nil
}

func (t *trimmingLog) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	n, err := t.f.Write(p)
	t.written += n
	// Checked by what has been written rather than by the clock: an hourly timer
	// let the file grow without bound in between, and a client that is logging
	// hard is exactly the one that fills a phone.
	if t.written >= logCheckEvery {
		t.written = 0
		t.trimLocked()
	}
	return n, err
}

func countLines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == 0x0a {
			n++
		}
	}
	return n
}

func (t *trimmingLog) trimLocked() {
	fi, err := t.f.Stat()
	if err != nil || fi.Size() == 0 {
		return
	}

	from := int64(0)
	if fi.Size() > logKeepBytes {
		from = fi.Size() - logKeepBytes
	}

	src, err := os.Open(t.path)
	if err != nil {
		return
	}
	buf := make([]byte, fi.Size()-from)
	n, _ := src.ReadAt(buf, from)
	src.Close()
	if n == 0 {
		return
	}
	buf = buf[:n]
	if from > 0 {
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}

	var kept []byte
	if countLines(buf) <= logMaxLines() {
		kept = buf
	}
	if from == 0 && len(kept) == len(buf) {
		return
	}

	w, err := os.OpenFile(t.path, os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer w.Close()
	if err := w.Truncate(0); err != nil {
		return
	}
	w.Write(kept)
}

func setupLogging() {
	underSystemd := os.Getenv("JOURNAL_STREAM") != "" || os.Getenv("INVOCATION_ID") != ""

	var logWriter io.Writer
	if *logFilePath != "" {
		trimmed, err := openTrimmingLog(*logFilePath)
		if err != nil {
			rb := newRingLogBuffer(2000)
			globalLogBuf = rb
			logWriter = rb
		} else {
			logWriter = trimmed
		}
	} else if underSystemd {
		logWriter = os.Stdout
	} else {
		if null, errNull := os.OpenFile(os.DevNull, os.O_WRONLY, 0666); errNull == nil {
			os.Stdout = null
			os.Stderr = null
		}
		rb := newRingLogBuffer(2000)
		globalLogBuf = rb
		logWriter = rb
	}
	stdlog.SetOutput(logWriter)
	log.SetOutput(logWriter)
	log = logger.Module("client")
	if lvl := os.Getenv("WHISPERA_LOG_LEVEL"); lvl != "" {
		log.SetLevel(logger.ParseLevel(lvl))
	}
	stdlog.Printf("Whispera Client v%s starting...", Version)
}

func loadClientConfig() *config.ClientConfig {
	var cfg *config.ClientConfig

	if *connKey != "" {
		key, err := config.ParseConnectionKey(*connKey)
		if err != nil {
			fatalf("Failed to parse connection key: %v", err)
		}
		cfg = key.ToClientConfig()
		stdlog.Printf("Loaded config from key: %s", key.Name)
		stdlog.Printf("Server: %s (transport: %s, obfuscation: %s)", key.GetPrimaryServer(), key.Transport, key.ObfsPreset)
	} else if *configPath != "" {
		var loadErr error
		cfg, loadErr = config.LoadClient(*configPath)
		if loadErr != nil {
			fatalf("Failed to load config: %v", loadErr)
		}
	} else {
		cfg = &config.ClientConfig{
			Server: *serverAddr,
		}
	}

	if *connKey == "" && *serverAddr != "" {
		cfg.Server = *serverAddr
	}

	if *userKey != "" && cfg.PSK == "" {
		cfg.PSK = *userKey
		stdlog.Printf("ML mode: user-key PSK set")
	}

	if cfg.Server == "" && cfg.ServerTCP == "" {
		fatalf("No server address specified. Use -server, -key, or -config")
	}
	for _, a := range []struct{ field, addr string }{
		{"server", cfg.Server},
		{"server_tcp", cfg.ServerTCP},
	} {
		if a.addr == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(a.addr); err != nil {
			fatalf("%s = %q has no port: write it as host:port (the server listens on 443 unless whispera.listen_addr says otherwise)", a.field, a.addr)
		}
	}

	stdlog.Printf("Starting Whispera Client v%s", Version)
	stdlog.Printf("Server: %s", cfg.Server)
	if cfg.ServerTCP != "" {
		stdlog.Printf("TCP Fallback: %s", cfg.ServerTCP)
	}
	if cfg.ObfsPreset != "" {
		stdlog.Printf("Obfuscation: %s", cfg.ObfsPreset)
	}

	return cfg
}
