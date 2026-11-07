package tunnel

import (
	"bytes"
	"context"
	"fmt"
	stdlog "log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
)

func netSetFields(choice dialChoice, arm, presets int, levers bool) string {
	if arm < 0 {
		return "-"
	}
	preset, budget := protocol.JointArmParts(arm, presets)
	var fields []string
	if choice.netFingerprint {
		id := fingerprint.PresetAt(preset)
		fields = append(fields, id.Str())
	}
	if choice.netRecords {
		fields = append(fields, fmt.Sprintf("%drec", budget))
	}
	if choice.netDropPQ {
		pq := "keep-PQ"
		if protocol.JointArmDropPQ(arm, presets) {
			pq = "drop-PQ"
		}
		fields = append(fields, pq)
	}
	if levers && protocol.JointArmMigrates(arm, presets) {
		fields = append(fields, "migrate")
	}
	if levers && protocol.JointArmShaped(arm, presets) {
		fields = append(fields, "shaped")
	}
	if len(fields) == 0 {
		return "-"
	}
	return strings.Join(fields, "/")
}

type DialCause string

const (
	CauseNetworkDown       DialCause = "network_down"
	CauseForeignCut        DialCause = "foreign_cut"
	CauseServerUnreachable DialCause = "server_unreachable"
	CauseServerRefused     DialCause = "server_refused"
	CauseHandshakeBlocked  DialCause = "handshake_blocked"
	CauseLiveBlocked       DialCause = "live_blocked"

	controlProbeTimeout = 3 * time.Second
	controlProbeFresh   = 15 * time.Second
)

var controlProbeDialer = &net.Dialer{Timeout: controlProbeTimeout, Control: bindDefaultRoute}

var causeText = map[DialCause]string{
	CauseNetworkDown:       "no internet: the domestic control address does not answer either",
	CauseForeignCut:        "only domestic internet works: the foreign control address does not answer",
	CauseServerUnreachable: "the server does not answer while the rest of the internet does: its IP is blocked or the server is off",
	CauseServerRefused:     "the server refuses connections: its service is not running",
	CauseHandshakeBlocked:  "the handshake is blocked on the way",
	CauseLiveBlocked:       "connections are cut while they carry data",
}

type FailureCause struct {
	Cause    DialCause `json:"cause"`
	Symptom  string    `json:"symptom,omitempty"`
	Wire     string    `json:"wire,omitempty"`
	Pattern  int       `json:"pattern,omitempty"`
	Down     int64     `json:"down_bytes,omitempty"`
	AtMs     int64     `json:"at_ms"`
	SinceMs  int64     `json:"since_ms"`
	Failures int       `json:"failures"`
}

type controlEndpoints struct {
	domestic, foreign string
}

type controlProbe struct {
	endpoints             atomic.Pointer[controlEndpoints]
	mu                    sync.Mutex
	checkedAt             time.Time
	domesticUp, foreignUp bool
}

var sharedControl = &controlProbe{}

func SetControlEndpoints(domestic, foreign string) {
	sharedControl.endpoints.Store(&controlEndpoints{domestic: domestic, foreign: foreign})
	sharedControl.mu.Lock()
	sharedControl.checkedAt = time.Time{}
	sharedControl.mu.Unlock()
}

func (c *controlProbe) domesticAddr() (*net.TCPAddr, bool) {
	ep := c.endpoints.Load()
	if ep == nil || ep.domestic == "" {
		return nil, false
	}
	addr, err := net.ResolveTCPAddr("tcp", ep.domestic)
	return addr, err == nil
}

func (c *controlProbe) reach() (domesticUp, foreignUp bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.checkedAt.IsZero() && time.Since(c.checkedAt) < controlProbeFresh {
		return c.domesticUp, c.foreignUp
	}
	ep := c.endpoints.Load()
	if ep == nil {
		ep = &controlEndpoints{}
	}
	var wg sync.WaitGroup
	answers := func(addr string, up *bool) {
		defer wg.Done()
		if addr == "" {
			*up = true
			return
		}
		conn, err := controlProbeDialer.DialContext(context.Background(), "tcp", addr)
		if err == nil {
			conn.Close()
		}
		*up = err == nil
	}
	wg.Add(2)
	go answers(ep.domestic, &c.domesticUp)
	go answers(ep.foreign, &c.foreignUp)
	wg.Wait()
	c.checkedAt = time.Now()
	return c.domesticUp, c.foreignUp
}

func connectFailure(symptom protocol.Symptom) (FailureCause, bool) {
	c := FailureCause{Symptom: string(symptom), AtMs: time.Now().UnixMilli()}
	if symptom == protocol.SymptomTCPReset {
		c.Cause = CauseServerRefused
		return c, true
	}
	domesticUp, foreignUp := sharedControl.reach()
	switch {
	case !domesticUp:
		c.Cause = CauseNetworkDown
	case symptom == protocol.SymptomLocal:
		return c, false
	case !foreignUp:
		c.Cause = CauseForeignCut
	default:
		c.Cause = CauseServerUnreachable
	}
	return c, true
}

func (m *Manager) noteFailure(c FailureCause) {
	prev := m.failure.Load()
	for {
		c.Failures, c.SinceMs = 1, c.AtMs
		if prev != nil {
			c.Failures, c.SinceMs = prev.Failures+1, prev.SinceMs
		}
		next := c
		if m.failure.CompareAndSwap(prev, &next) {
			break
		}
		prev = m.failure.Load()
	}
	if prev == nil || prev.Cause != c.Cause {
		detail := ""
		if c.Wire != "" {
			detail += ", wire " + c.Wire
		}
		if c.Pattern > 0 {
			detail += fmt.Sprintf(", new block pattern #%d", c.Pattern)
		}
		stdlog.Printf("[DIAL] failure cause: %s (%s%s)", causeText[c.Cause], c.Symptom, detail)
	}
}

func (m *Manager) clearFailure() { m.failure.Store(nil) }

func (m *Manager) LastFailure() *FailureCause { return m.failure.Load() }

var dialHist = struct {
	mu      sync.Mutex
	lastArm map[string]int
	lastSym map[string]protocol.Symptom
	rows    int
}{lastArm: map[string]int{}, lastSym: map[string]protocol.Symptom{}}

func changeReason(ctx string, arm int, symptom protocol.Symptom) string {
	dialHist.mu.Lock()
	defer dialHist.mu.Unlock()
	last, had := dialHist.lastArm[ctx]
	prev := dialHist.lastSym[ctx]
	dialHist.lastArm[ctx] = arm
	dialHist.lastSym[ctx] = symptom
	switch {
	case !had:
		return "first dial"
	case arm != last:
		return fmt.Sprintf("switch (prev arm %d saw %s)", last, symptomTag(prev))
	case prev != protocol.SymptomOK:
		return "retry (prev " + symptomTag(prev) + ")"
	default:
		return "kept (last dial alive)"
	}
}

func symptomTag(s protocol.Symptom) string {
	switch s {
	case protocol.SymptomOK:
		return "ok"
	case protocol.SymptomTCPReset, protocol.SymptomHelloReset:
		return "RST"
	case protocol.SymptomLiveReset:
		return "RSTmid"
	case protocol.SymptomTCPSilent:
		return "noSYNACK"
	case protocol.SymptomHelloSilent:
		return "noSrvHello"
	case protocol.SymptomStall:
		return "stall"
	case protocol.SymptomStallVolume:
		return "freeze"
	case protocol.SymptomHelloRejected:
		return "alert"
	case protocol.SymptomLocal:
		return "local"
	default:
		return string(s)
	}
}

type dialRow struct {
	ctx     string
	arm     int
	result  protocol.HandshakeResult
	stage   string
	latency time.Duration
	connect time.Duration
	symptom protocol.Symptom
	down    int64
	wire    protocol.WireVerdict
	measure protocol.DialMeasure
	trust   float64
	check   float64
	set     string
	predict float64
}

func dialOutcome(row dialRow) string {
	switch {
	case row.stage != dialStageHandshake:
		return "live-dead"
	case row.result == protocol.HandshakeOK:
		return "alive"
	default:
		return "dead"
	}
}

func logDialRow(net string, row dialRow) {
	reason := changeReason(row.ctx, row.arm, row.symptom)
	dialHist.mu.Lock()
	header := dialHist.rows%25 == 0
	dialHist.rows++
	dialHist.mu.Unlock()
	if header {
		stdlog.Printf("[DIAL] legend  set: what the policy net chose for this dial | predicted: its survival estimate for that choice | trust: net / check head | outcome: what happened")
		stdlog.Printf("[DIAL] %-9s %-3s %-32s %-9s %-9s %-9s %s", "net", "arm", "set", "predicted", "trust", "outcome", "reason")
	}
	stdlog.Printf("[DIAL] %-9s %-3d %-32s %-9s %-9s %-9s %s", net, row.arm, row.set, fmt.Sprintf("%.2f", row.predict),
		fmt.Sprintf("%.2f/%.2f", row.trust, row.check), dialOutcome(row), reason)
}

// One line per dial for the trainer, off unless WHISPERA_DIAL_TRACE names a
// file. The ring buffer behind logger.Snapshot drops a line's fields and the
// client's /logs refuses when logging to a file, so neither carries this.
const (
	dialTraceDefaultMB  = 4
	dialTraceCheckEvery = 64 << 10
	dialTraceHeader     = "ms,ctx,arm,result,alive,stage,latency_ms,symptom,down_bytes,wire,connect_ms,hello_bytes,hello_segments,hello_acked,retransmits,reset_ms,reset_ttl,server_ttl,packets,chain_pos,chain_gap_ms,presets"
)

func measureColumns(m protocol.DialMeasure) string {
	tail := strings.Join([]string{protocol.EncodeWirePackets(m.Packets), strconv.Itoa(m.ChainPos), strconv.FormatInt(m.ChainGap.Milliseconds(), 10),
		strconv.Itoa(fingerprint.PresetCount())}, ",")
	if !m.Captured {
		return ",,,,,,," + tail
	}
	reset, resetTTL := "", ""
	if m.Reset {
		reset, resetTTL = strconv.FormatInt(m.ResetAfter.Milliseconds(), 10), strconv.Itoa(m.ResetTTL)
	}
	server := ""
	if m.ServerTTL > 0 {
		server = strconv.Itoa(m.ServerTTL)
	}
	return strings.Join([]string{strconv.Itoa(m.HelloBytes), strconv.Itoa(m.HelloSegments), strconv.Itoa(m.HelloAcked),
		strconv.Itoa(m.Retransmits), reset, resetTTL, server, tail}, ",")
}

func upgradeDialTraceHeader(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	head, rest, _ := bytes.Cut(raw, []byte("\n"))
	if string(bytes.TrimSpace(head)) == dialTraceHeader {
		return nil
	}
	return os.WriteFile(path, append([]byte(dialTraceHeader+"\n"), rest...), 0o600)
}

var dialTrace struct {
	once    sync.Once
	mu      sync.Mutex
	file    *os.File
	path    string
	keep    int64
	written int
}

var dialTraceMB atomic.Int64

func SetDialTraceMB(mb int) {
	if mb != 0 {
		dialTraceMB.Store(int64(mb))
	}
}

func dialTraceKeepBytes() int64 {
	if mb := dialTraceMB.Load(); mb < 0 {
		return -1
	} else if mb > 0 {
		return mb << 20
	}
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

var dialTraceFallback atomic.Pointer[string]

func SetDialTracePath(path string) { dialTraceFallback.Store(&path) }

// defaultDialTracePath puts the trace next to the client's own config, so a
// GUI build with no console still collects it and the file can be handed over
// as it is. "off" in the env turns the whole thing off.
func defaultDialTracePath() string {
	if path := dialTraceFallback.Load(); path != nil && *path != "" {
		return *path
	}
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
		if err := upgradeDialTraceHeader(path); err != nil && !os.IsNotExist(err) {
			log.Warn("dial trace header not upgraded in %s: %v", path, err)
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
	dialStageConnect   = "connect"
	dialStageLiveOK    = "live_ok"
	dialStageLiveReset = "live_reset"
	dialStageLiveEnd   = "live_end"
)

func recordDial(row dialRow) {
	alive := 0
	if row.result == protocol.HandshakeOK {
		alive = 1
	}
	ctx := row.ctx

	// Written through the standard logger, the way the socks5 module writes the
	// lines a user actually sees: the zap level starts at Error and only
	// WHISPERA_LOG_LEVEL moves it, which a GUI build cannot set, and lowering it
	// globally would turn on Info for every module at once.
	net := ctx
	if i := strings.IndexByte(ctx, '|'); i >= 0 {
		rest := ctx[i+1:]
		if j := strings.IndexByte(rest, '|'); j >= 0 {
			net = rest[:j]
		} else {
			net = rest
		}
	}
	logDialRow(net, row)

	f := dialTraceFile()
	if f == nil {
		return
	}
	dialTrace.mu.Lock()
	defer dialTrace.mu.Unlock()
	n, err := fmt.Fprintf(f, "%d,%s,%d,%d,%d,%s,%d,%s,%d,%s,%d,%s\n", time.Now().UnixMilli(), ctx, row.arm, int(row.result), alive, row.stage,
		row.latency.Milliseconds(), row.symptom, row.down, row.wire, row.connect.Milliseconds(), measureColumns(row.measure))
	if err != nil {
		log.Warn("dial trace write failed: %v", err)
		return
	}
	dialTrace.written += n
	if dialTrace.written >= dialTraceCheckEvery {
		dialTrace.written = 0
		if curateErr := curateDialTrace(dialTrace.path, dialTrace.keep); curateErr != nil {
			log.Warn("dial trace curate failed: %v", curateErr)
		}
	}
}

const (
	dialTraceLocalResult = int(protocol.HandshakeLocal)
	dialTraceJointTail   = "|joint"
	dialTraceClassCap    = 8
)

func dialTraceTrains(fields []string) bool {
	if len(fields) < 6 {
		return false
	}
	if !strings.HasSuffix(fields[1], dialTraceJointTail) {
		return false
	}
	switch fields[5] {
	case dialStageHandshake, dialStageLiveReset, dialStageLiveEnd:
	default:
		return false
	}
	return fields[3] != strconv.Itoa(dialTraceLocalResult)
}

// curateDialTrace bounds the trace to keep bytes by value, not by age: it drops
// the rows policyfit never trains on, keeps the newest trainable rows whole for
// the sequence model, and thins only the older rows whose (ctx,arm,outcome) is
// already well represented, so rare outcomes survive. keep < 0 leaves it alone.
func curateDialTrace(path string, keep int64) error {
	if keep < 0 {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Size() <= keep {
		return nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := bytes.Split(raw, []byte("\n"))

	var trainable [][]byte
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		if dialTraceTrains(strings.Split(string(line), ",")) {
			trainable = append(trainable, line)
		}
	}

	recent := keep * 7 / 10
	kept := make([][]byte, 0, len(trainable))
	seen := map[string]int{}
	var size int64
	for i := len(trainable) - 1; i >= 0; i-- {
		line := trainable[i]
		cost := int64(len(line)) + 1
		if size+cost > keep {
			break
		}
		if size < recent {
			kept = append(kept, line)
			size += cost
			continue
		}
		f := strings.Split(string(line), ",")
		class := f[1] + "," + f[2] + "," + f[4]
		if seen[class] >= dialTraceClassCap {
			continue
		}
		seen[class]++
		kept = append(kept, line)
		size += cost
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
	for i := len(kept) - 1; i >= 0; i-- {
		if _, err := out.Write(append(kept[i], '\n')); err != nil {
			return err
		}
	}
	return nil
}
