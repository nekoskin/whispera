package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

type spliceReadConn struct {
	net.Conn
	r *bytes.Reader
}

func (c *spliceReadConn) Read(b []byte) (int, error) { return c.r.Read(b) }

type spliceWriteConn struct {
	net.Conn
	w bytes.Buffer
}

func (c *spliceWriteConn) Write(b []byte) (int, error) { return c.w.Write(b) }

func framedRecord(data []byte, marker int) []byte {
	const pad = 20
	body := 2 + len(data) + pad
	out := []byte{0x17, 0x03, 0x03, byte(body >> 8), byte(body)}
	if marker >= 0 {
		out = append(out, byte(marker>>8), byte(marker))
	} else {
		out = append(out, byte(len(data)>>8), byte(len(data)))
	}
	out = append(out, data...)
	return append(out, make([]byte, pad)...)
}

func buildFramedWire(payloads [][]byte) []byte {
	var w bytes.Buffer
	for _, p := range payloads {
		w.Write(framedRecord(p, -1))
	}
	return w.Bytes()
}

func newKeepAliveStream(wire []byte) (*keepAliveStream, *spliceWriteConn) {
	src := &spliceReadConn{r: bytes.NewReader(wire)}
	fc := protocol.NewFramedConn(src, protocol.NewShapeBudget())
	return &keepAliveStream{Conn: src, up: fc, down: fc, base: src, raw: src}, &spliceWriteConn{}
}

func TestKeepAliveStreamShortResponseStaysFramed(t *testing.T) {
	payloads := [][]byte{[]byte("hello"), []byte("world!!"), bytes.Repeat([]byte("x"), 200)}
	ks, dst := newKeepAliveStream(buildFramedWire(payloads))

	if _, err := ks.SpliceTo(dst); err != nil {
		t.Fatalf("SpliceTo() error = %v", err)
	}
	want := bytes.Join(payloads, nil)
	if !bytes.Equal(dst.w.Bytes(), want) {
		t.Fatalf("mismatch: got %q, want %q", dst.w.Bytes(), want)
	}
}

func TestKeepAliveStreamFollowsSwitchToRaw(t *testing.T) {
	payloads := [][]byte{[]byte("page"), bytes.Repeat([]byte("y"), 300)}
	wire := buildFramedWire(payloads)
	wire = append(wire, framedRecord(nil, 0xFFFF)...)
	tail := bytes.Repeat([]byte("RAW"), 100)
	wire = append(wire, tail...)

	ks, dst := newKeepAliveStream(wire)

	if _, err := ks.SpliceTo(dst); err != nil {
		t.Fatalf("SpliceTo() error = %v", err)
	}
	want := append(bytes.Join(payloads, nil), tail...)
	if !bytes.Equal(dst.w.Bytes(), want) {
		t.Fatalf("mismatch: got %d bytes, want %d", dst.w.Len(), len(want))
	}
	if ks.down.StreamDone() {
		t.Error("stream marked done after following the switch to raw")
	}
}

type poolConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *poolConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func newPoolConn(t *testing.T, wire []byte) *poolConn {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	go func() {
		if _, err := remote.Write(wire); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, remote)
	}()
	return &poolConn{Conn: local}
}

// Wire the server sends for a short answer: data records, then the end marker.
func shortAnswerWire(payloads [][]byte) []byte {
	var w bytes.Buffer
	for _, p := range payloads {
		w.Write(framedRecord(p, -1))
	}
	w.Write(framedRecord(nil, 0))
	return w.Bytes()
}

func TestKeepAliveStreamReturnsConnectionToPool(t *testing.T) {
	m := newTestManager(t)
	base := newPoolConn(t, shortAnswerWire([][]byte{[]byte("page"), []byte("body")}))
	fc := protocol.NewFramedConn(base, protocol.NewShapeBudget())
	ks := &keepAliveStream{Conn: base, up: fc, down: fc, m: m, base: base}

	var got bytes.Buffer
	sink := &spliceWriteConn{}
	if _, err := ks.SpliceTo(sink); err != nil {
		t.Fatalf("SpliceTo() error = %v", err)
	}
	got.Write(sink.w.Bytes())
	if got.String() != "pagebody" {
		t.Fatalf("payload = %q, want %q", got.String(), "pagebody")
	}

	if err := ks.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	// The connection joins the set once the drain finishes, which is off the
	// closing path.
	pooled := 0
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.idle.mu.Lock()
		pooled = len(m.idle.conns)
		m.idle.mu.Unlock()
		if pooled == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if base.closed.Load() {
		t.Error("connection was closed instead of pooled")
	}
	if pooled != 1 {
		t.Fatalf("idleSet holds %d connections, want 1: without pooling the next stream pays a full handshake", pooled)
	}
}

func TestKeepAliveStreamDiscardsUnfinishedStream(t *testing.T) {
	m := newTestManager(t)
	base := newPoolConn(t, framedRecord([]byte("partial"), -1))
	fc := protocol.NewFramedConn(base, protocol.NewShapeBudget())
	ks := &keepAliveStream{Conn: base, up: fc, down: fc, m: m, base: base}

	var one [4]byte
	if _, err := ks.Read(one[:]); err != nil && err != io.EOF {
		t.Fatalf("Read() error = %v", err)
	}
	_ = ks.Close()

	// Draining happens off the closing path, so give it a moment: an unfinished
	// stream must end up closed, never in the set where the next user would read
	// someone else's tail.
	deadline := time.Now().Add(2 * time.Second)
	for !base.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !base.closed.Load() {
		t.Error("connection stayed open after an unfinished stream")
	}
	m.idle.mu.Lock()
	pooled := len(m.idle.conns)
	m.idle.mu.Unlock()
	if pooled != 0 {
		t.Errorf("idleSet holds %d connections: an unfinished stream was pooled", pooled)
	}
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(DefaultConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return m
}

func TestDisconnectOnFreshManagerIsSafe(t *testing.T) {
	m := newTestManager(t)

	m.Disconnect()

	if got := m.GetState(); got != StateDisconnected {
		t.Errorf("GetState() after Disconnect() = %v, want %v", got, StateDisconnected)
	}
}

func TestRefusedStreamMuxIsRetriedAndComesBack(t *testing.T) {
	m := newTestManager(t)
	for range muxRefusalsToFallback {
		m.noteMuxTransport(true)
	}
	if !m.muxRefused() {
		t.Fatalf("stream-mux stayed on after the server refused %d sessions", muxRefusalsToFallback)
	}
	first := m.muxRefusedFlows.Load()
	for range first {
		m.notePerFlowWhileRefused()
	}
	if m.muxRefused() {
		t.Fatalf("stream-mux was not tried again after %d flows went their own way", first)
	}
	m.noteMuxTransport(true)
	if !m.muxRefused() {
		t.Fatal("a refused retry did not turn stream-mux off again")
	}
	second := m.muxRefusedFlows.Load()
	if second <= first {
		t.Fatalf("the retry wait did not grow after another refusal: %d flows, then %d", first, second)
	}
	for range second {
		m.notePerFlowWhileRefused()
	}
	m.noteMuxTransport(false)
	if m.muxRefused() || m.muxRetries.Load() != 0 || m.muxRefusals.Load() != 0 {
		t.Fatal("a working stream-mux session left the refusal state in place")
	}
}

func TestFallbackRetriesThePrimaryByFlowsAndReturnsOnItsFirstSuccess(t *testing.T) {
	var f fallback
	if f.flow() {
		t.Fatal("a flow asked for a primary retry while nothing rode the fallback")
	}
	if !f.engage() || f.engage() {
		t.Fatal("engage did not report the switch exactly once")
	}
	if got := f.armRetry(); got != fallbackRetryAfterFlows {
		t.Fatalf("the first retry came after %d flows, want %d", got, fallbackRetryAfterFlows)
	}
	for i := int64(1); i < fallbackRetryAfterFlows; i++ {
		if f.flow() {
			t.Fatalf("the primary was retried after %d flows instead of %d", i, fallbackRetryAfterFlows)
		}
	}
	if !f.flow() {
		t.Fatal("the primary was not retried once the flow countdown ran out")
	}
	if got := f.armRetry(); got != 2*fallbackRetryAfterFlows {
		t.Fatalf("a failed retry did not double the wait: %d flows", got)
	}
	for range fallbackRetryDoublings + 2 {
		f.armRetry()
	}
	if got := f.armRetry(); got != fallbackRetryAfterFlows<<fallbackRetryDoublings {
		t.Fatalf("the wait between retries grew past its cap: %d flows", got)
	}
	if !f.primaryWorks() || f.active.Load() {
		t.Fatal("a working primary did not end the fallback")
	}
	f.engage()
	if got := f.armRetry(); got != fallbackRetryAfterFlows {
		t.Fatalf("the retry wait was not reset after the primary worked: %d flows", got)
	}
}

func TestServerIPv6IsDialedOnlyWhenTheKeyHasIt(t *testing.T) {
	m := newTestManager(t)
	m.config.WhisperaAddr = "203.0.113.7:443"
	m.config.IPv6Fallback = true
	m.config.IPv6Only = true
	if addr, v6 := m.selector.serverAddr(context.Background()); v6 || addr != "203.0.113.7:443" {
		t.Fatalf("a key without whispera_ipv6 got dialed at %s (IPv6 %v); existing keys must keep their address", addr, v6)
	}
	if m.noteConnectSilent(false) {
		t.Fatal("a silent IPv4 connect was taken over by IPv6 for a key that has no IPv6 address")
	}

	m.config.IPv6Only = false
	m.config.WhisperaIPv6 = "2001:db8::7"
	if _, v6 := m.selector.serverAddr(context.Background()); v6 {
		t.Fatal("IPv6 was dialed before IPv4 failed, with only the fallback on")
	}
	if !m.noteConnectSilent(false) {
		t.Fatal("a silent IPv4 connect did not move dials to the key's IPv6 address")
	}
	if addr, v6 := m.selector.serverAddr(context.Background()); !v6 || addr != "[2001:db8::7]:443" {
		t.Fatalf("after IPv4 went silent the server was dialed at %s (IPv6 %v)", addr, v6)
	}
	if addr, _ := m.selector.serverAddr(withServerIPv6(context.Background(), false)); addr != "203.0.113.7:443" {
		t.Fatalf("the IPv4 retry dialed %s instead of the IPv4 address", addr)
	}
	m.noteServerAnswered(false)
	if _, v6 := m.selector.serverAddr(context.Background()); v6 {
		t.Fatal("dials stayed on IPv6 after the server answered at its IPv4 address")
	}

	m.config.IPv6Fallback = false
	if m.noteConnectSilent(false) {
		t.Fatal("IPv6 took over with the fallback switched off")
	}
}

func TestUnansweredMuxFlowGoesAgainOnItsOwnConnection(t *testing.T) {
	dead, deadPeer := net.Pipe()
	deadPeer.Close()
	fresh, freshPeer := net.Pipe()
	got := make(chan []byte, 1)
	go func() {
		b := make([]byte, 5)
		_, _ = io.ReadFull(freshPeer, b)
		got <- b
		_, _ = freshPeer.Write([]byte("reply"))
	}()
	c := &replayConn{conn: dead, reopen: func() (net.Conn, error) { return fresh, nil }}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("a write into a stream-mux session the server dropped failed instead of going again on its own connection: %v", err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(c, reply); err != nil || string(reply) != "reply" {
		t.Fatalf("the flow got %q, %v after going again on its own connection", reply, err)
	}
	if sent := <-got; string(sent) != "hello" {
		t.Fatalf("the new connection got %q instead of the bytes the flow had sent", sent)
	}

	answered, answeredPeer := net.Pipe()
	go func() {
		_, _ = answeredPeer.Write([]byte("x"))
		answeredPeer.Close()
	}()
	reopened := false
	c = &replayConn{conn: answered, reopen: func() (net.Conn, error) { reopened = true; return nil, io.EOF }}
	b := make([]byte, 1)
	_, _ = c.Read(b)
	if _, err := c.Read(b); err == nil || reopened {
		t.Fatal("a flow the server had already answered was sent again, which could repeat a request")
	}
}
