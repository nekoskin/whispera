package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	mrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	singlog "github.com/sagernet/sing/common/logger"

	xmux "github.com/sagernet/sing-mux"
	singM "github.com/sagernet/sing/common/metadata"

	"github.com/nekoskin/whispera/core/protocol"
)

type camoDialer struct{ m *Manager }

func (d camoDialer) DialContext(ctx context.Context, network string, dest singM.Socksaddr) (net.Conn, error) {
	dial := d.m.dial()
	if dial == nil {
		return nil, fmt.Errorf("stream-mux: no whispera dialer")
	}
	c, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	return &muxTransport{Conn: c, m: d.m, opened: time.Now()}, nil
}

const (
	muxRefuseWindow       = 3 * time.Second
	muxRefusalsToFallback = 3
	muxRetryAfterFlows    = 256
	muxRetryDoublings     = 4

	fallbackRetryAfterFlows = 32
	fallbackRetryDoublings  = 4
)

type muxTransport struct {
	net.Conn
	m      *Manager
	opened time.Time
	read   atomic.Int64
	ended  atomic.Bool
}

func (t *muxTransport) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 && t.read.Add(int64(n)) == int64(n) {
		t.m.noteMuxTransport(false)
	}
	if err != nil && t.ended.CompareAndSwap(false, true) && t.read.Load() == 0 {
		t.m.noteMuxTransport(time.Since(t.opened) < muxRefuseWindow)
	}
	return n, err
}

func (t *muxTransport) Close() error {
	t.ended.Store(true)
	return t.Conn.Close()
}

func (t *muxTransport) NetConn() net.Conn { return t.Conn }

func (m *Manager) muxRefused() bool {
	return m.muxRefusedFlows.Load() > 0
}

func (m *Manager) notePerFlowWhileRefused() {
	for {
		left := m.muxRefusedFlows.Load()
		if left <= 0 || m.muxRefusedFlows.CompareAndSwap(left, left-1) {
			return
		}
	}
}

func (m *Manager) useStreamMux() bool {
	return !m.muxRefused() && protocol.StreamMuxEnabled()
}

func (m *Manager) muxOverflowOn() bool {
	return os.Getenv("WHISPERA_STREAM_MUX") != "0"
}

func (m *Manager) noteMuxOverflow() {
	if m.muxOverflowed.CompareAndSwap(false, true) {
		stdlog.Printf("[INFO] new flows arrived while a handshake to the server was still running or %d had gone out within %s, so they share a stream-mux session until the handshakes pause", helloChainSafe, helloChainGap+helloChainSlack)
	}
}

func (m *Manager) noteMuxTransport(refused bool) {
	m.muxProven.Store(!refused)
	if !refused {
		m.muxRefusals.Store(0)
		if m.muxRetries.Swap(0) > 0 {
			stdlog.Printf("[INFO] the server speaks stream-mux now, so new flows overflow into stream-mux again")
		}
		return
	}
	if m.muxRefused() {
		return
	}
	if m.muxRefusals.Add(1) < muxRefusalsToFallback && m.muxRetries.Load() == 0 {
		return
	}
	flows := int64(muxRetryAfterFlows) << min(m.muxRetries.Load(), muxRetryDoublings)
	if !m.muxRefusedFlows.CompareAndSwap(0, flows) {
		return
	}
	m.muxRetries.Add(1)
	m.idle.reopen()
	m.selector.startDatagramLane()
	stdlog.Printf("[WARN] the server closed stream-mux sessions right after the handshake without sending a byte, so it does not speak stream-mux: each flow gets its own connection, at most %d handshakes in a quick chain, and stream-mux is tried again after %d more flows", helloChainSafe, flows)
}

func (d camoDialer) ListenPacket(ctx context.Context, dest singM.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("stream-mux: udp not supported")
}

func (m *Manager) getStreamMuxClient() (*xmux.Client, error) {
	m.smMu.Lock()
	defer m.smMu.Unlock()
	if m.smClient != nil {
		return m.smClient, nil
	}
	c, err := xmux.NewClient(xmux.Options{
		Dialer:         camoDialer{m},
		Logger:         singlog.NOP(),
		Protocol:       "smux",
		MaxConnections: streamMuxConnections,
		Padding:        true,
	})
	if err != nil {
		return nil, err
	}
	m.smClient = c
	return c, nil
}

type decoyLeaveConn struct {
	net.Conn
	denyChecked bool
	upLeft      int
	recCap      int
	replicate   bool
	pad         *protocol.ShapeBudget
	acct        *downAcct
}

type downAcct struct{ down atomic.Int64 }

const downstreamCapDefault = 7 << 10

var downstreamCapBytes = downstreamCap()

func downstreamCap() int64 {
	if v := os.Getenv("WHISPERA_DOWNSTREAM_CAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return int64(n)
		}
	}
	return downstreamCapDefault
}

var openingProfile = []int{31, 40, 53, 64, 71, 96, 110, 118, 130}

func drawOpeningSize() int {
	return openingProfile[mrand.Intn(len(openingProfile))]
}

const openingSizeMax = 130

func openingShape() (writes, recCap int, replicate bool) {
	if os.Getenv("WHISPERA_OPENING_RESHAPE") == "0" {
		return 3, 480, false
	}
	return upstreamShapedWrites, openingSizeMax, true
}

func newDecoyLeaveConn(conn net.Conn) *decoyLeaveConn {
	writes, recCap, replicate := openingShape()
	acct := &downAcct{}
	if inner, ok := conn.(*decoyLeaveConn); ok && inner.acct != nil {
		acct = inner.acct
	}
	return &decoyLeaveConn{Conn: conn, upLeft: writes, recCap: recCap, replicate: replicate, pad: protocol.NewShapeBudget(), acct: acct}
}

func (d *decoyLeaveConn) NetConn() net.Conn {
	if nc, ok := d.Conn.(interface{ NetConn() net.Conn }); ok {
		return nc.NetConn()
	}
	return nil
}

func (d *decoyLeaveConn) Levers() (protocol.ConnLevers, bool) { return protocol.LeversOf(d.Conn) }

func (d *decoyLeaveConn) Arm() (int, bool) { return protocol.ArmOf(d.Conn) }

func (d *decoyLeaveConn) Read(b []byte) (int, error) {
	n, err := d.Conn.Read(b)
	if !d.denyChecked && n > 0 {
		d.denyChecked = true
		if msg, ok := protocol.ParseDenial(b[:n]); ok {
			d.Conn.Close()
			return 0, errors.New("whispera: " + msg)
		}
	}
	return n, err
}

func (d *decoyLeaveConn) Write(b []byte) (int, error) {
	return d.writeShaped(b)
}

func (d *decoyLeaveConn) writeShaped(b []byte) (int, error) {
	written := 0
	for len(b) > 0 {
		n := len(b)
		cut := d.upLeft > 0 && n > d.recCap
		if cut {
			if d.replicate {
				n = drawOpeningSize()
			} else {
				n = d.recCap
			}
			if n > len(b) {
				n = len(b)
			}
		}
		c, err := d.Conn.Write(b[:n])
		written += c
		if err != nil {
			return written, err
		}
		if cut {
			d.upLeft--
		}
		b = b[n:]
	}
	return written, nil
}

func (d *decoyLeaveConn) Close() error { return d.Conn.Close() }

type perFlowStream struct {
	*decoyLeaveConn
	lastRead atomic.Int64
	sawEnd   atomic.Bool
}

func newPerFlowStream(base *decoyLeaveConn) *perFlowStream {
	s := &perFlowStream{decoyLeaveConn: base}
	s.lastRead.Store(time.Now().UnixNano())
	return s
}

func (s *perFlowStream) Read(b []byte) (int, error) {
	n, err := s.decoyLeaveConn.Read(b)
	if n > 0 {
		s.lastRead.Store(time.Now().UnixNano())
	}
	if errors.Is(err, io.EOF) {
		s.sawEnd.Store(true)
	}
	return n, err
}

func (s *perFlowStream) Close() error {
	if !s.sawEnd.Load() && time.Since(time.Unix(0, s.lastRead.Load())) >= protocol.StreamStallSilence {
		protocol.NoteStall(s.decoyLeaveConn)
	}
	return s.decoyLeaveConn.Close()
}

func (m *Manager) connectPerFlow(ctx context.Context) error {
	dial := m.dial()
	if dial == nil {
		err := fmt.Errorf("direct: no camo dialer")
		m.setError(err)
		return err
	}
	m.selector.startDatagramLane()
	probe, err := dialWithRetry(ctx, dial)
	if err != nil && !m.connectOverQUIC(ctx) {
		m.setError(err)
		return err
	}
	m.idle.reopen()
	if err == nil {
		if protocol.KeepAliveEnabled() {
			m.idle.put(probe)
		} else {
			probe.Close()
		}
	}

	m.setState(StateConnected)
	m.connMu.Lock()
	m.connectedAt = time.Now()
	m.connMu.Unlock()
	return nil
}

func (m *Manager) connectOverQUIC(ctx context.Context) bool {
	if errors.Is(ctx.Err(), context.Canceled) {
		return false
	}
	m.noteTCPFailed()
	lane, err := m.selector.quicLane(ctx)
	if err != nil || !lane.Flows() {
		return false
	}
	m.noteTCPDown()
	return true
}

func (m *Manager) openStreamPerFlow(ctx context.Context, proto byte, addr string, port uint16, overflow bool) (net.Conn, error) {
	dial := m.dial()
	if dial == nil {
		return nil, fmt.Errorf("direct: no camo dialer")
	}
	dialCtx := ctx
	if overflow {
		dialCtx = withChainGuard(ctx, chainOverflow)
	}
	wantSplice := proto&protocol.SpliceProtoBit != 0
	proto &^= protocol.SpliceProtoBit

	keepAlive := protocol.KeepAliveEnabled()

	var conn net.Conn
	reused := false
	if keepAlive {
		if c := m.idle.take(m.selector.leversFit); c != nil {
			conn, reused = c, true
		}
	}
	if conn == nil {
		c, err := dialWithRetry(dialCtx, dial)
		if err != nil {
			return nil, fmt.Errorf("direct dial: %w", err)
		}
		conn = c
	}

	raw := protocol.NetConnOf(conn)
	splice := wantSplice && protocol.SpliceEnabled() && raw != nil && !protocol.FullFrameEnabled()

	hdrProto := proto
	if keepAlive {
		hdrProto |= protocol.KeepAliveProtoBit
	}
	if splice {
		hdrProto |= protocol.SpliceProtoBit
	}

	var flowToken []byte
	levers, _ := protocol.LeversOf(conn)
	if keepAlive && !splice && proto != protoUDP && (protocol.MigrateEnabled() || levers.Migrate) {
		if t, err := protocol.NewFlowToken(); err == nil {
			flowToken = t
			hdrProto |= protocol.MigrateProtoBit
		}
	}

	header := flowHeader(hdrProto, addr, port, flowToken)
	if _, err := conn.Write(header); err != nil {
		conn.Close()
		if !reused {
			return nil, fmt.Errorf("direct connect header: %w", err)
		}
		fresh, derr := dialWithRetry(dialCtx, dial)
		if derr != nil {
			return nil, fmt.Errorf("direct dial: %w", derr)
		}
		conn = fresh
		raw = protocol.NetConnOf(conn)
		splice = wantSplice && protocol.SpliceEnabled() && raw != nil && !protocol.FullFrameEnabled()
		if _, err := conn.Write(header); err != nil {
			conn.Close()
			return nil, fmt.Errorf("direct connect header: %w", err)
		}
	}

	if !keepAlive {
		return newPerFlowStream(newDecoyLeaveConn(conn)), nil
	}
	base := newDecoyLeaveConn(conn)
	pad := shapeBudgetOf(base)
	up := protocol.NewFramedConnFilling(base, pad)
	if levers, ok := protocol.LeversOf(conn); ok {
		up.ShapeRecords(levers.Shaped)
	}
	down := up
	stream := &keepAliveStream{Conn: base, up: up, down: down, m: m, base: base}
	stream.lastRead.Store(time.Now().UnixNano())
	if splice {
		stream.down = protocol.NewFramedConn(raw, pad)
		stream.raw = raw
	}
	if len(flowToken) > 0 {
		stream.pad = pad
		stream.token = flowToken
		stream.ctx = ctx
		arm, chosen := protocol.ArmOf(conn)
		stream.resumeDial = func(ctx context.Context) (net.Conn, error) {
			if chosen {
				ctx = withResumedArm(ctx, arm)
			}
			return dialWithRetry(ctx, dial)
		}
	}
	return stream, nil
}

func flowHeader(proto byte, addr string, port uint16, token []byte) []byte {
	addrBytes := []byte(addr)
	header := make([]byte, 1+2+len(addrBytes)+2+len(token))
	header[0] = proto
	binary.BigEndian.PutUint16(header[1:3], uint16(len(addrBytes)))
	copy(header[3:], addrBytes)
	binary.BigEndian.PutUint16(header[3+len(addrBytes):], port)
	copy(header[3+len(addrBytes)+2:], token)
	return header
}

func (m *Manager) openStreamQUIC(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	lane, err := m.selector.quicLane(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := lane.OpenFlow(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(flowHeader(proto&^protocol.SpliceProtoBit, addr, port, nil)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("QUIC flow header: %w", err)
	}
	return conn, nil
}

type fallback struct {
	active  atomic.Bool
	failed  atomic.Bool
	retries atomic.Int32
	flows   atomic.Int64
}

func (f *fallback) primaryWorks() bool {
	f.failed.Store(false)
	if !f.active.Swap(false) {
		return false
	}
	f.retries.Store(0)
	return true
}

func (f *fallback) engage() bool {
	if f.active.Swap(true) {
		return false
	}
	f.flows.Store(0)
	return true
}

func (f *fallback) flow() bool { return f.active.Load() && f.flows.Add(-1) == 0 }

func (f *fallback) armRetry() int64 {
	flows := int64(fallbackRetryAfterFlows) << min(f.retries.Add(1)-1, fallbackRetryDoublings)
	f.flows.Store(flows)
	return flows
}

func (m *Manager) retryPrimary(ctx context.Context, f *fallback, failed string) {
	dial := m.dial()
	if dial == nil {
		return
	}
	conn, err := dial(ctx)
	if err == nil {
		if protocol.KeepAliveEnabled() {
			m.idle.put(conn)
		} else {
			conn.Close()
		}
		return
	}
	stdlog.Printf(failed, err, f.armRetry())
}

func (m *Manager) noteFlow() {
	if m.overQUIC.flow() {
		safeGo("TCPRetry", m.retryTCP)
	}
	if m.overIPv6.flow() {
		safeGo("IPv4Retry", m.retryIPv4)
	}
}

func (m *Manager) retryTCP() {
	m.retryPrimary(context.Background(), &m.overQUIC, "[WARN] a handshake to the server over TCP failed again (%v), so flows stay on QUIC and TCP is tried again after %d more flows")
}

func (m *Manager) retryIPv4() {
	m.retryPrimary(withServerIPv6(context.Background(), false), &m.overIPv6, "[WARN] the server's IPv4 address still does not answer (%v), so dials stay on IPv6 and IPv4 is tried again after %d more flows")
}

func (m *Manager) noteServerAnswered(overIPv6 bool) {
	if !overIPv6 && m.overIPv6.primaryWorks() {
		stdlog.Printf("[INFO] the server answers at its IPv4 address again, so dials go back to IPv4")
	}
	if m.overQUIC.primaryWorks() {
		stdlog.Printf("[INFO] a handshake to the server over TCP worked again, so new flows leave QUIC for TCP")
	}
}

func (m *Manager) noteConnectSilent(overIPv6 bool) bool {
	if !m.ipv6Switchable() {
		return false
	}
	if overIPv6 {
		if m.overIPv6.active.Swap(false) {
			stdlog.Printf("[WARN] the server does not answer at its IPv6 address either, so dials go back to IPv4")
		}
		return false
	}
	if !m.overIPv6.engage() {
		return true
	}
	m.dropServerConns()
	stdlog.Printf("[WARN] connects to the server's IPv4 address get no answer, so dials go to its IPv6 address %s and IPv4 is tried again after %d flows", m.config.WhisperaIPv6, m.overIPv6.armRetry())
	return true
}

func (m *Manager) dropServerConns() {
	m.idle.closeAll()
	m.idle.reopen()
	m.smMu.Lock()
	client := m.smClient
	m.smClient = nil
	m.smMu.Unlock()
	if client != nil {
		client.Close()
	}
}

type serverIPv6Key struct{}

func withServerIPv6(ctx context.Context, on bool) context.Context {
	return context.WithValue(ctx, serverIPv6Key{}, on)
}

func (m *Manager) serverIPv6() string { return strings.Trim(m.config.WhisperaIPv6, "[]") }

func (m *Manager) ipv6Switchable() bool {
	return m.serverIPv6() != "" && m.config.IPv6Fallback && !m.config.IPv6Only
}

func (m *Manager) dialsIPv6(ctx context.Context) bool {
	if m.serverIPv6() == "" {
		if m.config.IPv6Only && !m.ipv6Missing.Swap(true) {
			stdlog.Printf("[WARN] IPv6 only is on, but the key has no IPv6 address for the server (whispera_ipv6), so it is dialed at the address the key gives")
		}
		return false
	}
	if on, ok := ctx.Value(serverIPv6Key{}).(bool); ok {
		return on
	}
	return m.config.IPv6Only || m.config.IPv6Fallback && m.overIPv6.active.Load()
}

func (m *Manager) onIPv6(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return net.JoinHostPort(m.serverIPv6(), port)
}

func (m *Manager) quicAddr() string {
	if m.dialsIPv6(context.Background()) {
		return m.onIPv6(m.config.WhisperaQUICAddr)
	}
	return m.config.WhisperaQUICAddr
}

func (m *Manager) noteDialFailed(overIPv6, connectFailed, deadNet bool) {
	if connectFailed && m.noteConnectSilent(overIPv6) {
		return
	}
	if connectFailed || deadNet {
		m.noteTCPFailed()
	}
}

func (m *Manager) noteTCPFailed() {
	m.overQUIC.failed.Store(true)
	m.selector.startDatagramLane()
	if lane := m.selector.currentLane(); lane != nil && lane.Flows() {
		m.noteTCPDown()
	}
}

func (m *Manager) noteQUICLaneUp(lane *protocol.QUICLane) {
	if !lane.Flows() {
		if !m.quicNoFlows.Swap(true) {
			stdlog.Printf("[WARN] the server does not carry TCP flows over QUIC, so they have nowhere to go while TCP to it is dead")
		}
		return
	}
	m.quicNoFlows.Store(false)
	if m.overQUIC.failed.Load() {
		m.noteTCPDown()
	}
}

func (m *Manager) noteTCPDown() {
	if !m.overQUIC.engage() {
		return
	}
	stdlog.Printf("[WARN] a handshake to the server over TCP failed while QUIC to it works, so flows ride QUIC streams until a TCP handshake works again")
	safeGo("TCPRetry", m.retryTCP)
}

const (
	flowDialAttempts = 5
	flowDialBackoff  = helloChainGap + helloChainSlack
)

func dialWithRetry(ctx context.Context, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	var err error
	for attempt := 0; attempt < flowDialAttempts; attempt++ {
		started := time.Now()
		var conn net.Conn
		if conn, err = dial(ctx); err == nil {
			return conn, nil
		}
		if ctx.Err() != nil || errors.Is(err, errHelloNoRoom) || attempt == flowDialAttempts-1 {
			return nil, err
		}
		if !sleepUntil(ctx, started.Add(flowRetryPause(attempt))) {
			return nil, err
		}
	}
	return nil, err
}

func flowRetryPause(attempt int) time.Duration {
	pause := flowDialBackoff << attempt
	return pause + time.Duration(mrand.Int63n(int64(pause/4)+1))
}

func sleepUntil(ctx context.Context, deadline time.Time) bool {
	pause := time.Until(deadline)
	if pause <= 0 {
		return true
	}
	t := time.NewTimer(pause)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

const upstreamShapedWrites = 24

func (m *Manager) connectStreamMux(ctx context.Context) error {
	if _, err := m.getStreamMuxClient(); err != nil {
		m.setError(err)
		return err
	}
	dial := m.dial()
	if dial == nil {
		err := fmt.Errorf("stream-mux: no whispera dialer")
		m.setError(err)
		return err
	}
	probe, err := dialWithRetry(ctx, dial)
	if err != nil {
		m.setError(err)
		return err
	}
	probe.Close()

	m.setState(StateConnected)
	m.connMu.Lock()
	m.connectedAt = time.Now()
	m.connMu.Unlock()
	log.Warn("stream-mux mode active (h2mux) — yamux pool bypassed")
	return nil
}

func (m *Manager) openStreamMux(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	c, err := m.getStreamMuxClient()
	if err != nil {
		return nil, err
	}
	conn, err := c.DialContext(ctx, "tcp", singM.ParseSocksaddrHostPort(addr, port))
	if err != nil {
		if ctx.Err() == nil {
			m.setError(err)
		}
		return nil, fmt.Errorf("stream-mux dial: %w", err)
	}
	if _, err := conn.Write([]byte{proto}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("stream-mux proto write: %w", err)
	}
	return newDecoyLeaveConn(conn), nil
}

func shapeBudgetOf(c net.Conn) *protocol.ShapeBudget {
	if d, ok := c.(*decoyLeaveConn); ok {
		return d.pad
	}
	return protocol.NewShapeBudget()
}

const streamMuxConnections = 2

func (m *Manager) OpenStream(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	m.noteFlow()
	if m.overQUIC.active.Load() {
		if conn, err := m.openStreamQUIC(ctx, proto, addr, port); err == nil {
			return conn, nil
		}
	}
	conn, err := m.openStreamTCP(ctx, proto, addr, port)
	if err == nil || ctx.Err() != nil || !m.overQUIC.failed.Load() {
		return conn, err
	}
	quicConn, qerr := m.openStreamQUIC(ctx, proto, addr, port)
	if qerr != nil {
		return nil, err
	}
	m.noteTCPDown()
	return quicConn, nil
}

func (m *Manager) openStreamTCP(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	if m.useStreamMux() {
		return m.openStreamMux(ctx, proto, addr, port)
	}
	if !m.muxOverflowOn() {
		return m.openStreamPerFlow(ctx, proto, addr, port, false)
	}
	held := withChainGuard(ctx, chainHold)
	conn, err := m.openStreamPerFlow(held, proto, addr, port, !m.muxRefused())
	if err == nil {
		m.notePerFlowWhileRefused()
	}
	if !errors.Is(err, errHelloNoRoom) {
		return conn, err
	}
	m.noteMuxOverflow()
	if m.muxProven.Load() {
		return m.openStreamMux(held, proto, addr, port)
	}
	perFlow := func() (net.Conn, error) {
		return m.openStreamPerFlow(withChainGuard(context.WithoutCancel(ctx), chainHold), proto, addr, port, false)
	}
	conn, err = m.openStreamMux(held, proto, addr, port)
	if err != nil {
		return perFlow()
	}
	return &replayConn{conn: conn, reopen: perFlow}, nil
}

const muxReplayLimit = 64 << 10

type replayConn struct {
	mu       sync.Mutex
	conn     net.Conn
	reopen   func() (net.Conn, error)
	sent     []byte
	answered atomic.Bool
}

func (c *replayConn) current() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

func (c *replayConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.reopen != nil && !c.answered.Load() {
		if len(c.sent)+len(b) <= muxReplayLimit {
			c.sent = append(c.sent, b...)
		} else {
			c.reopen, c.sent = nil, nil
		}
	}
	conn := c.conn
	c.mu.Unlock()
	n, err := conn.Write(b)
	if err != nil && c.replay(conn) {
		return len(b), nil
	}
	return n, err
}

func (c *replayConn) Read(b []byte) (int, error) {
	conn := c.current()
	n, err := conn.Read(b)
	if n > 0 {
		if !c.answered.Swap(true) {
			c.mu.Lock()
			c.reopen, c.sent = nil, nil
			c.mu.Unlock()
		}
		return n, err
	}
	if err != nil && c.replay(conn) {
		return c.Read(b)
	}
	return n, err
}

func (c *replayConn) replay(failed net.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != failed {
		return true
	}
	if c.reopen == nil || c.answered.Load() {
		return false
	}
	reopen := c.reopen
	c.reopen = nil
	fresh, err := reopen()
	if err != nil {
		return false
	}
	if _, err := fresh.Write(c.sent); err != nil {
		fresh.Close()
		return false
	}
	failed.Close()
	c.conn, c.sent = fresh, nil
	stdlog.Printf("[INFO] a flow sent into a stream-mux session the server closed unanswered went again on its own connection")
	return true
}

func (c *replayConn) Close() error                       { return c.current().Close() }
func (c *replayConn) LocalAddr() net.Addr                { return c.current().LocalAddr() }
func (c *replayConn) RemoteAddr() net.Addr               { return c.current().RemoteAddr() }
func (c *replayConn) SetDeadline(t time.Time) error      { return c.current().SetDeadline(t) }
func (c *replayConn) SetReadDeadline(t time.Time) error  { return c.current().SetReadDeadline(t) }
func (c *replayConn) SetWriteDeadline(t time.Time) error { return c.current().SetWriteDeadline(t) }

const (
	protoTCP = 0x06
	protoUDP = 0x11
)

func (m *Manager) dial() func(context.Context) (net.Conn, error) { return m.selector.dial() }

func (m *Manager) GetState() TunnelState { return m.sm.Get() }
