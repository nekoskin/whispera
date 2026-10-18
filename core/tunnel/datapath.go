package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"os"
	"strconv"
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
	return dial(ctx)
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
		Dialer:   camoDialer{m},
		Logger:   singlog.NOP(),
		Protocol: "smux",
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

func (m *Manager) connectPerFlow(ctx context.Context) error {
	dial := m.dial()
	if dial == nil {
		err := fmt.Errorf("direct: no camo dialer")
		m.setError(err)
		return err
	}
	probe, err := dialWithRetry(ctx, dial)
	if err != nil {
		m.setError(err)
		return err
	}
	m.idle.reopen()
	if protocol.KeepAliveEnabled() {
		m.idle.put(probe)
	} else {
		probe.Close()
	}

	m.setState(StateConnected)
	m.connMu.Lock()
	m.connectedAt = time.Now()
	m.connMu.Unlock()

	m.selector.startDatagramLane()
	return nil
}

func (m *Manager) openStreamPerFlow(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	dial := m.dial()
	if dial == nil {
		return nil, fmt.Errorf("direct: no camo dialer")
	}
	limitedDial := func(ctx context.Context) (net.Conn, error) { return m.dialLimit(ctx, dial) }
	wantSplice := proto&protocol.SpliceProtoBit != 0
	proto &^= protocol.SpliceProtoBit

	keepAlive := protocol.KeepAliveEnabled()

	var conn net.Conn
	reused := false
	if keepAlive {
		if c := m.idle.take(); c != nil {
			conn, reused = c, true
		}
	}
	if conn == nil {
		c, err := dialWithRetry(ctx, limitedDial)
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
	if keepAlive && !splice && proto != protoUDP && protocol.MigrateEnabled() {
		if t, err := protocol.NewFlowToken(); err == nil {
			flowToken = t
			hdrProto |= protocol.MigrateProtoBit
		}
	}

	addrBytes := []byte(addr)
	header := make([]byte, 1+2+len(addrBytes)+2+len(flowToken))
	header[0] = hdrProto
	binary.BigEndian.PutUint16(header[1:3], uint16(len(addrBytes)))
	copy(header[3:], addrBytes)
	binary.BigEndian.PutUint16(header[3+len(addrBytes):], port)
	copy(header[3+len(addrBytes)+2:], flowToken)
	if _, err := conn.Write(header); err != nil {
		conn.Close()
		if !reused {
			return nil, fmt.Errorf("direct connect header: %w", err)
		}
		fresh, derr := dialWithRetry(ctx, limitedDial)
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
		return newDecoyLeaveConn(conn), nil
	}
	base := newDecoyLeaveConn(conn)
	pad := shapeBudgetOf(base)
	up := protocol.NewFramedConn(base, pad)
	down := up
	stream := &keepAliveStream{Conn: base, up: up, down: down, m: m, base: base}
	if splice {
		stream.down = protocol.NewFramedConn(raw, pad)
		stream.raw = raw
	}
	if len(flowToken) > 0 {
		stream.pad = pad
		stream.token = flowToken
		stream.ctx = ctx
		stream.resumeDial = func(ctx context.Context) (net.Conn, error) {
			return dialWithRetry(ctx, limitedDial)
		}
	}
	return stream, nil
}

const flowDialAttempts = 3

func dialWithRetry(ctx context.Context, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	var err error
	for attempt := 0; attempt < flowDialAttempts; attempt++ {
		var conn net.Conn
		if conn, err = dial(ctx); err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
	}
	return nil, err
}

func (m *Manager) dialLimit(ctx context.Context, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	if !m.flowCB.Allow() {
		return nil, errors.New("circuit breaker open")
	}
	select {
	case m.dialSem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	c, err := dial(ctx)
	<-m.dialSem
	switch {
	case err == nil:
		m.flowCB.Success()
	case isConnectError(err):
		m.flowCB.Fail()
	}
	return c, err
}

func isConnectError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
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

func (m *Manager) OpenStream(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	if protocol.StreamMuxEnabled() {
		return m.openStreamMux(ctx, proto, addr, port)
	}
	return m.openStreamPerFlow(ctx, proto, addr, port)
}

const (
	protoTCP = 0x06
	protoUDP = 0x11
)

func (m *Manager) dial() func(context.Context) (net.Conn, error) { return m.selector.dial() }

func (m *Manager) GetState() TunnelState { return m.sm.Get() }
