package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nekoskin/whispera/common/buf"
	"github.com/nekoskin/whispera/common/cache"
	logger "github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/common/runtime/base"
	"github.com/nekoskin/whispera/common/runtime/interfaces"
	"github.com/nekoskin/whispera/common/targetguard"
	"github.com/nekoskin/whispera/core/protocol"

	xmux "github.com/sagernet/sing-mux"
	singlog "github.com/sagernet/sing/common/logger"
	singM "github.com/sagernet/sing/common/metadata"
	singN "github.com/sagernet/sing/common/network"
	"golang.org/x/net/proxy"
)

func isNormalConnClose(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "read/write on closed pipe") ||
		strings.Contains(msg, "closed pipe") ||
		strings.Contains(msg, "forcibly closed")
}

const (
	ModuleName    = "relay.server"
	ModuleVersion = "1.0.0"
)

type ResponseWriter interface {
	Write(data []byte) error
	RemoteAddr() net.Addr
}
type Config struct {
	EnableTCP     bool
	EnableUDP     bool
	Debug         bool
	UpstreamProxy string
	TargetGuard   *targetguard.Guard
}

func DefaultConfig() *Config {
	return &Config{
		EnableTCP: true,
		EnableUDP: true,
		Debug:     false,
	}
}

func (c *Config) Validate() error {
	return nil
}

var udpCopyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 2+65535)
		return &buf
	},
}

const (
	routeLookupWait = 300 * time.Millisecond
	routeCacheTTL   = time.Minute
	routeCacheSize  = 4096
)

var routeCache = cache.NewLRUCache[[]net.IP](routeCacheSize)

func lookupIPCached(host string) ([]net.IP, error) {
	if ips, err := routeCache.Get(context.Background(), host); err == nil && len(ips) > 0 {
		return ips, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), routeLookupWait)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, a := range addrs {
		ips[i] = a.IP
	}
	_ = routeCache.Set(context.Background(), host, ips, routeCacheTTL)
	return ips, nil
}

const targetDialTimeout = 8 * time.Second

func targetIPs(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	ips, err := lookupIPCached(host)
	if err != nil {
		return nil
	}
	return ips
}

func firstTCPAddr(ips []net.IP, port uint16) net.Addr {
	if len(ips) == 0 {
		return nil
	}
	return &net.TCPAddr{IP: ips[0], Port: int(port)}
}

func (s *Server) dialTarget(dialer proxy.Dialer, network, host string, port uint16, ips []net.IP) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	ctx, cancel := context.WithTimeout(context.Background(), targetDialTimeout)
	defer cancel()
	dial := func(a string) (net.Conn, error) {
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, a)
		}
		return dialer.Dial(network, a)
	}
	if dialer != s.direct || net.ParseIP(host) != nil || len(ips) == 0 {
		return dial(addr)
	}
	var lastErr error
	for _, ip := range preferIPv6(ips) {
		conn, derr := dial(net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

func preferIPv6(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip.To4() == nil {
			out = append(out, ip)
		}
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			out = append(out, ip)
		}
	}
	return out
}

type Server struct {
	*base.Module
	config      *Config
	direct      *net.Dialer
	proxyDialer proxy.Dialer
	router      interfaces.Router
	routerMu    sync.RWMutex

	outboundDial func(ctx context.Context, tag, network, addr string) (net.Conn, error)

	log   *logger.Logger
	mu    sync.RWMutex
	flows *flowTable
}

type copyResult struct {
	n   int64
	err error
	dir string
}

func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	s := &Server{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		log:    logger.Module("relay"),
		flows:  newFlowTable(),
	}

	s.direct = cfg.TargetGuard.Dialer()
	s.proxyDialer = s.direct
	if cfg.UpstreamProxy != "" {
		u, err := url.Parse(cfg.UpstreamProxy)
		if err != nil {
			s.log.Error("Invalid upstream proxy URL: %v", err)
			return nil, fmt.Errorf("invalid upstream proxy URL: %v", err)
		}
		dialer, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			s.log.Error("Failed to create proxy dialer: %v", err)
			return nil, fmt.Errorf("failed to create proxy dialer: %v", err)
		}
		s.proxyDialer = dialer
	}

	return s, nil
}

func (s *Server) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}
	return nil
}

func (s *Server) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	return nil
}

func (s *Server) Stop() error {
	return s.Module.Stop()
}

func (s *Server) SetRouter(r interfaces.Router) {
	s.routerMu.Lock()
	s.router = r
	s.routerMu.Unlock()
}

func (s *Server) SetOutboundDial(fn func(ctx context.Context, tag, network, addr string) (net.Conn, error)) {
	s.mu.Lock()
	s.outboundDial = fn
	s.mu.Unlock()
}

func (s *Server) TargetDialer() *net.Dialer {
	return s.direct
}

func (s *Server) SetProxyDialer(d proxy.Dialer) {
	s.mu.Lock()
	s.proxyDialer = d
	s.mu.Unlock()
}

func (s *Server) HealthCheck() interfaces.HealthStatus {
	return s.Module.HealthCheck()
}

var tunnelTraceSeq uint64

func (s *Server) ServeTunnel(conn net.Conn, streamObf bool) {
	s.serveTunnel(conn, streamObf, "", nil, nil)
}

func (s *Server) ServeTunnelRaw(conn net.Conn, streamObf bool) {
	s.serveTunnel(conn, streamObf, "", nil, nil)
}

func (s *Server) ServeTunnelResilient(conn net.Conn, streamObf bool, user string, secret []byte, onTorrent func()) {
	s.serveTunnel(conn, streamObf, user, secret, onTorrent)
}

func (s *Server) serveTunnel(conn net.Conn, streamObf bool, user string, secret []byte, onTorrent func()) {
	clientID := conn.RemoteAddr().String()
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("PANIC in tunnel session for %s: %v\n%s", clientID, r, debug.Stack())
		}
	}()
	s.runSession(conn, streamObf, user, clientID, onTorrent)
}

func (s *Server) runSession(under net.Conn, streamObf bool, user, clientID string, onTorrent func()) {
	traceID := atomic.AddUint64(&tunnelTraceSeq, 1)
	openFields := []any{"trace_id", traceID, "client", clientID}
	if user != "" {
		openFields = append(openFields, "user", user)
	}
	logger.Trace().Infow("tunnel stream opened", openFields...)

	if tcpConn := buf.RawTCP(under); tcpConn != nil {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	_ = under.SetReadDeadline(time.Now().Add(proxyHeaderWait))
	var first [1]byte
	if _, err := io.ReadFull(under, first[:]); err != nil {
		return
	}
	_ = under.SetReadDeadline(time.Time{})
	under = &sniffedConn{Conn: under, head: first[:]}
	if first[0] <= xmux.Version1 {
		s.serveStreamMux(under, clientID, traceID)
		return
	}

	pad := protocol.NewShapeBudget()
	wait := proxyHeaderWait
	for {
		if !s.handleProxyStream(traceID, user, clientID, under, wait, pad, onTorrent) {
			return
		}
		wait = 0
		traceID = atomic.AddUint64(&tunnelTraceSeq, 1)
	}
}

const (
	proxyHeaderWait = 10 * time.Second

	spliceAfterBytes = 4 << 20
	targetDrainWait  = 5 * time.Second

	spliceReadBuf = 64 << 10
)

type serverSpliceConn struct {
	net.Conn
	up   *protocol.FramedConn
	down *protocol.FramedConn
	raw  net.Conn
	left int64
}

func (c *serverSpliceConn) Read(b []byte) (int, error) { return c.up.Read(b) }

func (c *serverSpliceConn) Write(b []byte) (int, error) { return c.down.Write(b) }

func (c *serverSpliceConn) countTx(n int) {
	if n > 0 {
		if tc, ok := c.Conn.(interface{ CountTx(int) }); ok {
			tc.CountTx(n)
		}
	}
}

func (c *serverSpliceConn) spliceFrom(src net.Conn) (int64, error) {
	var total int64

	pb := buf.New()
	defer pb.Release()
	pre := pb.Extend(spliceReadBuf)
	for c.left > 0 {
		rn, rerr := src.Read(pre)
		if rn > 0 {
			n, werr := c.down.Write(pre[:rn])
			total += int64(n)
			c.left -= int64(n)
			if werr != nil {
				return total, werr
			}
		}
		if rerr != nil {
			return total, rerr
		}
	}
	if err := c.down.SwitchRaw(); err != nil {
		return total, err
	}
	if dst, s := buf.RawTCP(c.raw), buf.RawTCP(src); dst != nil && s != nil {
		n, err := dst.ReadFrom(s)
		c.countTx(int(n))
		return total + n, err
	}
	n, err := io.Copy(c.raw, src)
	c.countTx(int(n))
	return total + n, err
}

type sniffedConn struct {
	net.Conn
	head []byte
}

func (c *sniffedConn) Read(p []byte) (int, error) {
	if len(c.head) > 0 {
		n := copy(p, c.head)
		c.head = c.head[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *sniffedConn) NetConn() net.Conn { return protocol.NetConnOf(c.Conn) }

func (c *sniffedConn) CountTx(n int) {
	if tc, ok := c.Conn.(interface{ CountTx(int) }); ok {
		tc.CountTx(n)
	}
}

func (s *Server) serveStreamMux(under net.Conn, clientID string, traceID uint64) {
	svc, err := xmux.NewService(xmux.ServiceOptions{
		NewStreamContext: func(ctx context.Context, _ net.Conn) context.Context { return ctx },
		Logger:           singlog.NOP(),
		HandlerEx:        &muxHandler{s: s, clientID: clientID, traceID: traceID},
	})
	if err != nil {
		s.log.Error("[T%d] stream-mux init for %s: %v", traceID, clientID, err)
		return
	}
	svc.NewConnectionEx(context.Background(), under, singM.Socksaddr{}, singM.Socksaddr{}, nil)
}

type muxHandler struct {
	s        *Server
	clientID string
	traceID  uint64
}

func (h *muxHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, dest singM.Socksaddr, onClose singN.CloseHandlerFunc) {
	h.serveStream(conn, dest)
	if onClose != nil {
		onClose(nil)
	}
}

func (h *muxHandler) NewPacketConnectionEx(ctx context.Context, conn singN.PacketConn, source, dest singM.Socksaddr, onClose singN.CloseHandlerFunc) {
	conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func (h *muxHandler) serveStream(stream net.Conn, dest singM.Socksaddr) {
	defer stream.Close()
	defer func() {
		if r := recover(); r != nil {
			h.s.log.Error("PANIC in stream-mux stream: %v\n%s", r, debug.Stack())
		}
	}()

	var pb [1]byte
	if _, err := io.ReadFull(stream, pb[:]); err != nil {
		return
	}
	network := "tcp"
	if pb[0] == 0x11 {
		network = "udp"
	}

	addr := dest.Fqdn
	if addr == "" {
		addr = dest.Addr.String()
	}
	port := dest.Port

	ips := h.s.routeIPs(addr)
	dialer, outboundTag, blocked := h.s.resolveProxyDialer(network, addr, port, ips)
	if blocked {
		return
	}
	targetAddr := net.JoinHostPort(addr, strconv.Itoa(int(port)))
	target, err := h.s.dialProxyTarget(outboundTag, network, targetAddr, addr, port, dialer, ips)
	if err != nil {
		logger.Trace().Warnw("stream-mux dial failed", "trace_id", h.traceID, "target", targetAddr, "err", err.Error())
		return
	}
	defer target.Close()

	if tc, ok := target.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(45 * time.Second)
	}

	resCh := make(chan copyResult, 2)
	if network == "udp" {
		h.s.relayUDP(stream, target, resCh)
	} else {
		h.s.relayTCP(stream, target, resCh, nil)
	}
	<-resCh
	<-resCh
}

func (s *Server) dialProxyTarget(outboundTag, network, targetAddr, addr string, port uint16, dialer proxy.Dialer, ips []net.IP) (net.Conn, error) {
	if outboundTag == "" {
		return s.dialTarget(dialer, network, addr, port, ips)
	}
	s.mu.RLock()
	dialFn := s.outboundDial
	s.mu.RUnlock()
	if dialFn == nil {
		return s.dialTarget(dialer, network, addr, port, ips)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), targetDialTimeout)
	defer dcancel()
	return dialFn(dctx, outboundTag, network, targetAddr)
}

func (s *Server) routeIPs(host string) []net.IP {
	s.routerMu.RLock()
	rtr := s.router
	s.routerMu.RUnlock()
	if rtr == nil {
		return nil
	}
	if byAddr, ok := rtr.(interface{ RoutesOnAddress() bool }); ok && !byAddr.RoutesOnAddress() {
		return nil
	}
	return targetIPs(host)
}

func (s *Server) resolveProxyDialer(network, addr string, port uint16, ips []net.IP) (proxy.Dialer, string, bool) {
	if network == "udp" {
		return s.direct, "", false
	}
	s.routerMu.RLock()
	rtr := s.router
	s.routerMu.RUnlock()
	if rtr == nil {
		return s.proxyDialer, "", false
	}
	dest, err := rtr.Route(context.Background(), &interfaces.Packet{DstAddr: firstTCPAddr(ips, port)})
	if err != nil {
		return s.proxyDialer, "", false
	}
	switch dest.Type {
	case interfaces.DestinationDirect:
		return s.direct, "", false
	case interfaces.DestinationBlock:
		return nil, "", true
	default:
		return s.proxyDialer, dest.Tag, false
	}
}

func (s *Server) relayUDP(stream, target net.Conn, resCh chan copyResult) {
	go func() {
		res := copyResult{dir: "up"}
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("PANIC in UDP upstream copy: %v\n%s", r, debug.Stack())
				if res.err == nil {
					res.err = fmt.Errorf("panic in UDP upstream copy: %v", r)
				}
			}
			resCh <- res
		}()
		defer target.Close()
		bufp := udpCopyBufPool.Get().(*[]byte)
		defer udpCopyBufPool.Put(bufp)
		localBuf := *bufp
		hdr := localBuf[:2]
		data := localBuf[2:]
		for {
			if _, err := io.ReadFull(stream, hdr); err != nil {
				res.err = err
				return
			}
			sz := int(binary.BigEndian.Uint16(hdr))
			if sz == 0 || sz > len(data) {
				res.err = fmt.Errorf("invalid UDP frame size %d", sz)
				return
			}
			if _, err := io.ReadFull(stream, data[:sz]); err != nil {
				res.err = err
				return
			}
			if _, err := target.Write(data[:sz]); err != nil {
				res.err = err
				return
			}
			res.n += int64(sz)
		}
	}()
	func() {
		defer stream.Close()
		bufp := udpCopyBufPool.Get().(*[]byte)
		defer udpCopyBufPool.Put(bufp)
		localBuf := *bufp
		var n int64
		for {
			r, err := target.Read(localBuf[2:])
			if r > 0 {
				binary.BigEndian.PutUint16(localBuf[:2], uint16(r))
				if _, werr := stream.Write(localBuf[:2+r]); werr != nil {
					resCh <- copyResult{n, werr, "down"}
					return
				}
				n += int64(r)
			}
			if err != nil {
				resCh <- copyResult{n, err, "down"}
				return
			}
		}
	}()
}

func (s *Server) relayTCP(stream, target net.Conn, resCh chan copyResult, downDone func()) {
	go func() {
		res := copyResult{dir: "up"}
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("PANIC in TCP upstream copy: %v\n%s", r, debug.Stack())
				if res.err == nil {
					res.err = fmt.Errorf("panic in TCP upstream copy: %v", r)
				}
			}
			if res.err != nil {
				target.Close()
			}
			resCh <- res
		}()
		res.n, res.err = buf.Copy(buf.NewReader(stream), buf.NewWriter(target))
		if res.err != nil {
			return
		}

		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
			tc.SetReadDeadline(time.Now().Add(targetDrainWait))
		} else {
			target.Close()
		}
	}()

	var n int64
	var err error
	if sc, ok := stream.(*serverSpliceConn); ok {
		n, err = sc.spliceFrom(target)
	} else {
		n, err = buf.Copy(buf.NewReader(target), buf.NewWriter(stream))
	}
	if tc, ok := stream.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	if downDone != nil && err == nil {
		downDone()
	}
	resCh <- copyResult{n, err, "down"}
}

type proxyStreamHeader struct {
	proto      byte
	splice     bool
	keepAlive  bool
	torrent    bool
	migratable bool
	resume     bool
	token      []byte
	addr       string
	port       uint16
}

func (h proxyStreamHeader) target() string {
	return net.JoinHostPort(h.addr, strconv.Itoa(int(h.port)))
}

const (
	streamProtoUDP   byte = 0x11
	streamHeaderBits      = protocol.SpliceProtoBit | protocol.KeepAliveProtoBit | protocol.TorrentProtoBit
)

func (h proxyStreamHeader) network() string {
	if h.proto == streamProtoUDP {
		return "udp"
	}
	return "tcp"
}

func streamProto(raw byte) (proto byte, migrate bool) {
	proto = raw &^ streamHeaderBits
	if proto == streamProtoUDP {
		return proto, false
	}
	return proto &^ protocol.MigrateProtoBit, proto&protocol.MigrateProtoBit != 0
}

func readProxyStreamHeader(stream net.Conn, wait time.Duration) (proxyStreamHeader, bool) {
	if wait > 0 {
		stream.SetReadDeadline(time.Now().Add(wait))
		defer stream.SetReadDeadline(time.Time{})
	}

	hdr := make([]byte, 3)
	for {
		if _, err := io.ReadFull(stream, hdr); err != nil {
			return proxyStreamHeader{}, false
		}
		if hdr[0] != 0x17 || hdr[1] != 0x03 || hdr[2] != 0x03 {
			break
		}
		if !protocol.SkipFillerRecord(stream) {
			return proxyStreamHeader{}, false
		}
		if wait > 0 {
			stream.SetReadDeadline(time.Now().Add(wait))
		}
	}
	raw := hdr[0]
	addrLen := binary.BigEndian.Uint16(hdr[1:3])
	proto, migrate := streamProto(raw)

	if migrate && addrLen == 0 {
		token := make([]byte, protocol.FlowTokenLen)
		if _, err := io.ReadFull(stream, token); err != nil {
			return proxyStreamHeader{}, false
		}
		return proxyStreamHeader{
			proto:     proto,
			keepAlive: raw&protocol.KeepAliveProtoBit != 0,
			resume:    true,
			token:     token,
		}, true
	}

	if addrLen == 0 || addrLen > 255 {
		return proxyStreamHeader{}, false
	}

	rest := make([]byte, int(addrLen)+2)
	if _, err := io.ReadFull(stream, rest); err != nil {
		return proxyStreamHeader{}, false
	}
	h := proxyStreamHeader{
		proto:     proto,
		splice:    raw&protocol.SpliceProtoBit != 0 && protocol.SpliceEnabled(),
		keepAlive: raw&protocol.KeepAliveProtoBit != 0,
		torrent:   raw&protocol.TorrentProtoBit != 0,
		addr:      string(rest[:addrLen]),
		port:      binary.BigEndian.Uint16(rest[addrLen:]),
	}
	if migrate {
		token := make([]byte, protocol.FlowTokenLen)
		if _, err := io.ReadFull(stream, token); err != nil {
			return proxyStreamHeader{}, false
		}
		h.migratable = true
		h.token = token
	}
	return h, true
}

func spliceWrap(stream net.Conn, framed *protocol.FramedConn, h proxyStreamHeader, tunnelID uint64, targetAddr string, pad *protocol.ShapeBudget) (net.Conn, *protocol.FramedConn) {
	if !h.splice {
		return framed, framed
	}
	raw := protocol.NetConnOf(stream)
	if raw == nil {
		return framed, framed
	}

	left := int64(math.MaxInt64)
	if cpuBusy() {
		left = spliceAfterBytes
	}
	down := protocol.NewFramedConn(raw, pad)
	logger.Trace().Infow("proxy stream spliced", "trace_id", tunnelID, "target", targetAddr, "to_raw_after", left)
	return &serverSpliceConn{Conn: stream, up: framed, down: down, raw: raw, left: left}, down
}

func collectCopyResults(resCh chan copyResult) (up, down int64, firstErr error, firstDir string) {
	for i := 0; i < 2; i++ {
		r := <-resCh
		if r.dir == "up" {
			up = r.n
		} else {
			down = r.n
		}
		if firstErr == nil && r.err != nil && !errors.Is(r.err, io.EOF) {
			firstErr, firstDir = r.err, r.dir
		}
	}
	return up, down, firstErr, firstDir
}

func (s *Server) handleProxyStream(tunnelID uint64, user, clientID string, stream net.Conn, wait time.Duration, pad *protocol.ShapeBudget, onTorrent func()) (reusable bool) {
	defer func() {
		if !reusable {
			stream.Close()
		}
	}()
	defer func() {
		if r := recover(); r != nil {
			reusable = false
			s.log.Error("PANIC in handleProxyStream: %v\n%s", r, debug.Stack())
		}
	}()

	h, ok := readProxyStreamHeader(stream, wait)
	if !ok {
		return false
	}
	if h.torrent && onTorrent != nil {
		onTorrent()
	}
	if h.resume {
		framed := protocol.NewFramedConn(stream, pad)
		ok := s.resume(user, h.token, framed)
		logger.Trace().Infow("flow resume", "trace_id", tunnelID, "user", user, "accepted", ok)
		return false
	}
	targetAddr := h.target()
	network := h.network()

	streamStart := time.Now()
	startFields := []any{
		"trace_id", tunnelID,
		"client", clientID,
		"target", targetAddr,
		"proto", fmt.Sprintf("0x%02x", h.proto),
	}
	if user != "" {
		startFields = append(startFields, "user", user)
	}
	logger.Trace().Infow("proxy stream started", startFields...)

	ips := s.routeIPs(h.addr)
	dialer, outboundTag, blocked := s.resolveProxyDialer(network, h.addr, h.port, ips)
	if blocked {
		return false
	}

	dialStart := time.Now()
	target, err := s.dialProxyTarget(outboundTag, network, targetAddr, h.addr, h.port, dialer, ips)
	dialDur := time.Since(dialStart)
	if err != nil {
		logger.Trace().Warnw("proxy stream dial failed",
			"trace_id", tunnelID,
			"target", targetAddr,
			"dial_ms", dialDur.Milliseconds(),
			"err", err.Error(),
			"err_type", fmt.Sprintf("%T", err),
		)
		return false
	}
	ownTarget := true
	defer func() {
		if ownTarget {
			target.Close()
		}
	}()

	if tcpTarget, ok := target.(*net.TCPConn); ok {
		tcpTarget.SetKeepAlive(true)
		tcpTarget.SetKeepAlivePeriod(45 * time.Second)
	}

	if h.migratable && h.keepAlive && network == "tcp" {
		logger.Trace().Infow("flow migratable start", "trace_id", tunnelID, "user", user, "target", targetAddr)
		framed := protocol.NewFramedConn(stream, pad)
		release := make(chan struct{})
		s.serveMigratable(framed, target, user, h.token, release)
		ownTarget = false
		<-release
		return false
	}

	var framed *protocol.FramedConn
	if h.keepAlive {
		framed = protocol.NewFramedConn(stream, pad)
	}

	var downFramed *protocol.FramedConn
	resCh := make(chan copyResult, 2)
	switch {
	case network == "udp" && framed != nil:

		downFramed = framed
		s.relayUDP(framed, target, resCh)
	case network == "udp":
		s.relayUDP(stream, target, resCh)
	case framed != nil:
		var wrapped net.Conn
		wrapped, downFramed = spliceWrap(stream, framed, h, tunnelID, targetAddr, pad)
		end := downFramed
		s.relayTCP(wrapped, target, resCh, func() { _ = end.EndStream() })
	default:
		s.relayTCP(stream, target, resCh, nil)
	}

	up, down, firstErr, firstDir := collectCopyResults(resCh)
	errField := ""
	if firstErr != nil && !isNormalConnClose(firstErr) && !errors.Is(firstErr, io.EOF) {
		errField = firstErr.Error()
	}
	fields := []any{
		"trace_id", tunnelID,
		"target", targetAddr,
		"up", up,
		"down", down,
		"dial_ms", dialDur.Milliseconds(),
		"dur_ms", time.Since(streamStart).Milliseconds(),
	}
	if user != "" {
		fields = append(fields, "user", user)
	}
	if errField != "" {
		fields = append(fields, "err_dir", firstDir, "err", errField)
	}
	logger.Trace().Infow("proxy stream finished", fields...)

	if downFramed != nil {
		reusable = framed.StreamDone() && !downFramed.SwitchedRaw() && downFramed.EndStream() == nil
	}
	return reusable
}
