package protocol

import (
	"bytes"
	"context"
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nekoskin/whispera/core/protocol/camo"
	quicpkg "github.com/nekoskin/whispera/core/protocol/quic"

	quicgo "github.com/quic-go/quic-go"
	http3 "github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
)

const dialTimeout = 10 * time.Second

const handshakeTimeout = 3 * time.Second

const FastRotateHandshakeTimeout = 2500 * time.Millisecond

const liveResetWindow = 8 * time.Second

type livenessConn struct {
	net.Conn
	onReset     func()
	onOK        func()
	onEnd       func(LiveEnd)
	onHelloSent func()

	reading   atomic.Bool
	moved     atomic.Int64
	down      atomic.Int64
	stalled   atomic.Bool
	midRecord atomic.Bool
	records   recordCursor

	mu            sync.Mutex
	establishedAt time.Time
	established   bool
	closedByUs    bool
	fired         bool
	ended         bool
	frozen        *time.Timer
}

func (c *livenessConn) reportEnd(reset bool) {
	c.mu.Lock()
	if c.frozen != nil {
		c.frozen.Stop()
	}
	if c.ended || !c.established || c.onEnd == nil {
		c.mu.Unlock()
		return
	}
	c.ended = true
	dur := time.Since(c.establishedAt)
	cb := c.onEnd
	c.mu.Unlock()
	cb(LiveEnd{Dur: dur, Moved: c.moved.Load(), Down: c.down.Load(), Reset: reset, Stalled: c.stalled.Load(), MidRecord: c.midRecord.Load()})
}

func (c *livenessConn) watchVolume(b []byte, down int64) {
	if down-int64(len(b)) > volumeFreezeMaxBytes {
		return
	}
	c.records.feed(b)
	inside := c.records.inside()
	c.midRecord.Store(inside)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.established || c.ended || c.onEnd == nil {
		return
	}
	if !inside || !inVolumeWindow(down) {
		if c.frozen != nil {
			c.frozen.Stop()
		}
		return
	}
	if c.frozen == nil {
		c.frozen = time.AfterFunc(StreamStallSilence, c.freezeSeen)
		return
	}
	c.frozen.Reset(StreamStallSilence)
}

func (c *livenessConn) freezeSeen() {
	if !c.midRecord.Load() {
		return
	}
	c.stalled.Store(true)
	c.Close()
}

func (c *livenessConn) NetConn() net.Conn { return c.Conn }

func (c *livenessConn) Note(err error) { c.note(err) }

func (c *livenessConn) markEstablished() {
	c.mu.Lock()
	c.established = true
	c.establishedAt = time.Now()
	c.mu.Unlock()
}

func (c *livenessConn) Read(b []byte) (int, error) {
	if c.onHelloSent != nil && !c.reading.Swap(true) {
		c.onHelloSent()
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.moved.Add(int64(n))
		c.watchVolume(b[:n], c.down.Add(int64(n)))
	}
	if err != nil {
		c.note(err)
	}
	return n, err
}

func (c *livenessConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.moved.Add(int64(n))
	}
	if err != nil {
		c.note(err)
	}
	return n, err
}

func (c *livenessConn) Close() error {
	c.mu.Lock()
	report := c.established && !c.fired && !c.closedByUs
	c.closedByUs = true
	cb := c.onOK
	c.mu.Unlock()
	if report && cb != nil {
		cb()
	}
	c.reportEnd(false)
	return c.Conn.Close()
}

func (c *livenessConn) note(err error) {
	c.mu.Lock()
	if c.fired || !c.established || c.closedByUs || c.onReset == nil {
		c.mu.Unlock()
		return
	}
	if time.Since(c.establishedAt) > liveResetWindow || !isCensorReset(err) {
		c.mu.Unlock()
		return
	}
	c.fired = true
	cb := c.onReset
	c.mu.Unlock()
	cb()
	c.reportEnd(true)
}

func isCensorReset(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "reset") && !strings.Contains(s, "abort")
}

type HandshakeResult int

const (
	HandshakeOK HandshakeResult = iota
	HandshakeResetFast
	HandshakeIncomplete
	HandshakeRejected
	HandshakeError
	HandshakeLocal
)

const handshakeResetBlockThreshold = 15 * time.Millisecond

func classifyHandshake(err error, latency time.Duration) HandshakeResult {
	if err == nil {
		return HandshakeOK
	}
	s := err.Error()
	switch {
	case isLocalDialError(s):
		return HandshakeLocal
	case strings.Contains(s, "served the decoy"):
		return HandshakeLocal
	case strings.Contains(s, "reset"):
		if latency < handshakeResetBlockThreshold {
			return HandshakeResetFast
		}
		return HandshakeError
	case strings.Contains(s, "decoding message"), strings.Contains(s, "bad certificate"),
		strings.Contains(s, "handshake failure"), strings.Contains(s, "alert"):
		return HandshakeRejected
	case strings.Contains(s, "deadline exceeded"), strings.Contains(s, "timeout"):
		return HandshakeIncomplete
	default:
		return HandshakeError
	}
}

func (r HandshakeResult) String() string {
	switch r {
	case HandshakeOK:
		return "ok"
	case HandshakeResetFast:
		return "reset"
	case HandshakeIncomplete:
		return "incomplete"
	case HandshakeRejected:
		return "rejected"
	case HandshakeLocal:
		return "local"
	default:
		return "error"
	}
}

func HandshakeBlocked(r HandshakeResult) bool {
	return r == HandshakeResetFast || r == HandshakeRejected
}

var fragmentBudgets = []int{1, 2, 4, 8}

type HandshakeStrategy struct{}

func NewHandshakeStrategy() *HandshakeStrategy { return &HandshakeStrategy{} }

const (
	armPQStates      = 2
	armMigrateStates = 2
	armShapeStates   = 2
)

func jointBlock(presets int) int {
	if presets < 1 {
		presets = 1
	}
	return presets * len(fragmentBudgets)
}

func JointArmCount(presets int) int {
	return jointBlock(presets) * armPQStates * armMigrateStates * armShapeStates
}

func jointArmBit(arm, below, states int) bool {
	if arm < 0 {
		return false
	}
	return (arm/below)%states == 1
}

func JointArmHello(arm, presets int) int {
	return arm % (jointBlock(presets) * armPQStates)
}

func JointArmMigrates(arm, presets int) bool {
	return jointArmBit(arm, jointBlock(presets)*armPQStates, armMigrateStates)
}

func JointArmShaped(arm, presets int) bool {
	return jointArmBit(arm, jointBlock(presets)*armPQStates*armMigrateStates, armShapeStates)
}

func JointArmParts(arm, presets int) (preset, budget int) {
	if presets < 1 {
		presets = 1
	}
	n := len(fragmentBudgets)
	if arm < 0 || arm >= JointArmCount(presets) {
		return 0, fragmentBudgets[0]
	}
	within := arm % jointBlock(presets)
	return within / n, fragmentBudgets[within%n]
}

func JointArmDropPQ(arm, presets int) bool {
	return jointArmBit(arm, jointBlock(presets), armPQStates)
}

func JointArmFor(preset, records int, dropPQ bool, presets int) (int, bool) {
	if preset < 0 || preset >= presets {
		return 0, false
	}
	for i, b := range fragmentBudgets {
		if b == records {
			arm := preset*len(fragmentBudgets) + i
			if dropPQ {
				arm += jointBlock(presets)
			}
			return arm, true
		}
	}
	return 0, false
}

func JointArmRemap(arm, from, to int) (int, bool) {
	if arm < 0 || arm >= JointArmCount(from) {
		return 0, false
	}
	preset, budget := JointArmParts(arm, from)
	base, ok := JointArmFor(preset, budget, JointArmDropPQ(arm, from), to)
	if !ok {
		return 0, false
	}
	levers := arm / (jointBlock(from) * armPQStates)
	return base + levers*jointBlock(to)*armPQStates, true
}

func JointArmWithPreset(arm, preset int) int {
	n := len(fragmentBudgets)
	block := jointBlock(polPresets())
	pq := arm / block
	return pq*block + preset*n + arm%n
}

func jointArmFits(fragmented bool) func(int) bool {
	return func(arm int) bool {
		return fragmented || fragmentBudgets[arm%len(fragmentBudgets)] == 1
	}
}

func Client(ctx context.Context, cfg *ClientConfig) (net.Conn, error) {
	sessionID := make([]byte, 16)
	if _, err := crand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("whispera: session id: %w", err)
	}
	keys := DeriveKeys(cfg.SharedSecret)
	token := AuthToken(keys.Auth, authTimeless, sessionID)

	sni := sessionSNI(cfg)
	var helloID utls.ClientHelloID
	var helloRaw []byte
	if cfg.HelloID.Client != "" {
		helloID, helloRaw = cfg.HelloID, cfg.HelloRaw
	} else {
		helloID, helloRaw = fingerprint.Session()
	}

	camoKey := camo.DeriveKey(cfg.SharedSecret)

	d := &clientDialer{
		cfg:      cfg,
		sni:      sni,
		camoKey:  camoKey,
		helloID:  helloID,
		helloRaw: helloRaw,
	}

	conn, err := dialPerflow(ctx, d, sessionID, token)
	if err != nil || cfg.Levers == nil {
		return conn, err
	}
	return &leverConn{Conn: conn, levers: *cfg.Levers, arm: cfg.Arm}, nil
}

type clientDialer struct {
	cfg      *ClientConfig
	sni      string
	camoKey  []byte
	helloID  utls.ClientHelloID
	helloRaw []byte

	mu     sync.Mutex
	dialed []net.Conn
	live   *livenessConn
}

func (d *clientDialer) markEstablished() {
	d.mu.Lock()
	live := d.live
	d.mu.Unlock()
	if live != nil {
		live.markEstablished()
	}
}

func (d *clientDialer) dialRaw(ctx context.Context, network, addr string) (net.Conn, error) {
	var rawConn net.Conn
	var err error
	start := time.Now()
	if d.cfg.TCPDialer != nil {
		rawConn, err = d.cfg.TCPDialer(ctx, network, addr)
	} else {
		dl := &net.Dialer{Timeout: dialTimeout, Control: d.cfg.Control}
		rawConn, err = dl.DialContext(ctx, network, addr)
	}
	if err != nil {
		if d.cfg.OnConnectFail != nil {
			latency := time.Since(start)
			d.cfg.OnConnectFail(classifyHandshake(err, latency), connectSymptom(err), latency)
		}
		return nil, err
	}
	if d.cfg.OnConnected != nil {
		d.cfg.OnConnected(rawConn.LocalAddr(), rawConn.RemoteAddr(), time.Since(start))
	}
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(time.Duration(30+mrand.Intn(61)) * time.Second)
		tcpConn.SetNoDelay(true)
	}
	lc := &livenessConn{Conn: rawConn, onReset: d.cfg.OnLiveReset, onOK: d.cfg.OnLiveOK, onEnd: d.cfg.OnLiveEnd, onHelloSent: d.cfg.OnHelloSent}
	d.mu.Lock()
	d.live = lc
	d.mu.Unlock()
	return lc, nil
}

func (d *clientDialer) selectorFor(uConn *utls.UConn, keyShare []byte) ([camo.SelectorSize]byte, bool) {
	var none [camo.SelectorSize]byte
	if d.cfg.ServerSelPub == "" || len(d.cfg.SharedSecret) != 32 {
		return none, false
	}
	rawPub, err := base64.StdEncoding.DecodeString(d.cfg.ServerSelPub)
	if err != nil || len(rawPub) != 32 {
		return none, false
	}
	serverPub, err := ecdh.X25519().NewPublicKey(rawPub)
	if err != nil {
		return none, false
	}
	ks := uConn.HandshakeState.State13.KeyShareKeys
	if ks == nil {
		return none, false
	}
	for _, cand := range []*ecdh.PrivateKey{ks.Ecdhe, ks.MlkemEcdhe} {
		if cand == nil || !bytes.Equal(cand.PublicKey().Bytes(), keyShare) {
			continue
		}
		sel, err := camo.BuildSelector(d.cfg.SharedSecret, cand, serverPub)
		if err != nil {
			return none, false
		}
		return sel, true
	}
	return none, false
}

func (d *clientDialer) tlsHandshake(ctx context.Context, rawConn net.Conn, useSpec bool) (*utls.UConn, error) {
	uCfg := &utls.Config{
		ServerName:                         d.sni,
		InsecureSkipVerify:                 true,
		PreferSkipResumptionOnNilExtension: true,
	}
	if d.cfg.ServerCertPin != "" || d.cfg.ServerIDPub != "" {
		uCfg.VerifyPeerCertificate = certVerifier(d.cfg.ServerCertPin, d.cfg.ServerIDPub, d.sni, d.cfg.OnServerSelPub)
	}
	if d.camoKey == nil {
		if sc, ok := d.cfg.SessionCache.(utls.ClientSessionCache); ok {
			uCfg.ClientSessionCache = sc
		}
	}
	var spec *utls.ClientHelloSpec
	if useSpec && len(d.helloRaw) > 0 {
		s, err := fingerprint.SpecFromRaw(d.helloRaw)
		if err != nil {
			return nil, fmt.Errorf("whispera: fingerprint: %w", err)
		}
		hasSNI := false
		for _, ext := range s.Extensions {
			if sni, ok := ext.(*utls.SNIExtension); ok {
				sni.ServerName = d.sni
				hasSNI = true
			}
		}
		if !hasSNI && d.sni != "" {
			s.Extensions = append([]utls.TLSExtension{&utls.SNIExtension{ServerName: d.sni}}, s.Extensions...)
		}
		spec = s
	} else {
		id := d.helloID
		if id == utls.HelloCustom {
			id = fingerprint.PresetAt(0)
		}
		s, err := fingerprint.SpecFor(id)
		if err != nil {
			return nil, fmt.Errorf("whispera: fingerprint: %w", err)
		}
		spec = s
	}
	if (d.cfg != nil && d.cfg.DropPQ) || fingerprint.DropPQEnabled() {
		fingerprint.DropPQKeyShares(spec)
	}
	if (d.cfg != nil && d.cfg.DropECH) || fingerprint.DropECHEnabled() {
		fingerprint.DropECH(spec)
	}
	if protos, ok := fingerprint.ForcedALPN(); ok {
		fingerprint.SetALPN(spec, protos)
	}
	uConn := utls.UClient(rawConn, uCfg, utls.HelloCustom)
	if err := uConn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("whispera: apply fingerprint: %w", err)
	}
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("whispera: build hello: %w", err)
	}
	if d.camoKey != nil {
		if hello := uConn.HandshakeState.Hello; hello != nil && len(hello.Random) == 32 {
			if keyShare := camo.ExtractX25519KeyShare(hello.KeyShares); len(keyShare) > 0 {
				if sel, ok := d.selectorFor(uConn, keyShare); ok {
					camo.WriteRandomStamp(hello.Random, sel, d.camoKey, keyShare, time.Now().Unix())
				} else {
					marker := camo.BuildStamp(d.camoKey, keyShare, time.Now().Unix())
					copy(hello.Random, marker[:])
				}
			}
		}
	}
	start := time.Now()
	hsErr := uConn.HandshakeContext(ctx)
	if d.cfg.OnHandshake != nil {
		latency := time.Since(start)
		result := classifyHandshake(hsErr, latency)
		d.cfg.OnHandshake(result, helloSymptom(result, hsErr), latency)
	}
	if hsErr != nil {
		return nil, fmt.Errorf("whispera: utls handshake: %w", hsErr)
	}
	return uConn, nil
}

func (d *clientDialer) handshakeWithin(ctx context.Context, rawConn net.Conn, useSpec bool) (*utls.UConn, error) {
	timeout := handshakeTimeout
	if d.cfg.HandshakeTimeout > 0 {
		timeout = d.cfg.HandshakeTimeout
	}
	hsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.tlsHandshake(hsCtx, rawConn, useSpec)
}

func helloRetryWorthwhile(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	return !errors.Is(err, os.ErrDeadlineExceeded)
}

const helloRedialGap = 500 * time.Millisecond

func (d *clientDialer) dialTLS(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	started := time.Now()
	rawConn, err := d.dialRaw(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	uConn, err := d.handshakeWithin(ctx, rawConn, true)
	if err != nil && len(d.helloRaw) > 0 && helloRetryWorthwhile(ctx, err) {
		rawConn.Close()
		wait := time.NewTimer(time.Until(started.Add(helloRedialGap)))
		select {
		case <-ctx.Done():
			wait.Stop()
			return nil, ctx.Err()
		case <-wait.C:
		}
		rawConn, err = d.dialRaw(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		uConn, err = d.handshakeWithin(ctx, rawConn, false)
	}
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	d.mu.Lock()
	d.dialed = append(d.dialed, uConn)
	d.mu.Unlock()
	return uConn, nil
}

func dialPerflow(ctx context.Context, d *clientDialer, sessionID []byte, token string) (net.Conn, error) {
	uConn, err := d.dialTLS(ctx, "tcp", d.cfg.ServerAddr, nil)
	if err != nil {
		return nil, err
	}
	pre := make([]byte, 0, 1+len(sessionID)+2+len(token))
	pre = append(pre, perflowMagic)
	pre = append(pre, sessionID...)
	pre = binary.BigEndian.AppendUint16(pre, uint16(len(token)))
	pre = append(pre, token...)
	for off := 0; off < len(pre); {
		n := len(pre) - off
		if n > 16 {
			n = 8 + mrand.Intn(n-8)
		}
		if _, err := uConn.Write(pre[off : off+n]); err != nil {
			uConn.Close()
			return nil, err
		}
		off += n
	}
	d.markEstablished()
	logTransportMode("perflow")
	return uConn, nil
}

var ErrQUICFlowsUnsupported = errors.New("whispera: the server does not carry flows over QUIC")

type QUICLane struct {
	conn   *quicgo.Conn
	client *http3.ClientConn
	cfg    *ClientConfig
	sni    string
	flows  bool
}

func DialQUICLane(ctx context.Context, cfg *ClientConfig) (*QUICLane, error) {
	if cfg.QUICAddr == "" {
		return nil, fmt.Errorf("whispera: no QUIC address configured")
	}
	sni := sessionSNI(cfg)
	conn, err := dialQUIC(ctx, cfg, sni)
	if err != nil {
		return nil, fmt.Errorf("whispera: QUIC dial: %w", err)
	}
	lane := &QUICLane{
		conn:   conn,
		client: (&http3.Transport{DisableCompression: true}).NewClientConn(conn),
		cfg:    cfg,
		sni:    sni,
	}
	req, err := lane.request(ctx, rtDatagramTokenHeader)
	if err != nil {
		lane.Close()
		return nil, err
	}
	resp, err := lane.client.RoundTrip(req)
	if err != nil {
		lane.Close()
		return nil, fmt.Errorf("whispera: rt datagram register: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		lane.Close()
		return nil, fmt.Errorf("whispera: rt datagram register: status %d", resp.StatusCode)
	}
	lane.flows = resp.Header.Get(rtFlowsHeader) == rtFlowsActive
	go func() {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
	}()
	if cfg.OnQUICConn != nil {
		cfg.OnQUICConn(conn)
	}
	logTransportMode("rt-datagrams")
	return lane, nil
}

func dialQUIC(ctx context.Context, cfg *ClientConfig, sni string) (*quicgo.Conn, error) {
	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}
	if cfg.ServerCertPin != "" || cfg.ServerIDPub != "" {
		tlsCfg.VerifyPeerCertificate = certVerifier(cfg.ServerCertPin, cfg.ServerIDPub, sni, cfg.OnServerSelPub)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.QUICAddr)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: cfg.Control}
	packetConn, err := lc.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}
	pconn := packetConn.(*net.UDPConn)
	if camoKey := camo.DeriveKey(cfg.SharedSecret); camoKey != nil {
		if probe, perr := quicpkg.BuildCamoProbe(camoKey, sni); perr == nil {
			_, _ = pconn.WriteToUDP(probe, udpAddr)
		}
	}
	conn, err := quicgo.Dial(ctx, pconn, udpAddr, tlsCfg, chromeLikeQUICConfig())
	if err != nil {
		pconn.Close()
		return nil, err
	}
	context.AfterFunc(conn.Context(), func() { pconn.Close() })
	return conn, nil
}

func (l *QUICLane) request(ctx context.Context, tokenHeader string) (*http.Request, error) {
	sessionID := make([]byte, 16)
	if _, err := crand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("whispera: session id: %w", err)
	}
	token := AuthToken(DeriveKeys(l.cfg.SharedSecret).Auth, authTimeless, sessionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://%s/", l.cfg.QUICAddr), http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Host = l.sni
	req.Header.Set(tokenHeader, "Bearer "+token)
	req.Header.Set(rtDatagramSessionHeader, hex.EncodeToString(sessionID))
	return req, nil
}

func (l *QUICLane) Flows() bool { return l.flows }

func (l *QUICLane) Done() <-chan struct{} { return l.conn.Context().Done() }

func (l *QUICLane) Close() { _ = l.conn.CloseWithError(0, "") }

func (l *QUICLane) OpenFlow(ctx context.Context) (net.Conn, error) {
	if !l.flows {
		return nil, ErrQUICFlowsUnsupported
	}
	str, err := l.client.OpenRequestStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("whispera: QUIC flow stream: %w", err)
	}
	flow := &quicFlowConn{str: str, conn: l.conn}
	stop := context.AfterFunc(ctx, flow.abort)
	defer stop()
	req, err := l.request(ctx, rtFlowTokenHeader)
	if err != nil {
		flow.abort()
		return nil, err
	}
	if err := str.SendRequestHeader(req); err != nil {
		flow.abort()
		return nil, fmt.Errorf("whispera: QUIC flow request: %w", err)
	}
	resp, err := str.ReadResponse()
	if err != nil {
		flow.abort()
		return nil, fmt.Errorf("whispera: QUIC flow response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get(rtFlowsHeader) != rtFlowsActive {
		flow.abort()
		return nil, ErrQUICFlowsUnsupported
	}
	return flow, nil
}

type quicFlowConn struct {
	str  *http3.RequestStream
	conn *quicgo.Conn
}

func (c *quicFlowConn) abort() {
	c.str.CancelRead(quicgo.StreamErrorCode(http3.ErrCodeRequestCanceled))
	c.str.CancelWrite(quicgo.StreamErrorCode(http3.ErrCodeRequestCanceled))
}

func (c *quicFlowConn) Read(b []byte) (int, error)  { return c.str.Read(b) }
func (c *quicFlowConn) Write(b []byte) (int, error) { return c.str.Write(b) }

func (c *quicFlowConn) Close() error {
	c.str.CancelRead(quicgo.StreamErrorCode(http3.ErrCodeNoError))
	return c.str.Close()
}

func (c *quicFlowConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *quicFlowConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *quicFlowConn) SetDeadline(t time.Time) error      { return c.str.SetDeadline(t) }
func (c *quicFlowConn) SetReadDeadline(t time.Time) error  { return c.str.SetReadDeadline(t) }
func (c *quicFlowConn) SetWriteDeadline(t time.Time) error { return c.str.SetWriteDeadline(t) }
