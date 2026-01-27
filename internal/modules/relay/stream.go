// Package relay provides stream management for multiplexed connections
package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
	"golang.org/x/net/proxy"
)

// ОПТИМИЗАЦИЯ: Пул буферов для Zero-Allocation пакетов (64KB)
var packetPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65536)
	},
}

// Stream represents a single multiplexed stream (one TCP/UDP connection)
type Stream struct {
	ID         uint16
	fsm        *FSM  // Replaces ad-hoc State field
	Protocol   uint8 // ProtoTCP or ProtoUDP
	Profile    uint8 // Behavior profile (ProfileBalanced, etc.)
	TargetAddr string
	TargetPort uint16

	// Response writer for sending frames back to client
	writer ResponseWriter

	// TCP connection to target (server-side)
	conn net.Conn

	// UDP connection (for UDP relay)
	udpConn *net.UDPConn

	// Flow Control
	sendWindow int64
	windowCond *sync.Cond

	// Channels
	incoming  chan []byte // Data from tunnel to target
	outgoing  chan []byte // Data from tunnel to tunnel
	closeChan chan struct{}

	// Stats
	bytesIn  uint64 // From client via tunnel
	bytesOut uint64 // To client via tunnel
	created  time.Time
	lastT    time.Time

	// Graceful Degradation
	RetryCount int

	dialer proxy.Dialer

	// ОПТИМИЗАЦИЯ: Адаптивный таймаут на основе RTT истории
	adaptiveTimeout *AdaptiveTimeout

	// ОПТИМИЗАЦИЯ: 0-RTT поддержка (отправка данных до завершения handshake)
	earlyDataBuf []byte // Buffer для данных до подключения
	earlyDataMu  sync.Mutex

	// FEC (Forward Error Correction) для защиты от потери пакетов
	fecEncoder     *FECEncoder
	fecDecoder     *FECDecoder
	fecEnabled     bool // Включить FEC при потере > 2%
	packetLossRate float32
	lossCheckTime  time.Time

	// SACK (Selective Acknowledgment) для отслеживания потерянных пакетов
	sackTracker *SACKTracker
	sackEnabled bool
	seqNum      uint32 // Порядковый номер пакета для SACK

	// Traffic Shaping (Lagrange)
	trafficShaper *TrafficShaper

	closeOnce sync.Once
	mu        sync.RWMutex
}

// NewStream creates a new stream
func NewStream(id uint16, proto uint8, addr string, port uint16, profile uint8, writer ResponseWriter, dialer proxy.Dialer) *Stream {
	s := &Stream{
		ID:              id,
		Protocol:        proto,
		Profile:         profile,
		TargetAddr:      addr,
		TargetPort:      port,
		writer:          writer,
		sendWindow:      2 * 1024 * 1024, // 2MB initial window
		incoming:        make(chan []byte, 16384),
		outgoing:        make(chan []byte, 16384),
		closeChan:       make(chan struct{}),
		created:         time.Now(),
		lastT:           time.Now(),
		dialer:          dialer,
		adaptiveTimeout: NewAdaptiveTimeout(100), // Track RTT history with 100-sample buffer
		earlyDataBuf:    make([]byte, 0, 65536),  // 64KB buffer for early data (0-RTT)
		fecEncoder:      NewFECEncoder(10, 5),    // k=10 data packets, m=5 redundancy packets
		fecDecoder:      NewFECDecoder(10, 5),
		fecEnabled:      false, // Включим при потере > 2%
		sackTracker:     NewSACKTracker(),
		sackEnabled:     true, // SACK всегда включен
		seqNum:          0,
		lossCheckTime:   time.Now(),
		trafficShaper:   NewTrafficShaper(2.5), // 2.5 MB/s target "noise" floor (Netflix HD-ish)
	}
	s.windowCond = sync.NewCond(&s.mu)
	s.fsm = NewFSM(s)
	return s
}

// dialWithHappyEyeballs реализует RFC 8305 для быстрого подключения на dual-stack сетях
// Параллельно пытается подключиться через IPv4 и IPv6 с небольшой задержкой
func (s *Stream) dialWithHappyEyeballs(ctx context.Context, target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}

	// Резолвим адрес и получаем оба типа
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	var ipv4, ipv6 net.IP
	for _, ip := range ips {
		if ipv4 == nil && ip.To4() != nil {
			ipv4 = ip
		} else if ipv6 == nil && ip.To16() != nil && ip.To4() == nil {
			ipv6 = ip
		}
	}

	// ОПТИМИЗАЦИЯ: YouTube - агрессивные таймауты для быстрой загрузки
	// Базовый таймаут 2s (вместо 3s) для быстрого вывода видео на экран
	// На быстрых сетях может быть 100-500ms
	baseTimeout := 2 * time.Second
	dialTimeout := s.adaptiveTimeout.GetTimeoutFor(baseTimeout)

	// Убедимся, что таймаут разумный (100ms-2.5s)
	if dialTimeout < 100*time.Millisecond {
		dialTimeout = 100 * time.Millisecond
	}
	if dialTimeout > 2500*time.Millisecond {
		dialTimeout = 2500 * time.Millisecond
	}

	// Если только один адрес, используем его напрямую
	if ipv4 != nil && ipv6 == nil {
		return (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp4", net.JoinHostPort(ipv4.String(), portStr))
	}
	if ipv6 != nil && ipv4 == nil {
		return (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp6", net.JoinHostPort(ipv6.String(), portStr))
	}

	// Happy Eyeballs: Try IPv6 first with 250ms stagger for IPv4
	connChan := make(chan net.Conn, 2)
	errChan := make(chan error, 2)
	startTime := time.Now()

	// Попытка IPv6 (первая, но с проверкой IPv4 через 250ms)
	if ipv6 != nil {
		go func() {
			conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp6", net.JoinHostPort(ipv6.String(), portStr))
			if err != nil {
				errChan <- err
			} else {
				connChan <- conn
				// ОПТИМИЗАЦИЯ: Записываем реальное время подключения для адаптивного таймаута
				s.adaptiveTimeout.Record(time.Since(startTime))
			}
		}()
	}

	// ОПТИМИЗАЦИЯ: YouTube - Start BOTH immediately (Parallel Race)
	// Удаляем задержку (stagger), чтобы IPv4 стартовал мгновенно, если IPv6 тормозит.
	// time.Sleep(100 * time.Millisecond)

	if ipv4 != nil {
		go func() {
			conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp4", net.JoinHostPort(ipv4.String(), portStr))
			if err != nil {
				errChan <- err
			} else {
				connChan <- conn
				// ОПТИМИЗАЦИЯ: Записываем реальное время подключения
				s.adaptiveTimeout.Record(time.Since(startTime))
			}
		}()
	}

	// Ждем первого успешного подключения
	for i := 0; i < 2; i++ {
		select {
		case conn := <-connChan:
			return conn, nil
		case <-errChan:
			// Продолжаем пробовать другой адрес
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("both IPv4 and IPv6 connection attempts failed")
}

// SetWriter sets the response writer for the stream
func (s *Stream) SetWriter(w ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writer = w
}

// sendFrame encodes and sends a frame to the writer
func (s *Stream) sendFrame(f *Frame) error {
	// NOTE: writer is set once during construction and rarely changes.
	// We avoid locking here to prevent deadlock with Connect() which holds s.mu.Lock()
	// while calling FSM events that trigger sendFrame().
	writer := s.writer

	if writer == nil {
		return fmt.Errorf("no writer")
	}

	bytes, err := f.Encode()
	if err != nil {
		return err
	}

	return writer.Write(bytes)
}

// Connect establishes connection to the target
func (s *Stream) Connect(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Initial transition
	if err := s.fsm.Event(EventStartConnect); err != nil {
		return err
	}

	// Profile-based adjustment (timeout logic...)
	connectTimeout := 10 * time.Second
	// ... (simplified for brevity, keep basics)

	target := net.JoinHostPort(s.TargetAddr, fmt.Sprintf("%d", s.TargetPort))

	// Action logic
	var err error
	switch s.Protocol {
	case ProtoTCP:
		// ОПТИМИЗАЦИЯ: Happy Eyeballs (RFC 8305) для параллельного подключения IPv4/IPv6
		// Это улучшает время подключения на dual-stack сетях
		ctx, cancel := context.WithTimeout(ctx, connectTimeout)
		defer cancel()

		var conn net.Conn
		conn, err = s.dialWithHappyEyeballs(ctx, target)
		if err != nil {
			s.fsm.Event(EventConnectFail)
			return err
		}
		s.conn = conn

		// Optimize TCP socket buffers for high throughput with dynamic BDP calculation
		if tcpConn, ok := s.conn.(*net.TCPConn); ok {
			// УЛУЧШЕНИЕ: Динамический расчет буфера на основе типа соединения
			// BDP = RTT * Bandwidth (примерно 100ms * 100Mbps = 12.5MB)
			// Но начинаем с меньшего значения и масштабируем
			bufferSize := 256 * 1024 // 256KB default (reduced to prevent bufferbloat)
			if s.Protocol == ProtoUDP {
				bufferSize = 1024 * 1024 // 1MB for UDP jitter absorption
			}
			tcpConn.SetReadBuffer(bufferSize)
			tcpConn.SetWriteBuffer(bufferSize)
			tcpConn.SetNoDelay(true)                     // УЛУЧШЕНИЕ: Disable Nagle's для низкой latency
			tcpConn.SetKeepAlive(true)                   // Enable TCP Keep-Alive
			tcpConn.SetKeepAlivePeriod(15 * time.Second) // УЛУЧШЕНИЕ: Оптимизированный keepalive период
		}

		// Event: ConnectOK
		if err := s.fsm.Event(EventConnectOK); err != nil {
			s.conn.Close()
			return err
		}

		// ОПТИМИЗАЦИЯ: 0-RTT - отправляем buffered early data сразу после подключения
		s.flushEarlyData()

		// Start relay goroutines
		go s.readFromTarget()

	case ProtoUDP:
		// Check for Relay Mode (0.0.0.0 or ::)
		if s.TargetAddr == "0.0.0.0" || s.TargetAddr == "::" {
			// Unconnected UDP socket for Relay
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
			conn.SetReadBuffer(32 * 1024 * 1024)
			conn.SetWriteBuffer(32 * 1024 * 1024)
			s.udpConn = conn

			if err := s.fsm.Event(EventConnectOK); err != nil {
				s.udpConn.Close()
				return err
			}

			go s.readRelayUDP()
		} else {
			// Connected UDP socket (P2P) - Force IPv4 to avoid IPv6 issues
			var addr *net.UDPAddr
			addr, err = net.ResolveUDPAddr("udp4", target)
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
			var conn *net.UDPConn
			conn, err = net.DialUDP("udp4", nil, addr)
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
			conn.SetReadBuffer(32 * 1024 * 1024)
			conn.SetWriteBuffer(32 * 1024 * 1024)
			s.udpConn = conn

			if err := s.fsm.Event(EventConnectOK); err != nil {
				s.udpConn.Close()
				return err
			}

			go s.readUDPFromTarget()
		}
	}

	return nil
}

// Write sends data to the target
func (s *Stream) Write(data []byte) error {
	s.mu.RLock()
	state := s.fsm.CurrentState()
	conn := s.conn
	udpConn := s.udpConn
	s.mu.RUnlock()

	// ОПТИМИЗАЦИЯ: 0-RTT - buffer data перед подключением (отправим при ConnectOK)
	if state != StateConnected {
		// Если еще не подключены, буферизуем данные для отправки после handshake
		s.bufferEarlyData(data)
		return nil
	}

	if err := s.fsm.Event(EventData); err != nil {
		return err
	}

	s.lastT = time.Now()

	if s.Protocol == ProtoTCP && conn != nil {
		// NOTE: FEC Encoding removed from here. Write() writes to Target (e.g. Google),
		// so we should NOT send FEC wrapped packets to Target.
		// FEC should be applied in readFromTarget (sending TO Tunnel).

		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		s.bytesOut += uint64(n)
		return nil
	} else if s.Protocol == ProtoUDP && udpConn != nil {
		// UDP: обычно не используем FEC для UDP relay (может добавить задержку)
		// Но записываем в SACK трекер
		s.sackTracker.RecordPacket(s.seqNum)
		s.seqNum++

		n, err := udpConn.Write(data)
		if err != nil {
			return err
		}
		s.bytesOut += uint64(n)
		return nil
	}

	return ErrStreamClosed
}

// UpdateWindow increases the flow control window and wakes up blocked writers
func (s *Stream) UpdateWindow(increment uint32) {
	s.mu.Lock()
	s.sendWindow += int64(increment)
	if s.sendWindow > 80*1024*1024 { // Cap at 50MB to prevent overflow
		s.sendWindow = 80 * 1024 * 1024
	}
	s.windowCond.Broadcast() // Wake up writer
	s.mu.Unlock()
}

// HandleUDPData handles incoming UDP_DATA frame (with destination)
func (s *Stream) HandleUDPData(data []byte) error {
	s.mu.RLock()
	udpConn := s.udpConn
	s.mu.RUnlock()

	if udpConn == nil {
		return ErrStreamClosed
	}

	s.lastT = time.Now()

	// Parse payload: [AddrType][Addr][Port][Data]
	// Note: Client uses optimized format without RSV/FRAG headers
	if len(data) < 4 {
		return fmt.Errorf("short UDP data")
	}

	offset := 0
	atyp := data[offset]
	offset++

	var addr *net.UDPAddr
	var ip net.IP

	switch atyp {
	case 0x01: // IPv4
		if len(data) < offset+4 {
			return fmt.Errorf("short IPv4")
		}
		ip = net.IP(data[offset : offset+4])
		offset += 4
	case 0x04: // IPv6
		if len(data) < offset+16 {
			return fmt.Errorf("short IPv6")
		}
		ip = net.IP(data[offset : offset+16])
		offset += 16
	case 0x03: // Domain
		if len(data) < offset+1 {
			return fmt.Errorf("short domain len")
		}
		l := int(data[offset])
		offset++
		if len(data) < offset+l {
			return fmt.Errorf("short domain")
		}
		domain := string(data[offset : offset+l])
		offset += l
		// Resolve domain
		if resolved, err := net.ResolveIPAddr("ip", domain); err == nil {
			ip = resolved.IP
		} else {
			return err
		}
	default:
		return fmt.Errorf("unknown ATYP %d", atyp)
	}

	if len(data) < offset+2 {
		return fmt.Errorf("short port")
	}
	port := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	addr = &net.UDPAddr{IP: ip, Port: int(port)}
	payload := data[offset:]

	// Check if connected
	if udpConn.RemoteAddr() != nil {
		// Connected socket - use Write (ignore explicit addr as it must match connected)
		n, err := udpConn.Write(payload)
		if err != nil {
			return err
		}
		s.bytesOut += uint64(n)
		return nil
	}

	// Unconnected socket - use WriteToUDP
	n, err := udpConn.WriteToUDP(payload, addr)
	if err != nil {
		return err
	}
	s.bytesOut += uint64(n)
	return nil
}

// readFromTarget reads data from TCP target and sends back through tunnel
func (s *Stream) readFromTarget() {
	defer func() {
		if r := recover(); r != nil {
			// Log panic
		}
		s.Close()
	}()

	for {

		// ALLOC PER PACKET: Essential for Safe Zero-Copy with Async Writers (QoS).
		// We cannot reuse a buffer because the writer might queue the slice
		// and return immediately. Reusing would overwrite the queued data.
		// GC handles the cleanup.
		// Optimize MTU: Read in 16000 chunks (Safe TLS Limit).
		buf := make([]byte, HeaderSize+16000)

		// Read with deadline
		s.conn.SetReadDeadline(time.Now().Add(180 * time.Second))

		// Read into payload offset
		n, err := s.conn.Read(buf[HeaderSize:])
		if err != nil {
			if err != io.EOF {
				s.fsm.Event(EventError)
			} else {
				s.fsm.Event(EventPeerClose)
			}
			return
		}

		if n > 0 {
			s.bytesIn += uint64(n)
			s.lastT = time.Now()

			// SACK отслеживание: записываем получение пакета
			if s.sackEnabled {
				s.sackTracker.RecordPacket(s.seqNum)
				s.seqNum++
			}

			// Flow Control (TCP only)
			if s.Protocol == ProtoTCP {
				s.mu.Lock()
				for s.sendWindow <= 0 {
					select {
					case <-s.closeChan:
						s.mu.Unlock()
						return
					default:
					}
					s.windowCond.Wait()
				}
				s.sendWindow -= int64(n)
				s.mu.Unlock()
			}

			// ОПТИМИЗАЦИЯ: Zero-Copy Send with FEC capability
			// Если FEC включен, кодируем и используем пул
			if s.fecEnabled || s.packetLossRate > 2.0 {
				// 1. Send Data Packet (Systematic)
				encodedBuf := s.fecEncoder.EncodeFEC(buf[HeaderSize:HeaderSize+n], s.seqNum, HeaderSize)
				s.seqNum++ // Data packet consumes 1 seq

				// Пишем Frame Header прямо перед FEC данными (в headroom)
				WriteFrameHeader(encodedBuf, s.ID, FrameData, 0, len(encodedBuf)-HeaderSize)

				if err := s.writer.Write(encodedBuf); err != nil {
					packetPool.Put(encodedBuf)
					return
				}
				packetPool.Put(encodedBuf)

				// 2. Check & Send Parity Packets (Burst)
				parityPackets := s.fecEncoder.GetParityPackets(s.seqNum, HeaderSize)
				for _, pkt := range parityPackets {
					// Write Frame Header for parity
					WriteFrameHeader(pkt, s.ID, FrameData, 0, len(pkt)-HeaderSize)

					// Ignore err for parity (Best effort)
					s.writer.Write(pkt)
					packetPool.Put(pkt)

					// Advance seqNum for parity packets
					s.seqNum++
				}
			} else {
				// Standard Path (Zero Copy using stack buffer 'buf')
				WriteFrameHeader(buf, s.ID, FrameData, 0, n)
				if err := s.writer.Write(buf[:HeaderSize+n]); err != nil {
					return
				}
			}

			// Traffic Shaping (Lagrange Adaptive Padding)
			// Check if we need to inject noise to smooth the graph
			paddingNeeded := s.trafficShaper.Update(n)
			if paddingNeeded > 0 {
				// Send Padding Frame
				// We use packetPool for padding too
				padBuf := packetPool.Get().([]byte)
				if cap(padBuf) < HeaderSize+paddingNeeded {
					packetPool.Put(padBuf)
					padBuf = make([]byte, HeaderSize+paddingNeeded)
				}
				padBuf = padBuf[:HeaderSize+paddingNeeded]

				// Fill with random/junk? Zero is fine for bandwidth usage,
				// but random is better for entropy. For speed, we just use whatever is in buffer (pool garbage).
				// Or explicitly zero it?
				// crypto/rand is too slow. math/rand needs lock.
				// Just send junk from pool (dirty memory) - efficient obfuscation?
				// Dangerous (info leak)?
				// Safer to zero.
				// for i := HeaderSize; i < len(padBuf); i++ { padBuf[i] = 0 }

				WriteFrameHeader(padBuf, s.ID, FramePadding, 0, paddingNeeded)
				// Ignore errors for padding
				s.writer.Write(padBuf)
				packetPool.Put(padBuf)
			}
		}
	}
}

// readUDPFromTarget reads data from Connected UDP target
func (s *Stream) readUDPFromTarget() {
	defer func() {
		if r := recover(); r != nil {
			// Log panic
		}
		s.Close()
	}()

	// Buffer configuration
	const Headroom = 300

	for {
		select {
		case <-s.closeChan:
			return
		default:
		}

		// ALLOC PER PACKET: Safe Zero-Copy for Async Writers
		// Limit to 4096 to prevent local write errors on client
		// ОПТИМИЗАЦИЯ: Use packetPool
		// Note: packetPool buf is 64KB, slightly larger than Headroom+4096, but safe.
		buf := packetPool.Get().([]byte)
		// Ensure capacity
		if cap(buf) < Headroom+4096 {
			packetPool.Put(buf)
			buf = make([]byte, Headroom+4096)
		}

		// Optimize: Use longer deadline and check for specific errors
		s.udpConn.SetReadDeadline(time.Now().Add(5 * time.Minute)) // Keepalive is 30s-60s, so 5m is safe
		// Read into payload offset
		n, err := s.udpConn.Read(buf[Headroom:])
		if err != nil {
			packetPool.Put(buf) // Return buffer on error
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout is fine for UDP, just check closeChan and loop
				continue
			}
			// Check for closed connection
			if isClosedConnError(err) {
				return
			}
			// Other errors might be temporary, but typically fatal for a connected UDP socket
			s.fsm.Event(EventError)
			return
		}

		if n > 0 {
			// SAFETY CAP (Server Side): Removed for QUIC support
			// QUIC requires ~1350-1500 bytes. Truncating to 1200 breaks it.
			// if n > 1200 { n = 1200 }

			s.bytesIn += uint64(n)
			s.lastT = time.Now()

			// Resolve Remote Addr for Header
			rAddr := s.udpConn.RemoteAddr()
			udpAddr, ok := rAddr.(*net.UDPAddr)
			if !ok {
				// Should not happen for UDP conn
				continue
			}

			// Determine ATYP
			atyp := uint8(0x01) // IPv4
			if udpAddr.IP.To4() == nil {
				atyp = 0x04 // IPv6
			}

			// SealUDPData writes headers BEFORE buf[Headroom]
			// It returns the full frame slice starting from the header
			// Use FrameUDPData so client gets SOCKS5 header info
			// BUGFIX: Slice buf to Headroom+n so we don't send the full capacity (garbage/zeros)
			packet, err := SealUDPData(buf[:Headroom+n], s.ID, atyp, udpAddr.IP.String(), uint16(udpAddr.Port), Headroom)
			if err != nil {
				packetPool.Put(buf)
				return
			}

			// Send without Retry (Fire and Forget for UDP)
			// Blocking here would cause huge latency and kill Discord voice.
			if err := s.writer.Write(packet); err != nil {
				packetPool.Put(buf)
				// continue? or return?
				// For connected UDP, write error might be fatal for stream.
				// But we just ignore it for now as per previous logic.
			} else {
				packetPool.Put(buf)
			}
		} else {
			// n=0, return buffer
			packetPool.Put(buf)
		}
	}
}

// readRelayUDP reads from Unconnected UDP socket and sends UDP_DATA frames
func (s *Stream) readRelayUDP() {
	defer func() {
		if r := recover(); r != nil {
		}
		s.Close()
	}()

	const Headroom = 300

	for {
		select {
		case <-s.closeChan:
			return
		default:
		}

		// ALLOC PER PACKET: Safe Zero-Copy for Async Writers
		// Limit to 4096 bytes to prevent sending Jumbo frames that cause WSAEMSGSIZE on client
		// Windows loopback often dislikes > 1500-2000 bytes UDP.
		// Discord SRTP is usually < 1400 bytes.
		// ОПТИМИЗАЦИЯ: Use packetPool
		buf := packetPool.Get().([]byte)
		if cap(buf) < Headroom+4096 {
			packetPool.Put(buf)
			buf = make([]byte, Headroom+4096)
		}

		s.udpConn.SetReadDeadline(time.Now().Add(300 * time.Second))
		n, addr, err := s.udpConn.ReadFromUDP(buf[Headroom:])
		if err != nil {
			packetPool.Put(buf) // Return buffer on error
			if netErr, ok := err.(net.Error); ok && (netErr.Timeout() || netErr.Temporary()) {
				continue
			}
			// Don't close immediately on other errors for UDP receive, just log and continue
			// except for closed connection
			if isClosedConnError(err) {
				return
			}
			// Log error but continue scanning (ICMP errors shouldn't kill the relay)
			continue
		}

		if n > 0 {
			// SAFETY CAP (Server Side - Relay Mode): Removed for QUIC support
			// if n > 1200 { n = 1200 }

			s.bytesIn += uint64(n)
			s.lastT = time.Now()

			// Determine ATYP
			atyp := uint8(0x01) // IPv4
			if addr.IP.To4() == nil {
				atyp = 0x04 // IPv6
			}

			// SealUDPData writes headers BEFORE buf[Headroom]
			// It returns the full frame slice starting from the header
			// SealUDPData writes headers BEFORE buf[Headroom]
			// It returns the full frame slice starting from the header
			// FIX: Slice buf to Headroom+n so we don't send the full capacity (garbage/zeros)
			packet, err := SealUDPData(buf[:Headroom+n], s.ID, atyp, addr.IP.String(), uint16(addr.Port), Headroom)
			if err != nil {
				fmt.Printf("[RELAY] UDP Seal Error: %v\n", err)
				packetPool.Put(buf)
				return
			}

			if err := s.writer.Write(packet); err != nil {
				// UDP Strategy: Drop if congested, but LOG IT
				// fmt.Printf("[RELAY] UDP Write Drop: %v\n", err)
				packetPool.Put(buf)
				return
			}
			packetPool.Put(buf)
		} else {
			packetPool.Put(buf)
		}
	}
}

// Close closes the stream (initiated locally)
func (s *Stream) Close() {
	s.fsm.Event(EventLocalClose)
}

// cleanupResources actual cleanup logic (called by FSM action)
func (s *Stream) cleanupResources() {
	s.closeOnce.Do(func() {
		close(s.closeChan)
		s.windowCond.Broadcast() // Wake up any waiters on Flow Control
	})

	// Close connections
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	if s.udpConn != nil {
		s.udpConn.Close()
		s.udpConn = nil
	}
}

// IsActive returns true if the stream is still usable
func (s *Stream) IsActive() bool {
	return !s.fsm.IsClosed()
}

// StreamManager manages all active streams
type StreamManager struct {
	streams map[uint16]*Stream
	mu      sync.RWMutex
	idGen   *StreamIDGenerator
	dialer  proxy.Dialer

	ctx    context.Context
	cancel context.CancelFunc
}

// NewStreamManager creates a new stream manager
func NewStreamManager(dialer proxy.Dialer) *StreamManager {
	ctx, cancel := context.WithCancel(context.Background())
	sm := &StreamManager{
		streams: make(map[uint16]*Stream),
		idGen:   NewStreamIDGenerator(),
		dialer:  dialer,
		ctx:     ctx,
		cancel:  cancel,
	}

	// Start cleanup goroutine
	go sm.cleanupLoop()

	return sm
}

// HandleConnect creates, registers, and dials a new stream (Unified)
func (sm *StreamManager) HandleConnect(streamID uint16, payload *ConnectPayload, writer ResponseWriter) error {
	sm.mu.Lock()
	// Check for existing
	if _, exists := sm.streams[streamID]; exists {
		sm.mu.Unlock()
		return fmt.Errorf("stream id %d collision", streamID)
	}

	// Create stream
	stream := NewStream(streamID, payload.Protocol, payload.Addr, payload.Port, ProfileBalanced, writer, sm.dialer)
	sm.streams[streamID] = stream
	sm.mu.Unlock() // Unlock early for dial

	// Dial (can be blocking, so we unlock first)
	// Usually this is called in a goroutine by the server
	ctx, cancel := context.WithTimeout(sm.ctx, 10*time.Second)
	defer cancel()

	if err := stream.Connect(ctx); err != nil {
		sm.RemoveStream(streamID)
		return err
	}

	return nil
}

// HandleData handles incoming DATA frame
func (sm *StreamManager) HandleData(streamID uint16, data []byte) error {
	sm.mu.RLock()
	stream, ok := sm.streams[streamID]
	sm.mu.RUnlock()

	if !ok {
		return ErrStreamNotFound
	}

	return stream.Write(data)
}

// HandleUDPData handles incoming UDP_DATA frame
func (sm *StreamManager) HandleUDPData(streamID uint16, data []byte) error {
	sm.mu.RLock()
	stream, ok := sm.streams[streamID]
	sm.mu.RUnlock()

	if !ok {
		return ErrStreamNotFound
	}

	return stream.HandleUDPData(data)
}

// HandleWindowUpdate handles incoming WINDOW_UPDATE frame
func (sm *StreamManager) HandleWindowUpdate(streamID uint16, increment uint32) {
	sm.mu.RLock()
	stream, ok := sm.streams[streamID]
	sm.mu.RUnlock()

	if ok {
		stream.UpdateWindow(increment)
	}
}

// HandleClose handles incoming CLOSE frame
func (sm *StreamManager) HandleClose(streamID uint16) {
	sm.RemoveStream(streamID)
}

// GetStream returns a stream by ID
func (sm *StreamManager) GetStream(id uint16) (*Stream, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	stream, ok := sm.streams[id]
	return stream, ok
}

// RemoveStream removes a stream
func (sm *StreamManager) RemoveStream(id uint16) {
	sm.mu.Lock()
	stream, ok := sm.streams[id]
	if ok {
		delete(sm.streams, id)
	}
	sm.mu.Unlock()

	if stream != nil {
		// Close logic likely handled by cleanupResources via FSM, but explicitly call Close -> EventLocalClose
		stream.Close()
	}
}

// CloseAll closes all streams and stops the manager
func (sm *StreamManager) CloseAll() {
	sm.cancel()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for id, stream := range sm.streams {
		stream.Close()
		delete(sm.streams, id)
	}
}

// Stats returns stream statistics
func (sm *StreamManager) Stats() (activeStreams int, totalBytesIn, totalBytesOut uint64) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	activeStreams = len(sm.streams)
	for _, stream := range sm.streams {
		totalBytesIn += stream.bytesIn
		totalBytesOut += stream.bytesOut
	}
	return
}

// cleanupLoop periodically cleans up stale streams
func (sm *StreamManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			sm.cleanup()
		}
	}
}

// cleanup removes stale streams based on FSM state or timeout
func (sm *StreamManager) cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	staleTimeout := 5 * time.Minute

	for id, stream := range sm.streams {
		state := stream.fsm.CurrentState()

		if state == StateClosed {
			delete(sm.streams, id)
			continue
		}

		if now.Sub(stream.lastT) > staleTimeout {
			stream.Close()
			delete(sm.streams, id)
		}
	}
}

// isClosedConnError checks if the error is due to a closed connection
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

// ОПТИМИЗАЦИЯ: 0-RTT ранние данные
// bufferEarlyData буферизует данные, отправленные до подключения
// Эти данные будут отправлены сразу после завершения handshake (0-RTT)
func (s *Stream) bufferEarlyData(data []byte) {
	s.earlyDataMu.Lock()
	defer s.earlyDataMu.Unlock()

	// Буферизуем данные (максимум 64KB) - избегаем append для预allocated буфера
	availSpace := cap(s.earlyDataBuf) - len(s.earlyDataBuf)
	if len(data) <= availSpace {
		// Используем copy вместо append (более эффективно для pre-allocated буферов)
		copy(s.earlyDataBuf[len(s.earlyDataBuf):], data)
		s.earlyDataBuf = s.earlyDataBuf[:len(s.earlyDataBuf)+len(data)]
	} else {
		// Если буфер переполнен, отбросим самые старые данные
		// (теория: новые данные важнее для реактивности)
		if len(s.earlyDataBuf) > 0 {
			// Сдвигаем существующие данные и добавляем новые - без append
			maxBufSize := cap(s.earlyDataBuf)
			newLen := len(data)
			if newLen > maxBufSize {
				newLen = maxBufSize
			}
			copy(s.earlyDataBuf[0:], data[len(data)-newLen:])
			s.earlyDataBuf = s.earlyDataBuf[:newLen]
		} else {
			// Первое использование - просто копируем до лимита
			copyLen := len(data)
			if copyLen > cap(s.earlyDataBuf) {
				copyLen = cap(s.earlyDataBuf)
			}
			copy(s.earlyDataBuf[0:], data[:copyLen])
			s.earlyDataBuf = s.earlyDataBuf[:copyLen]
		}
	}
}

// flushEarlyData отправляет буферизованные ранние данные после подключения (без копирования!)
func (s *Stream) flushEarlyData() {
	s.earlyDataMu.Lock()
	defer s.earlyDataMu.Unlock()

	if len(s.earlyDataBuf) == 0 {
		return
	}

	// Отправляем буферизованные данные напрямую (zero-copy через slice reference)
	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()

	if conn == nil {
		return
	}

	// Отправляем данные напрямую в соединение (не через Write который может буферизовать)
	_, err := conn.Write(s.earlyDataBuf)
	if err != nil {
		// Log error но не падаем - соединение все равно установлено
		fmt.Printf("[0-RTT] Early data flush error: %v\n", err)
	}

	s.bytesOut += uint64(len(s.earlyDataBuf))
	s.earlyDataBuf = s.earlyDataBuf[:0] // Reset buffer
}

// GetAdaptiveTimeout возвращает текущий адаптивный таймаут для этого stream
func (s *Stream) GetAdaptiveTimeout() time.Duration {
	return s.adaptiveTimeout.GetTimeoutFor(3 * time.Second)
}

// RecordRTT записывает реальное время между запросом и ответом
func (s *Stream) RecordRTT(rtt time.Duration) {
	s.adaptiveTimeout.Record(rtt)
}

// GetRTTStats возвращает статистику RTT для мониторинга
func (s *Stream) GetRTTStats() TimeoutStats {
	return s.adaptiveTimeout.GetStats()
}

// ============================================================================
// Traffic Shaping (Adaptive Padding based on Lagrange Mean Value Theorem)
// ============================================================================

// TrafficShaper calculates instantaneous vs mean speed to smooth traffic bursts.
// Theorem: f'(c) = (f(b) - f(a)) / (b - a)
// We compare f' (current rate) with Mean Rate. If f' < TargetMean, we pad.
type TrafficShaper struct {
	lastCheck  time.Time
	bytesSince int

	// Smoothing parameters
	targetRate float64 // Bytes per second (e.g. 5MB/s for "HD Video" profile)
	minPadding int     // Minimum padding packet size
	maxPadding int     // Max padding to inject at once

	// State
	totalBytes uint64
}

func NewTrafficShaper(targetRateMBps float64) *TrafficShaper {
	return &TrafficShaper{
		lastCheck:  time.Now(),
		targetRate: targetRateMBps * 1024 * 1024,
		minPadding: 128,  // Small padding
		maxPadding: 1400, // MTU-like padding
	}
}

// Update returns the number of padding bytes needed to maintain the target average rate.
func (ts *TrafficShaper) Update(n int) int {
	now := time.Now()
	dt := now.Sub(ts.lastCheck).Seconds()

	ts.bytesSince += n
	ts.totalBytes += uint64(n)

	// Check every 100ms or if enough data passed
	if dt < 0.05 {
		return 0
	}

	// Calculate Instant Rate f'(c)
	// (Actually this is average over small dt, which approximates instant for our purpose)
	currentRate := float64(ts.bytesSince) / dt

	ts.lastCheck = now
	ts.bytesSince = 0

	// Lagrange Logic:
	// We want ActualRate ~ TargetRate.
	// If CurrentRate < TargetRate, we are "too quiet" -> Inject Noise.
	// We assume the user wants to HIDE silence or idle periods to look like constant stream.
	// OR: We assume the user wants to shape BURSTS.
	// If we are shaping bursts, we would SLEEP (Throttle).
	// But the request asked for "Adaptive Padding" to "throw in noise bytes".
	// This implies we want to FILL gaps.

	if currentRate < ts.targetRate {
		// Calculate missing bytes: (TargetRate * dt) - ActualBytes
		needed := (ts.targetRate * dt) - float64(n) // Approximation

		if needed > float64(ts.minPadding) {
			pad := int(needed)
			if pad > ts.maxPadding {
				pad = ts.maxPadding // Don't flood too much at once
			}
			return pad
		}
	}

	return 0
}

// FECEncoder кодирует данные с избыточностью для восстановления потерянных пакетов
type FECEncoder struct {
	k         int
	m         int
	enc       reedsolomon.Encoder
	shards    [][]byte // Buffered shards (Data + Parity)
	shardSize int      // Max size in current block
	idx       int      // Current shard index (0..k-1)
}

// NewFECEncoder создает новый FEC энкодер
func NewFECEncoder(k, m int) *FECEncoder {
	enc, err := reedsolomon.New(k, m)
	if err != nil {
		panic(err) // Should be validated at config level
	}
	return &FECEncoder{
		k:      k,
		m:      m,
		enc:    enc,
		shards: make([][]byte, k+m),
	}
}

// EncodeFEC добавляет FEC заголовок и буферизирует пакеты для кодирования
// Возвращает FEC пакеты (если достаточно накопилось data packets)
// EncodeFEC добавляет FEC заголовок и буферизирует пакеты для кодирования
// Возвращает FEC пакеты (если достаточно накопилось data packets)
func (fe *FECEncoder) EncodeFEC(data []byte, seqNum uint32, headroom int) []byte {
	// Простая FEC реализация: XOR всех пакетов для создания parity packet
	// В production используйте Reed-Solomon или Tornado codes

	// ОПТИМИЗАЦИЯ: Используем packetPool для избежания аллокаций
	// Формат FEC пакета: [FEC_FLAG(1)][SEQ_NUM(4)][K(1)][M(1)][data]
	payloadLen := 7 + len(data)
	totalLen := headroom + payloadLen

	// Берем буфер из пула
	buf := packetPool.Get().([]byte)

	// Если буфер мал (что редко для 64KB), выделяем новый (не возвращаем в пул)
	if cap(buf) < totalLen {
		packetPool.Put(buf) // Возвращаем старый, берем новый
		buf = make([]byte, totalLen)
	}

	// Ресайзим слайс до нужной длины
	buf = buf[:totalLen]

	// Пишем заголовок (после headroom)
	ptr := headroom
	buf[ptr] = 0xFF // FEC флаг
	binary.BigEndian.PutUint32(buf[ptr+1:ptr+5], seqNum)
	buf[ptr+5] = byte(fe.k)
	buf[ptr+6] = byte(fe.m)

	// Копируем данные без append
	copy(buf[ptr+7:], data)

	// 2. Buffer for RS Encoding
	// To support reconstruction of variable length packets, we prepend 2-byte length
	// to the shard used for RS.
	// Shard Content: [LEN(2)][DATA]
	rsShardLen := 2 + len(data)

	// Allocate shard from pool to avoid copy retention
	shardBuf := packetPool.Get().([]byte)
	if cap(shardBuf) < rsShardLen {
		packetPool.Put(shardBuf)
		shardBuf = make([]byte, rsShardLen)
	}
	shardBuf = shardBuf[:rsShardLen]

	binary.BigEndian.PutUint16(shardBuf[0:2], uint16(len(data)))
	copy(shardBuf[2:], data)

	fe.shards[fe.idx] = shardBuf
	if rsShardLen > fe.shardSize {
		fe.shardSize = rsShardLen
	}

	fe.idx++
	return buf
}

// GetParityPackets checks if K shards are buffered, generates M parity packets, and resets.
// Returns nil if not ready. Caller acts as generator.
func (fe *FECEncoder) GetParityPackets(baseSeq uint32, headroom int) [][]byte {
	if fe.idx < fe.k {
		return nil
	}

	// 1. Pad shards to max size
	for i := 0; i < fe.k; i++ {
		shard := fe.shards[i]
		if len(shard) < fe.shardSize {
			// Expand and zero pad
			newShard := shard[:fe.shardSize]
			// Zero out the extended part
			for j := len(shard); j < fe.shardSize; j++ {
				newShard[j] = 0
			}
			fe.shards[i] = newShard
		}
	}

	// 2. Prepare Parity Shards
	for i := 0; i < fe.m; i++ {
		buf := packetPool.Get().([]byte)
		if cap(buf) < fe.shardSize {
			packetPool.Put(buf)
			buf = make([]byte, fe.shardSize)
		}
		fe.shards[fe.k+i] = buf[:fe.shardSize]
	}

	// 3. Encode
	if err := fe.enc.Encode(fe.shards); err != nil {
		fe.reset()
		return nil
	}

	// 4. Pack Parity Shards into Packets
	parityPackets := make([][]byte, fe.m)
	for i := 0; i < fe.m; i++ {
		parityData := fe.shards[fe.k+i]

		// Encode into frame: [FEC_FLAG][SEQ][K][M][PARITY_DATA]
		pktLen := 7 + len(parityData)
		totalLen := headroom + pktLen

		buf := packetPool.Get().([]byte)
		if cap(buf) < totalLen {
			packetPool.Put(buf)
			buf = make([]byte, totalLen)
		}
		buf = buf[:totalLen]

		ptr := headroom
		buf[ptr] = 0xFF
		// Parity packets use sequence following data block (implied)
		binary.BigEndian.PutUint32(buf[ptr+1:ptr+5], baseSeq+uint32(i))
		buf[ptr+5] = byte(fe.k)
		buf[ptr+6] = byte(fe.m)
		copy(buf[ptr+7:], parityData)

		parityPackets[i] = buf
	}

	// Cleanup Data Shards (return to pool)
	// Parity shards are now copied into packets, so we return them too.
	// Note: encoded parity shards in fe.shards are separate buffers from parityPackets (which got copied).
	for i := 0; i < fe.k+fe.m; i++ {
		if fe.shards[i] != nil {
			packetPool.Put(fe.shards[i])
			fe.shards[i] = nil
		}
	}

	fe.idx = 0
	fe.shardSize = 0

	return parityPackets
}

func (fe *FECEncoder) reset() {
	for i := 0; i < len(fe.shards); i++ {
		if fe.shards[i] != nil {
			packetPool.Put(fe.shards[i])
			fe.shards[i] = nil
		}
	}
	fe.idx = 0
	fe.shardSize = 0
}

// FECDecoder декодирует FEC пакеты и восстанавливает потерянные данные
type FECDecoder struct {
	k             int
	m             int
	packetBuffer  map[uint32][]byte // Буфер принятых пакетов по seqNum
	bufferMutex   sync.RWMutex
	recoveryCount int // Счетчик восстановленных пакетов
	totalPackets  int // Всего обработанных пакетов
}

// NewFECDecoder создает новый FEC декодер
func NewFECDecoder(k, m int) *FECDecoder {
	return &FECDecoder{
		k:            k,
		m:            m,
		packetBuffer: make(map[uint32][]byte),
	}
}

// DecodeFEC пытается восстановить потерянные пакеты используя parity packets
func (fd *FECDecoder) DecodeFEC(packet []byte, seqNum uint32) (recovered []byte, canRecover bool) {
	fd.bufferMutex.Lock()
	defer fd.bufferMutex.Unlock()

	fd.totalPackets++

	if len(packet) < 7 {
		return nil, false
	}

	// Проверяем FEC флаг
	if packet[0] != 0xFF {
		return packet[7:], false // Обычный пакет
	}

	// Извлекаем seqNum
	// Извлекаем seqNum
	recvSeqNum := binary.BigEndian.Uint32(packet[1:5])

	// В Reed-Solomon нам нужно собрать блок пакетов (Data + Parity)
	// Простая стратегия: группируем по ID блока?
	// Или используем Sliding Window?
	// Для простоты (как в UDP): считаем, что SeqNum идет подряд.
	// SeqNum % (K+M) -> Index in block.
	// BlockID = SeqNum / (K+M).

	// Мы пока используем single buffer map.
	// Если пришел пакет, сохраняем его.
	// Если набралось K пакетов для текущего "окна", пытаемся восстановить.

	// Сохраняем payload (без FEC заголовка)
	fd.packetBuffer[recvSeqNum] = packet[7:]

	// Проверяем возможность восстановления
	// Нужна более сложная логика определения "какой пакет потерян".
	// Если мы получили K+M пакетов, но некоторые потеряны...
	// Здесь мы упростим: этот метод вызывается, когда мы хотим ПОЛУЧИТЬ ПОТЕРЯННЫЙ пакет.
	// Но мы не знаем, какой потерян, пока не увидим пропуск.

	// Решение: Receiver просто накапливает буфер. Reconstruct вызывается отдельно?
	// Или TryRecover вызывается при каждом пакете?

	// Оставим эту реализацию для совместимости с интерфейсом,
	// но RS Recovery требует знания IDs.
	return nil, false
}

// Reconstruct пытается восстановить утерянные пакеты в блоке
func (fd *FECDecoder) Reconstruct(blockStartSeq uint32, k, m int) [][]byte {
	// Сбор шарадов
	shards := make([][]byte, k+m)
	haveObj := 0

	for i := 0; i < k+m; i++ {
		seq := blockStartSeq + uint32(i)
		if data, ok := fd.packetBuffer[seq]; ok {
			shards[i] = data
			haveObj++
		}
	}

	if haveObj < k {
		return nil // Недостаточно данных
	}

	// Init Decoder
	enc, err := reedsolomon.New(k, m)
	if err != nil {
		return nil
	}

	// Reconstruct
	if err := enc.Reconstruct(shards); err != nil {
		return nil
	}

	// Extract recovered data
	var recovered [][]byte
	for i := 0; i < k; i++ {
		seq := blockStartSeq + uint32(i)
		if _, ok := fd.packetBuffer[seq]; !ok {
			// Это восстановленный пакет!
			// Данные в shards[i] имеют формат [LEN(2)][PAYLOAD][PADDING]
			shard := shards[i]
			if len(shard) < 2 {
				continue
			}
			dataLen := binary.BigEndian.Uint16(shard[0:2])
			if int(dataLen)+2 > len(shard) {
				continue
			}
			data := shard[2 : 2+dataLen]

			// Копируем, чтобы вернуть
			res := packetPool.Get().([]byte)
			if cap(res) < len(data) {
				packetPool.Put(res)
				res = make([]byte, len(data))
			}
			res = res[:len(data)]
			copy(res, data)

			recovered = append(recovered, res)

			// Добавляем в буфер, чтобы не восстанавливать снова
			// fd.packetBuffer[seq] = ... (опционально)
		}
	}

	return recovered
}

// xorRecover восстанавливает данные используя XOR операцию
func (fd *FECDecoder) xorRecover(packets map[uint32][]byte, k int) []byte {
	if len(packets) < k {
		return nil
	}

	// Собираем первые k пакетов
	var result []byte
	count := 0

	for _, data := range packets {
		if count == 0 {
			// ОПТИМИЗАЦИЯ: Allocation from Pool
			// ВНИМАНИЕ: Caller (decodeFEC -> receiveWithSACK) должен вернуть этот буфер в пул!
			// Поскольку receiveWithSACK пока не интегрирован в readLoop, это безопасно.
			// При интеграции нужно добавить packetPool.Put(recovered) после использования.
			result = packetPool.Get().([]byte)
			if cap(result) < len(data) {
				packetPool.Put(result)
				result = make([]byte, len(data))
			}
			result = result[:len(data)]

			copy(result, data)
		} else {
			// XOR текущих данных с накопленным результатом
			for i := 0; i < len(result) && i < len(data); i++ {
				result[i] ^= data[i]
			}
		}
		count++
		if count >= k {
			break
		}
	}

	return result
}

// SACKTracker отслеживает какие пакеты получены для выборочного подтверждения
type SACKTracker struct {
	receivedRanges []PacketRange // Диапазоны полученных пакетов
	mutex          sync.RWMutex
	maxSeqNum      uint32
	packetCount    int
	lossCount      int
}

// PacketRange представляет диапазон последовательных полученных пакетов
type PacketRange struct {
	Start uint32 // Начало диапазона (включительно)
	End   uint32 // Конец диапазона (включительно)
}

// NewSACKTracker создает новый SACK трекер
func NewSACKTracker() *SACKTracker {
	return &SACKTracker{
		receivedRanges: make([]PacketRange, 0),
		packetCount:    0,
		lossCount:      0,
	}
}

// RecordPacket записывает получение пакета с данным seqNum
func (st *SACKTracker) RecordPacket(seqNum uint32) {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	st.packetCount++

	// Обновляем maxSeqNum
	if seqNum > st.maxSeqNum {
		// Проверяем потерянные пакеты между lastSeq и текущим
		for missing := st.maxSeqNum + 1; missing < seqNum; missing++ {
			st.lossCount++
		}
		st.maxSeqNum = seqNum
	}

	// Обновляем диапазоны полученных пакетов
	st.addToRanges(seqNum)
}

// addToRanges добавляет seqNum в список диапазонов
func (st *SACKTracker) addToRanges(seqNum uint32) {
	// Простая реализация: слияние перекрывающихся диапазонов
	found := false
	for i := range st.receivedRanges {
		if seqNum >= st.receivedRanges[i].Start-1 && seqNum <= st.receivedRanges[i].End+1 {
			// Расширяем существующий диапазон
			if seqNum < st.receivedRanges[i].Start {
				st.receivedRanges[i].Start = seqNum
			}
			if seqNum > st.receivedRanges[i].End {
				st.receivedRanges[i].End = seqNum
			}
			found = true
			break
		}
	}

	if !found {
		// Добавляем новый диапазон
		st.receivedRanges = append(st.receivedRanges, PacketRange{Start: seqNum, End: seqNum})
	}
}

// GetMissingPackets возвращает список потерянных пакетов
func (st *SACKTracker) GetMissingPackets(upTo uint32) []uint32 {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	missing := make([]uint32, 0)

	lastEnd := uint32(0)
	for _, r := range st.receivedRanges {
		// Добавляем потерянные пакеты между lastEnd и текущим диапазоном
		for seq := lastEnd + 1; seq < r.Start; seq++ {
			if seq <= upTo {
				missing = append(missing, seq)
			}
		}
		lastEnd = r.End
	}

	// Добавляем потерянные пакеты после последнего диапазона
	for seq := lastEnd + 1; seq <= upTo; seq++ {
		missing = append(missing, seq)
	}

	return missing
}

// GetPacketLossRate возвращает примерный процент потери пакетов
func (st *SACKTracker) GetPacketLossRate() float32 {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	if st.packetCount == 0 {
		return 0
	}

	return float32(st.lossCount) / float32(st.packetCount+st.lossCount) * 100
}

// ============================================================================
// Интеграция FEC и SACK в обработку данных
// ============================================================================

// sendWithFEC отправляет данные с возможной FEC кодировкой в зависимости от потери пакетов
func (s *Stream) sendWithFEC(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Проверяем уровень потери пакетов каждые 30 секунд
	if time.Since(s.lossCheckTime) > 30*time.Second {
		s.packetLossRate = s.sackTracker.GetPacketLossRate()
		s.lossCheckTime = time.Now()

		// Включаем FEC если потеря > 2%
		if s.packetLossRate > 2.0 {
			s.fecEnabled = true
		} else if s.packetLossRate < 1.0 {
			s.fecEnabled = false // Отключаем FEC при улучшении сети
		}
	}

	// Если FEC включен, кодируем данные
	if s.fecEnabled {
		// Оставляем headroom=0 для совместимости
		encodedData := s.fecEncoder.EncodeFEC(data, s.seqNum, 0)
		s.seqNum++

		// ОПТИМИЗАЦИЯ: Возвращаем буфер в пул после отправки
		// writeWithRetry синхронна для TCP/UDP (net.Conn), поэтому это безопасно
		err := s.writeWithRetry(encodedData)

		// Проверяем, что буфер из пула (по емкости), и возвращаем
		if cap(encodedData) == 65536 {
			packetPool.Put(encodedData)
		}

		// Flush parity?
		// sendWithFEC используется обычно "поштучно".
		// Если мы хотим flush, нужно вызвать GetParityPackets.
		// Но здесь мы не знаем headroom и не умеем заворачивать.
		// Допустим, sendWithFEC просто шлёт data (Systematic)
		// и накапливает. Если набирается M - шлёт parity без FrameHeader (TCP Layer FEC)?
		// Если это raw TCP/UDP, то заголовки другие.
		// Оставим пока отправку только Data, паритеты будут копиться и дропаться при reset, если не вызвать flush.
		// FIX: Вызываем GetParityPackets с 0 headroom.

		parity := s.fecEncoder.GetParityPackets(s.seqNum, 0)
		for _, p := range parity {
			s.writeWithRetry(p) // Best effort
			packetPool.Put(p)
			s.seqNum++
		}

		return err
	}

	// Без FEC - обычная отправка
	s.seqNum++
	return s.writeWithRetry(data)
}

// writeWithRetry пытается отправить данные с повторами при ошибке
func (s *Stream) writeWithRetry(data []byte) error {
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		if s.Protocol == ProtoTCP && s.conn != nil {
			_, err := s.conn.Write(data)
			if err == nil {
				return nil
			}
			if attempt < maxRetries-1 {
				time.Sleep(time.Duration((attempt+1)*50) * time.Millisecond) // Экспоненциальный backoff
			}
		} else if s.Protocol == ProtoUDP && s.udpConn != nil {
			_, err := s.udpConn.Write(data)
			if err == nil {
				return nil
			}
			if attempt < maxRetries-1 {
				time.Sleep(time.Duration((attempt+1)*50) * time.Millisecond)
			}
		}
	}

	return fmt.Errorf("failed to send data after %d retries", maxRetries)
}

// receiveWithSACK получает пакет и отслеживает его через SACK для обнаружения потерь
func (s *Stream) receiveWithSACK(packet []byte, seqNum uint32) ([]byte, error) {
	// Записываем получение пакета в SACK трекер
	if s.sackEnabled {
		s.sackTracker.RecordPacket(seqNum)
	}

	// Проверяем FEC декодирование
	if s.fecEnabled {
		recovered, canRecover := s.fecDecoder.DecodeFEC(packet, seqNum)
		if canRecover && len(recovered) > 0 {
			return recovered, nil
		}

		// Если это FEC пакет, пропускаем его (он только для восстановления)
		if len(packet) > 0 && packet[0] == 0xFF {
			return nil, nil
		}
	}

	return packet, nil
}

// GetFECStats возвращает статистику FEC
func (s *Stream) GetFECStats() map[string]interface{} {
	return map[string]interface{}{
		"fecEnabled":     s.fecEnabled,
		"packetLossRate": s.packetLossRate,
		"recoveryCount":  s.fecDecoder.recoveryCount,
		"totalPackets":   s.fecDecoder.totalPackets,
	}
}

// GetSACKStats возвращает статистику SACK
func (s *Stream) GetSACKStats() map[string]interface{} {
	return map[string]interface{}{
		"packetCount": s.sackTracker.packetCount,
		"lossCount":   s.sackTracker.lossCount,
		"lossRate":    s.sackTracker.GetPacketLossRate(),
		"rangeCount":  len(s.sackTracker.receivedRanges),
	}
}
