package core

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"whispera/internal/dns"
	"whispera/internal/proto"
)

// Пул буферов для переиспользования памяти
var (
	// Пул для маленьких payload буферов (до 256 байт)
	smallPayloadPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 256)
		},
	}
	
	// Пул для средних payload буферов (до 32KB)
	mediumPayloadPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 32*1024)
		},
	}
)

// getPayloadBuffer получает буфер из пула в зависимости от размера
func getPayloadBuffer(size int) []byte {
	var pool *sync.Pool
	if size <= 256 {
		pool = &smallPayloadPool
	} else {
		pool = &mediumPayloadPool
	}
	
	buf := pool.Get().([]byte)
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

// putPayloadBuffer возвращает буфер в пул
func putPayloadBuffer(buf []byte) {
	if cap(buf) == 0 {
		return
	}
	
	var pool *sync.Pool
	capSize := cap(buf)
	if capSize <= 256 {
		pool = &smallPayloadPool
	} else if capSize <= 32*1024 {
		pool = &mediumPayloadPool
	} else {
		// Слишком большой буфер - не возвращаем в пул
		return
	}
	
	pool.Put(buf[:0])
}

// StreamFrame represents a unit of data or signal for the dataplane.
type StreamFrame struct {
	StreamID uint16
	Payload  []byte
	Close    bool
}

// ClientStreamConn describes a client TCP flow forwarded to gVisor.
type ClientStreamConn struct {
	StreamID uint16
	Conn     net.Conn
	ToRemote chan *StreamFrame
	Done     chan struct{}
}

// Handler manages the flow of data between gVisor (TUN) and the Dataplane.
type Handler struct {
	// Dependencies
	FakeIPPool *dns.FakeIPPool

	// State
	nextStreamID uint32
	streams      map[uint16]*ClientStreamConn
	streamsMu    sync.RWMutex

	// Output channel to the Dataplane (WebSocket/TCP writer)
	StreamChan chan *StreamFrame
}

// NewHandler creates a new core handler.
func NewHandler(fakeIPPool *dns.FakeIPPool) *Handler {
	return &Handler{
		FakeIPPool: fakeIPPool,
		streams:    make(map[uint16]*ClientStreamConn),
		StreamChan: make(chan *StreamFrame, 1024),
	}
}

// GetStreamChan returns the read-only channel for the dataplane.
func (h *Handler) GetStreamChan() <-chan *StreamFrame {
	return h.StreamChan
}

// HandleTunConnection is the callback for gVisor's tunstack.
// It allocates a StreamID, registers the flow, and pumps data.
func (h *Handler) HandleTunConnection(conn net.Conn, target string, protocol string) {
	// 1. Allocate StreamID
	streamID := uint16(atomic.AddUint32(&h.nextStreamID, 1))
	if streamID == 0 {
		streamID = uint16(atomic.AddUint32(&h.nextStreamID, 1))
	}

	// 2. Register stream
	streamConn := &ClientStreamConn{
		StreamID: streamID,
		Conn:     conn,
		ToRemote: make(chan *StreamFrame, 64),
		Done:     make(chan struct{}),
	}

	h.streamsMu.Lock()
	h.streams[streamID] = streamConn
	h.streamsMu.Unlock()

	log.Printf("[TUN] New %s flow to %s -> StreamID=%d", protocol, target, streamID)

	// 3. Construct & Send STREAM_OPEN (асинхронно)
	go h.sendStreamOpen(conn, target, protocol, streamID)

	// 4. Start Pump: Conn -> Channel
	go h.pumpConnToChannel(streamConn)
}

func (h *Handler) sendStreamOpen(conn net.Conn, target string, protocol string, streamID uint16) {
	lAddr := conn.LocalAddr()
	rAddr := conn.RemoteAddr()

	parseAddr := func(addr net.Addr) (net.IP, uint16) {
		host, portStr, _ := net.SplitHostPort(addr.String())
		port, _ := strconv.Atoi(portStr)
		return net.ParseIP(host), uint16(port)
	}

	dstIP, dstPort := parseAddr(lAddr)
	srcIP, srcPort := parseAddr(rAddr)

	protoNum := byte(6) // TCP
	if protocol == "udp" {
		protoNum = 17
	}

	var frame []byte

	// Check Fake-IP first
	if dstIP != nil && h.FakeIPPool != nil && h.FakeIPPool.IsFakeIP(dstIP) {
		domain := h.FakeIPPool.Lookup(dstIP)
		if domain != "" {
			log.Printf("[TUN] Flow to %s matches Fake-IP -> domain %s", target, domain)
			domainBytes := []byte(domain)
			dLen := len(domainBytes)
			if dLen <= 255 {
				// [Proto:1][SrcIP:4][SrcPort:2][DomainLen:1][Domain:N][DstPort:2]
				// ОПТИМИЗАЦИЯ: Используем пул буферов
				payloadSize := 1 + 4 + 2 + 1 + dLen + 2
				payload := getPayloadBuffer(payloadSize)
				payload[0] = protoNum
				if ip4 := srcIP.To4(); ip4 != nil {
					copy(payload[1:5], ip4)
				}
				binary.BigEndian.PutUint16(payload[5:7], srcPort)
				payload[7] = byte(dLen)
				copy(payload[8:8+dLen], domainBytes)
				binary.BigEndian.PutUint16(payload[8+dLen:], dstPort)

				// ОПТИМИЗАЦИЯ: Создаем frame напрямую из payload, затем возвращаем буфер в пул
				frame = proto.EncodeStreamControlFrame(proto.StreamOpenDomain, payload)
				putPayloadBuffer(payload)
			}
		}
	}

	// Standard IP (IPv4)
	if frame == nil && dstIP != nil {
		if ip4 := dstIP.To4(); ip4 != nil {
			// [Proto:1][SrcIP:4][SrcPort:2][DstIP:4][DstPort:2]
			// ОПТИМИЗАЦИЯ: Используем пул буферов
			openPayload := getPayloadBuffer(1 + 4 + 2 + 4 + 2)
			openPayload[0] = protoNum
			if srcIp4 := srcIP.To4(); srcIp4 != nil {
				copy(openPayload[1:5], srcIp4)
			}
			binary.BigEndian.PutUint16(openPayload[5:7], srcPort)
			copy(openPayload[7:11], ip4)
			binary.BigEndian.PutUint16(openPayload[11:13], dstPort)

			// ОПТИМИЗАЦИЯ: Создаем frame напрямую из payload, затем возвращаем буфер в пул
			frame = proto.EncodeStreamControlFrame(proto.StreamOpen, openPayload)
			putPayloadBuffer(openPayload)
		}
	}

	if frame != nil {
		openFrame := &StreamFrame{
			StreamID: streamID,
			Payload:  frame,
			Close:    false,
		}
		select {
		case h.StreamChan <- openFrame:
		default:
			log.Printf("[TUN] Stream channel full, dropping OPEN for ID=%d", streamID)
		}
	}
}

func (h *Handler) pumpConnToChannel(c *ClientStreamConn) {
	defer func() {
		c.Conn.Close()
		close(c.Done)
		h.streamsMu.Lock()
		delete(h.streams, c.StreamID)
		h.streamsMu.Unlock()

		closeFrame := &StreamFrame{
			StreamID: c.StreamID,
			Close:    true,
		}
		select {
		case h.StreamChan <- closeFrame:
		default:
		}
	}()

	// ОПТИМИЗАЦИЯ: Используем пул буферов для чтения
	buf := make([]byte, 32*1024)
	
	// ОПТИМИЗАЦИЯ: Создаем канал для батчинга операций записи
	writeChan := make(chan []byte, 64)
	defer close(writeChan)
	
	// Воркер для асинхронной записи в StreamChan
	go func() {
		for data := range writeChan {
			// ОПТИМИЗАЦИЯ: Для маленьких payload создаем напрямую, для больших используем пул
			var payload []byte
			n := len(data)
			if n > 1024 {
				payload = getPayloadBuffer(n)
				copy(payload, data)
			} else {
				payload = make([]byte, n)
				copy(payload, data)
			}
			
			frame := &StreamFrame{
				StreamID: c.StreamID,
				Payload:  payload,
			}
			
			select {
			case h.StreamChan <- frame:
				// Буфер будет использован в другом месте
			case <-c.Done:
				if n > 1024 {
					putPayloadBuffer(payload)
				}
				return
			default:
				// Канал переполнен, возвращаем буфер в пул
				if n > 1024 {
					putPayloadBuffer(payload)
				}
			}
		}
	}()
	
	for {
		n, err := c.Conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				// log.Printf("[TUN] Read error for ID=%d: %v", c.StreamID, err)
			}
			return
		}
		if n > 0 {
			// ОПТИМИЗАЦИЯ: Используем слайс напрямую без копирования для маленьких пакетов
			// Для больших пакетов создаем копию
			var data []byte
			if n > 4096 {
				// Большие пакеты - создаем копию
				data = make([]byte, n)
				copy(data, buf[:n])
			} else {
				// Маленькие пакеты - используем слайс напрямую (быстрее)
				data = buf[:n:n] // Создаем слайс с правильной capacity
			}
			
			select {
			case writeChan <- data:
			case <-c.Done:
				return
			default:
				// Канал переполнен - пропускаем пакет для производительности
			}
		}
	}
}

