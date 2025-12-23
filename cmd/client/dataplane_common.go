package main

import (
	"encoding/binary"
	"log"
	"sync"

	metr "whispera/internal/metrics"
	"whispera/internal/proto"
	tunpkg "whispera/internal/tun"
)

// Common dataplane structures and functions shared across all protocols

var (
	// Shared pools for all dataplane implementations
	// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Увеличен размер пула для поддержки больших пакетов
	dataPayloadPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 65535) // Увеличено с 1500 до 65535 для поддержки jumbo frames
		},
	}
)

// processStreamV2Frame processes StreamV2 frame and extracts payload
// Returns: payload, shouldContinue, error
func processStreamV2Frame(pt []byte, verbosePackets bool) ([]byte, bool) {
	if len(pt) < 1 {
		return nil, true
	}
	cmd := proto.StreamCommand(pt[0])
	switch cmd {
	case proto.StreamData:
		if len(pt) < 3 {
			return nil, true
		}
		streamID := binary.BigEndian.Uint16(pt[1:3])
		payload := pt[3:]
		if streamID != proto.TunStreamID && verbosePackets {
			log.Printf("[STREAM] RX StreamData streamID=%d len=%d", streamID, len(payload))
		}
		return payload, false
	case proto.StreamClose:
		if verbosePackets {
			log.Printf("[STREAM] RX StreamClose, dropping")
		}
		return nil, true
	case proto.StreamOpen:
		if verbosePackets {
			log.Printf("[STREAM] RX StreamOpen, dropping")
		}
		return nil, true
	default:
		return pt, false
	}
}

// handleProxyConnection checks if data is for proxy connection and routes it
// Returns: shouldContinue (true if packet was handled as proxy and should be skipped)
func handleProxyConnection(finalData []byte) bool {
	// В этой сборке клиентский proxy-путь отключён: все пакеты обрабатываются
	// как обычный туннельный трафик. Функция оставлена для совместимости
	// вызовов, но всегда возвращает false.
	_ = binary.BigEndian // фиктивное использование для избежания unused импортов
	return false
}

// writeToTUN writes data to TUN interface using async writer or direct write
func writeToTUN(asyncWriter *tunpkg.AsyncWriter, tun *tunpkg.Interface, data []byte, pool *sync.Pool) {
	if asyncWriter != nil && len(data) > 0 {
		pktCopy := pool.Get().([]byte)
		if cap(pktCopy) < len(data) {
			pktCopy = make([]byte, len(data))
		} else {
			pktCopy = pktCopy[:len(data)]
		}
		copy(pktCopy, data)
		if !asyncWriter.WriteAsyncCopy(pktCopy) {
			pool.Put(pktCopy[:0])
		} else {
			pool.Put(pktCopy[:0])
		}
	} else if tun != nil && len(data) > 0 {
		if _, err := tun.Write(data); err != nil {
			log.Printf("[TUN] Write error: %v", err)
		}
	}
}

// updateMetrics updates transport-specific metrics
func updateMetrics(transport string, rxBytes, txBytes int64) {
	metr.PacketsRxByTransport.WithLabelValues(transport).Inc()
	metr.BytesRxByTransport.WithLabelValues(transport).Add(float64(rxBytes))
	metr.PacketsTxByTransport.WithLabelValues(transport).Inc()
	metr.BytesTxByTransport.WithLabelValues(transport).Add(float64(txBytes))
}

