package main

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/client/session"
	"whispera/internal/client/streamutil"
	metr "whispera/internal/metrics"
	"whispera/internal/obfuscation"
	"whispera/internal/proto"
	tunpkg "whispera/internal/tun"
)

var (
	// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Увеличен размер пула для поддержки больших пакетов и батчинга
	xhttpClientDataPayloadPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 131072) // 128KB для поддержки больших пакетов и батчинга
		},
	}
)

// runXHTTPClientDataPlane handles XHTTP data plane on client side
// XHTTP obfuscation (HTTP/2 + Marionette) is already applied by ObfuscatedConn
// This function only handles protocol-level framing and TUN I/O
func runXHTTPClientDataPlane(
	conn net.Conn,
	sess *session.SessionCtx,
	tun *tunpkg.Interface,
	keepaliveSec int,
	coreIM *obfuscation.IntegrationManager,
	verbosePackets bool,
	mode string,
	maxConcurrency int,
) {
	if conn == nil || sess == nil || sess.SessionID == 0 {
		log.Printf("[XHTTP] runXHTTPClientDataPlane: invalid session or connection")
		return
	}

	log.Printf("[XHTTP] 🚀 XHTTP client data plane started - mode=%s, maxConcurrency=%d (obfuscation handled by ObfuscatedConn)", mode, maxConcurrency)
	ctx := context.Background()
	var xhttpPacketsRxCount int64
	var xhttpPacketsTxCount int64

	// ОПТИМИЗАЦИЯ: Создаем AsyncWriter для неблокирующей записи в TUN
	var asyncWriter *tunpkg.AsyncWriter
	if tun != nil {
		asyncWriter = tunpkg.NewAsyncWriter(tun, 1024)
		defer asyncWriter.Close()
	}

	// Inbound: Server -> Client (through XHTTP)
	// ObfuscatedConn already handles de-obfuscation (HTTP/2 + Marionette)
	go func() {
		for {
			// ReadFrame reads from ObfuscatedConn, which already de-obfuscates
			frame, err := streamutil.ReadFrame(conn)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if err != io.EOF {
					log.Printf("[XHTTP] Read error: %v", err)
				}
				return
			}
			metr.PacketsRx.Inc()
			metr.BytesRx.Add(float64(len(frame)))
			metr.PacketsRxByTransport.WithLabelValues("xhttp").Inc()
			metr.BytesRxByTransport.WithLabelValues("xhttp").Add(float64(len(frame)))
			rxCount := atomic.AddInt64(&xhttpPacketsRxCount, 1)
			if verbosePackets || rxCount%100 == 0 {
				log.Printf("[XHTTP] 📥 RX #%d: %d bytes ← Server", rxCount, len(frame))
			}

			if len(frame) < proto.HeaderLen {
				continue
			}

			var h proto.PacketHeader
			if err := h.UnmarshalBinary(frame[:proto.HeaderLen]); err != nil {
				continue
			}

			if h.SessionID != sess.SessionID {
				continue
			}

			// XHTTP doesn't use AEAD encryption - obfuscation is in ObfuscatedConn
			// Data is already de-obfuscated by ObfuscatedConn.Read()
			payload := frame[proto.HeaderLen:]

			if h.Flags&proto.FlagControl != 0 {
				if len(payload) > 0 && payload[0] == proto.CtrlKeepAlive {
					if rxCount%10 == 0 {
						log.Printf("[XHTTP] 💓 Keepalive received (packet #%d)", rxCount)
					}
					continue
				}
				continue
			}

			if (h.Flags & proto.FlagStreamV2) != 0 {
				if len(payload) < 1 {
					continue
				}
				cmd := proto.StreamCommand(payload[0])
				switch cmd {
				case proto.StreamData:
					if len(payload) < 3 {
						continue
					}
					streamID := binary.BigEndian.Uint16(payload[1:3])
					payload = payload[3:]
					if streamID != proto.TunStreamID && verbosePackets {
						log.Printf("[XHTTP] RX StreamData streamID=%d len=%d", streamID, len(payload))
					}
				case proto.StreamClose:
					if verbosePackets {
						log.Printf("[XHTTP] RX StreamClose, dropping")
					}
					continue
				case proto.StreamOpen:
					if verbosePackets {
						log.Printf("[XHTTP] RX StreamOpen, dropping")
					}
					continue
				default:
				}
			}

			finalData := payload

			// NO additional ML processing - already done by ObfuscatedConn
			// ObfuscatedConn already applied Marionette de-obfuscation

			// Handle proxy connections using common function
			if handleProxyConnection(finalData) {
				continue
			}

			// Write to TUN using common function
			writeToTUN(asyncWriter, tun, finalData, &xhttpClientDataPayloadPool)
		}
	}()

	buf := make([]byte, 65535)
	kaTicker := time.NewTicker(time.Duration(keepaliveSec) * time.Second)
	defer kaTicker.Stop()

	// Outbound: Client -> Server (through XHTTP)
	// ObfuscatedConn already handles obfuscation (HTTP/2 + Marionette)
	for {
		select {
		case <-kaTicker.C:
			var hdr proto.PacketHeader
			hdr.Version = proto.Version
			hdr.Flags = proto.FlagControl
			hdr.SessionID = sess.SessionID
			seq := sess.NextSeq()
			if seq == 0 {
				continue
			}
			hdr.Seq = seq
			hdr.PayloadLen = 1
			aad := hdr.MarshalBinary()
			// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Используем пул буферов для keepalive пакетов
			keepAlivePkt := xhttpClientDataPayloadPool.Get().([]byte)
			if cap(keepAlivePkt) < len(aad)+1 {
				keepAlivePkt = make([]byte, len(aad)+1)
			} else {
				keepAlivePkt = keepAlivePkt[:len(aad)+1]
			}
			copy(keepAlivePkt, aad)
			keepAlivePkt[len(aad)] = proto.CtrlKeepAlive
			// WriteFrame writes to ObfuscatedConn, which already obfuscates
			if err := streamutil.WriteFrame(conn, keepAlivePkt); err != nil {
				proto.PutHeaderBuffer(aad)
				xhttpClientDataPayloadPool.Put(keepAlivePkt[:0])
				return
			}
			proto.PutHeaderBuffer(aad)
			xhttpClientDataPayloadPool.Put(keepAlivePkt[:0])
			if seq%5 == 0 {
				log.Printf("[XHTTP] 💓 Keepalive sent (seq: %d)", seq)
			}
		default:
			var payload []byte
			// В Mixed режиме: gVisor обрабатывает TCP/UDP, dataplane читает остальные пакеты
			// В gVisor режиме: только gVisor, dataplane не читает
			// В System режиме: только dataplane
			if tunStack != nil && tunStack.IsActive() {
				// Проверяем режим: в Mixed режиме dataplane может читать не-TCP/UDP пакеты
				// Но gVisor уже читает из TUN, поэтому dataplane не должен читать напрямую
				// В Mixed режиме gVisor обрабатывает TCP/UDP, остальные пакеты пропускаются
				// Для простоты: если gVisor активен, dataplane не читает (избегаем конфликта)
				// В будущем можно добавить механизм для обработки не-TCP/UDP пакетов через gVisor
				time.Sleep(100 * time.Millisecond)
				continue
			} else {
				// System режим или gVisor недоступен - dataplane читает напрямую из TUN
				if tun == nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				n, err := tun.Read(buf)
				if err != nil {
					if err.Error() == "No more data" || err.Error() == "no more data" {
						continue
					}
					continue
				}
				payload = buf[:n]
			}

			// NO additional ML processing - ObfuscatedConn will handle it
			// ObfuscatedConn.Write() will apply HTTP/2 + Marionette obfuscation

			streamID := proto.TunStreamID
			dataPayload := xhttpClientDataPayloadPool.Get().([]byte)
			if cap(dataPayload) < 2+len(payload) {
				dataPayload = make([]byte, 2+len(payload))
			} else {
				dataPayload = dataPayload[:2+len(payload)]
			}
			binary.BigEndian.PutUint16(dataPayload[0:2], streamID)
			copy(dataPayload[2:], payload)
			dataFrame := proto.EncodeStreamControlFrame(proto.StreamData, dataPayload)

			var hdr proto.PacketHeader
			hdr.Version = proto.Version
			hdr.Flags = proto.FlagStreamV2
			hdr.SessionID = sess.SessionID
			payloadLen, ok := streamutil.SafeUint16(len(dataFrame))
			if !ok {
				xhttpClientDataPayloadPool.Put(dataPayload[:0])
				continue
			}
			hdr.PayloadLen = payloadLen
			seq := sess.NextSeq()
			if seq == 0 {
				xhttpClientDataPayloadPool.Put(dataPayload[:0])
				continue
			}
			hdr.Seq = seq
			aad := hdr.MarshalBinary()

			// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Используем пул буферов для полного пакета
			pkt := xhttpClientDataPayloadPool.Get().([]byte)
			if cap(pkt) < len(aad)+len(dataFrame) {
				pkt = make([]byte, len(aad)+len(dataFrame))
			} else {
				pkt = pkt[:len(aad)+len(dataFrame)]
			}
			copy(pkt, aad)
			copy(pkt[len(aad):], dataFrame)

			// XHTTP doesn't use AEAD encryption - obfuscation is in ObfuscatedConn
			// WriteFrame writes to ObfuscatedConn, which already obfuscates
			if err := streamutil.WriteFrame(conn, pkt); err != nil {
				proto.PutHeaderBuffer(aad)
				xhttpClientDataPayloadPool.Put(dataPayload[:0])
				xhttpClientDataPayloadPool.Put(pkt[:0])
				log.Printf("[XHTTP] Write error: %v", err)
				return
			}
			proto.PutHeaderBuffer(aad)
			xhttpClientDataPayloadPool.Put(dataPayload[:0])
			xhttpClientDataPayloadPool.Put(pkt[:0])

			metr.PacketsTx.Inc()
			metr.BytesTx.Add(float64(len(pkt)))
			metr.PacketsTxByTransport.WithLabelValues("xhttp").Inc()
			metr.BytesTxByTransport.WithLabelValues("xhttp").Add(float64(len(pkt)))
			txCount := atomic.AddInt64(&xhttpPacketsTxCount, 1)

			xhttpClientDataPayloadPool.Put(dataPayload[:0])

			if txCount == 1 {
				log.Printf("[XHTTP] 📤 First packet sent - VPN tunnel active")
			} else if verbosePackets || txCount%100 == 0 {
				log.Printf("[XHTTP] 📤 TX #%d: %d bytes → Server", txCount, len(payload))
			}
		}
	}
}

