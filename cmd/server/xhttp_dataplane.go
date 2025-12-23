package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"time"

	metr "whispera/internal/metrics"
	"whispera/internal/obfuscation"
	"whispera/internal/proto"
	tunpkg "whispera/internal/tun"
	streamutil "whispera/internal/client/streamutil"
)

var (
	// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Увеличен размер пула для поддержки больших пакетов и батчинга
	xhttpDataPayloadPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 131072) // 128KB для поддержки больших пакетов и батчинга
		},
	}
)

// runXHTTPDataPlane handles XHTTP data plane with Marionette obfuscation
func runXHTTPDataPlane(
	conn net.Conn,
	sid uint32,
	tun *tunpkg.Interface,
	keepaliveSec int,
	coreIM *obfuscation.IntegrationManager,
	mode string,
	maxConcurrency int,
) {
	log.Printf("[XHTTP] 🚀 XHTTP server data plane started - sid=%d, mode=%s, maxConcurrency=%d", sid, mode, maxConcurrency)
	var seqSend uint32 = 1
	var seqMutex sync.Mutex

	asyncWriter := tunpkg.NewAsyncWriter(tun, 1024)
	defer asyncWriter.Close()

	// Inbound: Server -> Client (through XHTTP)
	go func() {
		for {
			frame, err := streamutil.ReadFrame(conn)
			if err != nil {
				if err != io.EOF {
					log.Printf("[XHTTP] Read error: %v", err)
				}
				return
			}
			metr.PacketsRx.Inc()
			metr.BytesRx.Add(float64(len(frame)))
			metr.PacketsRxByTransport.WithLabelValues("xhttp").Inc()
			metr.BytesRxByTransport.WithLabelValues("xhttp").Add(float64(len(frame)))

			if len(frame) < proto.HeaderLen {
				continue
			}

			var h proto.PacketHeader
			if err := h.UnmarshalBinary(frame[:proto.HeaderLen]); err != nil {
				continue
			}

			if h.SessionID != sid {
				continue
			}

			if h.Flags&proto.FlagControl != 0 {
				if len(frame) > proto.HeaderLen && frame[proto.HeaderLen] == proto.CtrlKeepAlive {
					continue
				}
				continue
			}

			payload := frame[proto.HeaderLen:]

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
					if sessionMgr != nil {
						if streamEntry := sessionMgr.GetStream(sid, streamID); streamEntry == nil {
							metr.Drops.Inc()
							continue
						}
					}
					payload = payload[3:]
				case proto.StreamOpen:
					if len(payload) < 16 {
						continue
					}
					streamID := binary.BigEndian.Uint16(payload[1:3])
					protoByte := payload[3]
					srcIP := net.IP(payload[4:8])
					srcPort := binary.BigEndian.Uint16(payload[8:10])
					dstIP := net.IP(payload[10:14])
					dstPort := binary.BigEndian.Uint16(payload[14:16])
					if sessionMgr != nil {
						sessionMgr.RegisterStream(sid, streamID, protoByte, srcIP, srcPort, dstIP, dstPort)
					}
					// КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Проверяем, является ли dstIP Fake-IP и пытаемся определить домен
					if routingEngine != nil {
						domain := routingEngine.LookupFakeIP(dstIP)
						if domain != "" {
							log.Printf("[XHTTP] StreamOpen: Fake-IP %s -> domain %s (streamID=%d)", dstIP.String(), domain, streamID)
							routingEngine.SyncFakeIPMapping(dstIP, domain)
						}
					}
					continue
				case proto.StreamOpenDomain:
					// КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Обрабатываем StreamOpenDomain для синхронизации Fake-IP маппинга
					if len(payload) < 10 {
						continue
					}
					streamID := binary.BigEndian.Uint16(payload[1:3])
					protoByte := payload[3]
					srcIP := net.IP(payload[4:8])
					srcPort := binary.BigEndian.Uint16(payload[8:10])
					domainLen := int(payload[10])
					if len(payload) < 11+domainLen+2 {
						continue
					}
					domain := string(payload[11 : 11+domainLen])
					dstPort := binary.BigEndian.Uint16(payload[11+domainLen : 11+domainLen+2])
					
					// Получаем Fake-IP из routing engine или создаем новый
					var dstIP net.IP
					if routingEngine != nil {
						// Пытаемся найти Fake-IP для домена
						var ok bool
						dstIP, ok = routingEngine.GetDomainCache(domain)
						if !ok || dstIP == nil {
							// Создаем новый Fake-IP (используем пул на сервере, если есть)
							// Для простоты используем первый доступный Fake-IP из диапазона
							dstIP = net.ParseIP("198.18.0.1") // Временное решение
						}
						routingEngine.SyncFakeIPMapping(dstIP, domain)
						log.Printf("[XHTTP] StreamOpenDomain: domain %s -> Fake-IP %s (streamID=%d)", domain, dstIP.String(), streamID)
					} else {
						dstIP = net.ParseIP("198.18.0.1") // Fallback
					}
					
					if sessionMgr != nil {
						sessionMgr.RegisterStream(sid, streamID, protoByte, srcIP, srcPort, dstIP, dstPort)
					}
					continue
				case proto.StreamClose:
					if len(payload) < 3 {
						continue
					}
					continue
				}
			}

			finalData := payload

			// ML processing with protocol context (XHTTP)
			// Marionette obfuscation is handled by XHTTP connection wrapper
			// Additional ML processing if needed
			if coreIM != nil {
				if processed, _, err := coreIM.ProcessTrafficWithML(finalData, "inbound", "xhttp"); err == nil && len(processed) > 0 {
					finalData = processed
				}
			}

			if asyncWriter != nil && len(finalData) > 0 {
				pktCopy := xhttpDataPayloadPool.Get().([]byte)
				if cap(pktCopy) < len(finalData) {
					pktCopy = make([]byte, len(finalData))
				} else {
					pktCopy = pktCopy[:len(finalData)]
				}
				copy(pktCopy, finalData)
				if !asyncWriter.WriteAsyncCopy(pktCopy) {
					xhttpDataPayloadPool.Put(pktCopy[:0])
				} else {
					xhttpDataPayloadPool.Put(pktCopy[:0])
				}
			} else if tun != nil && len(finalData) > 0 {
				if _, err := tun.Write(finalData); err != nil {
					log.Printf("[XHTTP] TUN write error: %v", err)
				}
			}
		}
	}()

	buf := make([]byte, 65535)
	kaTicker := time.NewTicker(time.Duration(keepaliveSec) * time.Second)
	defer kaTicker.Stop()

	// Outbound: Client -> Server (through XHTTP)
	for {
		select {
		case <-kaTicker.C:
			var hdr proto.PacketHeader
			hdr.Version = proto.Version
			hdr.Flags = proto.FlagControl
			hdr.SessionID = sid
			seqMutex.Lock()
			hdr.Seq = seqSend
			seqSend++
			seqMutex.Unlock()
			hdr.PayloadLen = 1
			aad := hdr.MarshalBinary()
			// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Используем пул буферов для keepalive пакетов
			keepAlivePkt := xhttpDataPayloadPool.Get().([]byte)
			if cap(keepAlivePkt) < len(aad)+1 {
				keepAlivePkt = make([]byte, len(aad)+1)
			} else {
				keepAlivePkt = keepAlivePkt[:len(aad)+1]
			}
			copy(keepAlivePkt, aad)
			keepAlivePkt[len(aad)] = proto.CtrlKeepAlive
			if err := streamutil.WriteFrame(conn, keepAlivePkt); err != nil {
				proto.PutHeaderBuffer(aad)
				xhttpDataPayloadPool.Put(keepAlivePkt[:0])
				return
			}
			proto.PutHeaderBuffer(aad)
			xhttpDataPayloadPool.Put(keepAlivePkt[:0])
		default:
			if tun == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			n, err := tun.Read(buf)
			if err != nil {
				log.Printf("[XHTTP] TUN read error: %v", err)
				return
			}

			payload := buf[:n]

			// ML processing with protocol context (XHTTP)
			// Marionette obfuscation is handled by XHTTP connection wrapper
			// Additional ML processing if needed
			if coreIM != nil {
				if processed, _, err := coreIM.ProcessTrafficWithML(payload, "outbound", "xhttp"); err == nil && len(processed) > 0 {
					payload = processed
				}
			}

			payload = proto.EncodeStreamControlFrame(proto.StreamData, payload)

			var hdr proto.PacketHeader
			hdr.Version = proto.Version
			hdr.Flags = proto.FlagStreamV2
			hdr.SessionID = sid

			seqMutex.Lock()
			currentSeq := seqSend
			seqSend++
			seqMutex.Unlock()

			hdr.Seq = currentSeq
			payloadLen := len(payload)
			if payloadLen > 65535 {
				payloadLen = 65535
			}
			hdr.PayloadLen = uint16(payloadLen)
			aad := hdr.MarshalBinary()

			// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Используем пул буферов для полного пакета
			pkt := xhttpDataPayloadPool.Get().([]byte)
			if cap(pkt) < len(aad)+len(payload) {
				pkt = make([]byte, len(aad)+len(payload))
			} else {
				pkt = pkt[:len(aad)+len(payload)]
			}
			copy(pkt, aad)
			copy(pkt[len(aad):], payload)

			if err := streamutil.WriteFrame(conn, pkt); err != nil {
				proto.PutHeaderBuffer(aad)
				xhttpDataPayloadPool.Put(pkt[:0])
				log.Printf("[XHTTP] Write error: %v", err)
				return
			}
			proto.PutHeaderBuffer(aad)
			xhttpDataPayloadPool.Put(pkt[:0])

			metr.PacketsTx.Inc()
			metr.BytesTx.Add(float64(len(pkt)))
			metr.PacketsTxByTransport.WithLabelValues("xhttp").Inc()
			metr.BytesTxByTransport.WithLabelValues("xhttp").Add(float64(len(pkt)))
		}
	}
}

