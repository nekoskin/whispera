package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	aeadpkg "whispera/internal/crypto"
	"whispera/internal/handshake"
	"whispera/internal/obfuscation"
	metr "whispera/internal/metrics"
	routingpkg "whispera/internal/routing"
)

type handshakeLimiter struct {
	tokens     float64
	rate       float64
	burst      float64
	lastRefill time.Time
}

func newHandshakeLimiter(rate float64, burst int) *handshakeLimiter {
	if rate <= 0 || burst <= 0 {
		return nil
	}
	return &handshakeLimiter{
		tokens:     float64(burst),
		rate:       rate,
		burst:      float64(burst),
		lastRefill: time.Now(),
	}
}

// Allow возвращает true, если handshake разрешен в данный момент (token bucket).
func (lb *handshakeLimiter) Allow(now time.Time) bool {
	if lb == nil {
		return false
	}
	dt := now.Sub(lb.lastRefill).Seconds()
	if dt > 0 {
		lb.tokens += dt * lb.rate
		if lb.tokens > lb.burst {
			lb.tokens = lb.burst
		}
		lb.lastRefill = now
	}
	if lb.tokens >= 1 {
		lb.tokens--
		return true
	}
	return false
}

// Set обновляет параметры rate/burst для live‑reload.
func (lb *handshakeLimiter) Set(rate float64, burst int) {
	if lb == nil {
		return
	}
	if rate <= 0 || burst <= 0 {
		// Отключаем, если заданы невалидные значения.
		lb.rate = 0
		lb.burst = 0
		lb.tokens = 0
		return
	}
	lb.rate = rate
	lb.burst = float64(burst)
	if lb.tokens > lb.burst {
		lb.tokens = lb.burst
	}
}

func initStaticPrivateKey(staticKeyHex string, psk []byte) ([]byte, error) {
	if staticKeyHex != "" {
		key, err := hex.DecodeString(staticKeyHex)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("invalid -static-key (need hex32)")
		}
		return key, nil
	}
	if len(psk) == 0 {
		return nil, fmt.Errorf("either -static-key (Noise IK) or -psk is required")
	}
	return nil, nil
}

func processNonDataPacket(
	buf []byte,
	n int,
	parseErr error,
	raddr *net.UDPAddr,
	conn *net.UDPConn,
	packetCount int,
	audit *bool,
	allowHandshake *handshakeLimiter,
	ampMaxRatio float64,
	ampMaxBytes int,
	staticPriv []byte,
	hasStaticKey bool,
	coreIM *obfuscation.IntegrationManager,
) bool {
	if n >= 20 && (buf[0]>>4 == 4 || buf[0]>>4 == 6) {
		if auditFlag != nil && *auditFlag {
			log.Printf("[PARSE] ⚠️ Packet #%d from %s: size=%d bytes, looks like raw IP packet (should have Whispera header!)",
				packetCount, raddr, n)
		}
		metr.Drops.Inc()
		return true
	}

	if n >= 1 && buf[0] == 0x16 {
		if auditFlag != nil && *auditFlag && packetCount <= 3 {
			log.Printf("[PARSE] 🔍 Packet #%d from %s: size=%d bytes, detected as TLS/DTLS handshake (0x16), ignoring (client may be attempting DTLS connection)",
				packetCount, raddr, n)
		}
		metr.Drops.Inc()
		return true
	}

	if n == 152 {
		sessionByAddr := sessionMgr.GetSessionByClientAddr(raddr)
		if sessionByAddr != nil {
			if auditFlag != nil && *auditFlag && packetCount <= 5 {
				log.Printf("[PARSE] ⚠️ Packet #%d from %s: size=152 bytes, not recognized as data packet, but active session exists (ignoring - may be from old connection)",
					packetCount, raddr)
			}
			metr.Drops.Inc()
			return true
		}
		if auditFlag != nil && *auditFlag && packetCount <= 5 {
			log.Printf("[PARSE] ⚠️ Packet #%d from %s: size=152 bytes, not recognized as data packet (parse error: %v), no active session (may be from disconnected client or wrong protocol version)",
				packetCount, raddr, parseErr)
		}
	}

	if hasStaticKey && n >= 32 && n <= 96 {
		log.Printf("[UDP] Potential handshake packet from %s (size: %d bytes, parse error: %v)", raddr, n, parseErr)
		if allowHandshake == nil || !allowHandshake.Allow(time.Now()) {
			if audit != nil && *audit {
				log.Printf("[UDP] Handshake rate limited for %s (packet size: %d bytes)", raddr, n)
			}
			metr.Drops.Inc()
			return true
		}
		bytesIn := n
		estMsg2 := 48
		estSeed := 4 + 32 + 16
		if float64(estMsg2+estSeed) <= ampMaxRatio*float64(bytesIn) && (estMsg2+estSeed) <= ampMaxBytes {
			if coreIM != nil && coreIM.GetMLSystem() != nil {
				go func(packetData []byte) {
					if _, _, err := coreIM.ProcessTrafficWithML(packetData, "inbound", "udp"); err != nil {
						log.Printf("ML traffic processing error: %v", err)
					}
				}(append([]byte(nil), buf[:n]...))
			}

			metr.HandshakeAttempts.Inc()
			log.Printf("[UDP] Attempting handshake with %s (packet size: %d bytes, first bytes: %02x %02x %02x %02x)",
				raddr, n, buf[0], buf[1], buf[2], buf[3])
			var outboundTag string
			seed, sid, _, err := handshake.ServerIKFromFirst(conn, staticPriv, buf[:n], raddr, &outboundTag)
			if err != nil {
				metr.HandshakeFailed.Inc()
				log.Printf("[UDP] Handshake FAILED with %s (packet size: %d bytes): %v", raddr, n, err)
				metr.Drops.Inc()
				return true
			}
			metr.HandshakeSuccess.Inc()
			log.Printf("✓ Handshake SUCCESS with client %s, sessionID=%d", raddr, sid)

			sendK, recvK, err := aeadpkg.DeriveDirectionalKeys(seed, false)
			if err != nil {
				log.Printf("derive keys error: %v", err)
				metr.Drops.Inc()
				return true
			}
			aeadState, err := aeadpkg.NewAEADState(sendK, recvK)
			if err != nil {
				log.Printf("aead error: %v", err)
				metr.Drops.Inc()
				return true
			}
			// Определяем userID для сессии
			ipAddr := getIPFromAddr(raddr)
			userID := resolveUserID(ipAddr, "") // Пока публичный ключ недоступен в handshake
			
			// Проверяем connection limits
			if !checkPolicyConnection(userID, ipAddr) {
				log.Printf("[POLICY] ⚠️ Connection blocked for %s (userID=%s): connection limit exceeded", ipAddr, userID)
				metr.Drops.Inc()
				return true
			}
			
			// Проверяем time-based policies
			if !checkPolicyTimeBased(userID, time.Now()) {
				log.Printf("[POLICY] ⚠️ Connection blocked for %s (userID=%s): time-based policy restriction", ipAddr, userID)
				metr.Drops.Inc()
				return true
			}
			
			// Все проверки пройдены - легитимный клиент
			log.Printf("[POLICY] ✅ Policy checks passed for %s (userID=%s, sessionID=%d)", ipAddr, userID, sid)
			
			session := sessionMgr.AddSession(sid, raddr, aeadState, seed)
			log.Printf("  Session %d created for client %s", sid, raddr)
			
			// Устанавливаем userID в сессию (если известен)
			if userID != "" {
				sessionMgr.SetUserID(sid, userID)
			}
			
			// Регистрируем connection в connection enforcer
			api := getGlobalManagementAPI()
			if api != nil {
				api.GetConnectionEnforcer().AddConnection(userID, ipAddr)
			}
			
			// Регистрируем outbound tag в routing engine если он указан
			// Используем outbound tag полученный от клиента, или дефолтный если не указан
			if routingEngine != nil && session != nil {
				// Если клиент не отправил outbound tag, используем дефолтный
				if outboundTag == "" {
					outboundTag = "default"
				}
				
				// Если все еще пустой, пытаемся получить из routing engine на основе IP адреса клиента
				if outboundTag == "default" && raddr != nil {
					// Создаем PacketInfo для определения outbound tag по IP адресу клиента
					packetInfo := &routingpkg.PacketInfo{
						SrcIP:     raddr.IP,
						DstIP:     nil, // Неизвестен на этапе handshake
						SrcPort:   0,
						DstPort:   0,
						Protocol:  "unknown", // Протокол неизвестен на этапе handshake
						Domain:    "",       // Домен неизвестен на этапе handshake
						UserID:    "",       // UserID может быть получен из API позже
						InboundTag: "",      // Inbound tag неизвестен
					}
					
					// Пытаемся найти outbound tag через routing rules
					// Если есть правило для этого IP (source-based routing), используем его outbound tag
					if tag, _, matched := routingEngine.Route(packetInfo); matched && tag != "" {
						outboundTag = tag
					}
				}
				
				// Регистрируем outbound tag
				outboundMgr := routingEngine.GetOutboundManager()
				outboundMgr.RegisterOutbound(sid, outboundTag)
				
				// КРИТИЧЕСКОЕ: Гарантируем, что всегда есть "default" outbound (как в Clash/Mihomo)
				// Если эта сессия регистрируется как "default" или default еще не зарегистрирован,
				// автоматически регистрируем её как default outbound
				if outboundTag == "default" || outboundMgr.EnsureDefaultOutbound(sid) {
					if auditFlag != nil && *auditFlag {
						log.Printf("[HANDSHAKE] Registered session %d as default outbound (client: %s)", sid, raddr)
					}
				}
				
				sessionMgr.SetOutboundTag(sid, outboundTag)
				
				if auditFlag != nil && *auditFlag {
					log.Printf("[HANDSHAKE] Registered outbound tag '%s' for session %d (client: %s)", 
						outboundTag, sid, raddr)
				}
			}
			
			return true
		}
		metr.HandshakeAmplifyBlocked.Inc()
	}

	metr.Drops.Inc()
	return true
}
