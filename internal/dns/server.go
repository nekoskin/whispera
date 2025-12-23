package dns

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Server is a simple DNS server that answers with Fake-IPs.
type Server struct {
	pool      *FakeIPPool
	srv       *dns.Server
	addr      string
	dohClient *DoHClient // DoH клиент для upstream запросов
	doqClient *DoQClient // DoQ клиент для upstream запросов
	dotClient *DoTClient // DoT клиент для upstream запросов
	adblock   AdBlockEngine // AdBlock движок для блокировки рекламы
}

// AdBlockEngine интерфейс для AdBlock движка
type AdBlockEngine interface {
	ShouldBlock(domain, url string) bool
	IsEnabled() bool
}

func NewServer(addr string, pool *FakeIPPool) *Server {
	return &Server{
		pool: pool,
		addr: addr,
	}
}

// SetDoHClient устанавливает DoH клиент для upstream запросов
func (s *Server) SetDoHClient(client *DoHClient) {
	s.dohClient = client
}

// SetDoQClient устанавливает DoQ клиент для upstream запросов
func (s *Server) SetDoQClient(client *DoQClient) {
	s.doqClient = client
}

// SetDoTClient устанавливает DoT клиент для upstream запросов
func (s *Server) SetDoTClient(client *DoTClient) {
	s.dotClient = client
}

// SetAdBlockEngine устанавливает AdBlock движок для блокировки рекламы
func (s *Server) SetAdBlockEngine(engine AdBlockEngine) {
	s.adblock = engine
}

func (s *Server) Start() error {
	// КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Используем UDP и TCP для надежности
	// UDP для обычных запросов, TCP для больших ответов
	s.srv = &dns.Server{
		Addr:      s.addr,
		Net:       "udp",
		Handler:   dns.HandlerFunc(s.handleRequest),
		ReusePort: true,
	}
	
	log.Printf("[DNS] Starting Fake-IP DNS server on %s (UDP)", s.addr)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil {
			log.Printf("[DNS] UDP Server error: %v", err)
		}
	}()
	
	// Также запускаем TCP сервер для больших ответов и надежности
	tcpSrv := &dns.Server{
		Addr:      s.addr,
		Net:       "tcp",
		Handler:   dns.HandlerFunc(s.handleRequest),
		ReusePort: true,
	}
	go func() {
		if err := tcpSrv.ListenAndServe(); err != nil {
			log.Printf("[DNS] TCP Server error: %v", err)
		}
	}()
	log.Printf("[DNS] Starting Fake-IP DNS server on %s (TCP)", s.addr)
	
	return nil
}

func (s *Server) Stop() error {
	if s.srv != nil {
		return s.srv.Shutdown()
	}
	return nil
}

func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	// КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Добавляем логирование для диагностики
	if len(r.Question) > 0 {
		log.Printf("[DNS] Received query for %s (type=%d) from %s", r.Question[0].Name, r.Question[0].Qtype, w.RemoteAddr())
	}
	
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		s.parseQuery(m)
	default:
		log.Printf("[DNS] Unsupported opcode: %d", r.Opcode)
		m.SetRcode(r, dns.RcodeNotImplemented)
	}

	if err := w.WriteMsg(m); err != nil {
		log.Printf("[DNS] Failed to write response: %v", err)
	} else if len(m.Answer) > 0 {
		log.Printf("[DNS] Sent response with %d answers", len(m.Answer))
	}
}

func (s *Server) parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		domain := q.Name
		// normalize domain (remove trailing dot)
		normDomain := strings.TrimSuffix(domain, ".")

		// Проверяем AdBlock перед обработкой запроса
		if s.adblock != nil && s.adblock.IsEnabled() {
			if s.adblock.ShouldBlock(normDomain, "") {
				// Блокируем запрос - возвращаем NXDOMAIN или 0.0.0.0
				log.Printf("[DNS] Blocked %s (AdBlock)", normDomain)
				// Возвращаем пустой ответ (NXDOMAIN)
				return
			}
		}

		switch q.Qtype {
		case dns.TypeA:
			// Приоритет: DoQ > DoT > DoH > Fake-IP
			var resolvedIP net.IP
			
			// Пробуем DoQ сначала (быстрее)
			if s.doqClient != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				ips, err := s.doqClient.Resolve(ctx, normDomain, dns.TypeA)
				cancel()
				
				if err == nil && len(ips) > 0 {
					ip := net.ParseIP(ips[0])
					if ip != nil && ip.To4() != nil {
						resolvedIP = ip
						log.Printf("[DNS] Resolved %s -> %s via DoQ", normDomain, ip.String())
					}
				}
			}
			
			// Если DoQ не сработал, пробуем DoT
			if resolvedIP == nil && s.dotClient != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				ips, err := s.dotClient.Resolve(ctx, normDomain, dns.TypeA)
				cancel()
				
				if err == nil && len(ips) > 0 {
					ip := net.ParseIP(ips[0])
					if ip != nil && ip.To4() != nil {
						resolvedIP = ip
						log.Printf("[DNS] Resolved %s -> %s via DoT", normDomain, ip.String())
					}
				}
			}
			
			// Если DoT не сработал, пробуем DoH
			if resolvedIP == nil && s.dohClient != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				ips, err := s.dohClient.Resolve(ctx, normDomain, dns.TypeA)
				cancel()
				
				if err == nil && len(ips) > 0 {
					ip := net.ParseIP(ips[0])
					if ip != nil && ip.To4() != nil {
						resolvedIP = ip
						log.Printf("[DNS] Resolved %s -> %s via DoH", normDomain, ip.String())
					}
				}
			}
			
			// Если получили реальный IP, используем его
			if resolvedIP != nil {
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300, // 5 минут TTL для реальных IP
					},
					A: resolvedIP,
				}
				m.Answer = append(m.Answer, rr)
				continue
			}

			// Allocate Fake-IP
			ip := s.pool.Get(normDomain)
			log.Printf("[DNS] Resolved %s -> %s (Fake-IP)", normDomain, ip.String())

			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60, // Short TTL to force refresh if restarted
				},
				A: ip,
			}
			m.Answer = append(m.Answer, rr)

		case dns.TypeAAAA:
			// Приоритет: DoQ > DoT > DoH
			var resolvedIP net.IP
			
			// Пробуем DoQ сначала
			if s.doqClient != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				ips, err := s.doqClient.Resolve(ctx, normDomain, dns.TypeAAAA)
				cancel()
				
				if err == nil && len(ips) > 0 {
					ip := net.ParseIP(ips[0])
					if ip != nil && ip.To16() != nil {
						resolvedIP = ip
						log.Printf("[DNS] Resolved %s -> %s via DoQ (AAAA)", normDomain, ip.String())
					}
				}
			}
			
			// Если DoQ не сработал, пробуем DoT
			if resolvedIP == nil && s.dotClient != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				ips, err := s.dotClient.Resolve(ctx, normDomain, dns.TypeAAAA)
				cancel()
				
				if err == nil && len(ips) > 0 {
					ip := net.ParseIP(ips[0])
					if ip != nil && ip.To16() != nil {
						resolvedIP = ip
						log.Printf("[DNS] Resolved %s -> %s via DoT (AAAA)", normDomain, ip.String())
					}
				}
			}
			
			// Если DoT не сработал, пробуем DoH
			if resolvedIP == nil && s.dohClient != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				ips, err := s.dohClient.Resolve(ctx, normDomain, dns.TypeAAAA)
				cancel()
				
				if err == nil && len(ips) > 0 {
					ip := net.ParseIP(ips[0])
					if ip != nil && ip.To16() != nil {
						resolvedIP = ip
						log.Printf("[DNS] Resolved %s -> %s via DoH (AAAA)", normDomain, ip.String())
					}
				}
			}
			
			// Если получили реальный IP, используем его
			if resolvedIP != nil {
				rr := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    300, // 5 минут TTL для реальных IP
					},
					AAAA: resolvedIP,
				}
				m.Answer = append(m.Answer, rr)
				continue
			}
			
			// Fake-IP только для IPv4, для AAAA возвращаем пустой ответ
		}
	}
}

