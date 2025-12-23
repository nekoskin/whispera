package adblock

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
)

// DNSHandler обрабатывает DNS запросы с блокировкой рекламы
type DNSHandler struct {
	adBlocker *AdBlocker
	upstream  string // Upstream DNS сервер (например, 8.8.8.8:53)
	client    *dns.Client
}

// NewDNSHandler создает новый DNS handler
func NewDNSHandler(adBlocker *AdBlocker, upstream string) *DNSHandler {
	if upstream == "" {
		upstream = "8.8.8.8:53" // Google DNS по умолчанию
	}
	
	return &DNSHandler{
		adBlocker: adBlocker,
		upstream:  upstream,
		client:    &dns.Client{Timeout: 5 * time.Second},
	}
}

// HandleDNS обрабатывает DNS запрос
func (dh *DNSHandler) HandleDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	
	// Получаем домен из запроса
	domain := ""
	if len(r.Question) > 0 {
		domain = r.Question[0].Name
		domain = domain[:len(domain)-1] // Убираем точку в конце
	}
	
	// Проверяем нужно ли блокировать
	if dh.adBlocker.ShouldBlockDNS(domain) {
		dh.adBlocker.BlockDNS(domain)
		
		// Возвращаем пустой ответ или блокирующий IP
		msg.SetRcode(r, dns.RcodeSuccess)
		// Добавляем блокирующий ответ (0.0.0.0)
		if r.Question[0].Qtype == dns.TypeA {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(0, 0, 0, 0), // Блокирующий IP
			}
			msg.Answer = append(msg.Answer, rr)
		}
		
		w.WriteMsg(msg)
		return
	}
	
	// Если не блокируем - перенаправляем на upstream DNS
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	upstreamMsg, _, err := dh.client.ExchangeContext(ctx, r, dh.upstream)
	if err != nil {
		// В случае ошибки возвращаем SERVFAIL
		msg.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(msg)
		return
	}
	
	w.WriteMsg(upstreamMsg)
}

// StartDNSServer запускает DNS сервер для блокировки рекламы
func (dh *DNSHandler) StartDNSServer(listenAddr string) error {
	dns.HandleFunc(".", dh.HandleDNS)
	
	server := &dns.Server{
		Addr:    listenAddr,
		Net:     "udp",
		Handler: dns.DefaultServeMux,
	}
	
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Printf("[DNSHandler] Error starting DNS server: %v", err)
		}
	}()
	
	// Также запускаем TCP сервер
	tcpServer := &dns.Server{
		Addr:    listenAddr,
		Net:     "tcp",
		Handler: dns.DefaultServeMux,
	}
	
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("[DNSHandler] Error starting TCP DNS server: %v", err)
		}
	}()
	
	log.Printf("[DNSHandler] DNS server started on %s", listenAddr)
	return nil
}

