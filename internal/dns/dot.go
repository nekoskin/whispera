package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
)

// DoTClient представляет клиент DNS over TLS
type DoTClient struct {
	endpoints []string // Список DoT endpoints (host:port)
	timeout   time.Duration
	tlsConfig *tls.Config
	dialer    *net.Dialer
}

// NewDoTClient создает новый DoT клиент
func NewDoTClient(endpoints []string, timeout time.Duration) *DoTClient {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &DoTClient{
		endpoints: endpoints,
		timeout:   timeout,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: false, // По умолчанию проверяем сертификаты
		},
		dialer: &net.Dialer{
			Timeout: timeout,
		},
	}
}

// NewDoTClientWithDefaults создает DoT клиент с дефолтными endpoints
func NewDoTClientWithDefaults() *DoTClient {
	defaultEndpoints := []string{
		"dns.adguard.com:853",
		"dns.cloudflare.com:853",
		"dns.quad9.net:853",
		"1.1.1.1:853", // Cloudflare
		"9.9.9.9:853", // Quad9
	}
	return NewDoTClient(defaultEndpoints, 10*time.Second)
}

// SetTLSConfig устанавливает TLS конфигурацию
func (c *DoTClient) SetTLSConfig(config *tls.Config) {
	c.tlsConfig = config
}

// Query выполняет DNS запрос через DoT
func (c *DoTClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(c.endpoints) == 0 {
		return nil, fmt.Errorf("no DoT endpoints configured")
	}

	// Пробуем все endpoints по порядку
	var lastErr error
	for _, endpoint := range c.endpoints {
		response, err := c.queryEndpoint(ctx, endpoint, msg)
		if err == nil {
			return response, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("all DoT endpoints failed: %w", lastErr)
}

// queryEndpoint выполняет запрос к конкретному DoT endpoint
func (c *DoTClient) queryEndpoint(ctx context.Context, endpoint string, msg *dns.Msg) (*dns.Msg, error) {
	// Создаем контекст с таймаутом
	queryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Устанавливаем TCP соединение
	conn, err := c.dialer.DialContext(queryCtx, "tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to dial DoT endpoint %s: %w", endpoint, err)
	}
	defer conn.Close()

	// Устанавливаем TLS поверх TCP
	// Для DoT используется стандартный TLS handshake
	tlsConn := tls.Client(conn, c.tlsConfig)
	
	// Выполняем TLS handshake с контекстом
	handshakeDone := make(chan error, 1)
	go func() {
		handshakeDone <- tlsConn.Handshake()
	}()
	
	select {
	case err := <-handshakeDone:
		if err != nil {
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
	case <-queryCtx.Done():
		return nil, fmt.Errorf("TLS handshake timeout: %w", queryCtx.Err())
	}

	// Кодируем DNS сообщение
	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// DoT использует TCP-style DNS (RFC 7858): сначала 2 байта длины, затем сообщение
	length := uint16(len(wire))
	lengthBuf := make([]byte, 2)
	lengthBuf[0] = byte(length >> 8)
	lengthBuf[1] = byte(length & 0xFF)

	// Отправляем длину и сообщение
	if _, err := tlsConn.Write(lengthBuf); err != nil {
		return nil, fmt.Errorf("failed to write DNS query length: %w", err)
	}
	if _, err := tlsConn.Write(wire); err != nil {
		return nil, fmt.Errorf("failed to write DNS query: %w", err)
	}

	// Читаем ответ (сначала читаем длину сообщения - 2 байта)
	responseLengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(tlsConn, responseLengthBuf); err != nil {
		return nil, fmt.Errorf("failed to read DNS response length: %w", err)
	}

	// Длина сообщения в big-endian формате
	responseLength := int(responseLengthBuf[0])<<8 | int(responseLengthBuf[1])
	if responseLength > 65535 || responseLength < 12 {
		return nil, fmt.Errorf("invalid DNS message length: %d", responseLength)
	}

	// Читаем само сообщение
	responseBuf := make([]byte, responseLength)
	if _, err := io.ReadFull(tlsConn, responseBuf); err != nil {
		return nil, fmt.Errorf("failed to read DNS response: %w", err)
	}

	// Парсим DNS ответ
	response := new(dns.Msg)
	if err := response.Unpack(responseBuf); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return response, nil
}

// Resolve выполняет DNS запрос для домена
func (c *DoTClient) Resolve(ctx context.Context, domain string, qtype uint16) ([]string, error) {
	// Создаем DNS запрос
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true

	// Выполняем запрос
	response, err := c.Query(ctx, msg)
	if err != nil {
		return nil, err
	}

	// Извлекаем IP адреса из ответа
	var ips []string
	for _, rr := range response.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A.String())
		case *dns.AAAA:
			ips = append(ips, v.AAAA.String())
		}
	}

	return ips, nil
}

// ResolveA выполняет A запрос (IPv4)
func (c *DoTClient) ResolveA(ctx context.Context, domain string) ([]string, error) {
	return c.Resolve(ctx, domain, dns.TypeA)
}

// ResolveAAAA выполняет AAAA запрос (IPv6)
func (c *DoTClient) ResolveAAAA(ctx context.Context, domain string) ([]string, error) {
	return c.Resolve(ctx, domain, dns.TypeAAAA)
}

