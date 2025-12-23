package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// DoQClient представляет клиент DNS over QUIC
type DoQClient struct {
	endpoints []string // Список DoQ endpoints (host:port)
	timeout   time.Duration
	tlsConfig *tls.Config
}

// NewDoQClient создает новый DoQ клиент
func NewDoQClient(endpoints []string, timeout time.Duration) *DoQClient {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &DoQClient{
		endpoints: endpoints,
		timeout:   timeout,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: false, // По умолчанию проверяем сертификаты
		},
	}
}

// NewDoQClientWithDefaults создает DoQ клиент с дефолтными endpoints
func NewDoQClientWithDefaults() *DoQClient {
	defaultEndpoints := []string{
		"dns.adguard.com:853",
		"dns.cloudflare.com:853",
		"dns.quad9.net:853",
	}
	return NewDoQClient(defaultEndpoints, 10*time.Second)
}

// SetTLSConfig устанавливает TLS конфигурацию
func (c *DoQClient) SetTLSConfig(config *tls.Config) {
	c.tlsConfig = config
}

// Query выполняет DNS запрос через DoQ
func (c *DoQClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(c.endpoints) == 0 {
		return nil, fmt.Errorf("no DoQ endpoints configured")
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

	return nil, fmt.Errorf("all DoQ endpoints failed: %w", lastErr)
}

// queryEndpoint выполняет запрос к конкретному DoQ endpoint
func (c *DoQClient) queryEndpoint(ctx context.Context, endpoint string, msg *dns.Msg) (*dns.Msg, error) {
	// Создаем контекст с таймаутом
	queryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Устанавливаем QUIC соединение
	conn, err := quic.DialAddr(queryCtx, endpoint, c.tlsConfig, &quic.Config{
		KeepAlivePeriod: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dial DoQ endpoint %s: %w", endpoint, err)
	}
	defer conn.CloseWithError(0, "")

	// Открываем поток для DNS запроса
	stream, err := conn.OpenStreamSync(queryCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to open QUIC stream: %w", err)
	}
	defer stream.Close()

	// Кодируем DNS сообщение
	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Отправляем DNS запрос
	if _, err := stream.Write(wire); err != nil {
		return nil, fmt.Errorf("failed to write DNS query: %w", err)
	}

	// Закрываем поток для отправки (half-close)
	stream.CancelWrite(0)

	// Читаем ответ
	responseBuf := make([]byte, 4096)
	n, err := stream.Read(responseBuf)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read DNS response: %w", err)
	}

	// Парсим DNS ответ
	response := new(dns.Msg)
	if err := response.Unpack(responseBuf[:n]); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return response, nil
}

// Resolve выполняет DNS запрос для домена
func (c *DoQClient) Resolve(ctx context.Context, domain string, qtype uint16) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true

	response, err := c.Query(ctx, msg)
	if err != nil {
		return nil, err
	}

	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query failed with RCODE: %d", response.Rcode)
	}

	// Извлекаем IP адреса из ответа
	ips := make([]string, 0)
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

// AddEndpoint добавляет DoQ endpoint
func (c *DoQClient) AddEndpoint(endpoint string) {
	c.endpoints = append(c.endpoints, endpoint)
}

// GetEndpoints возвращает список endpoints
func (c *DoQClient) GetEndpoints() []string {
	return c.endpoints
}

// SetTimeout устанавливает таймаут для запросов
func (c *DoQClient) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

