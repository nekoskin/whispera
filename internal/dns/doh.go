package dns

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// DoHClient представляет клиент DNS over HTTPS
type DoHClient struct {
	client    *http.Client
	endpoints []string // Список DoH endpoints
	timeout   time.Duration
}

// NewDoHClient создает новый DoH клиент
func NewDoHClient(endpoints []string, timeout time.Duration) *DoHClient {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &DoHClient{
		client: &http.Client{
			Timeout: timeout,
		},
		endpoints: endpoints,
		timeout:   timeout,
	}
}

// NewDoHClientWithDefaults создает DoH клиент с дефолтными endpoints
func NewDoHClientWithDefaults() *DoHClient {
	defaultEndpoints := []string{
		"https://cloudflare-dns.com/dns-query",
		"https://dns.google/dns-query",
		"https://dns.quad9.net/dns-query",
	}
	return NewDoHClient(defaultEndpoints, 10*time.Second)
}

// Query выполняет DNS запрос через DoH
func (c *DoHClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(c.endpoints) == 0 {
		return nil, fmt.Errorf("no DoH endpoints configured")
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

	return nil, fmt.Errorf("all DoH endpoints failed: %w", lastErr)
}

// queryEndpoint выполняет запрос к конкретному DoH endpoint
func (c *DoHClient) queryEndpoint(ctx context.Context, endpoint string, msg *dns.Msg) (*dns.Msg, error) {
	// Кодируем DNS сообщение в base64url (RFC 8484)
	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(wire)
	url := fmt.Sprintf("%s?dns=%s", endpoint, encoded)

	// Создаем HTTP запрос
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Устанавливаем заголовки для DoH
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "Whispera-DoH/1.0")

	// Выполняем запрос
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH request failed with status: %d", resp.StatusCode)
	}

	// Читаем ответ
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	// Парсим DNS ответ
	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return response, nil
}

// QueryPOST выполняет DNS запрос через DoH используя POST метод
func (c *DoHClient) QueryPOST(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(c.endpoints) == 0 {
		return nil, fmt.Errorf("no DoH endpoints configured")
	}

	// Пробуем все endpoints по порядку
	var lastErr error
	for _, endpoint := range c.endpoints {
		response, err := c.queryEndpointPOST(ctx, endpoint, msg)
		if err == nil {
			return response, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("all DoH endpoints failed: %w", lastErr)
}

// queryEndpointPOST выполняет POST запрос к DoH endpoint
func (c *DoHClient) queryEndpointPOST(ctx context.Context, endpoint string, msg *dns.Msg) (*dns.Msg, error) {
	// Кодируем DNS сообщение
	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Создаем POST запрос
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Устанавливаем заголовки для DoH
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "Whispera-DoH/1.0")

	// Выполняем запрос
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH POST request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH POST request failed with status: %d", resp.StatusCode)
	}

	// Читаем ответ
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	// Парсим DNS ответ
	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return response, nil
}

// Resolve выполняет DNS запрос для домена
func (c *DoHClient) Resolve(ctx context.Context, domain string, qtype uint16) ([]string, error) {
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

// AddEndpoint добавляет DoH endpoint
func (c *DoHClient) AddEndpoint(endpoint string) {
	c.endpoints = append(c.endpoints, endpoint)
}

// GetEndpoints возвращает список endpoints
func (c *DoHClient) GetEndpoints() []string {
	return c.endpoints
}

// SetTimeout устанавливает таймаут для запросов
func (c *DoHClient) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
	c.client.Timeout = timeout
}

