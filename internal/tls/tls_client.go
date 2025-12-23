package tls

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/pion/dtls/v2"
	tunpkg "whispera/internal/tun"
)

// TLSClientConfig конфигурация TLS клиента
type TLSClientConfig struct {
	ServerName         string
	InsecureSkipVerify bool
	MinVersion         uint16
	MaxVersion         uint16
}

// NewTLSClientConfig создает конфигурацию TLS клиента
func NewTLSClientConfig(serverName string, insecureSkipVerify bool) *TLSClientConfig {
	return &TLSClientConfig{
		ServerName:         serverName,
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}
}

// GetTLSConfig возвращает TLS конфигурацию для клиента
// ОПТИМИЗИРОВАНО: Расширенная поддержка версий TLS для избежания Protocol Version ошибок
func (c *TLSClientConfig) GetTLSConfig() *tls.Config {
	// ОПТИМИЗАЦИЯ: Поддержка всех современных версий TLS для избежания Protocol Version ошибок
	minVersion := c.MinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}
	maxVersion := c.MaxVersion
	if maxVersion == 0 {
		maxVersion = tls.VersionTLS13
	}
	
	// SECURITY: Используем браузероподобный TLS fingerprint для обхода DPI
	config := GetBrowserLikeClientTLSConfig(
		GetDefaultBrowserFingerprint(),
		c.ServerName,
		c.InsecureSkipVerify,
	)
	
	// Устанавливаем версии TLS из конфигурации
	config.MinVersion = minVersion
	config.MaxVersion = maxVersion
	
	return config
}

// DialTLS подключается к TLS серверу
// ОПТИМИЗИРОВАНО: Улучшенная обработка таймаутов и ошибок Protocol Version
func DialTLS(addr string, config *TLSClientConfig) (net.Conn, error) {
	tlsConfig := config.GetTLSConfig()
	
	// ОПТИМИЗАЦИЯ: Увеличиваем таймаут для TCP dial до 15 секунд для медленных сетей
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to dial TCP: %w", err)
	}

	tlsConn := tls.Client(conn, tlsConfig)
	
	// ОПТИМИЗАЦИЯ: Увеличиваем deadline для TLS handshake до 15 секунд
	// Это критично, чтобы не зависнуть навсегда если сервер не отвечает
	handshakeDeadline := time.Now().Add(15 * time.Second)
	if err := tlsConn.SetDeadline(handshakeDeadline); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to set handshake deadline: %w", err)
	}
	
	// Выполняем TLS handshake с таймаутом
	handshakeStart := time.Now()
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		handshakeDuration := time.Since(handshakeStart)
		// SECURITY: Removed TLS 1.0/1.1 fallback to prevent downgrade attacks
		// TLS 1.0 and 1.1 are deprecated and insecure
		// If protocol version error occurs, it means server doesn't support TLS 1.2+
		errStr := err.Error()
		if strings.Contains(errStr, "protocol version") || strings.Contains(errStr, "Protocol Version") {
			// Server doesn't support TLS 1.2+, fail securely
			return nil, fmt.Errorf("server does not support TLS 1.2 or higher (required for security): %w", err)
		}
		// Проверяем, был ли это таймаут
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("TLS handshake timeout after %v: %w", handshakeDuration, err)
		}
		return nil, fmt.Errorf("TLS handshake failed after %v: %w", handshakeDuration, err)
	}
	
	// Сбрасываем deadline после успешного handshake
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("[WARN] Failed to clear TLS deadline: %v", err)
	}

	return tlsConn, nil
}

// DialDTLS подключается к DTLS серверу
func DialDTLS(addr string, config *TLSClientConfig) (*dtls.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	dtlsConfig := &dtls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.InsecureSkipVerify,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Используем таймаут для DTLS handshake (10 секунд)
	// Это критично, чтобы не зависнуть навсегда если сервер не отвечает
	// Используем горутину с каналом для реализации таймаута
	type result struct {
		conn *dtls.Conn
		err  error
	}
	
	resultChan := make(chan result, 1)
	handshakeStart := time.Now()
	
	// Запускаем Dial в отдельной горутине
	go func() {
		conn, err := dtls.Dial("udp", udpAddr, dtlsConfig)
		resultChan <- result{conn: conn, err: err}
	}()
	
	// Ждем результата или таймаута
	select {
	case res := <-resultChan:
		handshakeDuration := time.Since(handshakeStart)
		if res.err != nil {
			return nil, fmt.Errorf("DTLS dial failed after %v: %w", handshakeDuration, res.err)
		}
		return res.conn, nil
	case <-time.After(10 * time.Second):
		handshakeDuration := time.Since(handshakeStart)
		return nil, fmt.Errorf("DTLS handshake timeout after %v: server did not respond", handshakeDuration)
	}
}

// ProcessTLSClientDataPlane обрабатывает data plane через TLS соединение (клиент)
func ProcessTLSClientDataPlane(conn net.Conn, tun *tunpkg.Interface, keepaliveSec int) error {
	buf := make([]byte, 65535)
	var seqSend uint32 = 1

	// TUN -> TLS
	go func() {
		for {
			if tun == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			n, err := tun.Read(buf)
			if err != nil {
				return
			}
			payload := buf[:n]

			// В TLS режиме данные отправляются напрямую (TLS уже шифрует)
			if _, err := conn.Write(payload); err != nil {
				return
			}
			seqSend++
		}
	}()

	// TLS -> TUN
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}

		if n == 0 {
			continue
		}

		payload := buf[:n]
		if tun != nil {
			if _, err := tun.Write(payload); err != nil {
				log.Printf("tun write error: %v", err)
			}
		}
	}
}

// ProcessDTLSClientDataPlane обрабатывает data plane через DTLS соединение (клиент)
func ProcessDTLSClientDataPlane(conn *dtls.Conn, tun *tunpkg.Interface, keepaliveSec int) error {
	buf := make([]byte, 65535)
	var seqSend uint32 = 1

	// TUN -> DTLS
	go func() {
		for {
			if tun == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			n, err := tun.Read(buf)
			if err != nil {
				return
			}
			payload := buf[:n]

			// В DTLS режиме данные отправляются напрямую (DTLS уже шифрует)
			if _, err := conn.Write(payload); err != nil {
				return
			}
			seqSend++
		}
	}()

	// DTLS -> TUN
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Отправляем keepalive
				keepalive := []byte{0x00}
				_, _ = conn.Write(keepalive)
				continue
			}
			return err
		}

		if n == 0 {
			continue
		}

		payload := buf[:n]
		if tun != nil {
			if _, err := tun.Write(payload); err != nil {
				log.Printf("tun write error: %v", err)
			}
		}
	}
}

