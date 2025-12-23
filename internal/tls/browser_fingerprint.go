package tls

import (
	"crypto/tls"
	"crypto/x509"
)

// BrowserFingerprintType тип браузерного fingerprint
type BrowserFingerprintType string

const (
	// ChromeFingerprint имитирует Google Chrome
	ChromeFingerprint BrowserFingerprintType = "chrome"
	// FirefoxFingerprint имитирует Mozilla Firefox
	FirefoxFingerprint BrowserFingerprintType = "firefox"
	// SafariFingerprint имитирует Apple Safari
	SafariFingerprint BrowserFingerprintType = "safari"
	// EdgeFingerprint имитирует Microsoft Edge
	EdgeFingerprint BrowserFingerprintType = "edge"
)

// GetBrowserLikeTLSConfig создает TLS конфигурацию, имитирующую реальный браузер
// Это помогает обойти DPI и TLS fingerprinting детекцию
func GetBrowserLikeTLSConfig(fingerprintType BrowserFingerprintType, certs []tls.Certificate) *tls.Config {
	config := &tls.Config{
		Certificates: certs,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"}, // ALPN для HTTP/2
	}

	switch fingerprintType {
	case ChromeFingerprint:
		applyChromeFingerprint(config)
	case FirefoxFingerprint:
		applyFirefoxFingerprint(config)
	case SafariFingerprint:
		applySafariFingerprint(config)
	case EdgeFingerprint:
		applyEdgeFingerprint(config)
	default:
		// По умолчанию используем Chrome (самый популярный)
		applyChromeFingerprint(config)
	}

	return config
}

// applyChromeFingerprint применяет TLS fingerprint Google Chrome
func applyChromeFingerprint(config *tls.Config) {
	// Chrome TLS 1.3 cipher suites (в порядке приоритета)
	config.CipherSuites = []uint16{
		// TLS 1.3 cipher suites
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		// TLS 1.2 cipher suites (Chrome порядок)
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}

	// Chrome curve preferences
	config.CurvePreferences = []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}

	// Chrome предпочитает серверные cipher suites
	config.PreferServerCipherSuites = false

	// Chrome поддерживает session tickets
	config.SessionTicketsDisabled = false
}

// applyFirefoxFingerprint применяет TLS fingerprint Mozilla Firefox
func applyFirefoxFingerprint(config *tls.Config) {
	// Firefox TLS 1.3 cipher suites
	config.CipherSuites = []uint16{
		// TLS 1.3 cipher suites
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		// TLS 1.2 cipher suites (Firefox порядок)
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		// DHE cipher suites удалены - не поддерживаются в стандартной библиотеке Go
	}

	// Firefox curve preferences
	config.CurvePreferences = []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
		tls.CurveP256,
	}

	config.PreferServerCipherSuites = false
	config.SessionTicketsDisabled = false
}

// applySafariFingerprint применяет TLS fingerprint Apple Safari
func applySafariFingerprint(config *tls.Config) {
	// Safari TLS 1.3 cipher suites
	config.CipherSuites = []uint16{
		// TLS 1.3 cipher suites
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		// TLS 1.2 cipher suites (Safari порядок)
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	}

	// Safari curve preferences
	config.CurvePreferences = []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}

	config.PreferServerCipherSuites = false
	config.SessionTicketsDisabled = false
}

// applyEdgeFingerprint применяет TLS fingerprint Microsoft Edge
func applyEdgeFingerprint(config *tls.Config) {
	// Edge использует похожий fingerprint на Chrome (на базе Chromium)
	applyChromeFingerprint(config)
	// Edge может иметь небольшие отличия, но в целом похож на Chrome
}

// GetBrowserLikeServerTLSConfig создает TLS конфигурацию для сервера, имитирующую браузерный ответ
func GetBrowserLikeServerTLSConfig(fingerprintType BrowserFingerprintType, certs []tls.Certificate) *tls.Config {
	config := GetBrowserLikeTLSConfig(fingerprintType, certs)

	// Для сервера настраиваем GetConfigForClient для адаптации под клиента
	config.GetConfigForClient = func(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
		// Возвращаем конфигурацию, которая будет выглядеть как ответ реального веб-сервера
		serverConfig := &tls.Config{
			Certificates: certs,
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h2", "http/1.1"},
		}

		// Адаптируемся под клиента, но сохраняем браузероподобный вид
		switch fingerprintType {
		case ChromeFingerprint:
			applyChromeFingerprint(serverConfig)
		case FirefoxFingerprint:
			applyFirefoxFingerprint(serverConfig)
		case SafariFingerprint:
			applySafariFingerprint(serverConfig)
		case EdgeFingerprint:
			applyEdgeFingerprint(serverConfig)
		}

		// Включаем SNI поддержку
		if clientHello.ServerName != "" {
			// Можно добавить логику выбора сертификата по SNI
		}

		return serverConfig, nil
	}

	return config
}

// GetBrowserLikeClientTLSConfig создает TLS конфигурацию для клиента, имитирующую браузер
func GetBrowserLikeClientTLSConfig(fingerprintType BrowserFingerprintType, serverName string, insecureSkipVerify bool) *tls.Config {
	config := GetBrowserLikeTLSConfig(fingerprintType, nil)

	// Клиентские настройки
	config.ServerName = serverName
	config.InsecureSkipVerify = insecureSkipVerify

	// Клиент не предпочитает серверные cipher suites
	config.PreferServerCipherSuites = false

	// Включаем SNI
	if serverName != "" {
		config.ServerName = serverName
	}

	return config
}

// GetDefaultBrowserFingerprint возвращает fingerprint по умолчанию (Chrome)
func GetDefaultBrowserFingerprint() BrowserFingerprintType {
	return ChromeFingerprint
}

// ValidateBrowserCertificate проверяет сертификат на валидность для браузероподобного TLS
func ValidateBrowserCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	// Проверяем базовые требования
	if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() {
		return false
	}

	// Проверяем срок действия
	// (проверка времени должна быть сделана вызывающим кодом)

	return true
}

