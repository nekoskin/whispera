package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	aeadpkg "whispera/internal/crypto"
	"whispera/internal/proto"
	tunpkg "whispera/internal/tun"
)

// normalizeListenAddr нормализует адрес для IPv4
// Если указан только порт (например ":8080"), преобразует в "0.0.0.0:8080"
func normalizeListenAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		// Если адрес начинается с ":", добавляем 0.0.0.0 для IPv4
		return "0.0.0.0" + addr
	}
	// Если адрес уже содержит IP, возвращаем как есть
	return addr
}

// TLSServerConfig конфигурация TLS сервера
type TLSServerConfig struct {
	CertFile string
	KeyFile  string
	MinVersion uint16
	MaxVersion uint16
	// Loaded static certificates (if any) so callers can inspect
	Certificates []tls.Certificate
	// Dynamic certificate sources
	ExtraCerts map[string]*tls.Certificate // keyed by lower-case DNS name
	GetACMECert func(*tls.ClientHelloInfo) (*tls.Certificate, error) // optional autocert manager
}

// NewTLSServerConfig создает конфигурацию TLS сервера
func NewTLSServerConfig(certFile, keyFile string) (*TLSServerConfig, error) {
	// Static certs are optional now; may rely on ExtraCerts or ACME.
	return &TLSServerConfig{
		CertFile:   certFile,
		KeyFile:    keyFile,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}, nil
}

// GetTLSConfig возвращает TLS конфигурацию для сервера
func (c *TLSServerConfig) GetTLSConfig() (*tls.Config, error) {
	var certs []tls.Certificate
	// Load static certificate if provided and readable
	if c.CertFile != "" && c.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			// Only treat as fatal if no other certificate sources are configured
			if c.ExtraCerts == nil && c.GetACMECert == nil {
				return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
			}
		} else {
			certs = append(certs, cert)
		}
	}

	// expose loaded certs for external inspection
	c.Certificates = certs

	// Check if we have at least one certificate source
	hasCerts := len(certs) > 0
	hasExtraCerts := c.ExtraCerts != nil && len(c.ExtraCerts) > 0
	hasACMECert := c.GetACMECert != nil

	if !hasCerts && !hasExtraCerts && !hasACMECert {
		return nil, fmt.Errorf("no certificate sources configured: need -tls-cert/-tls-key, -tls-cert-dir, or -acme-domain")
	}

	// SECURITY: Используем браузероподобный TLS fingerprint для обхода DPI
	// По умолчанию используем Chrome fingerprint (самый популярный)
	browserConfig := GetBrowserLikeServerTLSConfig(GetDefaultBrowserFingerprint(), certs)
	
	// Сохраняем GetCertificate логику
	browserConfig.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if chi != nil {
			domain := strings.ToLower(chi.ServerName)
			if domain != "" && c.ExtraCerts != nil {
				if certPtr, ok := c.ExtraCerts[domain]; ok {
					return certPtr, nil
				}
			}
		}
		if c.GetACMECert != nil {
			if cert, err := c.GetACMECert(chi); err == nil && cert != nil {
				return cert, nil
			}
		}
		// fallback to static cert only if it exists
		if len(certs) > 0 {
			return &certs[0], nil
		}
		// If we reach here, something is wrong - we should have caught this earlier
		return nil, fmt.Errorf("no certificate available for SNI: %v", chi.ServerName)
	}
	
	// Устанавливаем версии TLS из конфигурации
	browserConfig.MinVersion = c.MinVersion
	browserConfig.MaxVersion = c.MaxVersion
	
	return browserConfig, nil
}

// RunTLSTCPServer запускает TLS TCP сервер
func RunTLSTCPServer(addr string, config *TLSServerConfig, handler func(net.Conn) error) error {
	tlsConfig, err := config.GetTLSConfig()
	if err != nil {
		return err
	}

	// Нормализуем адрес для IPv4 (если указан :port, используем 0.0.0.0:port)
	normalizedAddr := normalizeListenAddr(addr)
	// Явно используем IPv4 для слушателя
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", normalizedAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", normalizedAddr, err)
	}
	defer ln.Close()

	log.Printf("TLS TCP server listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("TLS TCP accept error: %v", err)
			continue
		}

		// Обертываем соединение в TLS
		tlsConn := tls.Server(conn, tlsConfig)
		
		// Выполняем TLS handshake
		tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			// Фильтруем ожидаемые ошибки (когда клиент пытается подключиться к TLS порту используя обычный TCP)
			errStr := err.Error()
			// Suppress common bot/scanner TLS errors - these are expected noise
			shouldSuppress := strings.Contains(errStr, "first record does not look like a TLS handshake") ||
				strings.Contains(errStr, "client sent an HTTP request to an HTTPS server") ||
				strings.Contains(errStr, ": EOF") ||
				strings.Contains(errStr, "unknown certificate") ||
				strings.Contains(errStr, "bad certificate") ||
				strings.Contains(errStr, "certificate verify failed") ||
				strings.Contains(errStr, "remote error: tls:") ||
				strings.Contains(errStr, "unsupported application protocols") ||
				strings.Contains(errStr, "unsupported versions") ||
				strings.Contains(errStr, "no cipher suite supported") ||
				strings.Contains(errStr, "client offered only unsupported versions") ||
				strings.Contains(errStr, "client requested unsupported application protocols") ||
				(strings.Contains(errStr, "tls:") && (strings.Contains(errStr, "handshake") || strings.Contains(errStr, "bad certificate") || strings.Contains(errStr, "record")))
			
			if !shouldSuppress {
				// Only log unexpected TLS errors
				log.Printf("TLS handshake failed: %v", err)
			}
			_ = conn.Close()
			continue
		}
		tlsConn.SetDeadline(time.Time{}) // Сбрасываем deadline после handshake

		// Обрабатываем соединение
		go func(c net.Conn) {
			defer c.Close()
			if err := handler(c); err != nil && err != io.EOF {
				log.Printf("TLS TCP handler error: %v", err)
			}
		}(tlsConn)
	}
}

// TLSConnectionState представляет состояние TLS соединения
type TLSConnectionState struct {
	Conn     net.Conn
	TLSState tls.ConnectionState
	SessionID uint32
	AEADState *aeadpkg.AEADState
}

// detectAndSkipVLESSHeader reads from the TLS connection and, if it detects a
// VLESS v0 request header, consumes it so that the remaining stream contains
// only payload bytes. It returns the first payload bytes that were read after
// the header (if any). We implement a *very* small subset of the spec: UUID
// (16 bytes) is read but **not** validated; optional addon length is read and
// skipped; for RequestCommandTCP/UDP we also skip address+port. Other
// commands (Mux / Rvs) are recognised and ignored.
//
// This allows Whispera TLS server to interoperate with generic VLESS clients
// by simply ignoring their proxy-specific header and treating the connection
// as a raw data pipe (equivalent to Reality or VLESS-padding). For more
// advanced routing you would need full DecodeRequestHeader implementation.
func detectAndSkipVLESSHeader(conn net.Conn) (net.Conn, []byte, error) {
    // We use a small buffer; most VLESS headers are < 64 bytes.
    buf := make([]byte, 64)
    n, err := io.ReadFull(conn, buf[:1])
    if err != nil {
        return nil, nil, err
    }
    if buf[0] != 0x00 {
        // Not VLESS, push byte back by wrapping with io.MultiReader.
        return &pushbackConn{Conn: conn, first: buf[:1]}, nil, nil
    }

    // Read UUID (16 bytes)
    if _, err := io.ReadFull(conn, buf[1:17]); err != nil {
        return nil, nil, err
    }

    // Read addon length (1 byte)
    var addonLen [1]byte
    if _, err := io.ReadFull(conn, addonLen[:]); err != nil {
        return nil, nil, err
    }
    if addonLen[0] > 0 {
        if _, err := io.CopyN(io.Discard, conn, int64(addonLen[0])); err != nil {
            return nil, nil, err
        }
    }

    // Read command
    var cmd [1]byte
    if _, err := io.ReadFull(conn, cmd[:]); err != nil {
        return nil, nil, err
    }

    switch cmd[0] {
    case 0x01, 0x02: // TCP or UDP: need to skip address & port
        // addr type
        var atyp [1]byte
        if _, err := io.ReadFull(conn, atyp[:]); err != nil {
            return nil, nil, err
        }
        switch atyp[0] {
        case 1: // IPv4: 4 bytes addr + 2 bytes port
            if _, err := io.CopyN(io.Discard, conn, 4+2); err != nil {
                return nil, nil, err
            }
        case 3: // Domain: 1 byte len + n bytes domain + 2 bytes port
            var dlen [1]byte
            if _, err := io.ReadFull(conn, dlen[:]); err != nil {
                return nil, nil, err
            }
            if _, err := io.CopyN(io.Discard, conn, int64(dlen[0])+2); err != nil {
                return nil, nil, err
            }
        case 4: // IPv6: 16 bytes + 2 bytes port
            if _, err := io.CopyN(io.Discard, conn, 16+2); err != nil {
                return nil, nil, err
            }
        default:
            return nil, nil, fmt.Errorf("unknown VLESS addr type %d", atyp[0])
        }
    case 0x03, 0x04: // Mux/Rvs – no address
    default:
        // Unknown command – treat as non-VLESS, push back all read bytes.
        data := append([]byte{0x00}, buf[1:n]...)
        return &pushbackConn{Conn: conn, first: data}, nil, nil
    }

    // After skipping header we have consumed it entirely. There might already
    // be payload bytes waiting in TCP buffer – read what is available without
    // blocking (non-blocking peek).
    conn.SetReadDeadline(time.Now())
    m, _ := conn.Read(buf)
    conn.SetReadDeadline(time.Time{})
    return conn, buf[:m], nil
}

// pushbackConn allows us to "unread" some bytes – we return them first on the
// next Read().
type pushbackConn struct {
    net.Conn
    first []byte
}

func (p *pushbackConn) Read(b []byte) (int, error) {
    if len(p.first) > 0 {
        n := copy(b, p.first)
        p.first = p.first[n:]
        return n, nil
    }
    return p.Conn.Read(b)
}

// ProcessTLSDataPlane обрабатывает data plane через TLS соединение
func ProcessTLSDataPlane(conn net.Conn, tun *tunpkg.Interface, keepaliveSec int) error {
	// Detect and discard VLESS header if present. If VLESS payload bytes are
	// already available, we keep them in prebuf.
	newConn, prebuf, _ := detectAndSkipVLESSHeader(conn)
	if newConn != nil {
		conn = newConn
	}

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
			// Xray-core style: raw data without protocol headers
			if _, err := conn.Write(payload); err != nil {
				return
			}
			seqSend++
		}
	}()

	// TLS -> TUN
	for {
		var n int
		var err error
		if len(prebuf) > 0 {
			n = copy(buf, prebuf)
			prebuf = prebuf[n:]
		} else {
			n, err = conn.Read(buf)
		}
		if err != nil {
			return err
		}

		if n == 0 {
			continue
		}

		// Try to parse as protocol header, fallback to raw data
		if n >= proto.HeaderLen {
			var h proto.PacketHeader
			if err := h.UnmarshalBinary(buf[:proto.HeaderLen]); err == nil {
				// Valid header, extract payload
				payload := buf[proto.HeaderLen:n]
				if tun != nil && len(payload) > 0 {
					if _, err := tun.Write(payload); err != nil {
						log.Printf("tun write error: %v", err)
					}
				}
				continue
			}
		}

		// No valid header, treat as raw data (Xray-core style)
		if tun != nil {
			if _, err := tun.Write(buf[:n]); err != nil {
				log.Printf("tun write error: %v", err)
			}
		}
	}
}

// ValidateCertificate проверяет валидность TLS сертификата
func ValidateCertificate(certFile, keyFile string) error {
    certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Проверяем, что сертификат не истек
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired")
	}

	if time.Now().Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid")
	}

	// Проверяем приватный ключ
    keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode PEM key")
	}

	_, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("certificate and key do not match: %w", err)
	}

	return nil
}

