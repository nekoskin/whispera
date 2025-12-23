package tls

import (
    "crypto/tls"
    "fmt"
    "log"
    "net"
    "time"

    "github.com/pion/dtls/v2"
    tunpkg "whispera/internal/tun"
)

// RunDTLSServer запускает DTLS сервер для UDP
func RunDTLSServer(addr string, config *TLSServerConfig, handler func(*dtls.Conn) error) error {
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load DTLS certificate: %w", err)
	}

	dtlsConfig := &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		InsecureSkipVerify:   false,
		ClientAuth:           dtls.NoClientCert, // Опциональная аутентификация клиента (можно изменить на RequireAnyClientCertificate)
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	listener, err := dtls.Listen("udp", udpAddr, dtlsConfig)
	if err != nil {
		return fmt.Errorf("failed to create DTLS listener: %w", err)
	}
	defer listener.Close()

	log.Printf("DTLS server listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("DTLS accept error: %v", err)
			continue
		}

		dtlsConn, ok := conn.(*dtls.Conn)
		if !ok {
			log.Printf("DTLS connection type assertion failed")
			_ = conn.Close()
			continue
		}

        // Обрабатываем соединение (Accept already handshaked)
		go func(c *dtls.Conn) {
			defer c.Close()
			if err := handler(c); err != nil {
				log.Printf("DTLS handler error: %v", err)
			}
		}(dtlsConn)
	}
}

// ProcessDTLSDataPlane обрабатывает data plane через DTLS соединение
func ProcessDTLSDataPlane(conn *dtls.Conn, tun *tunpkg.Interface, keepaliveSec int) error {
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

