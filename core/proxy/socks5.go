package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

const (
	socks5Version                    = 0x05
	socks5CmdConnect                 = 0x01
	socks5AtypIPv4                   = 0x01
	socks5AtypDomain                 = 0x03
	socks5AtypIPv6                   = 0x04
	socks5RepSuccess                 = 0x00
	socks5RepGeneralFailure          = 0x01
	socks5RepNotAllowed              = 0x02
	socks5RepNetworkUnreachable      = 0x03
	socks5RepHostUnreachable         = 0x04
	socks5RepConnectionRefused       = 0x05
	socks5RepTTLExpired              = 0x06
	socks5RepCommandNotSupported     = 0x07
	socks5RepAddressTypeNotSupported = 0x08
)

// SOCKS5Proxy реализует SOCKS5 прокси сервер
type SOCKS5Proxy struct {
	config   *Config
	listener net.Listener
	stats    *Stats
}

// NewSOCKS5Proxy создает новый SOCKS5 прокси
func NewSOCKS5Proxy(config *Config) *SOCKS5Proxy {
	return &SOCKS5Proxy{
		config: config,
		stats: &Stats{
			StartTime: time.Now(),
		},
	}
}

// Type возвращает тип прокси
func (p *SOCKS5Proxy) Type() ProxyType {
	return ProxySOCKS5
}

// Start запускает SOCKS5 прокси сервер
func (p *SOCKS5Proxy) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", p.config.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.config.Addr, err)
	}
	p.listener = listener

	log.Printf("[SOCKS5-PROXY] ✅ Server listening on %s", p.config.Addr)

	// Запускаем обработчик соединений в горутине
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Printf("[SOCKS5-PROXY] ❌ Accept error: %v", err)
				}
				continue
			}

			go p.handleConnection(conn)
		}
	}()

	// Ожидаем контекст для остановки
	<-ctx.Done()
	return p.Stop()
}

// Stop останавливает SOCKS5 прокси сервер
func (p *SOCKS5Proxy) Stop() error {
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// Addr возвращает адрес прослушивания
func (p *SOCKS5Proxy) Addr() net.Addr {
	if p.listener != nil {
		return p.listener.Addr()
	}
	return nil
}

// Stats возвращает статистику
func (p *SOCKS5Proxy) Stats() *Stats {
	return p.stats
}

// Reset сбрасывает статистику
func (p *SOCKS5Proxy) Reset() {
	p.stats = &Stats{
		StartTime: time.Now(),
	}
}

// handleConnection обрабатывает одно соединение
func (p *SOCKS5Proxy) handleConnection(conn net.Conn) {
	defer conn.Close()
	p.stats.Connections++

	// SOCKS5 handshake
	if err := p.handshake(conn); err != nil {
		p.stats.Errors++
		log.Printf("[SOCKS5-PROXY] ❌ Handshake failed: %v", err)
		return
	}

	// Обработка запроса
	if err := p.handleRequest(conn); err != nil {
		p.stats.Errors++
		log.Printf("[SOCKS5-PROXY] ❌ Request failed: %v", err)
		return
	}
}

// handshake выполняет SOCKS5 handshake
func (p *SOCKS5Proxy) handshake(conn net.Conn) error {
	// Читаем версию и количество методов
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != socks5Version {
		return fmt.Errorf("invalid version: %d", buf[0])
	}

	nMethods := int(buf[1])
	if nMethods == 0 {
		return fmt.Errorf("no authentication methods")
	}

	// Читаем методы
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Поддерживаем только метод без аутентификации (0x00)
	authMethod := byte(0x00)
	for _, method := range methods {
		if method == 0x00 {
			authMethod = method
			break
		}
	}

	// Отправляем выбранный метод
	response := []byte{socks5Version, authMethod}
	_, err := conn.Write(response)
	return err
}

// handleRequest обрабатывает SOCKS5 запрос
func (p *SOCKS5Proxy) handleRequest(conn net.Conn) error {
	// Читаем заголовок запроса
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	version := buf[0]
	cmd := buf[1]
	_ = buf[2] // reserved
	atyp := buf[3]

	if version != socks5Version {
		return fmt.Errorf("invalid version: %d", version)
	}

	if cmd != socks5CmdConnect {
		p.sendReply(conn, socks5RepCommandNotSupported, nil)
		return fmt.Errorf("unsupported command: %d", cmd)
	}

	// Читаем адрес назначения
	var dstAddr string
	var dstPort uint16

	switch atyp {
	case socks5AtypIPv4:
		addrBuf := make([]byte, 4+2) // 4 bytes IP + 2 bytes port
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return err
		}
		dstAddr = net.IP(addrBuf[:4]).String()
		dstPort = binary.BigEndian.Uint16(addrBuf[4:])

	case socks5AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		domainLen := int(lenBuf[0])

		domainBuf := make([]byte, domainLen+2) // domain + 2 bytes port
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return err
		}
		dstAddr = string(domainBuf[:domainLen])
		dstPort = binary.BigEndian.Uint16(domainBuf[domainLen:])

	case socks5AtypIPv6:
		addrBuf := make([]byte, 16+2) // 16 bytes IP + 2 bytes port
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return err
		}
		dstAddr = net.IP(addrBuf[:16]).String()
		dstPort = binary.BigEndian.Uint16(addrBuf[4:])

	default:
		p.sendReply(conn, socks5RepAddressTypeNotSupported, nil)
		return fmt.Errorf("unsupported address type: %d", atyp)
	}

	// Устанавливаем соединение с целевым сервером
	target := net.JoinHostPort(dstAddr, strconv.Itoa(int(dstPort)))
	dstConn, err := net.DialTimeout("tcp", target, p.config.Timeout)
	if err != nil {
		p.sendReply(conn, socks5RepHostUnreachable, nil)
		return fmt.Errorf("failed to connect to %s: %w", target, err)
	}
	defer dstConn.Close()

	// Отправляем успешный ответ
	if err := p.sendReply(conn, socks5RepSuccess, dstConn.LocalAddr()); err != nil {
		return err
	}

	// Начинаем проксирование данных
	p.proxyData(conn, dstConn)
	return nil
}

// sendReply отправляет SOCKS5 ответ
func (p *SOCKS5Proxy) sendReply(conn net.Conn, rep byte, bindAddr net.Addr) error {
	var buf []byte
	buf = append(buf, socks5Version, rep, 0x00) // version, reply, reserved

	if bindAddr != nil {
		addr := bindAddr.(*net.TCPAddr)
		if ip := addr.IP.To4(); ip != nil {
			// IPv4
			buf = append(buf, socks5AtypIPv4)
			buf = append(buf, ip...)
		} else if ip := addr.IP.To16(); ip != nil {
			// IPv6
			buf = append(buf, socks5AtypIPv6)
			buf = append(buf, ip...)
		} else {
			// Fallback to IPv4 0.0.0.0
			buf = append(buf, socks5AtypIPv4, 0, 0, 0, 0)
		}
		buf = append(buf, byte(addr.Port>>8), byte(addr.Port))
	} else {
		// No bind address
		buf = append(buf, socks5AtypIPv4, 0, 0, 0, 0, 0, 0)
	}

	_, err := conn.Write(buf)
	return err
}

// proxyData проксирует данные между соединениями
func (p *SOCKS5Proxy) proxyData(client, server net.Conn) {
	done := make(chan struct{}, 2)

	// Client -> Server
	go func() {
		io.Copy(server, client)
		done <- struct{}{}
	}()

	// Server -> Client
	go func() {
		io.Copy(client, server)
		done <- struct{}{}
	}()

	// Ждем завершения любой из горутин
	<-done
}
