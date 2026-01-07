package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"whispera/internal/logger"
)

const (
	socks5Version = 0x05

	socks5MethodNoAuth        = 0x00
	socks5MethodUsernamePass  = 0x02
	socks5MethodNotAcceptable = 0xFF

	socks5CmdConnect = 0x01
	socks5CmdBind    = 0x02
	socks5CmdUDP     = 0x03

	socks5ATYPIPv4   = 0x01
	socks5ATYPIPv6   = 0x04
	socks5ATYPDomain = 0x03

	socks5ReplySuccess                 = 0x00
	socks5ReplyGeneralFailure          = 0x01
	socks5ReplyConnectionNotAllowed    = 0x02
	socks5ReplyNetworkUnreachable      = 0x03
	socks5ReplyHostUnreachable         = 0x04
	socks5ReplyConnectionRefused       = 0x05
	socks5ReplyTTLExpired              = 0x06
	socks5ReplyCommandNotSupported     = 0x07
	socks5ReplyAddressTypeNotSupported = 0x08
)

// AuthHandler функция для проверки аутентификации
type AuthHandler func(username, password string) bool

// SOCKS5Server представляет SOCKS5 прокси сервер
type SOCKS5Server struct {
	listenAddr  string
	handler     func(net.Conn, string, uint16) error
	authHandler AuthHandler  // Обработчик аутентификации (nil = NoAuth)
	udpConn     *net.UDPConn // UDP соединение для UDP ASSOCIATE
	udpAddr     *net.UDPAddr // Адрес UDP сервера
	mu          sync.RWMutex
	log         *logger.Logger
}

// NewSOCKS5Server создает новый SOCKS5 сервер
func NewSOCKS5Server(addr string, handler func(net.Conn, string, uint16) error) *SOCKS5Server {
	return &SOCKS5Server{
		listenAddr: addr,
		handler:    handler,
		log:        logger.Module("socks5"),
	}
}

// SetAuthHandler устанавливает обработчик аутентификации
func (s *SOCKS5Server) SetAuthHandler(handler AuthHandler) {
	s.authHandler = handler
}

// SetUDPAddr устанавливает адрес для UDP ASSOCIATE
func (s *SOCKS5Server) SetUDPAddr(addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.udpAddr = addr
}

// ListenAndServe запускает SOCKS5 сервер
func (s *SOCKS5Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.listenAddr, err)
	}
	defer listener.Close()

	s.log.Info("✅ Server listening on %s - ready to accept connections", s.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.log.Error("Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// handleConnection обрабатывает одно SOCKS5 подключение
func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// SOCKS5 handshake
	if err := s.handleHandshake(conn); err != nil {
		s.log.Debug("Handshake failed: %v", err)
		return
	}

	// SOCKS5 request
	addr, port, err := s.handleRequest(conn)
	if err != nil {
		s.log.Debug("Request failed: %v", err)
		return
	}

	// Вызываем обработчик для проксирования
	if err := s.handler(conn, addr, port); err != nil {
		s.log.Debug("Handler failed: %v", err)
	}
}

// handleHandshake обрабатывает SOCKS5 handshake
func (s *SOCKS5Server) handleHandshake(conn net.Conn) error {
	// Читаем версию и количество методов
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	nMethods := int(buf[1])
	if nMethods == 0 {
		return errors.New("no authentication methods")
	}

	// Читаем методы
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Выбираем метод (предпочитаем Username/Password если есть handler, иначе NoAuth)
	selectedMethod := byte(socks5MethodNotAcceptable)
	hasNoAuth := false
	hasUsernamePass := false

	for _, method := range methods {
		if method == socks5MethodNoAuth {
			hasNoAuth = true
		}
		if method == socks5MethodUsernamePass {
			hasUsernamePass = true
		}
	}

	// Если есть auth handler, предпочитаем Username/Password
	if s.authHandler != nil && hasUsernamePass {
		selectedMethod = socks5MethodUsernamePass
	} else if hasNoAuth {
		selectedMethod = socks5MethodNoAuth
	}

	// Отправляем ответ
	response := []byte{socks5Version, selectedMethod}
	if _, err := conn.Write(response); err != nil {
		return err
	}

	if selectedMethod == socks5MethodNotAcceptable {
		return errors.New("no acceptable authentication method")
	}

	// Если выбран Username/Password, выполняем аутентификацию
	if selectedMethod == socks5MethodUsernamePass {
		if err := s.handleUsernamePasswordAuth(conn); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	return nil
}

// handleRequest обрабатывает SOCKS5 request
func (s *SOCKS5Server) handleRequest(conn net.Conn) (string, uint16, error) {
	// Читаем заголовок запроса
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}

	if header[0] != socks5Version {
		return "", 0, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	cmd := header[1]

	// Обрабатываем разные команды
	switch cmd {
	case socks5CmdConnect:
		// Обрабатывается ниже
	case socks5CmdUDP:
		// UDP ASSOCIATE
		return s.handleUDPAssociate(conn)
	case socks5CmdBind:
		// BIND не поддерживается
		s.sendReply(conn, socks5ReplyCommandNotSupported, nil, 0)
		return "", 0, fmt.Errorf("BIND command not supported")
	default:
		s.sendReply(conn, socks5ReplyCommandNotSupported, nil, 0)
		return "", 0, fmt.Errorf("unsupported command: %d", cmd)
	}

	// Читаем адрес
	atyp := header[3]
	var addr string
	var port uint16

	switch atyp {
	case socks5ATYPIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", 0, err
		}
		addr = net.IP(ip).String()

	case socks5ATYPIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", 0, err
		}
		addr = net.IP(ip).String()

	case socks5ATYPDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", 0, err
		}
		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", 0, err
		}
		addr = string(domain)

	default:
		s.sendReply(conn, socks5ReplyAddressTypeNotSupported, nil, 0)
		return "", 0, fmt.Errorf("unsupported address type: %d", atyp)
	}

	// Читаем порт
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, err
	}
	port = binary.BigEndian.Uint16(portBuf)

	// Обрабатываем разные команды
	switch cmd {
	case socks5CmdConnect:
		// Отправляем успешный ответ с адресом клиента
		// Определяем тип адреса для ответа
		var replyAddr []byte
		var replyPort uint16 = 0 // Порт не используется для CONNECT

		if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			if ip4 := tcpAddr.IP.To4(); ip4 != nil {
				// IPv4
				replyAddr = append([]byte{socks5ATYPIPv4}, ip4...)
			} else if ip6 := tcpAddr.IP.To16(); ip6 != nil {
				// IPv6
				replyAddr = append([]byte{socks5ATYPIPv6}, ip6...)
			}
		}

		// Если не удалось определить адрес, используем заглушку
		if replyAddr == nil {
			replyAddr = []byte{socks5ATYPIPv4, 0, 0, 0, 0}
		}

		if err := s.sendReply(conn, socks5ReplySuccess, replyAddr, replyPort); err != nil {
			return "", 0, err
		}

		return addr, port, nil

	case socks5CmdUDP:
		// UDP ASSOCIATE
		return s.handleUDPAssociate(conn)

	case socks5CmdBind:
		// BIND не поддерживается
		s.sendReply(conn, socks5ReplyCommandNotSupported, nil, 0)
		return "", 0, fmt.Errorf("BIND command not supported")

	default:
		s.sendReply(conn, socks5ReplyCommandNotSupported, nil, 0)
		return "", 0, fmt.Errorf("unsupported command: %d", cmd)
	}
}

// sendReply отправляет SOCKS5 reply
func (s *SOCKS5Server) sendReply(conn net.Conn, reply byte, addr []byte, port uint16) error {
	response := []byte{socks5Version, reply, 0} // версия, reply, зарезервировано

	if addr != nil && len(addr) > 0 {
		// Добавляем адрес (уже содержит ATYP)
		response = append(response, addr...)
		// Добавляем порт
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, port)
		response = append(response, portBuf...)
	} else {
		// IPv4 заглушка (ATYP + 4 байта IP + 2 байта порта)
		response = append(response, socks5ATYPIPv4, 0, 0, 0, 0)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, port)
		response = append(response, portBuf...)
	}

	_, err := conn.Write(response)
	return err
}

// handleUsernamePasswordAuth обрабатывает Username/Password аутентификацию
func (s *SOCKS5Server) handleUsernamePasswordAuth(conn net.Conn) error {
	// Читаем версию (должна быть 0x01)
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return err
	}
	if version[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", version[0])
	}

	// Читаем длину username
	usernameLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, usernameLen); err != nil {
		return err
	}

	// Читаем username
	username := make([]byte, int(usernameLen[0]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	// Читаем длину password
	passwordLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, passwordLen); err != nil {
		return err
	}

	// Читаем password
	password := make([]byte, int(passwordLen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	// Проверяем аутентификацию
	if s.authHandler == nil || !s.authHandler(string(username), string(password)) {
		// Отправляем ошибку аутентификации
		response := []byte{0x01, 0xFF} // версия, статус (0xFF = failure)
		if _, err := conn.Write(response); err != nil {
			return err
		}
		return errors.New("authentication failed")
	}

	// Отправляем успешный ответ
	response := []byte{0x01, 0x00} // версия, статус (0x00 = success)
	if _, err := conn.Write(response); err != nil {
		return err
	}

	return nil
}

// handleUDPAssociate обрабатывает UDP ASSOCIATE команду
func (s *SOCKS5Server) handleUDPAssociate(conn net.Conn) (string, uint16, error) {
	s.mu.RLock()
	udpAddr := s.udpAddr
	s.mu.RUnlock()

	// Если UDP адрес не установлен, используем адрес клиента
	if udpAddr == nil {
		if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			udpAddr = &net.UDPAddr{
				IP:   tcpAddr.IP,
				Port: 0, // Система выберет свободный порт
			}
		} else {
			s.sendReply(conn, socks5ReplyGeneralFailure, nil, 0)
			return "", 0, errors.New("failed to determine UDP address")
		}
	}

	// Отправляем ответ с адресом и портом для UDP
	var replyAddr []byte
	var port uint16

	if ip4 := udpAddr.IP.To4(); ip4 != nil {
		// IPv4
		replyAddr = append([]byte{socks5ATYPIPv4}, ip4...)
		port = uint16(udpAddr.Port)
	} else if ip6 := udpAddr.IP.To16(); ip6 != nil {
		// IPv6
		replyAddr = append([]byte{socks5ATYPIPv6}, ip6...)
		port = uint16(udpAddr.Port)
	} else {
		s.sendReply(conn, socks5ReplyGeneralFailure, nil, 0)
		return "", 0, errors.New("invalid UDP address")
	}

	if err := s.sendReply(conn, socks5ReplySuccess, replyAddr, port); err != nil {
		return "", 0, err
	}

	// Для UDP ASSOCIATE возвращаем специальные значения
	// Клиент будет использовать UDP соединение для отправки данных
	return "udp-associate", port, nil
}
