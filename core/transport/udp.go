package transport

import (
	"net"
	"time"
)

// UDPTransport реализует UDP транспорт
type UDPTransport struct {
	conn     net.PacketConn
	config   *Config
	listener net.PacketConn
}

// NewUDPTransport создает новый UDP транспорт
func NewUDPTransport(config *Config) *UDPTransport {
	return &UDPTransport{
		config: config,
	}
}

// Dial устанавливает UDP соединение
func (t *UDPTransport) Dial(addr string) error {
	timeout := time.Duration(t.config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}

	t.conn = conn
	return nil
}

// Listen запускает UDP слушатель
func (t *UDPTransport) Listen() error {
	udpAddr, err := net.ResolveUDPAddr("udp", t.config.Addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	t.listener = conn
	return nil
}

// WriteRaw отправляет данные в UDP соединение
func (t *UDPTransport) WriteRaw(pkt []byte) error {
	if t.conn == nil {
		return ErrNotConnected
	}
	_, err := t.conn.Write(pkt)
	return err
}

// ReadRaw читает данные из UDP соединения
func (t *UDPTransport) ReadRaw(buf []byte) (int, error) {
	if t.conn == nil {
		return 0, ErrNotConnected
	}
	return t.conn.Read(buf)
}

// WriteTo отправляет данные на указанный адрес
func (t *UDPTransport) WriteTo(pkt []byte, addr net.Addr) (int, error) {
	if t.listener == nil {
		return 0, ErrNotListening
	}
	return t.listener.WriteTo(pkt, addr)
}

// ReadFrom читает данные с адресом отправителя
func (t *UDPTransport) ReadFrom(buf []byte) (int, net.Addr, error) {
	if t.listener == nil {
		return 0, nil, ErrNotListening
	}
	return t.listener.ReadFrom(buf)
}

// Close закрывает UDP соединение и/или слушатель
func (t *UDPTransport) Close() error {
	var lastErr error

	if t.conn != nil {
		if err := t.conn.Close(); err != nil {
			lastErr = err
		}
	}

	if t.listener != nil {
		if err := t.listener.Close(); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// LocalAddr возвращает локальный адрес
func (t *UDPTransport) LocalAddr() net.Addr {
	if t.conn != nil {
		return t.conn.LocalAddr()
	}
	if t.listener != nil {
		return t.listener.LocalAddr()
	}
	return nil
}

// RemoteAddr возвращает удаленный адрес
func (t *UDPTransport) RemoteAddr() net.Addr {
	if t.conn != nil {
		return t.conn.RemoteAddr()
	}
	return nil
}
