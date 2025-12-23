package transport

import (
	"net"
	"time"
)

// TCPTransport реализует TCP транспорт
type TCPTransport struct {
	conn     net.Conn
	config   *Config
	listener net.Listener
}

// NewTCPTransport создает новый TCP транспорт
func NewTCPTransport(config *Config) *TCPTransport {
	return &TCPTransport{
		config: config,
	}
}

// Dial устанавливает TCP соединение
func (t *TCPTransport) Dial(addr string) error {
	timeout := time.Duration(t.config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}

	t.conn = conn
	return nil
}

// Listen запускает TCP слушатель
func (t *TCPTransport) Listen() error {
	listener, err := net.Listen("tcp", t.config.Addr)
	if err != nil {
		return err
	}

	t.listener = listener
	return nil
}

// Accept принимает новое соединение
func (t *TCPTransport) Accept() (net.Conn, error) {
	if t.listener == nil {
		return nil, ErrNotListening
	}
	return t.listener.Accept()
}

// WriteRaw отправляет данные в TCP соединение
func (t *TCPTransport) WriteRaw(pkt []byte) error {
	if t.conn == nil {
		return ErrNotConnected
	}
	_, err := t.conn.Write(pkt)
	return err
}

// ReadRaw читает данные из TCP соединения
func (t *TCPTransport) ReadRaw(buf []byte) (int, error) {
	if t.conn == nil {
		return 0, ErrNotConnected
	}
	return t.conn.Read(buf)
}

// Close закрывает TCP соединение и/или слушатель
func (t *TCPTransport) Close() error {
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
func (t *TCPTransport) LocalAddr() net.Addr {
	if t.conn != nil {
		return t.conn.LocalAddr()
	}
	if t.listener != nil {
		return t.listener.Addr()
	}
	return nil
}

// RemoteAddr возвращает удаленный адрес
func (t *TCPTransport) RemoteAddr() net.Addr {
	if t.conn != nil {
		return t.conn.RemoteAddr()
	}
	return nil
}
