package transport

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	"nhooyr.io/websocket"
)

// WebSocketTransport реализует WebSocket транспорт
type WebSocketTransport struct {
	conn       *websocket.Conn
	config     *Config
	server     *http.Server
	isClient   bool
	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewWebSocketTransport создает новый WebSocket транспорт
func NewWebSocketTransport(config *Config) *WebSocketTransport {
	return &WebSocketTransport{
		config: config,
	}
}

// Dial устанавливает WebSocket соединение (клиент)
func (t *WebSocketTransport) Dial(addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return err
	}

	opts := &websocket.DialOptions{
		HTTPClient: &http.Client{
			Timeout: time.Duration(t.config.Timeout) * time.Second,
		},
	}

	conn, resp, err := websocket.Dial(context.Background(), u.String(), opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return ErrWebSocketUpgradeFailed
	}

	t.conn = conn
	t.isClient = true
	t.remoteAddr, _ = net.ResolveTCPAddr("tcp", u.Host)
	return nil
}

// Listen запускает WebSocket сервер
func (t *WebSocketTransport) Listen() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", t.handleWebSocket)

	t.server = &http.Server{
		Addr:    t.config.Addr,
		Handler: mux,
	}

	return t.server.ListenAndServe()
}

// handleWebSocket обрабатывает WebSocket апгрейд
func (t *WebSocketTransport) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}

	t.conn = conn
	t.isClient = false
	t.remoteAddr, _ = net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if addr, err := net.ResolveTCPAddr("tcp", t.config.Addr); err == nil {
		t.localAddr = addr
	}

	// Keep connection alive
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Блокируем, пока соединение активно
	for {
		_, _, err := conn.Read(context.Background())
		if err != nil {
			break
		}
	}
}

// WriteRaw отправляет данные в WebSocket
func (t *WebSocketTransport) WriteRaw(pkt []byte) error {
	if t.conn == nil {
		return ErrNotConnected
	}

	ctx := context.Background()
	timeout := time.Duration(t.config.Timeout) * time.Second
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	return t.conn.Write(ctx, websocket.MessageBinary, pkt)
}

// ReadRaw читает данные из WebSocket
func (t *WebSocketTransport) ReadRaw(buf []byte) (int, error) {
	if t.conn == nil {
		return 0, ErrNotConnected
	}

	ctx := context.Background()
	timeout := time.Duration(t.config.Timeout) * time.Second
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	typ, data, err := t.conn.Read(ctx)
	if err != nil {
		return 0, err
	}

	if typ != websocket.MessageBinary {
		return 0, ErrWebSocketInvalidMessageType
	}

	copy(buf, data)
	return len(data), nil
}

// Close закрывает WebSocket соединение и/или сервер
func (t *WebSocketTransport) Close() error {
	var lastErr error

	if t.conn != nil {
		err := t.conn.Close(websocket.StatusNormalClosure, "")
		if err != nil {
			lastErr = err
		}
	}

	if t.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := t.server.Shutdown(ctx)
		if err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// LocalAddr возвращает локальный адрес
func (t *WebSocketTransport) LocalAddr() net.Addr {
	return t.localAddr
}

// RemoteAddr возвращает удаленный адрес
func (t *WebSocketTransport) RemoteAddr() net.Addr {
	return t.remoteAddr
}
