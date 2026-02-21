package transport

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	"nhooyr.io/websocket"
)


type WebSocketTransport struct {
	conn       *websocket.Conn
	config     *Config
	server     *http.Server
	isClient   bool
	localAddr  net.Addr
	remoteAddr net.Addr
}


func NewWebSocketTransport(config *Config) *WebSocketTransport {
	return &WebSocketTransport{
		config: config,
	}
}


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


func (t *WebSocketTransport) Listen() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", t.handleWebSocket)

	t.server = &http.Server{
		Addr:    t.config.Addr,
		Handler: mux,
	}

	return t.server.ListenAndServe()
}


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

	
	defer conn.Close(websocket.StatusNormalClosure, "")

	
	for {
		_, _, err := conn.Read(context.Background())
		if err != nil {
			break
		}
	}
}


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


func (t *WebSocketTransport) LocalAddr() net.Addr {
	return t.localAddr
}
func (t *WebSocketTransport) RemoteAddr() net.Addr {
	return t.remoteAddr
}
