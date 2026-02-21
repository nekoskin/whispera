package tunnel

import (
	"net"
	"os"
	"time"
	"whispera/internal/obfuscation/russian"
)

type RussianConnAdapter struct {
	tunnel        *russian.ServiceTunnel
	closeCh       chan struct{}
	readDeadline  time.Time
	writeDeadline time.Time
}

func NewRussianConnAdapter(tunnel *russian.ServiceTunnel) *RussianConnAdapter {
	return &RussianConnAdapter{
		tunnel:  tunnel,
		closeCh: make(chan struct{}),
	}
}

func (c *RussianConnAdapter) Read(b []byte) (n int, err error) {
	timeout := 30 * time.Second
	if !c.readDeadline.IsZero() {
		timeout = time.Until(c.readDeadline)
		if timeout <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
	}

	data, err := c.tunnel.ReceiveData(timeout)
	if err != nil {
		return 0, err
	}
	return copy(b, data), nil
}

func (c *RussianConnAdapter) Write(b []byte) (n int, err error) {
	if !c.writeDeadline.IsZero() && time.Now().After(c.writeDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	err = c.tunnel.SendData(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *RussianConnAdapter) Close() error {
	select {
	case <-c.closeCh:
	default:
		close(c.closeCh)
	}
	return nil
}

func (c *RussianConnAdapter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (c *RussianConnAdapter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 443}
}

func (c *RussianConnAdapter) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *RussianConnAdapter) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *RussianConnAdapter) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}
