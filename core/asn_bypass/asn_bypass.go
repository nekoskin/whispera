package asn_bypass

import (
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"sync"
	"time"
)

const defaultFragSize = 40

const maxHelloRecords = 8

type Config struct {
	EnableTLSFragmentation bool
	TLSFragmentSize        int
}

type Dialer struct {
	config *Config
}

func NewDialer(cfg *Config) *Dialer {
	if cfg == nil {
		cfg = &Config{EnableTLSFragmentation: true}
	}
	return &Dialer{config: cfg}
}

type firstWriteFragConn struct {
	net.Conn
	fragSize int
	done     bool
	mu       sync.Mutex
}

func (d *Dialer) DialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.dialDirect(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if d.config.EnableTLSFragmentation {
		fragSize := d.config.TLSFragmentSize
		if fragSize <= 0 {
			fragSize = defaultFragSize
		}
		return &firstWriteFragConn{Conn: conn, fragSize: fragSize}, nil
	}
	return conn, nil
}

func (c *firstWriteFragConn) NetConn() net.Conn { return c.Conn }

func (c *firstWriteFragConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return c.Conn.Write(b)
	}
	c.done = true
	err := writeFragmentedTLSRecord(c.Conn, b, c.fragSize)
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func sniSplitOffset(payload []byte) int {
	if len(payload) < 39 || payload[0] != 0x01 {
		return -1
	}
	p := 38
	p += 1 + int(payload[p])
	if p+2 > len(payload) {
		return -1
	}
	p += 2 + int(binary.BigEndian.Uint16(payload[p:]))
	if p+1 > len(payload) {
		return -1
	}
	p += 1 + int(payload[p])
	if p+2 > len(payload) {
		return -1
	}
	end := p + 2 + int(binary.BigEndian.Uint16(payload[p:]))
	p += 2
	if end > len(payload) {
		end = len(payload)
	}
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(payload[p:])
		size := int(binary.BigEndian.Uint16(payload[p+2:]))
		body := p + 4
		if body+size > end {
			return -1
		}
		if typ == 0 {
			if size < 5 {
				return -1
			}
			nameLen := int(binary.BigEndian.Uint16(payload[body+3:]))
			name := body + 5
			if nameLen < 2 || name+nameLen > len(payload) {
				return -1
			}
			return name + nameLen/2
		}
		p = body + size
	}
	return -1
}

func writeFragmentedTLSRecord(conn net.Conn, data []byte, fragSize int) error {
	if len(data) < 6 || data[0] != 0x16 {
		_, err := conn.Write(data)
		return err
	}
	contentType := data[0]
	majorVer := data[1]
	minorVer := data[2]
	payload := data[5:]

	base := fragSize
	if base < 8 {
		base = 8
	}
	if min := (len(payload) + maxHelloRecords - 1) / maxHelloRecords; base < min {
		base = min
	}
	lo, hi := base/2, base+base/2
	if lo < 8 {
		lo = 8
	}

	split := sniSplitOffset(payload)
	sent, count := 0, 0

	for len(payload) > 0 {
		chunk := lo + rand.Intn(hi-lo+1)
		if chunk > len(payload) {
			chunk = len(payload)
		}
		if count+1 == maxHelloRecords+1 {
			chunk = len(payload)
		}
		if split > sent && split-sent < chunk {
			chunk = split - sent
		}
		record := make([]byte, 5+chunk)
		record[0] = contentType
		record[1] = majorVer
		record[2] = minorVer
		record[3] = byte(chunk >> 8)
		record[4] = byte(chunk)
		copy(record[5:], payload[:chunk])
		payload = payload[chunk:]
		sent += chunk
		count++
		if _, err := conn.Write(record); err != nil {
			return err
		}
		if len(payload) > 0 {
			time.Sleep(time.Duration(rand.Intn(4)+1) * time.Millisecond)
		}
	}
	return nil
}

func (d *Dialer) dialDirect(ctx context.Context, _, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{
		KeepAlive: 30 * time.Second,
	}).DialContext(ctx, "tcp4", addr)

	if err != nil {
		return nil, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
	}

	return conn, nil
}
