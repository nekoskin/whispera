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

const defaultMaxHelloRecords = 8

type Config struct {
	EnableTLSFragmentation bool
	TLSFragmentSize        int

	// Pause between fragments in ms, against an inspector that reassembles the
	// stream. Zero keeps the split without waiting.
	FragmentDelayMinMs int
	FragmentDelayMaxMs int

	// How many records the hello may become.
	MaxFragments int
}

type fragmentPlan struct {
	size       int
	maxRecords int
	delayMin   int
	delayMax   int
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
	plan fragmentPlan
	done bool
	mu   sync.Mutex
}

func (d *Dialer) Fragmenting() bool { return d.config.EnableTLSFragmentation }

func (d *Dialer) DialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.DialTCPWithFragments(ctx, network, addr, 0)
}

// DialTCPWithFragments dials with a per-connection hello budget; zero keeps the
// configured default.
func (d *Dialer) DialTCPWithFragments(ctx context.Context, network, addr string, maxRecords int) (net.Conn, error) {
	conn, err := d.dialDirect(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if !d.config.EnableTLSFragmentation {
		return conn, nil
	}
	p := d.plan()
	if maxRecords > 0 {
		p.maxRecords = maxRecords
	}
	return &firstWriteFragConn{Conn: conn, plan: p}, nil
}

func (d *Dialer) DialTCPWithShape(ctx context.Context, network, addr string, records, pauseMs int) (net.Conn, error) {
	conn, err := d.dialDirect(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if !d.config.EnableTLSFragmentation {
		return conn, nil
	}
	p := d.plan()
	if records > 0 {
		p.maxRecords = records
	}
	if pauseMs >= 0 {
		p.delayMin, p.delayMax = pauseMs, pauseMs
	}
	return &firstWriteFragConn{Conn: conn, plan: p}, nil
}

func (d *Dialer) plan() fragmentPlan {
	p := fragmentPlan{
		size:       d.config.TLSFragmentSize,
		maxRecords: d.config.MaxFragments,
		delayMin:   d.config.FragmentDelayMinMs,
		delayMax:   d.config.FragmentDelayMaxMs,
	}
	if p.size <= 0 {
		p.size = defaultFragSize
	}
	if p.maxRecords <= 0 {
		// A fixed count is itself a fingerprint; vary it per connection.
		p.maxRecords = 4 + rand.Intn(defaultMaxHelloRecords-3)
	}
	return p
}

func (c *firstWriteFragConn) NetConn() net.Conn { return c.Conn }

func (c *firstWriteFragConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return c.Conn.Write(b)
	}
	c.done = true
	err := writeFragmentedTLSRecord(c.Conn, b, c.plan)
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

func writeFragmentedTLSRecord(conn net.Conn, data []byte, plan fragmentPlan) error {
	if len(data) < 6 || data[0] != 0x16 {
		_, err := conn.Write(data)
		return err
	}
	contentType := data[0]
	majorVer := data[1]
	minorVer := data[2]
	payload := data[5:]

	maxRecords := plan.maxRecords
	if maxRecords < 1 {
		maxRecords = defaultMaxHelloRecords
	}
	base := plan.size
	if base < 8 {
		base = 8
	}
	if min := (len(payload) + maxRecords - 1) / maxRecords; base < min {
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
		// Splitting inside the server name only helps against an inspector that
		// reads records, and it must not buy a record past the budget.
		if split > sent && split-sent < chunk && count+1 < maxRecords {
			chunk = split - sent
		}
		// The last allowed record takes the rest; earlier this permitted
		// maxRecords+1, so a count of one still left in two packets.
		if count+1 >= maxRecords {
			chunk = len(payload)
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
			fragmentPause(plan.delayMin, plan.delayMax)
		}
	}
	return nil
}

func fragmentPause(minMs, maxMs int) {
	if maxMs <= 0 {
		return
	}
	if minMs < 0 {
		minMs = 0
	}
	if minMs > maxMs {
		minMs = maxMs
	}
	wait := minMs
	if maxMs > minMs {
		wait += rand.Intn(maxMs - minMs + 1)
	}
	if wait > 0 {
		time.Sleep(time.Duration(wait) * time.Millisecond)
	}
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
