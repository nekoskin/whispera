package socks5

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// startStormSink accepts connections, reads whatever the relay forwards, writes
// a short reply and closes -- a stand-in for a CDN endpoint under a connection
// storm.
func startStormSink(tb testing.TB) net.Addr {
	ln, err := (&net.ListenConfig{}).Listen(tb.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("sink listen: %v", err)
	}
	tb.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b := make([]byte, 64)
				if _, err := c.Read(b); err != nil {
					return
				}
				c.Write([]byte("ok"))
			}(c)
		}
	}()
	return ln.Addr()
}

func startDirectModule(tb testing.TB) string {
	addr := "127.0.0.1:0"
	ln, err := (&net.ListenConfig{}).Listen(tb.Context(), "tcp", addr)
	if err != nil {
		tb.Fatalf("probe listen: %v", err)
	}
	addr = ln.Addr().String()
	ln.Close()

	mod, err := New(&Config{
		ListenAddr: addr,
		BypassFunc: func(string, uint16) bool { return true },
	})
	if err != nil {
		tb.Fatalf("new module: %v", err)
	}
	if err := mod.Start(); err != nil {
		tb.Fatalf("start module: %v", err)
	}
	tb.Cleanup(func() { mod.Stop() })

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := (&net.Dialer{}).DialContext(tb.Context(), "tcp", addr); err == nil {
			c.Close()
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	tb.Fatal("socks server never came up")
	return ""
}

func oneDirectConn(tb testing.TB, socksAddr string, target net.Addr) error {
	c, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(tb.Context(), "tcp", socksAddr)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		return err
	}
	host, portStr, _ := net.SplitHostPort(target.String())
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil {
		return err
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		return err
	}
	out := make([]byte, 2)
	_, err = io.ReadFull(c, out)
	return err
}

// BenchmarkDirectStorm drives short direct (bypass) connections through the
// SOCKS module the way a page opening a flood of them does, so the profile and
// the alloc counters show what each connection costs on the direct relay path.
func BenchmarkDirectStorm(b *testing.B) {
	sink := startStormSink(b)
	socksAddr := startDirectModule(b)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := oneDirectConn(b, socksAddr, sink); err != nil {
				b.Fatalf("direct conn: %v", err)
			}
		}
	})
}
