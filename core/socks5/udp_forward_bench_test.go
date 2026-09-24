package socks5

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/nekoskin/whispera/core/protocol/quic"
)

type stubTunnel struct{}

func (stubTunnel) IsConnected() bool      { return true }
func (stubTunnel) Ready() <-chan struct{} { return nil }
func (stubTunnel) DialStream(context.Context, string, string) (net.Conn, error) {
	return nil, nil
}
func (stubTunnel) OpenStream(context.Context, byte, string, uint16) (net.Conn, error) {
	return nil, nil
}
func (stubTunnel) DatagramClient(string) (*quic.DatagramClient, bool) { return nil, false }

type discardConn struct{ net.Conn }

func (discardConn) Write(b []byte) (int, error) { return len(b), nil }

func benchRelay(targets int) (*udpRelay, []string) {
	m := &Module{}
	m.tunnel = stubTunnel{}
	r := &udpRelay{
		module:    m,
		streams:   make(map[targetKey]net.Conn),
		rtTargets: make(map[targetKey]func()),
	}
	hosts := make([]string, targets)
	for i := 0; i < targets; i++ {
		hosts[i] = "peer" + string(rune('a'+i%26)) + ".game.invalid"
		r.streams[targetKey{host: hosts[i], port: 27015}] = discardConn{}
	}
	return r, hosts
}

func BenchmarkUDPForward(b *testing.B) {
	r, hosts := benchRelay(8)
	payload := make([]byte, 200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.forward(hosts[i%len(hosts)], 27015, payload)
	}
}

func BenchmarkUDPForwardParallel(b *testing.B) {
	r, hosts := benchRelay(8)
	payload := make([]byte, 200)
	var n int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := atomic.AddInt64(&n, 1)
			r.forward(hosts[i%int64(len(hosts))], 27015, payload)
		}
	})
}

func TestReplyHeaderMatchesBuildUDPReply(t *testing.T) {
	payload := []byte("hello")
	for _, host := range []string{"1.2.3.4", "2001:db8::1", "peer.game.invalid"} {
		want := buildUDPReply(host, 27015, payload)
		got := append(replyHeader(host, 27015), payload...)
		if !bytes.Equal(got, want) {
			t.Errorf("host %s: header path produced %x, want %x", host, got, want)
		}
	}
}

func BenchmarkUDPReplyBuild(b *testing.B) {
	payload := make([]byte, 200)
	const host = "peer.game.invalid"

	b.Run("old", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = buildUDPReply(host, 27015, payload)
		}
	})

	b.Run("new", func(b *testing.B) {
		hdr := replyHeader(host, 27015)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			bp := udpFramePool.Get().(*[]byte)
			reply := (*bp)[:0]
			reply = append(reply, hdr...)
			reply = append(reply, payload...)
			*bp = reply
			udpFramePool.Put(bp)
		}
	})
}
