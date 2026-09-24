package relay

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

type panicConn struct{ net.Conn }

func (panicConn) Read([]byte) (int, error) {
	panic("сбой в апстрим-копировании")
}
func (panicConn) Write(b []byte) (int, error) { return len(b), nil }
func (panicConn) Close() error                { return nil }

func TestUpstreamPanicStillReportsResult(t *testing.T) {
	s, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	resCh := make(chan copyResult, 2)
	s.relayTCP(panicConn{}, b, resCh, nil)

	done := make(chan struct{})
	go func() {
		_, _, _, _ = collectCopyResults(resCh)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("collectCopyResults завис: апстрим не отчитался после паники")
	}
}

func resettingOrigin(t *testing.T) *net.TCPAddr {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.(*net.TCPConn).SetLinger(0)
		_ = c.Close()
	}()
	return ln.Addr().(*net.TCPAddr)
}

func TestProxyStreamKeepsConnectionAfterOriginReset(t *testing.T) {
	origin := resettingOrigin(t)
	s, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	client, server := net.Pipe()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	reusable := make(chan bool, 1)
	go func() {
		reusable <- s.handleProxyStream(1, "test", server, time.Second, protocol.NewShapeBudget(), nil)
	}()

	ip := origin.IP.String()
	hdr := []byte{0x06 | protocol.KeepAliveProtoBit, 0, byte(len(ip))}
	hdr = append(hdr, ip...)
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(origin.Port))
	if _, err := client.Write(hdr); err != nil {
		t.Fatalf("write header: %v", err)
	}

	stream := protocol.NewFramedConn(client, protocol.NewShapeBudget())
	if err := stream.EndStream(); err != nil {
		t.Fatalf("end stream: %v", err)
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		t.Fatalf("read answer: %v", err)
	}
	if !stream.StreamDone() {
		t.Fatal("server closed the stream without its end marker")
	}

	select {
	case ok := <-reusable:
		if !ok {
			t.Fatal("server dropped the connection over the origin's reset, though both end markers went through: the client has already pooled it")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleProxyStream did not return")
	}
}
