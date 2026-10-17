package relay

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

func pipeHeader(t *testing.T, raw []byte) (proxyStreamHeader, bool) {
	t.Helper()
	a, b := net.Pipe()
	go func() { a.Write(raw); a.Close() }()
	defer b.Close()
	return readProxyStreamHeader(b, time.Second)
}

func connectHeader(proto byte, addr string, port uint16, token []byte) []byte {
	out := []byte{proto}
	out = binary.BigEndian.AppendUint16(out, uint16(len(addr)))
	out = append(out, addr...)
	out = binary.BigEndian.AppendUint16(out, port)
	return append(out, token...)
}

func TestHeaderMigratableCarriesToken(t *testing.T) {
	token := bytes.Repeat([]byte{0xAB}, protocol.FlowTokenLen)
	h, ok := pipeHeader(t, connectHeader(protocol.KeepAliveProtoBit|protocol.MigrateProtoBit, "example.com", 443, token))
	if !ok || !h.migratable || h.resume {
		t.Fatalf("want migratable connect, got ok=%v mig=%v resume=%v", ok, h.migratable, h.resume)
	}
	if h.addr != "example.com" || h.port != 443 || !bytes.Equal(h.token, token) {
		t.Fatalf("header fields wrong: %q %d token=%x", h.addr, h.port, h.token)
	}
}

func TestHeaderResumeHasTokenNoTarget(t *testing.T) {
	token := bytes.Repeat([]byte{0x12}, protocol.FlowTokenLen)
	raw := append([]byte{protocol.KeepAliveProtoBit | protocol.MigrateProtoBit, 0x00, 0x00}, token...)
	h, ok := pipeHeader(t, raw)
	if !ok || !h.resume {
		t.Fatalf("want resume, got ok=%v resume=%v", ok, h.resume)
	}
	if !bytes.Equal(h.token, token) {
		t.Fatalf("resume token = %x, want %x", h.token, token)
	}
}

func TestHeaderPlainStillParses(t *testing.T) {
	h, ok := pipeHeader(t, connectHeader(protocol.KeepAliveProtoBit, "ya.ru", 443, nil))
	if !ok || h.migratable || h.resume || h.addr != "ya.ru" {
		t.Fatalf("plain header broke: ok=%v mig=%v addr=%q", ok, h.migratable, h.addr)
	}
}
