package relay

import (
	"bytes"
	"encoding/binary"
	"io"
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

func TestHeaderUDPIsNotAMigration(t *testing.T) {
	payload := []byte{0x00, 0x08, 'p', 'i', 'n', 'g', '-', 'u', 'd', 'p'}
	raw := append(connectHeader(protocol.KeepAliveProtoBit|streamProtoUDP, "udpecho", 7, nil), payload...)
	a, b := net.Pipe()
	go func() { a.Write(raw); a.Close() }()
	defer b.Close()
	h, ok := readProxyStreamHeader(b, time.Second)
	if !ok || h.network() != "udp" || h.migratable || h.resume {
		t.Fatalf("udp header misread: ok=%v network=%q mig=%v resume=%v", ok, h.network(), h.migratable, h.resume)
	}
	if h.addr != "udpecho" || h.port != 7 {
		t.Fatalf("udp target = %s:%d, want udpecho:7", h.addr, h.port)
	}
	rest := make([]byte, len(payload))
	if _, err := io.ReadFull(b, rest); err != nil || !bytes.Equal(rest, payload) {
		t.Fatalf("first datagram after the header = %x (%v), want %x", rest, err, payload)
	}
}

func TestHeaderTCPMigrationStillParses(t *testing.T) {
	token := bytes.Repeat([]byte{0xCD}, protocol.FlowTokenLen)
	h, ok := pipeHeader(t, connectHeader(protocol.KeepAliveProtoBit|protocol.MigrateProtoBit|0x06, "example.com", 443, token))
	if !ok || !h.migratable || h.network() != "tcp" || !bytes.Equal(h.token, token) {
		t.Fatalf("tcp migration header misread: ok=%v mig=%v network=%q token=%x", ok, h.migratable, h.network(), h.token)
	}
}

func TestHeaderPlainStillParses(t *testing.T) {
	h, ok := pipeHeader(t, connectHeader(protocol.KeepAliveProtoBit, "ya.ru", 443, nil))
	if !ok || h.migratable || h.resume || h.addr != "ya.ru" {
		t.Fatalf("plain header broke: ok=%v mig=%v addr=%q", ok, h.migratable, h.addr)
	}
}
