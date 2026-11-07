package tunnel

import (
	"bytes"
	stdlog "log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	utls "github.com/refraction-networking/utls"
)

const helloTestRecordVersion = 0x0301

func helloTestMessage(t *testing.T) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := utls.UClient(client, &utls.Config{ServerName: "example.com"}, utls.HelloChrome_Auto)
	if err := conn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	return conn.HandshakeState.Hello.Raw
}

func helloTestRecords(message []byte, records int) [][]byte {
	var out [][]byte
	chunk := (len(message) + records - 1) / records
	for start := 0; start < len(message); start += chunk {
		end := min(start+chunk, len(message))
		record := []byte{tlsRecordHandshake, helloTestRecordVersion >> 8, helloTestRecordVersion & 0xff, byte((end - start) >> 8), byte(end - start)}
		out = append(out, append(record, message[start:end]...))
	}
	return out
}

func helloTestSegments(records [][]byte) []wireSegment {
	var segs []wireSegment
	seq := uint32(wireTestClientISN + 1)
	for _, r := range records {
		segs = append(segs, wireSegment{at: time.Now(), tcp: &layers.TCP{Seq: seq, Payload: r}})
		seq += uint32(len(r))
	}
	return segs
}

func TestHelloMarksWhatTheNetSet(t *testing.T) {
	hello, records, _, ok := assembleHello(helloTestSegments(helloTestRecords(helloTestMessage(t), 4)))
	if !ok {
		t.Fatal("hello not assembled")
	}
	cases := []struct {
		name   string
		choice dialChoice
		has    []string
		hasnt  []string
	}{
		{"the net picked every axis", dialChoice{fingerprint: "Chrome-auto", netFingerprint: true, netRecords: true, netDropPQ: true},
			[]string{"tls.handshake.fingerprint=Chrome-auto", "tls.record.count=4", "tls.handshake.extensions_key_share_group="}, nil},
		{"records came from config", dialChoice{fingerprint: "Chrome-auto", netFingerprint: true},
			[]string{"tls.handshake.fingerprint=Chrome-auto"}, []string{"tls.record.count", "key_share"}},
		{"only drop-PQ was the net's", dialChoice{fingerprint: "Chrome-auto", netDropPQ: true},
			[]string{"tls.handshake.extensions_key_share_group="}, []string{"fingerprint", "tls.record.count"}},
	}
	for _, c := range cases {
		line, err := describeHello(hello, records, c.choice)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range c.has {
			if !strings.Contains(line, want) {
				t.Errorf("%s: %q missing from %q", c.name, want, line)
			}
		}
		for _, unwanted := range append(c.hasnt, "ciphersuites", "supported_groups", netChoiceMark) {
			if strings.Contains(line, unwanted) {
				t.Errorf("%s: %q logged although the net did not set it: %q", c.name, unwanted, line)
			}
		}
	}
	if line, _ := describeHello(hello, records, dialChoice{fingerprint: "Chrome-auto"}); line != "" {
		t.Errorf("a hello the net set nothing in was logged as %q", line)
	}
}

func TestHelloLoggedWhenCaptureLagsBehindTheHandshake(t *testing.T) {
	var out bytes.Buffer
	prev := stdlog.Writer()
	stdlog.SetOutput(&out)
	defer stdlog.SetOutput(prev)

	w := newWireWatch()
	w.start(nil)
	w.watch(wireTestClient, wireTestServer, dialChoice{fingerprint: "Chrome-auto", netFingerprint: true})
	sent := time.Now()
	w.settle(wireTestClient, wireTestServer, 0, true)
	w.see(wireTestFrame(t, wireTestPacket{seq: wireTestClientISN + 1, ack: wireTestServerISN + 1, data: helloTestRecords(helloTestMessage(t), 1)[0]}, sent))
	if !strings.Contains(out.String(), "set by the policy net: tls.handshake.fingerprint=Chrome-auto") {
		t.Fatalf("a hello captured after its handshake had succeeded was not logged:\n%s", out.String())
	}
	if len(w.flows) != 0 {
		t.Fatal("the flow stayed watched after its hello was logged")
	}
}
