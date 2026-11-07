package tunnel

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/nekoskin/whispera/core/protocol"
)

var (
	wireTestClient = &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 50000}
	wireTestServer = &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 443}
)

const (
	wireTestClientISN = 1000
	wireTestServerISN = 9000
	wireTestHello     = 517
	wireTestSegment   = 1400
)

type wireTestPacket struct {
	inbound  bool
	seq, ack uint32
	syn, rst bool
	fin      bool
	payload  int
	data     []byte
	after    time.Duration
	ttl      uint8
	options  []layers.TCPOption
}

const wireTestTTL = 64

func wireTestFrame(t *testing.T, p wireTestPacket, at time.Time) gopacket.Packet {
	t.Helper()
	src, dst := wireTestClient, wireTestServer
	if p.inbound {
		src, dst = dst, src
	}
	ttl := p.ttl
	if ttl == 0 {
		ttl = wireTestTTL
	}
	ip := &layers.IPv4{Version: 4, TTL: ttl, Protocol: layers.IPProtocolTCP, SrcIP: src.IP.To4(), DstIP: dst.IP.To4()}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(src.Port), DstPort: layers.TCPPort(dst.Port),
		Seq: p.seq, Ack: p.ack, SYN: p.syn, RST: p.rst, FIN: p.fin, ACK: !p.syn || p.inbound, Window: 64240, Options: p.options,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	data := p.data
	if data == nil {
		data = make([]byte, p.payload)
	}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(data)); err != nil {
		t.Fatal(err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = at
	return pkt
}

func wireTestVerdict(t *testing.T, packets []wireTestPacket, alive bool) protocol.WireVerdict {
	t.Helper()
	w := newWireWatch()
	w.start(nil)
	w.watch(wireTestClient, wireTestServer, dialChoice{})
	at := time.Now().Add(-time.Minute)
	for _, p := range packets {
		at = at.Add(p.after)
		w.see(wireTestFrame(t, p, at))
	}
	verdict, _, _ := w.settle(wireTestClient, wireTestServer, 0, alive)
	return verdict
}

func wireTestOpening() []wireTestPacket {
	return []wireTestPacket{
		{seq: wireTestClientISN, syn: true},
		{inbound: true, seq: wireTestServerISN, ack: wireTestClientISN + 1, syn: true, after: 70 * time.Millisecond},
		{seq: wireTestClientISN + 1, ack: wireTestServerISN + 1},
		{seq: wireTestClientISN + 1, ack: wireTestServerISN + 1, payload: wireTestHello},
	}
}

func wireTestServerData(n int) []wireTestPacket {
	var out []wireTestPacket
	for i := 0; i < n; i++ {
		out = append(out, wireTestPacket{inbound: true, seq: wireTestServerISN + 1 + uint32(i*wireTestSegment),
			ack: wireTestClientISN + 1 + wireTestHello, payload: wireTestSegment, after: time.Millisecond})
	}
	return out
}

func TestWireRewrittenResponseIsForgedReset(t *testing.T) {
	packets := wireTestOpening()
	for _, p := range wireTestServerData(3) {
		p.rst, p.payload = true, 0
		packets = append(packets, p)
	}
	packets[4].after = 70 * time.Millisecond
	if got := wireTestVerdict(t, packets, false); got != protocol.WireForgedReset {
		t.Fatalf("a server flight turned into RST/ACKs with rising seq (TSPU SNI-I) read as %v, want forged_reset", got)
	}
}

func TestWireDataAfterResetIsForgedReset(t *testing.T) {
	packets := append(wireTestOpening(),
		wireTestPacket{inbound: true, seq: wireTestServerISN + 1, ack: wireTestClientISN + 1 + wireTestHello, rst: true, after: 5 * time.Millisecond})
	packets = append(packets, wireTestServerData(1)...)
	if got := wireTestVerdict(t, packets, false); got != protocol.WireForgedReset {
		t.Fatalf("server data past the seq of a reset that came first read as %v, want forged_reset", got)
	}
}

func TestWireSingleServerResetIsNoSignature(t *testing.T) {
	packets := append(wireTestOpening(),
		wireTestPacket{inbound: true, seq: wireTestServerISN + 1, ack: wireTestClientISN + 1 + wireTestHello, rst: true, after: 70 * time.Millisecond})
	if got := wireTestVerdict(t, packets, false); got != protocol.WireNoSignature {
		t.Fatalf("one reset in sequence from the server read as %v, the wire does not prove it forged", got)
	}
}

func TestWireNothingAfterHelloIsHelloDropped(t *testing.T) {
	packets := append(wireTestOpening(),
		wireTestPacket{seq: wireTestClientISN + 1, ack: wireTestServerISN + 1, payload: wireTestHello, after: time.Second})
	if got := wireTestVerdict(t, packets, false); got != protocol.WireHelloDropped {
		t.Fatalf("no packet back after the ClientHello (TSPU SNI-IV) read as %v, want hello_dropped", got)
	}
}

func TestWireSilenceAfterSomeReplyIsCutOff(t *testing.T) {
	packets := append(wireTestOpening(), wireTestServerData(2)...)
	clientData := wireTestPacket{seq: wireTestClientISN + 1 + wireTestHello, ack: wireTestServerISN + 1 + 2*wireTestSegment, payload: 80, after: time.Millisecond}
	retry := clientData
	retry.after = 300 * time.Millisecond
	packets = append(packets, clientData, retry)
	if got := wireTestVerdict(t, packets, false); got != protocol.WireCutOff {
		t.Fatalf("a reply then a client retransmission nobody answered (TSPU SNI-II) read as %v, want cut_off", got)
	}
}

func TestWireMeasureShowsAHelloCutBySize(t *testing.T) {
	const serverTTL, injectedTTL = 50, 60
	head := wireTestPacket{seq: wireTestClientISN + 1, ack: wireTestServerISN + 1, payload: wireTestSegment}
	tail := wireTestPacket{seq: wireTestClientISN + 1 + wireTestSegment, ack: wireTestServerISN + 1, payload: wireTestHello, after: time.Millisecond}
	retry := tail
	retry.after = 300 * time.Millisecond
	packets := append(wireTestOpening()[:3], head, tail,
		wireTestPacket{inbound: true, seq: wireTestServerISN + 1, ack: wireTestClientISN + 1 + wireTestSegment, after: 70 * time.Millisecond, ttl: serverTTL},
		retry,
		wireTestPacket{inbound: true, seq: wireTestServerISN + 1, ack: wireTestClientISN + 1 + wireTestSegment, rst: true, after: 5 * time.Millisecond, ttl: injectedTTL})
	w := newWireWatch()
	w.start(nil)
	w.watch(wireTestClient, wireTestServer, dialChoice{})
	at := time.Now().Add(-time.Minute)
	for _, p := range packets {
		at = at.Add(p.after)
		w.see(wireTestFrame(t, p, at))
	}
	_, m, _ := w.settle(wireTestClient, wireTestServer, 70*time.Millisecond, false)
	if !m.Captured || m.HelloBytes != wireTestSegment+wireTestHello || m.HelloSegments != 2 {
		t.Fatalf("a two-segment hello measured as %+v", m)
	}
	if m.HelloAcked != wireTestSegment || m.Retransmits != 1 {
		t.Fatalf("the server acked only the first segment and the client resent the second, measured %+v", m)
	}
	if !m.Reset || m.ResetTTL-m.ServerTTL != injectedTTL-serverTTL {
		t.Fatalf("a reset arriving with another TTL than the server's measured %+v", m)
	}
}

func TestWireAliveHandshakeForgetsTheFlow(t *testing.T) {
	w := newWireWatch()
	w.start(nil)
	w.watch(wireTestClient, wireTestServer, dialChoice{})
	if got, _, _ := w.settle(wireTestClient, wireTestServer, 0, true); got != protocol.WireNoSignature {
		t.Fatalf("a live handshake got verdict %v", got)
	}
	if len(w.flows) != 1 {
		t.Fatal("a live flow was dropped before the capture had caught up with its hello")
	}
	w.see(wireTestFrame(t, wireTestPacket{inbound: true, seq: wireTestServerISN + 1}, time.Now().Add(time.Second)))
	if len(w.flows) != 0 || len(w.order) != 0 || w.settling != 0 {
		t.Fatal("a settled flow stayed watched after the capture passed its end")
	}
}

func TestWireWithoutCaptureWatchesNothing(t *testing.T) {
	w := newWireWatch()
	w.watch(wireTestClient, wireTestServer, dialChoice{})
	if len(w.flows) != 0 {
		t.Fatal("flows were watched with no capture running")
	}
	if got, _, _ := w.settle(wireTestClient, wireTestServer, time.Second, false); got != protocol.WireNoSignature {
		t.Fatalf("no capture gave verdict %v", got)
	}
}

func TestWirePacketsKeepTheOpeningAndTheOrder(t *testing.T) {
	opening := wireTestOpening()
	opening[0].options = []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
	}
	hello := make([]byte, wireTestHello)
	body := len(hello) - tlsRecordHeaderLen
	copy(hello, []byte{tlsRecordHandshake, tlsRecordMajor, 1, byte(body >> 8), byte(body), tlsClientHelloType})
	opening[3].data = hello
	resent := opening[3]
	resent.after = time.Second
	w := newWireWatch()
	w.start(nil)
	at := time.Now().Add(-time.Minute)
	for i, p := range append(opening, resent) {
		if i == 2 {
			w.watch(wireTestClient, wireTestServer, dialChoice{})
		}
		at = at.Add(p.after)
		w.see(wireTestFrame(t, p, at))
	}
	_, m, _ := w.settle(wireTestClient, wireTestServer, 70*time.Millisecond, false)
	if len(m.Packets) != 5 {
		t.Fatalf("%d packets kept, want the SYN, SYN-ACK, ACK, hello and its resend", len(m.Packets))
	}
	syn := m.Packets[0]
	if syn.Flags&protocol.WireSYN == 0 || syn.MSS != 1460 || syn.WScale != 7 || syn.Options&protocol.WireOptSACK == 0 {
		t.Fatalf("the SYN seen before the flow was watched came out as %+v", syn)
	}
	if h := m.Packets[3]; h.Hello != tlsClientHelloType || h.Records != 1 || h.SeqGap != 0 {
		t.Fatalf("the hello came out as %+v", h)
	}
	if r := m.Packets[4]; r.SeqGap != -wireTestHello {
		t.Fatalf("a resent hello should sit %d bytes behind the next expected sequence, got %+v", wireTestHello, r)
	}
}

func TestBlockPatternDumpReadsBackAsTheDial(t *testing.T) {
	packets := append(wireTestOpening(), wireTestPacket{seq: wireTestClientISN + 1, ack: wireTestServerISN + 1, payload: wireTestHello, after: time.Second})
	w := newWireWatch()
	w.start(nil)
	w.watch(wireTestClient, wireTestServer, dialChoice{})
	at := time.Now().Add(-time.Minute)
	var sent [][]byte
	for _, p := range packets {
		at = at.Add(p.after)
		pkt := wireTestFrame(t, p, at)
		sent = append(sent, pkt.Data())
		w.see(pkt)
	}
	_, _, frames := w.settle(wireTestClient, wireTestServer, 70*time.Millisecond, false)
	path := filepath.Join(t.TempDir(), "dial.pcap")
	if err := writeFrames(path, layers.LinkTypeIPv4, frames); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range sent {
		got, _, err := r.ReadPacketData()
		if err != nil {
			t.Fatalf("the dump of a failed dial ends after %d of its %d packets: %v", i, len(sent), err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("packet %d of the dump differs from the one captured", i)
		}
	}
}

func TestForgedPacketsStayOutOfTheNetInputButNotOutOfTheDump(t *testing.T) {
	opening := wireTestOpening()
	blind := wireTestPacket{inbound: true, seq: wireTestServerISN + 1, ack: wireTestClientISN + 1 + wireTestHello + 1<<20, payload: wireTestSegment, after: time.Millisecond}
	real := wireTestPacket{inbound: true, seq: wireTestServerISN + 1, ack: wireTestClientISN + 1 + wireTestHello, payload: wireTestSegment, after: time.Millisecond}
	w := newWireWatch()
	w.start(nil)
	w.watch(wireTestClient, wireTestServer, dialChoice{})
	at := time.Now().Add(-time.Minute)
	for _, p := range append(opening, blind, real) {
		at = at.Add(p.after)
		w.see(wireTestFrame(t, p, at))
	}
	_, m, frames := w.settle(wireTestClient, wireTestServer, 70*time.Millisecond, false)
	if len(m.Packets) != len(opening)+1 {
		t.Fatalf("the net sees %d packets, want the %d of the dial without the one acknowledging data never sent", len(m.Packets), len(opening)+1)
	}
	if len(frames) != len(opening)+2 {
		t.Fatalf("the dump holds %d packets, want all %d including the forged one", len(frames), len(opening)+2)
	}
	var r packetRecorder
	r.record(wireSegment{tcp: &layers.TCP{Seq: wireTestClientISN, SYN: true, Window: 1024}})
	r.record(wireSegment{inbound: true, tcp: &layers.TCP{Seq: wireTestServerISN, Ack: wireTestClientISN + 1, SYN: true, ACK: true, Window: 1024}})
	if r.acceptable(wireSegment{inbound: true, tcp: &layers.TCP{Seq: wireTestServerISN + 1<<30, RST: true}}) {
		t.Fatal("a reset far outside the receive window was taken for a real one")
	}
	if !r.acceptable(wireSegment{inbound: true, tcp: &layers.TCP{Seq: wireTestServerISN + 1, RST: true}}) {
		t.Fatal("a reset at the next expected sequence number was thrown away")
	}
}

func TestWireTailKeepsTheLastPacketsOfALiveFlow(t *testing.T) {
	opening := wireTestOpening()
	hello := make([]byte, wireTestHello)
	body := len(hello) - tlsRecordHeaderLen
	copy(hello, []byte{tlsRecordHandshake, tlsRecordMajor, 1, byte(body >> 8), byte(body), tlsClientHelloType})
	opening[3].data = hello
	w := newWireWatch()
	w.start(nil)
	w.watch(wireTestClient, wireTestServer, dialChoice{})
	at := time.Now().Add(-time.Minute)
	for _, p := range opening {
		at = at.Add(p.after)
		w.see(wireTestFrame(t, p, at))
	}
	w.settle(wireTestClient, wireTestServer, 70*time.Millisecond, true)
	data := wireTestServerData(protocol.WirePacketsMax + 3)
	for _, p := range data {
		at = at.Add(p.after)
		w.see(wireTestFrame(t, p, at))
	}
	tail, _ := w.tail(wireTestClient, wireTestServer)
	if len(tail) != protocol.WirePacketsMax {
		t.Fatalf("the tail holds %d packets, want the last %d", len(tail), protocol.WirePacketsMax)
	}
	if last := tail[len(tail)-1]; !last.Inbound || last.Size != wireTestSegment || last.SeqGap != 0 {
		t.Fatalf("the last packet of a steady download came out as %+v", last)
	}
	if again, _ := w.tail(wireTestClient, wireTestServer); again != nil {
		t.Fatal("a flow's tail was handed out twice")
	}
}
