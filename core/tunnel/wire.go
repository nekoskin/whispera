package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"maps"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	utls "github.com/refraction-networking/utls"

	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
)

type PcapConfig struct {
	Interface  string
	Filter     string
	Server     string
	LogPackets bool
}

const (
	wireInjectorDelay   = 2 * time.Second
	wireSeqSlack        = 2
	wireWatchedFlows    = 64
	wireFlowSegments    = 512
	wireOpeningSegments = 4
	wireLiveFlows       = 128
	pcapSnapLen         = 65536
	patternDumpPrefix   = "block-"
	patternDumpExt      = ".pcap"

	tlsRecordHeaderLen   = 5
	tlsRecordFirstType   = 20
	tlsRecordLastType    = 23
	tlsRecordMajor       = 3
	tlsRecordAlert       = 21
	tlsAlertLen          = 2
	tcpMSSOptionLen      = 2
	tcpWScaleOptionLen   = 1
	wireMaxWindowShift   = 14
	tlsServerHelloType   = 2
	tlsRecordAppData     = 23
	pcapProceededRecords = 2
)

type wireSegment struct {
	at      time.Time
	inbound bool
	ttl     uint8
	tcp     *layers.TCP
	frame   []byte
	length  int
}

type dialChoice struct {
	fingerprint    string
	netFingerprint bool
	netRecords     bool
	netDropPQ      bool
}

type wireFlow struct {
	segments    []wireSegment
	choice      dialChoice
	helloLogged bool
	settledAt   time.Time
}

type wireWatch struct {
	mu        sync.Mutex
	capturing bool
	follow    func(local, remote *net.TCPAddr)
	flows     map[string]*wireFlow
	order     []string
	settling  int
	latest    time.Time
	advanced  chan struct{}
	waiting   int
	serverTTL map[string]uint8
	opening   map[string][]wireSegment
	openOrder []string
	live      map[string]*liveTail
	liveOrder []string
	link      layers.LinkType
	hops      map[string]wireHop
}

type wireHop struct {
	mac net.HardwareAddr
	at  time.Time
}

var sharedWire = newWireWatch()

func newWireWatch() *wireWatch {
	return &wireWatch{flows: map[string]*wireFlow{}, advanced: make(chan struct{}), serverTTL: map[string]uint8{}, opening: map[string][]wireSegment{}, live: map[string]*liveTail{}, hops: map[string]wireHop{}}
}

func packetTTL(pkt gopacket.Packet) uint8 {
	switch ip := pkt.NetworkLayer().(type) {
	case *layers.IPv4:
		return ip.TTL
	case *layers.IPv6:
		return ip.HopLimit
	}
	return 0
}

func wireFlowKey(local, remote string) string { return local + ">" + remote }

func packetEndpoints(pkt gopacket.Packet, tcp *layers.TCP) (string, string, bool) {
	network := pkt.NetworkLayer()
	if network == nil {
		return "", "", false
	}
	flow := network.NetworkFlow()
	src := net.JoinHostPort(flow.Src().String(), strconv.Itoa(int(tcp.SrcPort)))
	dst := net.JoinHostPort(flow.Dst().String(), strconv.Itoa(int(tcp.DstPort)))
	return src, dst, true
}

func (w *wireWatch) start(follow func(local, remote *net.TCPAddr)) {
	w.mu.Lock()
	w.capturing, w.follow = true, follow
	w.mu.Unlock()
}

func (w *wireWatch) watch(local, remote net.Addr, choice dialChoice) {
	if local == nil || remote == nil {
		return
	}
	w.mu.Lock()
	capturing, follow := w.capturing, w.follow
	w.mu.Unlock()
	if !capturing {
		return
	}
	localTCP, localOK := local.(*net.TCPAddr)
	remoteTCP, remoteOK := remote.(*net.TCPAddr)
	if localOK && remoteOK && follow != nil {
		follow(localTCP, remoteTCP)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	key := wireFlowKey(local.String(), remote.String())
	if _, ok := w.flows[key]; ok {
		return
	}
	for len(w.order) >= wireWatchedFlows {
		w.forgetLocked(w.order[0])
	}
	w.flows[key] = &wireFlow{choice: choice, segments: w.opening[key]}
	delete(w.opening, key)
	w.order = append(w.order, key)
}

func (w *wireWatch) choiceOf(src, dst string) (dialChoice, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	flow, ok := w.flows[wireFlowKey(src, dst)]
	if !ok {
		return dialChoice{}, false
	}
	return flow.choice, true
}

func (w *wireWatch) see(pkt gopacket.Packet) {
	tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		return
	}
	src, dst, ok := packetEndpoints(pkt, tcp)
	if !ok {
		return
	}
	at := pkt.Metadata().Timestamp
	frame, length := pkt.Data(), pkt.Metadata().Length
	w.mu.Lock()
	defer w.mu.Unlock()
	if at.After(w.latest) {
		w.latest = at
	}
	inbound := false
	flow, found := w.flows[wireFlowKey(src, dst)]
	if !found {
		flow, found = w.flows[wireFlowKey(dst, src)]
		inbound = found
	}
	if found && !inbound || !found && tcp.SYN && !tcp.ACK {
		w.noteHopLocked(pkt, at)
	}
	if !found && tcp.SYN {
		w.noteOpening(src, dst, wireSegment{at: at, inbound: tcp.ACK, ttl: packetTTL(pkt), tcp: tcp, frame: frame, length: length})
	}
	if !found {
		w.recordLiveLocked(src, dst, wireSegment{at: at, ttl: packetTTL(pkt), tcp: tcp, frame: frame, length: length})
	}
	if found && len(flow.segments) < wireFlowSegments {
		ttl := packetTTL(pkt)
		flow.segments = append(flow.segments, wireSegment{at: at, inbound: inbound, ttl: ttl, tcp: tcp, frame: frame, length: length})
		if inbound && !tcp.RST && ttl > 0 {
			w.serverTTL[src] = ttl
		}
		if !inbound && !flow.helloLogged && len(tcp.Payload) > 0 {
			if hello, records, _, ok := assembleHello(flow.segments); ok {
				flow.helloLogged = true
				logHello(src, dst, hello, records, flow.choice)
			}
		}
	}
	w.forgetSettledLocked()
	if w.waiting > 0 {
		close(w.advanced)
		w.advanced = make(chan struct{})
	}
}

func (w *wireWatch) settle(local, remote net.Addr, connect time.Duration, alive bool) (protocol.WireVerdict, protocol.DialMeasure, []wireSegment) {
	unseen := protocol.DialMeasure{Connect: connect}
	if local == nil || remote == nil {
		return protocol.WireNoSignature, unseen, nil
	}
	key := wireFlowKey(local.String(), remote.String())
	if !alive {
		lag := min(connect, wireInjectorDelay)
		target := time.Now().Add(lag)
		w.caughtUp(target, target.Add(lag))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	flow, ok := w.flows[key]
	if !ok {
		return protocol.WireNoSignature, unseen, nil
	}
	if alive && !flow.helloLogged {
		flow.settledAt = time.Now()
		w.settling++
		return protocol.WireNoSignature, unseen, nil
	}
	if alive {
		w.keepLiveLocked(key, flow)
	}
	w.forgetLocked(key)
	measure := measureWire(flow.segments, connect, w.serverTTL[remote.String()])
	if alive {
		return protocol.WireNoSignature, measure, nil
	}
	return classifyWire(flow.segments), measure, flow.segments
}

func measureWire(segs []wireSegment, connect time.Duration, serverTTL uint8) protocol.DialMeasure {
	m := protocol.DialMeasure{Connect: connect, Packets: wirePackets(segs)}
	first := -1
	for i, s := range segs {
		if !s.inbound && len(s.tcp.Payload) > 0 {
			first = i
			break
		}
	}
	if first < 0 {
		return m
	}
	size := len(clientStream(segs))
	if _, _, whole, ok := assembleHello(segs); ok {
		size = whole
	}
	start, sentAt := segs[first].tcp.Seq, segs[first].at
	end := start + uint32(size)
	m.Captured, m.HelloBytes = true, size
	var sent uint32
	sentAny := false
	for _, s := range segs[first:] {
		tcp := s.tcp
		switch {
		case s.inbound && tcp.RST:
			if !m.Reset {
				m.Reset, m.ResetAfter, m.ResetTTL = true, s.at.Sub(sentAt), int(s.ttl)
			}
		case s.inbound:
			if m.ServerTTL == 0 {
				m.ServerTTL = int(s.ttl)
			}
			if tcp.ACK && seqAfter(tcp.Ack, start) {
				m.HelloAcked = max(m.HelloAcked, int(min(tcp.Ack-start, uint32(size))))
			}
		case len(tcp.Payload) == 0:
		case sentAny && !seqAfter(seqEnd(tcp), sent):
			m.Retransmits++
		default:
			if seqAfter(end, tcp.Seq) {
				m.HelloSegments++
			}
			sent, sentAny = seqEnd(tcp), true
		}
	}
	if m.ServerTTL == 0 {
		m.ServerTTL = int(serverTTL)
	}
	return m
}

func (w *wireWatch) forgetLocked(key string) {
	if flow, ok := w.flows[key]; ok && !flow.settledAt.IsZero() {
		w.settling--
	}
	delete(w.flows, key)
	for i, k := range w.order {
		if k == key {
			w.order = append(w.order[:i], w.order[i+1:]...)
			break
		}
	}
}

func (w *wireWatch) forgetSettledLocked() {
	if w.settling == 0 {
		return
	}
	for _, key := range append([]string(nil), w.order...) {
		flow := w.flows[key]
		if !flow.settledAt.IsZero() && (flow.helloLogged || !w.latest.Before(flow.settledAt)) {
			w.keepLiveLocked(key, flow)
			w.forgetLocked(key)
		}
	}
}

func (w *wireWatch) caughtUp(target, deadline time.Time) {
	w.await(func() bool { return !w.latest.Before(target) }, deadline)
}

func (w *wireWatch) await(done func() bool, deadline time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.capturing {
		return
	}
	for !done() {
		left := time.Until(deadline)
		if left <= 0 {
			return
		}
		advanced := w.advanced
		w.waiting++
		w.mu.Unlock()
		timer := time.NewTimer(left)
		select {
		case <-advanced:
		case <-timer.C:
		}
		timer.Stop()
		w.mu.Lock()
		w.waiting--
	}
}

func (w *wireWatch) noteHopLocked(pkt gopacket.Packet, at time.Time) {
	eth, ok := pkt.LinkLayer().(*layers.Ethernet)
	network := pkt.NetworkLayer()
	if !ok || network == nil {
		return
	}
	flow := network.NetworkFlow()
	src, dst := net.IP(flow.Src().Raw()), net.IP(flow.Dst().Raw())
	if localPrefix(src).Contains(dst) {
		return
	}
	w.hops[src.String()] = wireHop{mac: append(net.HardwareAddr(nil), eth.DstMAC...), at: at}
}

func (w *wireWatch) nextHop(local net.IP) (net.HardwareAddr, bool) {
	key := local.String()
	fresh := func(since time.Time) (wireHop, bool) {
		hop, ok := w.hops[key]
		return hop, ok && !hop.at.Before(since)
	}
	w.mu.Lock()
	capturing, follow := w.capturing, w.follow
	hop, ok := fresh(time.Now().Add(-controlProbeFresh))
	w.mu.Unlock()
	if !capturing || ok {
		return hop.mac, ok
	}
	target, known := sharedControl.domesticAddr()
	if !known {
		return nil, false
	}
	if follow != nil {
		follow(&net.TCPAddr{IP: local}, target)
	}
	probed := time.Now()
	if conn, err := controlProbeDialer.DialContext(context.Background(), "tcp", target.String()); err == nil {
		conn.Close()
	}
	w.await(func() bool { _, ok := fresh(probed); return ok }, probed.Add(controlProbeTimeout))
	w.mu.Lock()
	defer w.mu.Unlock()
	hop, ok = w.hops[key]
	return hop.mac, ok
}

func seqAfter(a, b uint32) bool { return int32(a-b) > 0 }

func seqEnd(tcp *layers.TCP) uint32 { return tcp.Seq + uint32(len(tcp.Payload)) }

func classifyWire(segs []wireSegment) protocol.WireVerdict {
	hello := -1
	for i, s := range segs {
		if !s.inbound && len(s.tcp.Payload) > 0 {
			hello = i
			break
		}
	}
	if hello < 0 {
		return protocol.WireNoSignature
	}
	switch {
	case forgedReset(segs):
		return protocol.WireForgedReset
	case !answered(segs[hello+1:]):
		return protocol.WireHelloDropped
	case cutOff(segs[hello:]):
		return protocol.WireCutOff
	case retransmitted(segs[hello:], true):
		return protocol.WireRetransmitted
	}
	return protocol.WireNoSignature
}

func answered(segs []wireSegment) bool {
	for _, s := range segs {
		if s.inbound {
			return true
		}
	}
	return false
}

func forgedReset(segs []wireSegment) bool {
	var prev *layers.TCP
	var prevAt time.Time
	var maxSeq, maxAck, minResetSeq uint32
	var seenSeq, seenAck, seenReset, finBefore, outboundReset bool
	for _, s := range segs {
		tcp := s.tcp
		if !s.inbound {
			outboundReset = outboundReset || tcp.RST
			if tcp.ACK && (!seenAck || seqAfter(tcp.Ack, maxAck)) {
				maxAck, seenAck = tcp.Ack, true
			}
			continue
		}
		if prev != nil && s.at.Sub(prevAt) < wireInjectorDelay {
			switch {
			case prev.RST && tcp.RST && rstSeqChange(prev, tcp, maxSeq, maxAck, seenAck, finBefore || outboundReset):
				return true
			case prev.RST && !tcp.RST && len(tcp.Payload) > 0 && seqAfter(seqEnd(tcp), minResetSeq):
				return true
			case !prev.RST && len(prev.Payload) > 0 && tcp.RST && !finBefore && seqAfter(seqEnd(prev), tcp.Seq):
				return true
			}
		}
		if prev != nil {
			if !seenSeq || seqAfter(prev.Seq, maxSeq) {
				maxSeq, seenSeq = prev.Seq, true
			}
			finBefore = finBefore || prev.FIN || prev.RST
		}
		if tcp.RST && (!seenReset || seqAfter(minResetSeq, tcp.Seq)) {
			minResetSeq, seenReset = tcp.Seq, true
		}
		prev, prevAt = tcp, s.at
	}
	return false
}

func rstSeqChange(first, second *layers.TCP, maxSeq, maxAck uint32, seenAck, closedBefore bool) bool {
	if closedBefore {
		return false
	}
	if !seqAfter(second.Seq, first.Seq+wireSeqSlack) || !seqAfter(second.Seq, maxSeq) {
		return false
	}
	return !seenAck || seqAfter(second.Seq, maxAck+wireSeqSlack)
}

func cutOff(segs []wireSegment) bool {
	last := -1
	for i, s := range segs {
		if s.inbound {
			last = i
		}
	}
	if last < 0 {
		return false
	}
	var sentEnd uint32
	sent := false
	for i, s := range segs {
		if s.inbound || len(s.tcp.Payload) == 0 {
			continue
		}
		end := seqEnd(s.tcp)
		if i > last && sent && !seqAfter(end, sentEnd) {
			return true
		}
		if !sent || seqAfter(end, sentEnd) {
			sentEnd, sent = end, true
		}
	}
	return false
}

func retransmitted(segs []wireSegment, inbound bool) bool {
	var end uint32
	seen := false
	for _, s := range segs {
		if s.inbound != inbound || len(s.tcp.Payload) == 0 {
			continue
		}
		segEnd := seqEnd(s.tcp)
		if seen && !seqAfter(segEnd, end) {
			return true
		}
		if !seen || seqAfter(segEnd, end) {
			end, seen = segEnd, true
		}
	}
	return false
}

type packetRecorder struct {
	next    [2]uint32
	seen    [2]bool
	last    time.Time
	shift   [2]int
	scaled  [2]bool
	window  [2]int64
	acked   uint32
	ackSeen bool
}

func wireSide(inbound bool) int {
	if inbound {
		return 1
	}
	return 0
}

func (r *packetRecorder) record(s wireSegment) protocol.WirePacket {
	tcp := s.tcp
	p := protocol.WirePacket{Inbound: s.inbound, Size: len(tcp.Payload), TTL: int(s.ttl), Window: int(tcp.Window)}
	if !r.last.IsZero() && s.at.After(r.last) {
		p.Gap = s.at.Sub(r.last)
	}
	if s.at.After(r.last) {
		r.last = s.at
	}
	for _, flag := range []struct {
		set bool
		bit uint8
	}{{tcp.SYN, protocol.WireSYN}, {tcp.ACK, protocol.WireACK}, {tcp.RST, protocol.WireRST}, {tcp.FIN, protocol.WireFIN},
		{tcp.PSH, protocol.WirePSH}, {tcp.URG, protocol.WireURG}, {tcp.ECE, protocol.WireECE}, {tcp.CWR, protocol.WireCWR}} {
		if flag.set {
			p.Flags |= flag.bit
		}
	}
	own, other := wireSide(s.inbound), wireSide(!s.inbound)
	if r.seen[own] {
		p.SeqGap = int64(int32(tcp.Seq - r.next[own]))
	}
	if tcp.ACK && r.seen[other] {
		p.AckGap = int64(int32(tcp.Ack - r.next[other]))
	}
	end := seqEnd(tcp)
	if tcp.SYN || tcp.FIN {
		end++
	}
	if !r.seen[own] || seqAfter(end, r.next[own]) {
		r.next[own], r.seen[own] = end, true
	}
	tcpOptions(tcp, &p)
	tlsRecords(tcp.Payload, &p)
	if tcp.SYN {
		r.shift[own], r.scaled[own] = p.WScale, true
	}
	shift := wireMaxWindowShift
	if r.scaled[own] {
		shift = r.shift[own]
	}
	r.window[own] = max(r.window[own], int64(tcp.Window)<<shift)
	if s.inbound && tcp.ACK && (!r.ackSeen || seqAfter(tcp.Ack, r.acked)) {
		r.acked, r.ackSeen = tcp.Ack, true
	}
	return p
}

func (r *packetRecorder) acceptable(s wireSegment) bool {
	tcp := s.tcp
	if !s.inbound {
		return true
	}
	out, in := wireSide(false), wireSide(true)
	if tcp.ACK && r.seen[out] && seqAfter(tcp.Ack, r.next[out]) {
		return false
	}
	if tcp.ACK && r.ackSeen && int64(int32(tcp.Ack-r.acked)) < -r.window[in] {
		return false
	}
	if tcp.RST && r.seen[in] {
		gap := int64(int32(tcp.Seq - r.next[in]))
		return max(gap, -gap) <= r.window[out]
	}
	return true
}

func wirePackets(segs []wireSegment) []protocol.WirePacket {
	out := make([]protocol.WirePacket, 0, min(len(segs), protocol.WirePacketsMax))
	var r packetRecorder
	for _, s := range segs {
		if len(out) == protocol.WirePacketsMax {
			break
		}
		if r.acceptable(s) {
			out = append(out, r.record(s))
		}
	}
	return out
}

type liveTail struct {
	rec    packetRecorder
	ring   []protocol.WirePacket
	frames []wireSegment
}

func (t *liveTail) push(s wireSegment) {
	t.frames = append(t.frames, headerFrame(s))
	if over := len(t.frames) - protocol.WirePacketsMax; over > 0 {
		t.frames = append(t.frames[:0:0], t.frames[over:]...)
	}
	if !t.rec.acceptable(s) {
		return
	}
	t.ring = append(t.ring, t.rec.record(s))
	if over := len(t.ring) - protocol.WirePacketsMax; over > 0 {
		t.ring = append(t.ring[:0:0], t.ring[over:]...)
	}
}

func headerFrame(s wireSegment) wireSegment {
	keep := len(s.frame) - len(s.tcp.Payload) + min(len(s.tcp.Payload), tlsRecordHeaderLen)
	keep = max(0, min(keep, len(s.frame)))
	return wireSegment{at: s.at, inbound: s.inbound, frame: append([]byte(nil), s.frame[:keep]...), length: max(s.length, len(s.frame))}
}

func (w *wireWatch) keepLiveLocked(key string, flow *wireFlow) {
	t := &liveTail{}
	for _, s := range flow.segments {
		t.push(s)
	}
	if _, ok := w.live[key]; !ok {
		for len(w.liveOrder) >= wireLiveFlows {
			delete(w.live, w.liveOrder[0])
			w.liveOrder = w.liveOrder[1:]
		}
		w.liveOrder = append(w.liveOrder, key)
	}
	w.live[key] = t
}

func (w *wireWatch) tail(local, remote net.Addr) ([]protocol.WirePacket, []wireSegment) {
	if local == nil || remote == nil {
		return nil, nil
	}
	key := wireFlowKey(local.String(), remote.String())
	w.mu.Lock()
	defer w.mu.Unlock()
	t, ok := w.live[key]
	if !ok {
		return nil, nil
	}
	delete(w.live, key)
	return t.ring, t.frames
}

func (w *wireWatch) linkTo(link layers.LinkType) {
	w.mu.Lock()
	w.link = link
	w.mu.Unlock()
}

var patternDumps struct {
	sync.Mutex
	dir string
}

func SetPatternDumps(dir string) {
	patternDumps.Lock()
	patternDumps.dir = dir
	patternDumps.Unlock()
}

func noteBlockPattern(outcome protocol.DialOutcome, wire protocol.WireVerdict, pkts []protocol.WirePacket, frames []wireSegment) int {
	p, ok := protocol.NoteBlockPattern(outcome, wire, pkts)
	if !ok {
		return 0
	}
	if p.Seen > 1 {
		return p.ID
	}
	saved := "not saved, no dump directory"
	path, err := sharedWire.dumpPattern(p, frames)
	switch {
	case err != nil:
		saved = "not saved: " + err.Error()
	case path != "":
		saved = "saved to " + path
	}
	stdlog.Printf("[POLICY] new block pattern #%d after a %s dial (wire %s): its packets lie %.0f from the trained ones, past the bar %.0f that at most %.0f%% of trained blocks cross; capture %s",
		p.ID, outcomeName(p.Outcome), p.Wire, p.Distance, p.Bar, 100*protocol.NoveltyFalseAlarm, saved)
	return p.ID
}

func outcomeName(o protocol.DialOutcome) string {
	if o == protocol.DialLiveDead {
		return "live-dead"
	}
	return "dead"
}

func (w *wireWatch) dumpPattern(p protocol.BlockPattern, frames []wireSegment) (string, error) {
	patternDumps.Lock()
	defer patternDumps.Unlock()
	if patternDumps.dir == "" || len(frames) == 0 {
		return "", nil
	}
	if err := os.MkdirAll(patternDumps.dir, 0o755); err != nil {
		return "", err
	}
	w.mu.Lock()
	link := w.link
	w.mu.Unlock()
	path := filepath.Join(patternDumps.dir, fmt.Sprintf("%s%d-%s-%d%s", patternDumpPrefix, p.ID, outcomeName(p.Outcome), p.FirstMs, patternDumpExt))
	if err := writeFrames(path, link, frames); err != nil {
		return "", err
	}
	trimPatternDumps(patternDumps.dir)
	return path, nil
}

func writeFrames(path string, link layers.LinkType, frames []wireSegment) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	pw := pcapgo.NewWriter(f)
	err = pw.WriteFileHeader(pcapSnapLen, link)
	for _, s := range frames {
		if err != nil {
			break
		}
		if len(s.frame) > 0 {
			err = pw.WritePacket(gopacket.CaptureInfo{Timestamp: s.at, CaptureLength: len(s.frame), Length: max(s.length, len(s.frame))}, s.frame)
		}
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func trimPatternDumps(dir string) {
	paths, err := filepath.Glob(filepath.Join(dir, patternDumpPrefix+"*"+patternDumpExt))
	if err != nil || len(paths) <= protocol.BlockPatternLimit {
		return
	}
	modified := func(path string) time.Time {
		if info, err := os.Stat(path); err == nil {
			return info.ModTime()
		}
		return time.Time{}
	}
	sort.Slice(paths, func(i, j int) bool { return modified(paths[i]).Before(modified(paths[j])) })
	for _, path := range paths[:len(paths)-protocol.BlockPatternLimit] {
		os.Remove(path)
	}
}

func (w *wireWatch) drop(local, remote net.Addr) {
	if local == nil || remote == nil {
		return
	}
	w.mu.Lock()
	delete(w.live, wireFlowKey(local.String(), remote.String()))
	w.mu.Unlock()
}

func tcpOptions(tcp *layers.TCP, p *protocol.WirePacket) {
	for _, opt := range tcp.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) == tcpMSSOptionLen {
				p.MSS = int(opt.OptionData[0])<<8 | int(opt.OptionData[1])
			}
		case layers.TCPOptionKindWindowScale:
			if len(opt.OptionData) == tcpWScaleOptionLen {
				p.WScale, p.Options = int(opt.OptionData[0]), p.Options|protocol.WireOptWScale
			}
		case layers.TCPOptionKindSACKPermitted:
			p.Options |= protocol.WireOptSACK
		case layers.TCPOptionKindTimestamps:
			p.Options |= protocol.WireOptTimestamps
		}
	}
}

func tlsRecords(pl []byte, p *protocol.WirePacket) {
	for off := 0; off+tlsRecordHeaderLen <= len(pl); {
		typ := pl[off]
		if typ < tlsRecordFirstType || typ > tlsRecordLastType || pl[off+1] != tlsRecordMajor {
			return
		}
		length := int(pl[off+3])<<8 | int(pl[off+4])
		body := off + tlsRecordHeaderLen
		if p.Records == 0 {
			p.Record, p.RecLen = typ, length
		}
		p.Records++
		if body < len(pl) {
			switch {
			case typ == tlsRecordHandshake && p.Hello == 0:
				p.Hello = pl[body]
			case typ == tlsRecordAlert && length == tlsAlertLen && p.Alert == 0:
				p.Alert = pl[body]
			}
		}
		off = body + length
	}
}

func (w *wireWatch) noteOpening(src, dst string, seg wireSegment) {
	key := wireFlowKey(src, dst)
	if seg.inbound {
		key = wireFlowKey(dst, src)
	}
	if _, ok := w.opening[key]; !ok {
		for len(w.openOrder) >= wireWatchedFlows {
			delete(w.opening, w.openOrder[0])
			w.openOrder = w.openOrder[1:]
		}
		w.openOrder = append(w.openOrder, key)
	}
	if len(w.opening[key]) < wireOpeningSegments {
		w.opening[key] = append(w.opening[key], seg)
	}
}

func (w *wireWatch) recordLiveLocked(src, dst string, seg wireSegment) {
	t, ok := w.live[wireFlowKey(src, dst)]
	if !ok {
		if t, ok = w.live[wireFlowKey(dst, src)]; !ok {
			return
		}
		seg.inbound = true
	}
	t.push(seg)
}

type pcapFlow struct {
	first time.Time
	segs  []wireSegment
}

func PcapDials(path, server string) ([]protocol.PolicyDial, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, err
	}
	flows := map[string]*pcapFlow{}
	var done []*pcapFlow
	for {
		data, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		pkt := gopacket.NewPacket(data, r.LinkType(), gopacket.Default)
		tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			continue
		}
		src, dst, ok := packetEndpoints(pkt, tcp)
		if !ok || (src != server && dst != server) {
			continue
		}
		inbound := src == server
		client := src
		if inbound {
			client = dst
		}
		key := wireFlowKey(client, server)
		if tcp.SYN && !inbound {
			if fl, ok := flows[key]; ok {
				done = append(done, fl)
			}
			flows[key] = &pcapFlow{first: ci.Timestamp}
		}
		fl, ok := flows[key]
		if !ok || len(fl.segs) >= wireFlowSegments {
			continue
		}
		fl.segs = append(fl.segs, wireSegment{at: ci.Timestamp, inbound: inbound, ttl: packetTTL(pkt), tcp: tcp})
	}
	for _, fl := range flows {
		done = append(done, fl)
	}
	var dials []protocol.PolicyDial
	presets := fingerprint.PresetCount()
	for _, fl := range done {
		hello, records, _, ok := assembleHello(fl.segs)
		if !ok {
			continue
		}
		spec, err := fingerprint.SpecFromRaw(hello)
		if err != nil {
			continue
		}
		preset, ok := presetOfSpec(spec)
		if !ok {
			continue
		}
		arm, ok := protocol.JointArmFor(preset, records, !specHasPQ(spec), presets)
		if !ok {
			continue
		}
		m := measureWire(fl.segs, synAckAfter(fl.segs), 0)
		dials = append(dials, protocol.PolicyDial{Ms: fl.first.UnixMilli(), Arm: arm, Outcome: pcapOutcome(fl.segs),
			Wire: classifyWire(fl.segs), Measure: m})
	}
	return dials, nil
}

func presetOfSpec(spec *utls.ClientHelloSpec) (int, bool) {
	suites, exts := cipherSet(spec.CipherSuites), extensionSet(spec.Extensions)
	best, fewest := -1, 0
	for i := 0; i < fingerprint.PresetCount(); i++ {
		want, err := fingerprint.SpecFor(fingerprint.PresetAt(i))
		if err != nil || !maps.Equal(cipherSet(want.CipherSuites), suites) {
			continue
		}
		differ := 0
		wanted := extensionSet(want.Extensions)
		for kind := range wanted {
			if !exts[kind] {
				differ++
			}
		}
		for kind := range exts {
			if !wanted[kind] {
				differ++
			}
		}
		if best < 0 || differ < fewest {
			best, fewest = i, differ
		}
	}
	return best, best >= 0
}

func extensionSet(exts []utls.TLSExtension) map[string]bool {
	set := map[string]bool{}
	for _, ext := range exts {
		switch e := ext.(type) {
		case *utls.UtlsGREASEExtension, *utls.UtlsPaddingExtension, utls.PreSharedKeyExtension:
		case *utls.GenericExtension:
			set[fmt.Sprintf("generic-%d", e.Id)] = true
		default:
			set[fmt.Sprintf("%T", ext)] = true
		}
	}
	return set
}

func cipherSet(ids []uint16) map[uint16]bool {
	set := map[uint16]bool{}
	for _, id := range ids {
		if id&0x0f0f != 0x0a0a {
			set[id] = true
		}
	}
	return set
}

func specHasPQ(spec *utls.ClientHelloSpec) bool {
	for _, ext := range spec.Extensions {
		if ks, ok := ext.(*utls.KeyShareExtension); ok {
			for _, k := range ks.KeyShares {
				if k.Group == utls.X25519MLKEM768 {
					return true
				}
			}
		}
	}
	return false
}

func synAckAfter(segs []wireSegment) time.Duration {
	for _, s := range segs {
		if s.inbound && s.tcp.SYN && s.tcp.ACK && len(segs) > 0 {
			return s.at.Sub(segs[0].at)
		}
	}
	return 0
}

func pcapOutcome(segs []wireSegment) protocol.DialOutcome {
	serverHello := false
	proceeded := 0
	for _, s := range segs {
		pl := s.tcp.Payload
		switch {
		case s.inbound && s.tcp.RST && !serverHello:
			return protocol.DialHandshakeDead
		case s.inbound && len(pl) > tlsRecordHeaderLen && pl[0] == tlsRecordHandshake && pl[tlsRecordHeaderLen] == tlsServerHelloType:
			serverHello = true
		case !s.inbound && serverHello && len(pl) > 0 && pl[0] == tlsRecordAppData:
			proceeded++
		}
	}
	if serverHello && proceeded >= pcapProceededRecords {
		return protocol.DialAlive
	}
	return protocol.DialHandshakeDead
}
