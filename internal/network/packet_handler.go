package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"whispera/internal/util"
)

type PacketBuffer struct {
	buf      map[uint32]*bufferedPacket
	maxSeq   uint32
	mu       sync.RWMutex
	maxSize  int
	maxDelay time.Duration
}

type bufferedPacket struct {
	data      []byte
	timestamp time.Time
}

func NewPacketBuffer(maxSize int, maxDelay time.Duration) *PacketBuffer {
	return &PacketBuffer{
		buf:      make(map[uint32]*bufferedPacket),
		maxSize:  maxSize,
		maxDelay: maxDelay,
	}
}

func (pb *PacketBuffer) Insert(seq uint32, data []byte) []byte {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	timeCache := util.GetGlobalTimeCache()
	now := timeCache.Now()

	if pb.maxDelay > 0 {
		pb.cleanupExpired(now)
	}

	if pb.maxSeq > 0 && seq < pb.maxSeq-100 {
		return nil
	}

	if seq > pb.maxSeq {
		pb.maxSeq = seq
	}

	pb.buf[seq] = &bufferedPacket{
		data:      append([]byte(nil), data...),
		timestamp: now,
	}

	var ready [][]byte
	expected := pb.maxSeq - uint32(len(pb.buf)) + 1

	if len(pb.buf) > 0 {
		minSeq := seq
		for s := range pb.buf {
			if s < minSeq {
				minSeq = s
				if len(pb.buf) > 100 {
					break
				}
			}
		}
		expected = minSeq
	}

	for {
		if pkt, ok := pb.buf[expected]; ok {
			ready = append(ready, pkt.data)
			delete(pb.buf, expected)
			expected++
		} else {
			break
		}
	}

	if len(pb.buf) > pb.maxSize {
		pb.cleanupOldest()
	} else if len(pb.buf) > (pb.maxSize*9)/10 {
		pb.cleanupExpired(now)
	}

	if len(ready) > 0 {
		return ready[0]
	}

	return nil
}

func (pb *PacketBuffer) cleanupExpired(now time.Time) {
	if pb.maxDelay <= 0 {
		return
	}

	for seq, pkt := range pb.buf {
		if now.Sub(pkt.timestamp) > pb.maxDelay {
			delete(pb.buf, seq)
		}
	}
}

func (pb *PacketBuffer) cleanupOldest() {
	if len(pb.buf) <= pb.maxSize {
		return
	}

	toRemove := len(pb.buf) - pb.maxSize + 64
	if toRemove <= 0 {
		return
	}

	type seqTime struct {
		seq       uint32
		timestamp time.Time
	}

	oldest := make([]seqTime, 0, toRemove)

	for seq, pkt := range pb.buf {
		if len(oldest) < toRemove {
			oldest = append(oldest, seqTime{seq: seq, timestamp: pkt.timestamp})
		} else {
			maxIdx := 0
			for i := 1; i < len(oldest); i++ {
				if oldest[i].timestamp.After(oldest[maxIdx].timestamp) {
					maxIdx = i
				}
			}
			if pkt.timestamp.Before(oldest[maxIdx].timestamp) {
				oldest[maxIdx] = seqTime{seq: seq, timestamp: pkt.timestamp}
			}
		}
	}

	for _, st := range oldest {
		delete(pb.buf, st.seq)
	}
}

type RetransmissionManager struct {
	pending       map[uint32]*PendingPacket
	mu            sync.RWMutex
	onRetransmit  func(seq uint32, data []byte) error
	timeout       time.Duration
	maxRetries    int
	ctx           context.Context
	cancel        context.CancelFunc
	stopDone      chan struct{}
	maxPending    int
	flowControlCh chan struct{}
}

type PendingPacket struct {
	Seq      uint32
	Data     []byte
	SentAt   time.Time
	Retries  int
	LastSent time.Time
}

func NewRetransmissionManager(timeout time.Duration, maxRetries int, onRetransmit func(uint32, []byte) error) *RetransmissionManager {
	ctx, cancel := context.WithCancel(context.Background())
	rm := &RetransmissionManager{
		pending:       make(map[uint32]*PendingPacket),
		onRetransmit:  onRetransmit,
		timeout:       timeout,
		maxRetries:    maxRetries,
		ctx:           ctx,
		cancel:        cancel,
		stopDone:      make(chan struct{}),
		maxPending:    32768,
		flowControlCh: make(chan struct{}, 32768),
	}

	go rm.processTimeouts()

	return rm
}

func (rm *RetransmissionManager) Send(seq uint32, data []byte) error {
	rm.mu.Lock()
	if len(rm.pending) >= rm.maxPending {
		rm.mu.Unlock()
		select {
		case <-rm.flowControlCh:
			rm.mu.Lock()
		default:
			return fmt.Errorf("packet buffer full - flow control activated")
		}
	}

	timeCache := util.GetGlobalTimeCache()
	now := timeCache.Now()

	rm.pending[seq] = &PendingPacket{
		Seq:      seq,
		Data:     data,
		SentAt:   now,
		Retries:  0,
		LastSent: now,
	}
	rm.mu.Unlock()

	return rm.onRetransmit(seq, data)
}

func (rm *RetransmissionManager) Ack(seq uint32) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	delete(rm.pending, seq)

	select {
	case rm.flowControlCh <- struct{}{}:
	default:
	}
}

func (rm *RetransmissionManager) processTimeouts() {
	defer close(rm.stopDone)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	timeCache := util.GetGlobalTimeCache()

	for {
		select {
		case <-rm.ctx.Done():
			rm.mu.Lock()
			rm.pending = make(map[uint32]*PendingPacket)
			rm.mu.Unlock()
			return
		case <-ticker.C:
			rm.mu.Lock()
			now := timeCache.Now()
			var toRetransmit []*PendingPacket

			if len(rm.pending) > 0 {
				toRetransmit = make([]*PendingPacket, 0, len(rm.pending)/4)
			}

			for seq, pkt := range rm.pending {
				if now.Sub(pkt.LastSent) > rm.timeout {
					if pkt.Retries < rm.maxRetries {
						toRetransmit = append(toRetransmit, pkt)
					} else {
						delete(rm.pending, seq)
					}
				}
			}
			rm.mu.Unlock()

			for _, pkt := range toRetransmit {
				rm.mu.Lock()
				pkt.Retries++
				pkt.LastSent = timeCache.Now()
				rm.mu.Unlock()

				if rm.onRetransmit != nil {
					_ = rm.onRetransmit(pkt.Seq, pkt.Data)
				}
			}
		}
	}
}

func (rm *RetransmissionManager) Stop() {
	if rm.cancel != nil {
		rm.cancel()
		select {
		case <-rm.stopDone:
		case <-time.After(1 * time.Second):
		}
	}
}

type MTUDiscovery struct {
	currentMTU int
	probeSize  int
	minMTU     int
	maxMTU     int
	mu         sync.RWMutex
}

func NewMTUDiscovery(initialMTU, minMTU, maxMTU int) *MTUDiscovery {
	return &MTUDiscovery{
		currentMTU: initialMTU,
		probeSize:  initialMTU,
		minMTU:     minMTU,
		maxMTU:     maxMTU,
	}
}

func (md *MTUDiscovery) GetCurrentMTU() int {
	md.mu.RLock()
	defer md.mu.RUnlock()
	return md.currentMTU
}

func (md *MTUDiscovery) ProbeMTU(size int) {
	md.mu.Lock()
	defer md.mu.Unlock()

	if size >= md.minMTU && size <= md.maxMTU {
		md.probeSize = size
	}
}

func (md *MTUDiscovery) MTUConfirmed(size int) {
	md.mu.Lock()
	defer md.mu.Unlock()

	if size >= md.currentMTU {
		md.currentMTU = size
	}
}

func (md *MTUDiscovery) MTUFailed(size int) {
	md.mu.Lock()
	defer md.mu.Unlock()

	if size <= md.currentMTU {
		md.currentMTU = size - 100
		if md.currentMTU < md.minMTU {
			md.currentMTU = md.minMTU
		}
	}
}

type CongestionController struct {
	cwnd     int
	ssthresh int
	state    string
	mu       sync.RWMutex
	minCwnd  int
	maxCwnd  int
}

func NewCongestionController(initialCwnd, ssthresh, minCwnd, maxCwnd int) *CongestionController {
	return &CongestionController{
		cwnd:     initialCwnd,
		ssthresh: ssthresh,
		state:    "slow_start",
		minCwnd:  minCwnd,
		maxCwnd:  maxCwnd,
	}
}

func (cc *CongestionController) GetWindowSize() int {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.cwnd
}

func (cc *CongestionController) OnAck() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	switch cc.state {
	case "slow_start":
		cc.cwnd++
		if cc.cwnd >= cc.ssthresh {
			cc.state = "congestion_avoidance"
		}
	case "congestion_avoidance":
		cc.cwnd++
	}

	if cc.cwnd > cc.maxCwnd {
		cc.cwnd = cc.maxCwnd
	}
}

func (cc *CongestionController) OnLoss() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.ssthresh = cc.cwnd / 2
	if cc.ssthresh < cc.minCwnd {
		cc.ssthresh = cc.minCwnd
	}
	cc.cwnd = cc.minCwnd
	cc.state = "slow_start"
}

func (cc *CongestionController) OnTimeout() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.ssthresh = cc.cwnd / 2
	if cc.ssthresh < cc.minCwnd {
		cc.ssthresh = cc.minCwnd
	}
	cc.cwnd = cc.minCwnd
	cc.state = "slow_start"
}

type RateLimiter struct {
	rate       float64
	burst      int
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

func (rl *RateLimiter) Allow(size int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()
	rl.lastUpdate = now

	rl.tokens += elapsed * rl.rate
	if rl.tokens > float64(rl.burst) {
		rl.tokens = float64(rl.burst)
	}

	if rl.tokens >= float64(size) {
		rl.tokens -= float64(size)
		return true
	}

	return false
}

func (rl *RateLimiter) WaitForTokens(size int) time.Duration {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()
	rl.lastUpdate = now

	rl.tokens += elapsed * rl.rate
	if rl.tokens > float64(rl.burst) {
		rl.tokens = float64(rl.burst)
	}

	if rl.tokens >= float64(size) {
		return 0
	}

	needed := float64(size) - rl.tokens
	waitTime := needed / rl.rate

	return time.Duration(waitTime * float64(time.Second))
}

type ConnectionState struct {
	RemoteAddr   *net.UDPAddr
	SessionID    uint32
	LastActivity time.Time
	PacketBuffer *PacketBuffer
	Retransmit   *RetransmissionManager
	MTU          *MTUDiscovery
	Congestion   *CongestionController
	RateLimit    *RateLimiter
	mu           sync.RWMutex
}

func NewConnectionState(remoteAddr *net.UDPAddr, sessionID uint32) *ConnectionState {
	cs := &ConnectionState{
		RemoteAddr:   remoteAddr,
		SessionID:    sessionID,
		LastActivity: time.Now(),
		PacketBuffer: NewPacketBuffer(100, 5*time.Second),
		MTU:          NewMTUDiscovery(1200, 576, 1500),
		Congestion:   NewCongestionController(100, 500, 10, 10000),
		RateLimit:    NewRateLimiter(1*1024*1024*1024, 10*1024*1024),
	}

	cs.Retransmit = NewRetransmissionManager(1000*time.Millisecond, 5, func(seq uint32, data []byte) error {
		return nil
	})

	return cs
}

func (cs *ConnectionState) UpdateActivity() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.LastActivity = time.Now()
}

func (cs *ConnectionState) IsStale(timeout time.Duration) bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return time.Since(cs.LastActivity) > timeout
}
