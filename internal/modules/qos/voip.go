package qos

import (
	"context"
	"net"
	"sync"
	"time"
)

type VoIPQoS struct {
	mu               sync.RWMutex
	enabled          bool
	priorityQueue    *PriorityPacketQueue
	rtpDetector      *RTPDetector
	jitterBuffer     *JitterBuffer
	latencyTracker   *LatencyTracker
	bandwidthLimiter *BandwidthLimiter

	metrics *VoIPMetrics
}

type VoIPMetrics struct {
	mu                sync.RWMutex
	AverageLatency    time.Duration
	JitterMs          float64
	PacketLossPercent float64
	CurrentBitrate    int64
	TargetBitrate     int64
	ActiveConnections int
	DroppedPackets    int64
	ReorderedPackets  int64
	RTCPReportCount   int64
}

type PriorityPacketQueue struct {
	mu           sync.Mutex
	rtpQueue     chan *QueuedPacket
	defaultQueue chan *QueuedPacket
	controlQueue chan *QueuedPacket
	maxRTPSize   int
	maxOtherSize int
}

type QueuedPacket struct {
	Data      []byte
	Dest      net.Addr
	Timestamp time.Time
	Priority  PacketPriority
	RTTHint   time.Duration
}

var packetPool = sync.Pool{
	New: func() interface{} {
		return &QueuedPacket{}
	},
}

func GetPacket() *QueuedPacket {
	return packetPool.Get().(*QueuedPacket)
}

func PutPacket(pkt *QueuedPacket) {
	pkt.Data = nil
	pkt.Dest = nil
	pkt.Priority = PriorityDefault
	pkt.RTTHint = 0
	packetPool.Put(pkt)
}

type PacketPriority int

const (
	PriorityRTPVoice PacketPriority = iota
	PriorityRTPVideo
	PriorityRTCP
	PriorityData
	PriorityDefault
)

type RTPDetector struct {
	mu                sync.RWMutex
	rtpFlows          map[string]*RTPFlow
	discordSignatures map[uint16]bool
}

type RTPFlow struct {
	SSRC           uint32
	PayloadType    uint8
	SequenceNumber uint16
	Timestamp      uint32
	PacketCount    int64
	OctetCount     int64
	JitterBuf      *JitterBuffer
	LastPacketTime time.Time
	IsActive       bool
}

type JitterBuffer struct {
	mu             sync.Mutex
	buffer         map[uint16]*RTPPacket
	minJitter      time.Duration
	maxJitter      time.Duration
	currentJitter  time.Duration
	targetJitter   time.Duration
	lastSeqNum     uint16
	packetLoss     int64
	reorderedCount int64

	measuredJitter time.Duration
	adaptAlpha     float64
}

func (jb *JitterBuffer) AdaptJitter(measuredDelay time.Duration) {
	jb.mu.Lock()
	defer jb.mu.Unlock()

	if jb.adaptAlpha == 0 {
		jb.adaptAlpha = 0.125
	}

	alpha := jb.adaptAlpha
	jb.measuredJitter = time.Duration(
		alpha*float64(measuredDelay) + (1-alpha)*float64(jb.measuredJitter),
	)

	newTarget := time.Duration(float64(jb.measuredJitter) * 1.2)
	if newTarget < jb.minJitter {
		newTarget = jb.minJitter
	}
	if newTarget > jb.maxJitter {
		newTarget = jb.maxJitter
	}
	jb.targetJitter = newTarget
}

type RTPPacket struct {
	Data      []byte
	SeqNum    uint16
	Timestamp uint32
	RecvTime  time.Time
}

type LatencyTracker struct {
	mu               sync.RWMutex
	samples          []time.Duration
	lastMeasure      time.Time
	averageLatency   time.Duration
	minLatency       time.Duration
	maxLatency       time.Duration
	measurementCount int64
}

type BandwidthLimiter struct {
	mu           sync.RWMutex
	maxBitrate   int64
	currentRate  int64
	window       time.Duration
	lastReset    time.Time
	tokensPerSec int64
	tokens       int64
}

func NewVoIPQoS() *VoIPQoS {
	return &VoIPQoS{
		enabled:       false,
		priorityQueue: NewPriorityPacketQueue(1000, 500),
		rtpDetector:   NewRTPDetector(),
		jitterBuffer:  NewJitterBuffer(),
		latencyTracker: &LatencyTracker{
			samples:    make([]time.Duration, 0, 100),
			minLatency: time.Hour,
		},
		bandwidthLimiter: &BandwidthLimiter{
			maxBitrate:   100 * 1024 * 1024,
			tokensPerSec: 100 * 1024 * 1024 / 8,
			window:       time.Second,
		},
		metrics: &VoIPMetrics{
			TargetBitrate: 512000,
		},
	}
}

func NewPriorityPacketQueue(rtpCapacity, otherCapacity int) *PriorityPacketQueue {
	return &PriorityPacketQueue{
		rtpQueue:     make(chan *QueuedPacket, rtpCapacity),
		defaultQueue: make(chan *QueuedPacket, otherCapacity),
		controlQueue: make(chan *QueuedPacket, 100),
		maxRTPSize:   rtpCapacity,
		maxOtherSize: otherCapacity,
	}
}

func (pq *PriorityPacketQueue) Enqueue(pkt *QueuedPacket) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	var targetQueue chan *QueuedPacket

	switch pkt.Priority {
	case PriorityRTPVoice, PriorityRTPVideo, PriorityRTCP:
		targetQueue = pq.rtpQueue
	case PriorityData, PriorityDefault:
		targetQueue = pq.defaultQueue
	default:
		targetQueue = pq.defaultQueue
	}

	select {
	case targetQueue <- pkt:
	default:
	}
}

func (pq *PriorityPacketQueue) Dequeue(ctx context.Context) (*QueuedPacket, error) {
	select {
	case pkt := <-pq.rtpQueue:
		return pkt, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	select {
	case pkt := <-pq.rtpQueue:
		return pkt, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case pkt := <-pq.rtpQueue:
		return pkt, nil
	case pkt := <-pq.defaultQueue:
		return pkt, nil
	}
}

func NewRTPDetector() *RTPDetector {
	return &RTPDetector{
		rtpFlows:          make(map[string]*RTPFlow),
		discordSignatures: makeDiscordSignatures(),
	}
}

func makeDiscordSignatures() map[uint16]bool {
	signatures := make(map[uint16]bool)
	for port := uint16(50000); port <= 65000; port++ {
		signatures[port] = true
	}
	return signatures
}

func NewJitterBuffer() *JitterBuffer {
	return &JitterBuffer{
		buffer:        make(map[uint16]*RTPPacket),
		minJitter:     5 * time.Millisecond,
		maxJitter:     50 * time.Millisecond,
		targetJitter:  20 * time.Millisecond,
		currentJitter: 15 * time.Millisecond,
	}
}

func (v *VoIPQoS) ProcessPacket(ctx context.Context, pkt []byte, inspectionData []byte, dest net.Addr) (*QueuedPacket, error) {
	v.mu.RLock()
	if !v.enabled {
		v.mu.RUnlock()
		queued := GetPacket()
		queued.Data = pkt
		queued.Dest = dest
		queued.Timestamp = time.Now()
		queued.Priority = PriorityDefault
		return queued, nil
	}
	v.mu.RUnlock()

	dataToInspect := inspectionData
	if dataToInspect == nil {
		dataToInspect = pkt
	}

	priority := v.classifyPacket(dataToInspect, dest)

	if priority == PriorityRTPVoice || priority == PriorityRTPVideo {
		v.rtpDetector.TrackFlow(dataToInspect)
	}

	v.latencyTracker.Record(time.Since(time.Now()))

	if !v.bandwidthLimiter.TryConsume(int64(len(pkt))) {
		v.metrics.mu.Lock()
		v.metrics.DroppedPackets++
		v.metrics.mu.Unlock()
		return nil, ErrBandwidthExceeded
	}

	queued := &QueuedPacket{
		Data:      pkt,
		Dest:      dest,
		Timestamp: time.Now(),
		Priority:  priority,
	}

	return queued, nil
}

func (v *VoIPQoS) EnqueuePacket(pkt *QueuedPacket) {
	v.priorityQueue.Enqueue(pkt)
}
func (v *VoIPQoS) ReadPacket(ctx context.Context) (*QueuedPacket, error) {
	return v.priorityQueue.Dequeue(ctx)
}

func (v *VoIPQoS) classifyPacket(pkt []byte, dest net.Addr) PacketPriority {
	if len(pkt) < 12 {
		return PriorityDefault
	}

	if (pkt[0] & 0xC0) == 0x80 {
		payloadType := pkt[1] & 0x7F

		if payloadType <= 20 {
			return PriorityRTPVoice
		} else if payloadType >= 96 && payloadType <= 127 {
			return PriorityRTPVoice
		}
	}

	if (pkt[0]&0xC0) == 0x80 && len(pkt) >= 8 {
		pt := pkt[1] & 0x7F
		if pt >= 200 && pt <= 204 {
			return PriorityRTCP
		}
	}

	if udpAddr, ok := dest.(*net.UDPAddr); ok {
		if v.rtpDetector.discordSignatures[uint16(udpAddr.Port)] {
			return PriorityRTPVoice
		}
	}

	return PriorityDefault
}

func (v *VoIPQoS) GetMetrics() *VoIPMetrics {
	v.metrics.mu.Lock()
	defer v.metrics.mu.Unlock()

	v.metrics.AverageLatency = v.latencyTracker.GetAverageLatency()
	v.metrics.JitterMs = v.latencyTracker.GetJitter()

	return v.metrics
}

func (v *VoIPQoS) SetBandwidthLimit(bitrate int64) {
	v.bandwidthLimiter.mu.Lock()
	defer v.bandwidthLimiter.mu.Unlock()
	v.bandwidthLimiter.maxBitrate = bitrate
	v.bandwidthLimiter.tokensPerSec = bitrate / 8
}

func (v *VoIPQoS) Enable() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.enabled = true
}

func (v *VoIPQoS) Disable() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.enabled = false
}

func (rd *RTPDetector) TrackFlow(pkt []byte) {
	if len(pkt) < 12 {
		return
	}

	rd.mu.Lock()
	defer rd.mu.Unlock()

	ssrc := uint32(pkt[8])<<24 | uint32(pkt[9])<<16 | uint32(pkt[10])<<8 | uint32(pkt[11])

	flowKey := string(pkt[:12])
	if flow, exists := rd.rtpFlows[flowKey]; exists {
		flow.PacketCount++
		flow.OctetCount += int64(len(pkt))
		flow.LastPacketTime = time.Now()
	} else {
		rd.rtpFlows[flowKey] = &RTPFlow{
			SSRC:           ssrc,
			PayloadType:    pkt[1] & 0x7F,
			SequenceNumber: uint16(pkt[2])<<8 | uint16(pkt[3]),
			Timestamp:      uint32(pkt[4])<<24 | uint32(pkt[5])<<16 | uint32(pkt[6])<<8 | uint32(pkt[7]),
			PacketCount:    1,
			OctetCount:     int64(len(pkt)),
			IsActive:       true,
			LastPacketTime: time.Now(),
		}
	}
}

func (lt *LatencyTracker) Record(latency time.Duration) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	lt.samples = append(lt.samples, latency)
	if len(lt.samples) > 100 {
		lt.samples = lt.samples[1:]
	}

	if latency < lt.minLatency {
		lt.minLatency = latency
	}
	if latency > lt.maxLatency {
		lt.maxLatency = latency
	}

	lt.measurementCount++
}

func (lt *LatencyTracker) GetAverageLatency() time.Duration {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	if len(lt.samples) == 0 {
		return 0
	}

	var sum time.Duration
	for _, sample := range lt.samples {
		sum += sample
	}
	return sum / time.Duration(len(lt.samples))
}

func (lt *LatencyTracker) GetJitter() float64 {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	if len(lt.samples) < 2 {
		return 0
	}

	var variance float64
	avg := lt.GetAverageLatency()
	avgMs := float64(avg.Milliseconds())

	for _, sample := range lt.samples {
		sampleMs := float64(sample.Milliseconds())
		diff := sampleMs - avgMs
		variance += diff * diff
	}
	variance /= float64(len(lt.samples))

	return variance
}

func (bl *BandwidthLimiter) TryConsume(bytes int64) bool {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	now := time.Now()
	if now.Sub(bl.lastReset) >= bl.window {
		bl.tokens = bl.tokensPerSec
		bl.lastReset = now
		bl.currentRate = 0
	}

	tokensNeeded := (bytes * 8)
	if bl.tokens >= tokensNeeded {
		bl.tokens -= tokensNeeded
		bl.currentRate += tokensNeeded
		return true
	}
	return false
}
