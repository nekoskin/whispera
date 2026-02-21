package qos

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

type DiscordDetector struct {
	mu                sync.RWMutex
	activeFlows       map[string]*DiscordFlow
	detectionCriteria *DetectionCriteria
	autoOptimizeVoIP  bool
	lastCleanupTime   time.Time
}

type DiscordFlow struct {
	SSRC             uint32
	LocalPort        uint16
	RemoteAddr       net.Addr
	FirstPacketTime  time.Time
	LastPacketTime   time.Time
	PacketCount      int64
	BytesTransferred int64
	IsVoice          bool
	CodecHint        string
	ConfidenceScore  float64
	IsActive         bool
}

type DetectionCriteria struct {
	PortRangeStart uint16
	PortRangeEnd   uint16

	MinVoicePacketSize   int
	MaxVoicePacketSize   int
	TypicalVoicePackSize int

	OpusPayloadType uint8
	MinPacketsPerSecond int
	MaxPacketsPerSecond int
	MinFlowDuration     time.Duration

	MinVoiceBitrate int64
	MaxVoiceBitrate int64
}

func NewDiscordDetector() *DiscordDetector {
	return &DiscordDetector{
		activeFlows: make(map[string]*DiscordFlow),
		detectionCriteria: &DetectionCriteria{
			PortRangeStart:       50000,
			PortRangeEnd:         65000,
			MinVoicePacketSize:   30,
			MaxVoicePacketSize:   500,
			TypicalVoicePackSize: 120,
			OpusPayloadType:      111,
			MinPacketsPerSecond:  40,
			MaxPacketsPerSecond:  120,
			MinFlowDuration:      2 * time.Second,
			MinVoiceBitrate:      20000,
			MaxVoiceBitrate:      320000,
		},
		autoOptimizeVoIP: true,
		lastCleanupTime:  time.Now(),
	}
}

func (dd *DiscordDetector) AnalyzePacket(pkt []byte, srcAddr, dstAddr net.Addr) *DiscordFlow {
	if len(pkt) < 28 {
		return nil
	}

	dd.mu.Lock()
	defer dd.mu.Unlock()

	dstUDP, ok := dstAddr.(*net.UDPAddr)
	if !ok {
		return nil
	}

	port := uint16(dstUDP.Port)
	if !dd.isDiscordPort(port) {
		return nil
	}

	rtpHeader := pkt[:12]
	version := (rtpHeader[0] >> 6) & 0x3
	if version != 2 {
		return nil
	}

	payloadType := rtpHeader[1] & 0x7F
	ssrc := binary.BigEndian.Uint32(rtpHeader[8:12])

	flowKey := dd.getFlowKey(srcAddr, port, ssrc)

	flow, exists := dd.activeFlows[flowKey]
	if !exists {
		flow = &DiscordFlow{
			SSRC:            ssrc,
			LocalPort:       port,
			RemoteAddr:      srcAddr,
			FirstPacketTime: time.Now(),
			LastPacketTime:  time.Now(),
			IsActive:        true,
		}
		dd.activeFlows[flowKey] = flow
	}

	flow.LastPacketTime = time.Now()
	flow.PacketCount++
	flow.BytesTransferred += int64(len(pkt))

	packetSize := len(pkt) - 12
	flow.IsVoice = dd.isVoicePacket(packetSize, payloadType)

	if payloadType == dd.detectionCriteria.OpusPayloadType ||
		(payloadType <= 20) {
		flow.CodecHint = "opus"
	}

	flow.ConfidenceScore = dd.calculateConfidenceScore(flow)

	return flow
}
func (dd *DiscordDetector) IsDiscordVoIP(flowKey string) bool {
	dd.mu.RLock()
	defer dd.mu.RUnlock()

	flow, exists := dd.activeFlows[flowKey]
	if !exists {
		return false
	}

	return flow.ConfidenceScore > 0.7 &&
		flow.PacketCount >= 10 &&
		flow.IsVoice
}

func (dd *DiscordDetector) GetAllActiveFlows() map[string]*DiscordFlow {
	dd.mu.RLock()
	defer dd.mu.RUnlock()

	result := make(map[string]*DiscordFlow)
	for k, v := range dd.activeFlows {
		result[k] = v
	}
	return result
}

func (dd *DiscordDetector) CleanupInactiveFlows(timeout time.Duration) {
	dd.mu.Lock()
	defer dd.mu.Unlock()

	now := time.Now()
	for key, flow := range dd.activeFlows {
		if now.Sub(flow.LastPacketTime) > timeout {
			delete(dd.activeFlows, key)
		}
	}
	dd.lastCleanupTime = now
}

func (dd *DiscordDetector) isDiscordPort(port uint16) bool {
	return port >= dd.detectionCriteria.PortRangeStart &&
		port <= dd.detectionCriteria.PortRangeEnd
}

func (dd *DiscordDetector) isVoicePacket(size int, payloadType uint8) bool {
	if size < dd.detectionCriteria.MinVoicePacketSize ||
		size > dd.detectionCriteria.MaxVoicePacketSize {
		return false
	}

	if payloadType == dd.detectionCriteria.OpusPayloadType {
		return true
	}
	if payloadType >= 0 && payloadType <= 20 {
		return true
	}

	return false
}

func (dd *DiscordDetector) calculateConfidenceScore(flow *DiscordFlow) float64 {
	if flow.PacketCount == 0 {
		return 0.0
	}

	score := 0.0

	avgPacketSize := flow.BytesTransferred / flow.PacketCount
	if avgPacketSize >= int64(dd.detectionCriteria.MinVoicePacketSize) &&
		avgPacketSize <= int64(dd.detectionCriteria.MaxVoicePacketSize) {
		score += 0.3
	}

	if flow.PacketCount > 0 {
		duration := flow.LastPacketTime.Sub(flow.FirstPacketTime)
		if duration > 0 {
			pps := int(flow.PacketCount) / int(duration.Seconds())
			if pps >= dd.detectionCriteria.MinPacketsPerSecond &&
				pps <= dd.detectionCriteria.MaxPacketsPerSecond {
				score += 0.3
			}
		}
	}

	duration := flow.LastPacketTime.Sub(flow.FirstPacketTime)
	if duration >= dd.detectionCriteria.MinFlowDuration {
		score += 0.2
	}

	if flow.CodecHint == "opus" {
		score += 0.2
	}

	return score
}

func (dd *DiscordDetector) getFlowKey(addr net.Addr, port uint16, ssrc uint32) string {
	return fmt.Sprintf("%s:%d:%d", addr.String(), port, ssrc)
}
func (dd *DiscordDetector) RecommendOptimization(flowKey string) bool {
	dd.mu.RLock()
	defer dd.mu.RUnlock()

	flow, exists := dd.activeFlows[flowKey]
	if !exists {
		return false
	}

	return flow.IsVoice &&
		flow.ConfidenceScore > 0.7 &&
		flow.PacketCount > 20 &&
		dd.autoOptimizeVoIP
}

func (dd *DiscordDetector) GetFlowStats(flowKey string) *DiscordFlowStats {
	dd.mu.RLock()
	defer dd.mu.RUnlock()

	flow, exists := dd.activeFlows[flowKey]
	if !exists {
		return nil
	}

	duration := flow.LastPacketTime.Sub(flow.FirstPacketTime)
	bitrate := int64(0)
	if duration > 0 {
		bitrate = (flow.BytesTransferred * 8) / int64(duration.Seconds())
	}

	return &DiscordFlowStats{
		SSRC:             flow.SSRC,
		PacketCount:      flow.PacketCount,
		BytesTransferred: flow.BytesTransferred,
		Duration:         duration,
		Bitrate:          bitrate,
		IsVoice:          flow.IsVoice,
		Confidence:       flow.ConfidenceScore,
	}
}

type DiscordFlowStats struct {
	SSRC             uint32
	PacketCount      int64
	BytesTransferred int64
	Duration         time.Duration
	Bitrate          int64
	IsVoice          bool
	Confidence       float64
}
