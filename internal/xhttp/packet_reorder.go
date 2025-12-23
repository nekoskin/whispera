package xhttp

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// PacketReorderer implements packet reassembly and reordering for DPI bypass
type PacketReorderer struct {
	strategy         ReorderStrategy
	buffer           map[uint32]*PacketSegment
	nextSeq          uint32
	baseSeq          uint32
	initialized      bool
	totalPackets     uint64
	reorderedPackets uint64
	bufferedPackets  uint64
	mu               sync.RWMutex
}

// ReorderStrategy defines reordering approach
type ReorderStrategy int

const (
	ReorderStrategyNone ReorderStrategy = iota
	ReorderStrategyRandom
	ReorderStrategyDelay
	ReorderStrategyInterleave
	ReorderStrategyFragment
)

// PacketSegment represents TCP packet
type PacketSegment struct {
	Sequence  uint32
	Data      []byte
	Flags     uint8
	Timestamp time.Time
	Delayed   bool
}

// NewPacketReorderer creates new packet reorderer
func NewPacketReorderer(strategy ReorderStrategy) *PacketReorderer {
	return &PacketReorderer{
		strategy:    strategy,
		buffer:      make(map[uint32]*PacketSegment),
		initialized: false,
	}
}

// AddPacket adds packet to buffer
func (pr *PacketReorderer) AddPacket(seq uint32, data []byte, flags uint8) error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if !pr.initialized {
		pr.baseSeq = seq
		pr.nextSeq = seq
		pr.initialized = true
	}

	segment := &PacketSegment{
		Sequence:  seq,
		Data:      make([]byte, len(data)),
		Flags:     flags,
		Timestamp: time.Now(),
	}
	copy(segment.Data, data)

	pr.buffer[seq] = segment
	pr.bufferedPackets++

	return nil
}

// GetReorderedPackets returns packets in reordered sequence
func (pr *PacketReorderer) GetReorderedPackets() ([]PacketSegment, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if len(pr.buffer) == 0 {
		return nil, nil
	}

	var result []PacketSegment

	switch pr.strategy {
	case ReorderStrategyNone:
		result = pr.getInOrder()
	case ReorderStrategyRandom:
		result = pr.getRandomOrder()
	case ReorderStrategyDelay:
		result = pr.getDelayedOrder()
	case ReorderStrategyInterleave:
		result = pr.getInterleaveOrder()
	case ReorderStrategyFragment:
		result = pr.getFragmentedOrder()
	}

	for _, seg := range result {
		delete(pr.buffer, seg.Sequence)
	}

	pr.totalPackets += uint64(len(result))
	if pr.strategy != ReorderStrategyNone {
		pr.reorderedPackets += uint64(len(result))
	}

	return result, nil
}

// getInOrder returns packets in sequence order
func (pr *PacketReorderer) getInOrder() []PacketSegment {
	var result []PacketSegment
	var seqs []uint32
	for seq := range pr.buffer {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	for _, seq := range seqs {
		result = append(result, *pr.buffer[seq])
	}
	return result
}

// getRandomOrder returns packets in random order
func (pr *PacketReorderer) getRandomOrder() []PacketSegment {
	var result []PacketSegment
	var seqs []uint32
	for seq := range pr.buffer {
		seqs = append(seqs, seq)
	}

	rand.Shuffle(len(seqs), func(i, j int) {
		seqs[i], seqs[j] = seqs[j], seqs[i]
	})

	for _, seq := range seqs {
		result = append(result, *pr.buffer[seq])
	}
	return result
}

// getDelayedOrder returns packets with some delayed
func (pr *PacketReorderer) getDelayedOrder() []PacketSegment {
	var inOrder []PacketSegment
	var delayed []PacketSegment
	var seqs []uint32
	for seq := range pr.buffer {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	delayCount := len(seqs) / 5
	for i, seq := range seqs {
		segment := *pr.buffer[seq]
		if i < delayCount && delayCount > 0 {
			segment.Delayed = true
			delayed = append(delayed, segment)
		} else {
			inOrder = append(inOrder, segment)
		}
	}

	var result []PacketSegment
	for i := 0; i < len(inOrder); i++ {
		result = append(result, inOrder[i])
		if i%3 == 0 && len(delayed) > 0 {
			result = append(result, delayed[0])
			delayed = delayed[1:]
		}
	}
	result = append(result, delayed...)
	return result
}

// getInterleaveOrder returns packets in alternating order
func (pr *PacketReorderer) getInterleaveOrder() []PacketSegment {
	var seqs []uint32
	for seq := range pr.buffer {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	var result []PacketSegment
	left, right := 0, len(seqs)-1

	for left <= right {
		if left <= right {
			result = append(result, *pr.buffer[seqs[left]])
			left++
		}
		if left <= right {
			result = append(result, *pr.buffer[seqs[right]])
			right--
		}
	}

	return result
}

// getFragmentedOrder returns packets fragmented and reordered
func (pr *PacketReorderer) getFragmentedOrder() []PacketSegment {
	var seqs []uint32
	for seq := range pr.buffer {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	var result []PacketSegment
	fragmentSize := 1024

	for _, seq := range seqs {
		segment := pr.buffer[seq]

		if len(segment.Data) > fragmentSize {
			for offset := 0; offset < len(segment.Data); offset += fragmentSize {
				end := offset + fragmentSize
				if end > len(segment.Data) {
					end = len(segment.Data)
				}

				frag := PacketSegment{
					Sequence:  uint32(uint32(seq) + uint32(offset)),
					Data:      segment.Data[offset:end],
					Flags:     segment.Flags,
					Timestamp: segment.Timestamp,
				}
				result = append(result, frag)
			}
		} else {
			result = append(result, *segment)
		}
	}

	rand.Shuffle(len(result), func(i, j int) {
		result[i], result[j] = result[j], result[i]
	})

	return result
}

// Clear clears buffer
func (pr *PacketReorderer) Clear() {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	pr.buffer = make(map[uint32]*PacketSegment)
	pr.bufferedPackets = 0
}

// GetStats returns statistics
func (pr *PacketReorderer) GetStats() map[string]interface{} {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	return map[string]interface{}{
		"strategy":          pr.strategy,
		"total_packets":     pr.totalPackets,
		"reordered_packets": pr.reorderedPackets,
		"buffered_packets":  pr.bufferedPackets,
		"buffer_size":       len(pr.buffer),
	}
}

// PacketReassembler reassembles reordered packets
type PacketReassembler struct {
	buffer           map[uint32]*PacketSegment
	nextExpectedSeq  uint32
	baseSeq          uint32
	initialized      bool
	timeout          time.Duration
	lastActivity     time.Time
	totalSegments    uint64
	reassembledBytes uint64
	mu               sync.RWMutex
}

// NewPacketReassembler creates new reassembler
func NewPacketReassembler() *PacketReassembler {
	return &PacketReassembler{
		buffer:       make(map[uint32]*PacketSegment),
		timeout:      30 * time.Second,
		lastActivity: time.Now(),
		initialized:  false,
	}
}

// AddSegment adds segment for reassembly
func (pr *PacketReassembler) AddSegment(seq uint32, data []byte) error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if !pr.initialized {
		pr.baseSeq = seq
		pr.nextExpectedSeq = seq
		pr.initialized = true
	}

	if _, exists := pr.buffer[seq]; exists {
		return fmt.Errorf("segment %d already exists", seq)
	}

	segment := &PacketSegment{
		Sequence:  seq,
		Data:      make([]byte, len(data)),
		Timestamp: time.Now(),
	}
	copy(segment.Data, data)

	pr.buffer[seq] = segment
	pr.lastActivity = time.Now()

	return nil
}

// GetReassembledData returns reassembled data up to next gap
func (pr *PacketReassembler) GetReassembledData() ([]byte, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	var result []byte
	currentSeq := pr.nextExpectedSeq

	for {
		segment, exists := pr.buffer[currentSeq]
		if !exists {
			break
		}

		result = append(result, segment.Data...)
		delete(pr.buffer, currentSeq)
		currentSeq += uint32(len(segment.Data))
	}

	if len(result) > 0 {
		pr.nextExpectedSeq = currentSeq
		pr.reassembledBytes += uint64(len(result))
		pr.lastActivity = time.Now()
	}

	return result, nil
}

// IsComplete checks if reassembly is complete
func (pr *PacketReassembler) IsComplete() bool {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	return len(pr.buffer) == 0
}

// HasTimeout checks if timed out
func (pr *PacketReassembler) HasTimeout() bool {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	return time.Since(pr.lastActivity) > pr.timeout
}

// GetStats returns statistics
func (pr *PacketReassembler) GetStats() map[string]interface{} {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	return map[string]interface{}{
		"total_segments":    pr.totalSegments,
		"reassembled_bytes": pr.reassembledBytes,
		"pending_segments":  len(pr.buffer),
		"next_expected_seq": pr.nextExpectedSeq,
		"timed_out":         time.Since(pr.lastActivity) > pr.timeout,
	}
}

// DPIEvadingPipeline combines reordering and reassembly
type DPIEvadingPipeline struct {
	reorderer   *PacketReorderer
	reassembler *PacketReassembler
	mu          sync.RWMutex
}

// NewDPIEvadingPipeline creates new DPI evasion pipeline
func NewDPIEvadingPipeline(strategy ReorderStrategy) *DPIEvadingPipeline {
	return &DPIEvadingPipeline{
		reorderer:   NewPacketReorderer(strategy),
		reassembler: NewPacketReassembler(),
	}
}

// ProcessOutgoing processes outgoing data with reordering
func (dep *DPIEvadingPipeline) ProcessOutgoing(data []byte, seq uint32) ([]PacketSegment, error) {
	dep.mu.Lock()
	defer dep.mu.Unlock()

	if err := dep.reorderer.AddPacket(seq, data, 0); err != nil {
		return nil, err
	}

	return dep.reorderer.GetReorderedPackets()
}

// ProcessIncoming processes incoming reordered data
func (dep *DPIEvadingPipeline) ProcessIncoming(seq uint32, data []byte) ([]byte, error) {
	dep.mu.Lock()
	defer dep.mu.Unlock()

	if err := dep.reassembler.AddSegment(seq, data); err != nil {
		return nil, err
	}

	return dep.reassembler.GetReassembledData()
}

// GetPipelineStats returns statistics
func (dep *DPIEvadingPipeline) GetPipelineStats() map[string]interface{} {
	dep.mu.RLock()
	defer dep.mu.RUnlock()

	return map[string]interface{}{
		"reorderer":   dep.reorderer.GetStats(),
		"reassembler": dep.reassembler.GetStats(),
	}
}
