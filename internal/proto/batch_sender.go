package proto

import (
	"sync"
	"time"

	"whispera/internal/proto/multi"
)

type BatchSender struct {
	maxPackets  int
	maxWait     time.Duration
	maxSize     int
	currentSize int
	batch       []multi.StreamPacket
	mu          sync.Mutex
	flushTimer  *time.Timer
	onFlush     func([]multi.StreamPacket)
	closed      chan struct{}
	wg          sync.WaitGroup
}

func NewBatchSender(maxPackets int, maxSize int, maxWait time.Duration, onFlush func([]multi.StreamPacket)) *BatchSender {
	bs := &BatchSender{
		maxPackets: maxPackets,
		maxSize:    maxSize,
		maxWait:    maxWait,
		batch:      make([]multi.StreamPacket, 0, maxPackets),
		onFlush:    onFlush,
		closed:     make(chan struct{}),
	}

	bs.flushTimer = time.AfterFunc(maxWait, bs.timerFlush)
	return bs
}

func (bs *BatchSender) AddPacket(pkt multi.StreamPacket) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if len(bs.batch) < cap(bs.batch) {
		bs.batch = bs.batch[:len(bs.batch)+1]
		bs.batch[len(bs.batch)-1] = pkt
	} else {
		bs.batch = append(bs.batch, pkt)
	}

	bs.currentSize += len(pkt.Payload)

	if len(bs.batch) >= bs.maxPackets || (bs.maxSize > 0 && bs.currentSize >= bs.maxSize) {
		bs.flushLocked()
	} else if len(bs.batch) == 1 {
		bs.flushTimer.Reset(bs.maxWait)
	}
}

func (bs *BatchSender) timerFlush() {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if len(bs.batch) > 0 {
		bs.flushLocked()
	}
}

func (bs *BatchSender) flushLocked() {
	if len(bs.batch) == 0 {
		return
	}

	batch := bs.batch
	bs.batch = make([]multi.StreamPacket, 0, bs.maxPackets)
	bs.currentSize = 0
	bs.flushTimer.Stop()

	if bs.onFlush != nil {
		go bs.onFlush(batch)
	}
}

func (bs *BatchSender) Flush() {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.flushLocked()
}

func (bs *BatchSender) Stop() {
	bs.mu.Lock()
	bs.flushLocked()
	bs.flushTimer.Stop()
	bs.mu.Unlock()
}
