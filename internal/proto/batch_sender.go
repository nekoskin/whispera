package proto

import (
	"sync"
	"time"
)

// BatchSender - собирает пакеты в batch для уменьшения overhead
type BatchSender struct {
	maxPackets   int
	maxWait      time.Duration
	batch        []StreamPacket
	mu           sync.Mutex
	notify       chan struct{}
	flushTimer   *time.Timer
}

// NewBatchSender создает новый batch sender
func NewBatchSender(maxPackets int, maxWait time.Duration) *BatchSender {
	bs := &BatchSender{
		maxPackets: maxPackets,
		maxWait:    maxWait,
		batch:      make([]StreamPacket, 0, maxPackets),
		notify:     make(chan struct{}, 1),
	}
	
	bs.flushTimer = time.NewTimer(maxWait)
	go bs.flushLoop()
	
	return bs
}

// AddPacket добавляет пакет в batch
func (bs *BatchSender) AddPacket(pkt StreamPacket) []StreamPacket {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	
	bs.batch = append(bs.batch, pkt)
	
	// Если batch заполнен, возвращаем его
	if len(bs.batch) >= bs.maxPackets {
		batch := bs.batch
		bs.batch = make([]StreamPacket, 0, bs.maxPackets)
		bs.resetTimer()
		return batch
	}
	
	// Уведомляем о новом пакете
	select {
	case bs.notify <- struct{}{}:
	default:
	}
	
	return nil
}

// Flush принудительно отправляет batch
func (bs *BatchSender) Flush() []StreamPacket {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	
	if len(bs.batch) == 0 {
		return nil
	}
	
	batch := bs.batch
	bs.batch = make([]StreamPacket, 0, bs.maxPackets)
	bs.resetTimer()
	return batch
}

func (bs *BatchSender) resetTimer() {
	bs.flushTimer.Stop()
	bs.flushTimer.Reset(bs.maxWait)
}

func (bs *BatchSender) flushLoop() {
	for {
		select {
		case <-bs.flushTimer.C:
			// Таймаут - отправляем batch
			if batch := bs.Flush(); batch != nil {
				// Отправляем batch (callback будет установлен извне)
				_ = batch
			}
		case <-bs.notify:
			// Новый пакет добавлен, сбрасываем таймер
			bs.mu.Lock()
			bs.resetTimer()
			bs.mu.Unlock()
		}
	}
}

