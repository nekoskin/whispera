package tun

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// AsyncWriterInterface определяет интерфейс для асинхронной записи
type AsyncWriterInterface interface {
	WriteAsync(data []byte) bool
	WriteAsyncCopy(data []byte) bool
	Stats() (writes int64, errors int64)
	Close() error
	Flush(timeout time.Duration) bool
}

// AsyncWriter обеспечивает асинхронную запись в TUN интерфейс
type AsyncWriter struct {
	tun        *Interface
	writeChan  chan []byte
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	closed     int32
	writeCount int64
	errorCount int64
}

// NewAsyncWriter создает новый асинхронный writer для TUN
func NewAsyncWriter(tun *Interface, bufferSize int) *AsyncWriter {
	if bufferSize <= 0 {
		bufferSize = 1024 // Размер по умолчанию
	}
	ctx, cancel := context.WithCancel(context.Background())
	aw := &AsyncWriter{
		tun:       tun,
		writeChan: make(chan []byte, bufferSize),
		ctx:       ctx,
		cancel:    cancel,
	}
	aw.start()
	return aw
}

// start запускает воркер для асинхронной записи
func (aw *AsyncWriter) start() {
	aw.wg.Add(1)
	go func() {
		defer aw.wg.Done()
		for {
			select {
			case <-aw.ctx.Done():
				return
			case data, ok := <-aw.writeChan:
				if !ok {
					return
				}
				// ОПТИМИЗАЦИЯ: Создаем копию данных для безопасной записи
				dataCopy := make([]byte, len(data))
				copy(dataCopy, data)
				
				// Записываем в TUN
				if _, err := aw.tun.Write(dataCopy); err != nil {
					atomic.AddInt64(&aw.errorCount, 1)
					// Ошибки логируются на уровне выше, здесь просто считаем
				} else {
					atomic.AddInt64(&aw.writeCount, 1)
				}
			}
		}
	}()
}

// WriteAsync записывает данные асинхронно в TUN
// Возвращает true если данные были добавлены в очередь, false если очередь переполнена
func (aw *AsyncWriter) WriteAsync(data []byte) bool {
	if atomic.LoadInt32(&aw.closed) != 0 {
		return false
	}
	
	// Безопасная отправка с защитой от паники при закрытом канале
	var sent bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Канал закрыт - это нормально при завершении
				atomic.StoreInt32(&aw.closed, 1)
				sent = false
			}
		}()
		select {
		case <-aw.ctx.Done():
			sent = false
		case aw.writeChan <- data:
			sent = true
		default:
			// ОПТИМИЗАЦИЯ: Очередь переполнена - пропускаем пакет для производительности
			// В реальных условиях это редко происходит при правильном размере буфера
			sent = false
		}
	}()
	return sent
}

// WriteAsyncCopy записывает данные асинхронно, создавая копию
// Используется когда исходные данные могут быть изменены
func (aw *AsyncWriter) WriteAsyncCopy(data []byte) bool {
	if atomic.LoadInt32(&aw.closed) != 0 {
		return false
	}
	
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	
	// Безопасная отправка с защитой от паники при закрытом канале
	var sent bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Канал закрыт - это нормально при завершении
				atomic.StoreInt32(&aw.closed, 1)
				sent = false
			}
		}()
		select {
		case <-aw.ctx.Done():
			sent = false
		case aw.writeChan <- dataCopy:
			sent = true
		default:
			sent = false
		}
	}()
	return sent
}

// Stats возвращает статистику записи
func (aw *AsyncWriter) Stats() (writes int64, errors int64) {
	return atomic.LoadInt64(&aw.writeCount), atomic.LoadInt64(&aw.errorCount)
}

// Close закрывает асинхронный writer
func (aw *AsyncWriter) Close() error {
	if !atomic.CompareAndSwapInt32(&aw.closed, 0, 1) {
		return nil // Уже закрыт
	}
	
	aw.cancel()
	close(aw.writeChan)
	aw.wg.Wait()
	return nil
}

// Flush ожидает завершения всех операций записи (с таймаутом)
func (aw *AsyncWriter) Flush(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		// Ждем пока очередь не опустеет
		for len(aw.writeChan) > 0 {
			time.Sleep(1 * time.Millisecond)
		}
		close(done)
	}()
	
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

