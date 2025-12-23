package streamutil

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"
)

// Пул буферов для переиспользования памяти при чтении фреймов
var (
	frameBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 65535) // Предварительно выделяем память для максимального размера фрейма
		},
	}
	// Пул для write batching - буферы для объединения нескольких записей
	writeBatchPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 131072) // 128KB для батчинга
		},
	}
)

// SafeUint16 converts an int to uint16 ensuring the value fits.
func SafeUint16(val int) (uint16, bool) {
	if val < 0 || val > math.MaxUint16 {
		return 0, false
	}
	return uint16(val), true
}

// WriteFrame writes a length-prefixed frame to the provided connection.
// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Объединяем заголовок и данные в один write для уменьшения syscalls
func WriteFrame(w net.Conn, b []byte) error {
	var hdr [2]byte
	payloadLen, ok := SafeUint16(len(b))
	if !ok {
		return errors.New("frame too large")
	}
	binary.BigEndian.PutUint16(hdr[:], payloadLen)
	
	// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Объединяем заголовок и данные в один write для уменьшения syscalls
	// Для маленьких пакетов создаем буфер напрямую, для больших используем пул
	var fullPacket []byte
	usePool := len(b) >= 4096
	if usePool {
		fullPacket = writeBatchPool.Get().([]byte)
		if cap(fullPacket) < 2+len(b) {
			fullPacket = make([]byte, 2+len(b))
			usePool = false
		} else {
			fullPacket = fullPacket[:2+len(b)]
		}
	} else {
		fullPacket = make([]byte, 2+len(b))
	}
	
	copy(fullPacket[0:2], hdr[:])
	copy(fullPacket[2:], b)
	
	_, err := w.Write(fullPacket)
	
	if usePool {
		writeBatchPool.Put(fullPacket[:0])
	}
	
	return err
}

// BatchWriter - батчер для множественных записей
type BatchWriter struct {
	conn     net.Conn
	buffer   []byte
	maxSize  int
	mu       sync.Mutex
}

// NewBatchWriter создает новый batch writer
func NewBatchWriter(conn net.Conn, maxBatchSize int) *BatchWriter {
	if maxBatchSize <= 0 {
		maxBatchSize = 65536 // 64KB по умолчанию
	}
	buf := writeBatchPool.Get().([]byte)
	if cap(buf) < maxBatchSize {
		buf = make([]byte, 0, maxBatchSize)
	} else {
		buf = buf[:0]
	}
	return &BatchWriter{
		conn:    conn,
		buffer:  buf,
		maxSize: maxBatchSize,
	}
}

// Write добавляет данные в batch
func (bw *BatchWriter) Write(data []byte) error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	
	// Если добавление данных превысит лимит, отправляем текущий batch
	if len(bw.buffer)+2+len(data) > bw.maxSize {
		if err := bw.Flush(); err != nil {
		return err
	}
	}
	
	// Добавляем заголовок и данные
	payloadLen, ok := SafeUint16(len(data))
	if !ok {
		return errors.New("frame too large")
	}
	
	// Расширяем буфер если нужно
	needed := len(bw.buffer) + 2 + len(data)
	if cap(bw.buffer) < needed {
		newBuf := make([]byte, len(bw.buffer), needed*2)
		copy(newBuf, bw.buffer)
		bw.buffer = newBuf
	}
	
	oldLen := len(bw.buffer)
	bw.buffer = bw.buffer[:needed]
	binary.BigEndian.PutUint16(bw.buffer[oldLen:oldLen+2], payloadLen)
	copy(bw.buffer[oldLen+2:], data)
	
	return nil
}

// Flush отправляет накопленные данные
func (bw *BatchWriter) Flush() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	
	if len(bw.buffer) == 0 {
		return nil
	}
	
	_, err := bw.conn.Write(bw.buffer)
	bw.buffer = bw.buffer[:0] // Очищаем буфер
	return err
}

// Close закрывает writer и отправляет оставшиеся данные
func (bw *BatchWriter) Close() error {
	if err := bw.Flush(); err != nil {
		return err
	}
	writeBatchPool.Put(bw.buffer[:0])
	return nil
}

// ReadFrame reads a length-prefixed frame from the provided connection.
// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Используем io.ReadFull для гарантированного чтения всех данных
func ReadFrame(r net.Conn) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n <= 0 || n > 65535 {
		return nil, errors.New("invalid frame size")
	}
	
	// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Используем пул буферов для всех размеров
	// Это уменьшает GC pressure и улучшает производительность
	buf := frameBufferPool.Get().([]byte)
		if cap(buf) < n {
			buf = make([]byte, n)
		} else {
			buf = buf[:n]
		}
	
	if _, err := io.ReadFull(r, buf); err != nil {
		// Возвращаем буфер в пул при ошибке
		if cap(buf) <= 65535 {
			frameBufferPool.Put(buf[:0])
		}
		return nil, err
	}
	
	// Возвращаем буфер - вызывающий код должен вернуть его в пул через PutFrameBuffer
	return buf, nil
}

// PutFrameBuffer возвращает буфер фрейма в пул
func PutFrameBuffer(buf []byte) {
	if cap(buf) > 0 && cap(buf) <= 65535 {
		frameBufferPool.Put(buf[:0])
	}
}

