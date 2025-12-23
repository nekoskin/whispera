package proto

import (
	"errors"
	"sync"
	"sync/atomic"

	"whispera/internal/util"
)

// StreamMultiplexer - мультиплексирование потоков в одной сессии
type StreamMultiplexer struct {
	streams      map[uint16]*Stream
	mu           sync.RWMutex
	nextID       uint32
	maxStreams   int // Максимальное количество потоков (0 = без ограничений)
	streamCount  int32 // Текущее количество потоков
	totalStreams uint64 // Общее количество созданных потоков
}

// Stream - отдельный поток в сессии
type Stream struct {
	ID           uint16
	Seq          uint32 // Атомарный счетчик последовательности
	State        StreamState
	Buffer       []byte
	Closed       bool
	LastActivity int64
	BytesIn      uint64 // Статистика: входящие байты
	BytesOut     uint64 // Статистика: исходящие байты
	PacketsIn    uint64 // Статистика: входящие пакеты
	PacketsOut   uint64 // Статистика: исходящие пакеты
	Created      int64  // Время создания потока
	mu           sync.RWMutex
}

type StreamState byte

const (
	StreamStateOpen StreamState = iota
	StreamStateHalfClosed
	StreamStateClosed
)

// Резервируем несколько well-known StreamID для простых сценариев.
// В дальнейшем tun2socks и proxy смогут использовать динамические ID через
// StreamMultiplexer.AllocateStream, но для первого шага достаточно
// "глобального" потока для всего TUN-трафика.
const (
	// TunStreamID — статический поток "сырого" TUN/IP-трафика.
	// Все IP‑пакеты из TUN могут идти в этом потоке, пока мы не
	// разрежем их на per‑flow‑streams на уровне tunstack.
	TunStreamID uint16 = 1

	// StreamProtoTunAggregate — специальный маркировочный proto byte для агрегированного TUN-трафика,
	// когда конкретный L4 протокол ещё не определён и весь IP поток идёт в одном StreamID.
	StreamProtoTunAggregate uint8 = 0
)

// StreamCommand описывает тип кадра stream-протокола.
// Он живёт "над" IP/TUN и "под" Noise/UDP/WS, и используется
// как логический протокол для tun2socks / proxy-потоков.
type StreamCommand byte

const (
	// StreamOpen открывает новый логический поток.
	// Payload кадра обычно содержит метаданные (сеть/адрес и т.п.),
	// а сам StreamID берётся из заголовка V2 (CompactHeaderV2 / BatchItem).
	StreamOpen StreamCommand = 0x01

	// StreamData передаёт пользовательские данные потока.
	// В большинстве случаев кадр DATA будет идти как обычный data‑пакет
	// без Control‑флага, но константа остаётся для симметрии и логирования.
	StreamData StreamCommand = 0x02

	// StreamClose закрывает логический поток.
	// Payload может нести reason code / stats, но это опционально.
	StreamClose StreamCommand = 0x03

	// StreamOpenDomain открывает поток по доменному имени (Fake-IP).
	// Payload: [Proto:1][SrcIP:4][SrcPort:2][DomainLen:1][Domain:N][DstPort:2]
	StreamOpenDomain StreamCommand = 0x09
)

// StreamControlFrame представляет STREAM_* кадр уровня потока.
// Он кодируется как [Cmd:1][Payload:N] внутри Payload BatchItem'а/StreamPacket'а
// при установленном флаге Control.
type StreamControlFrame struct {
	Command StreamCommand
	Payload []byte
}

// EncodeStreamControlFrame кодирует STREAM_OPEN / STREAM_CLOSE / другие
// управляющие команды в байтовый слайс для помещения в StreamPacket.Payload.
func EncodeStreamControlFrame(cmd StreamCommand, payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = byte(cmd)
	copy(out[1:], payload)
	return out
}

// DecodeStreamControlFrame декодирует байтовый слайс в StreamControlFrame.
// Ожидается формат [Cmd:1][Payload:N].
func DecodeStreamControlFrame(b []byte) (*StreamControlFrame, error) {
	if len(b) == 0 {
		return nil, errors.New("empty stream control frame")
	}
	frame := &StreamControlFrame{
		Command: StreamCommand(b[0]),
	}
	if len(b) > 1 {
		frame.Payload = make([]byte, len(b)-1)
		copy(frame.Payload, b[1:])
	}
	return frame, nil
}

// NewStreamMultiplexer создает новый мультиплексер
func NewStreamMultiplexer() *StreamMultiplexer {
	return &StreamMultiplexer{
		streams:     make(map[uint16]*Stream),
		nextID:      1, // Stream ID 0 зарезервирован для default
		maxStreams:  0, // Без ограничений по умолчанию
		streamCount: 0,
	}
}

// NewStreamMultiplexerWithLimit создает новый мультиплексер с ограничением на количество потоков
func NewStreamMultiplexerWithLimit(maxStreams int) *StreamMultiplexer {
	return &StreamMultiplexer{
		streams:     make(map[uint16]*Stream),
		nextID:      1,
		maxStreams:  maxStreams,
		streamCount: 0,
	}
}

// AllocateStream выделяет новый stream ID
// Исправлена race condition при wrap-around
func (m *StreamMultiplexer) AllocateStream() (uint16, error) {
	for {
	id := atomic.AddUint32(&m.nextID, 1)
		// Проверяем wrap-around до приведения к uint16
	if id > 65535 {
			// Пытаемся сбросить nextID на 1 атомарно
			if atomic.CompareAndSwapUint32(&m.nextID, id, 1) {
				id = 1
			} else {
				// Другая горутина уже сбросила, пробуем снова
				continue
			}
		}
		
		streamID := uint16(id)
		
		// Проверяем, не занят ли этот ID
		m.mu.RLock()
		_, exists := m.streams[streamID]
		m.mu.RUnlock()
		
		if !exists {
			return streamID, nil
		}
		
		// ID занят, пробуем следующий
		// Это может произойти при wrap-around, но крайне редко
	}
}

// GetStream получает существующий stream без создания
func (m *StreamMultiplexer) GetStream(streamID uint16) (*Stream, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	stream, exists := m.streams[streamID]
	if exists {
		// Обновляем активность с блокировкой
		stream.mu.Lock()
		atomic.StoreInt64(&stream.LastActivity, getCurrentTime())
		stream.mu.Unlock()
	}
	return stream, exists
}

// GetOrCreateStream получает или создает stream
func (m *StreamMultiplexer) GetOrCreateStream(streamID uint16) (*Stream, error) {
	// Быстрая проверка без блокировки
	m.mu.RLock()
	if stream, exists := m.streams[streamID]; exists {
		m.mu.RUnlock()
		stream.mu.Lock()
		atomic.StoreInt64(&stream.LastActivity, getCurrentTime())
		stream.mu.Unlock()
		return stream, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check
	if stream, exists := m.streams[streamID]; exists {
		stream.mu.Lock()
		atomic.StoreInt64(&stream.LastActivity, getCurrentTime())
		stream.mu.Unlock()
		return stream, nil
	}

	// Проверяем лимит потоков
	if m.maxStreams > 0 {
		currentCount := int(atomic.LoadInt32(&m.streamCount))
		if currentCount >= m.maxStreams {
			return nil, errors.New("maximum stream limit reached")
		}
	}

	// Создаем новый stream
	now := getCurrentTime()
	stream := &Stream{
		ID:           streamID,
		Seq:          1,
		State:        StreamStateOpen,
		Buffer:       make([]byte, 0, 4096),
		LastActivity: now,
		Created:      now,
	}

	m.streams[streamID] = stream
	atomic.AddInt32(&m.streamCount, 1)
	atomic.AddUint64(&m.totalStreams, 1)
	return stream, nil
}

// CloseStream закрывает stream
func (m *StreamMultiplexer) CloseStream(streamID uint16) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if stream, exists := m.streams[streamID]; exists {
		stream.mu.Lock()
		stream.Closed = true
		stream.State = StreamStateClosed
		stream.mu.Unlock()
		delete(m.streams, streamID)
		atomic.AddInt32(&m.streamCount, -1)
		return true
	}
	return false
}

// CleanupInactive очищает неактивные streams
// Возвращает количество удаленных потоков
func (m *StreamMultiplexer) CleanupInactive(timeout int64) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := getCurrentTime()
	removed := 0
	var toRemove []uint16

	// Собираем ID потоков для удаления
	for id, stream := range m.streams {
		stream.mu.RLock()
		lastActivity := atomic.LoadInt64(&stream.LastActivity)
		closed := stream.Closed
		stream.mu.RUnlock()

		if closed || (now-lastActivity > timeout) {
			toRemove = append(toRemove, id)
		}
	}

	// Удаляем потоки
	for _, id := range toRemove {
		if stream, exists := m.streams[id]; exists {
			stream.mu.Lock()
			stream.Closed = true
			stream.State = StreamStateClosed
			stream.mu.Unlock()
			delete(m.streams, id)
			atomic.AddInt32(&m.streamCount, -1)
			removed++
		}
	}

	return removed
}

// GetStreamCount возвращает текущее количество активных потоков
func (m *StreamMultiplexer) GetStreamCount() int {
	return int(atomic.LoadInt32(&m.streamCount))
}

// GetTotalStreams возвращает общее количество созданных потоков
func (m *StreamMultiplexer) GetTotalStreams() uint64 {
	return atomic.LoadUint64(&m.totalStreams)
}

// GetAllStreamIDs возвращает список всех активных StreamID
func (m *StreamMultiplexer) GetAllStreamIDs() []uint16 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]uint16, 0, len(m.streams))
	for id := range m.streams {
		ids = append(ids, id)
	}
	return ids
}

// GetStreamStats возвращает статистику потока
func (m *StreamMultiplexer) GetStreamStats(streamID uint16) (stats StreamStats, exists bool) {
	m.mu.RLock()
	stream, ok := m.streams[streamID]
	m.mu.RUnlock()

	if !ok {
		return StreamStats{}, false
	}

	stream.mu.RLock()
	defer stream.mu.RUnlock()

	return StreamStats{
		ID:           stream.ID,
		Seq:          atomic.LoadUint32(&stream.Seq),
		State:        stream.State,
		BytesIn:      atomic.LoadUint64(&stream.BytesIn),
		BytesOut:     atomic.LoadUint64(&stream.BytesOut),
		PacketsIn:    atomic.LoadUint64(&stream.PacketsIn),
		PacketsOut:   atomic.LoadUint64(&stream.PacketsOut),
		LastActivity: atomic.LoadInt64(&stream.LastActivity),
		Created:      stream.Created,
		Closed:       stream.Closed,
	}, true
}

// StreamStats - статистика потока
type StreamStats struct {
	ID           uint16
	Seq          uint32
	State        StreamState
	BytesIn      uint64
	BytesOut     uint64
	PacketsIn    uint64
	PacketsOut   uint64
	LastActivity int64
	Created      int64
	Closed       bool
}

// IncrementSeq атомарно увеличивает последовательность потока
func (s *Stream) IncrementSeq() uint32 {
	return atomic.AddUint32(&s.Seq, 1)
}

// GetSeq возвращает текущую последовательность
func (s *Stream) GetSeq() uint32 {
	return atomic.LoadUint32(&s.Seq)
}

// AddBytesIn добавляет входящие байты
func (s *Stream) AddBytesIn(bytes uint64) {
	atomic.AddUint64(&s.BytesIn, bytes)
	atomic.AddUint64(&s.PacketsIn, 1)
	atomic.StoreInt64(&s.LastActivity, getCurrentTime())
}

// AddBytesOut добавляет исходящие байты
func (s *Stream) AddBytesOut(bytes uint64) {
	atomic.AddUint64(&s.BytesOut, bytes)
	atomic.AddUint64(&s.PacketsOut, 1)
	atomic.StoreInt64(&s.LastActivity, getCurrentTime())
}

// ОПТИМИЗАЦИЯ: Используем кэшированное время для уменьшения системных вызовов
func getCurrentTime() int64 {
	timeCache := util.GetGlobalTimeCache()
	return timeCache.Now().Unix()
}

// StreamPacket - пакет с stream ID
type StreamPacket struct {
	StreamID  uint16
	Seq       uint32
	Payload   []byte
	Control   bool
	NoEncrypt bool
}

// PackStreams упаковывает несколько stream пакетов в один batch
func PackStreams(packets []StreamPacket) *BatchPacket {
	batch := &BatchPacket{
		Packets: make([]BatchItem, 0, len(packets)),
	}

	for _, pkt := range packets {
		batch.Packets = append(batch.Packets, BatchItem{
			StreamID:  pkt.StreamID,
			Seq:       pkt.Seq,
			Payload:   pkt.Payload,
			Control:   pkt.Control,
			NoEncrypt: pkt.NoEncrypt,
		})
	}

	return batch
}
