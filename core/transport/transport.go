package transport

import (
	"context"
	"net"
)

// TransportKind описывает тип транспорта между клиентом и сервером на STREAM-уровне.
// Он абстрагируется от конкретного протокола шифрования/обфускации (UDP/TCP/WS/WS2).
type TransportKind string

const (
	TransportUDP   TransportKind = "udp"
	TransportTCP   TransportKind = "tcp"
	TransportWS    TransportKind = "ws"
	TransportWS2   TransportKind = "ws2"
	TransportQUIC  TransportKind = "quic"
	TransportHTTP2 TransportKind = "http2"
	TransportAuto  TransportKind = "auto" // выбор по политике/ML
)

// StreamTransport абстрагирует raw-байтовый канал между клиентом и сервером
// для STREAM-слоя. В будущем сюда можно добавить контекст/метаданные.
type StreamTransport interface {
	// WriteRaw отправляет уже упакованный и зашифрованный пакет в транспорт.
	WriteRaw(pkt []byte) error
	// ReadRaw читает следующий зашифрованный пакет из транспорта.
	ReadRaw(buf []byte) (int, error)
	// Close закрывает транспорт.
	Close() error
	// LocalAddr возвращает локальный адрес
	LocalAddr() net.Addr
	// RemoteAddr возвращает удаленный адрес
	RemoteAddr() net.Addr
}

// Config содержит конфигурацию транспорта
type Config struct {
	Kind       TransportKind
	Addr       string
	Timeout    int // в секундах
	KeepAlive  bool
	BufferSize int
	Metadata   map[string]string
}

// TransportManager определяет интерфейс для управления транспортами
type TransportManager interface {
	// RegisterTransport регистрирует новый транспорт
	RegisterTransport(kind TransportKind, transport StreamTransport)

	// GetTransport получает транспорт по типу
	GetTransport(kind TransportKind) (StreamTransport, bool)

	// ActiveTransport возвращает текущий активный транспорт
	ActiveTransport() StreamTransport

	// SetActiveTransport устанавливает активный транспорт
	SetActiveTransport(kind TransportKind) error

	// Close закрывает все транспорты
	Close() error
}

// TransportSelector определяет логику выбора транспорта
type TransportSelector interface {
	// Select выбирает лучший транспорт на основе условий
	Select(candidates []TransportKind) TransportKind
}

// TransportMiddleware определяет middleware для транспортного уровня
type TransportMiddleware interface {
	// HandleRead обрабатывает чтение данных
	HandleRead(data []byte, next func([]byte) (int, error)) (int, error)

	// HandleWrite обрабатывает запись данных
	HandleWrite(data []byte, next func([]byte) error) error
}

// BaseManager базовая реализация менеджера (для обратной совместимости и базовой логики)
type BaseManager struct {
	transports map[TransportKind]StreamTransport
	active     TransportKind
	config     *Config
}

// NewManager создает новый менеджер транспортов
func NewManager(config *Config) *BaseManager {
	return &BaseManager{
		transports: make(map[TransportKind]StreamTransport),
		config:     config,
	}
}

// RegisterTransport регистрирует новый транспорт
func (m *BaseManager) RegisterTransport(kind TransportKind, transport StreamTransport) {
	m.transports[kind] = transport
	if m.active == "" {
		m.active = kind
	}
}

// GetTransport получает транспорт по типу
func (m *BaseManager) GetTransport(kind TransportKind) (StreamTransport, bool) {
	transport, exists := m.transports[kind]
	return transport, exists
}

// ActiveTransport возвращает текущий активный транспорт
func (m *BaseManager) ActiveTransport() StreamTransport {
	if m.active == "" {
		return nil
	}
	return m.transports[m.active]
}

// SetActiveTransport устанавливает активный транспорт
func (m *BaseManager) SetActiveTransport(kind TransportKind) error {
	if _, ok := m.transports[kind]; !ok {
		return context.DeadlineExceeded // TODO: Custom error
	}
	m.active = kind
	return nil
}

// Close закрывает все зарегистрированные транспорты
func (m *BaseManager) Close() error {
	var lastErr error
	for _, transport := range m.transports {
		if err := transport.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
