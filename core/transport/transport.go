package transport

// TransportKind описывает тип транспорта между клиентом и сервером на STREAM-уровне.
// Он абстрагируется от конкретного протокола шифрования/обфускации (UDP/TCP/WS/WS2).
type TransportKind string

const (
	TransportUDP   TransportKind = "udp"
	TransportTCP   TransportKind = "tcp"
	TransportWS    TransportKind = "ws"
	TransportWS2   TransportKind = "ws2"
	TransportGRPC  TransportKind = "grpc"
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
}

// Config содержит конфигурацию транспорта
type Config struct {
	Kind         TransportKind
	Addr         string
	Timeout      int // в секундах
	KeepAlive    bool
	BufferSize   int
	Metadata     map[string]string
}

// Manager управляет различными транспортами
type Manager struct {
	transports map[TransportKind]StreamTransport
	config     *Config
}

// NewManager создает новый менеджер транспортов
func NewManager(config *Config) *Manager {
	return &Manager{
		transports: make(map[TransportKind]StreamTransport),
		config:     config,
	}
}

// RegisterTransport регистрирует новый транспорт
func (m *Manager) RegisterTransport(kind TransportKind, transport StreamTransport) {
	m.transports[kind] = transport
}

// GetTransport получает транспорт по типу
func (m *Manager) GetTransport(kind TransportKind) (StreamTransport, bool) {
	transport, exists := m.transports[kind]
	return transport, exists
}

// Close закрывает все зарегистрированные транспорты
func (m *Manager) Close() error {
	var lastErr error
	for _, transport := range m.transports {
		if err := transport.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
