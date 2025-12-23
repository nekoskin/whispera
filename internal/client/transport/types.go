package transport

// TransportKind описывает тип транспорта между клиентом и сервером на STREAM-уровне.
// Он абстрагируется от конкретного протокола шифрования/обфускации (UDP/TCP/WS/WS2).
type TransportKind string

const (
	TransportUDP  TransportKind = "udp"
	TransportTCP  TransportKind = "tcp"
	TransportWS   TransportKind = "ws"
	TransportWS2  TransportKind = "ws2"
	TransportGRPC TransportKind = "grpc"
	TransportQUIC TransportKind = "quic"
	TransportHTTP2 TransportKind = "http2"
	TransportAuto TransportKind = "auto" // выбор по политике/ML
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

