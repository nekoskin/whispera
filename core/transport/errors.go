package transport

import "errors"

var (
	// ErrNotConnected возвращается когда операция требует активного соединения
	ErrNotConnected = errors.New("transport: not connected")

	// ErrNotListening возвращается когда операция требует активного слушателя
	ErrNotListening = errors.New("transport: not listening")

	// ErrUnsupportedTransport возвращается для неподдерживаемых типов транспорта
	ErrUnsupportedTransport = errors.New("transport: unsupported transport type")

	// ErrInvalidConfig возвращается при неверной конфигурации
	ErrInvalidConfig = errors.New("transport: invalid configuration")

	// ErrWebSocketUpgradeFailed возвращается при неудачном WebSocket апгрейде
	ErrWebSocketUpgradeFailed = errors.New("transport: websocket upgrade failed")

	// ErrWebSocketInvalidMessageType возвращается при неверном типе сообщения
	ErrWebSocketInvalidMessageType = errors.New("transport: invalid websocket message type")
)
