package transport

import "errors"

var (
	
	ErrNotConnected = errors.New("transport: not connected")

	
	ErrNotListening = errors.New("transport: not listening")

	
	ErrUnsupportedTransport = errors.New("transport: unsupported transport type")

	
	ErrInvalidConfig = errors.New("transport: invalid configuration")

	
	ErrWebSocketUpgradeFailed = errors.New("transport: websocket upgrade failed")

	
	ErrWebSocketInvalidMessageType = errors.New("transport: invalid websocket message type")
)
