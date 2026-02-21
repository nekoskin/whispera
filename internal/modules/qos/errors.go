package qos

import "fmt"

var (
	ErrNotConnected      = fmt.Errorf("transport not connected")
	ErrNotListening      = fmt.Errorf("transport not listening")
	ErrBandwidthExceeded = fmt.Errorf("bandwidth limit exceeded")
	ErrQueueFull         = fmt.Errorf("queue is full")
	ErrInvalidPacket     = fmt.Errorf("invalid packet format")
)
