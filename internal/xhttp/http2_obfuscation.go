package xhttp

import (
	"math/rand"
	"sync"
)

// HTTP/2 Frame Types (RFC 7540)
const (
	FrameData         uint8 = 0x0
	FrameHeaders      uint8 = 0x1
	FramePriority     uint8 = 0x2
	FrameRstStream    uint8 = 0x3
	FrameSettings     uint8 = 0x4
	FramePushPromise  uint8 = 0x5
	FramePing         uint8 = 0x6
	FrameGoAway       uint8 = 0x7
	FrameWindowUpdate uint8 = 0x8
	FrameContinuation uint8 = 0x9
)

// HTTP/2 Frame Flags
const (
	FlagEndStream  uint8 = 0x1
	FlagEndHeaders uint8 = 0x4
	FlagPadded     uint8 = 0x8
	FlagPriority   uint8 = 0x20
)

// HTTP2Obfuscator handles HTTP/2 frame obfuscation for XHTTP
// This is the primary obfuscation layer that makes traffic look like HTTP/2
type HTTP2Obfuscator struct {
	streamID uint32
	mutex    sync.RWMutex
	rand     *rand.Rand
}

// NewHTTP2Obfuscator creates a new HTTP/2 obfuscator
func NewHTTP2Obfuscator() *HTTP2Obfuscator {
	return &HTTP2Obfuscator{
		streamID: 1,
		rand:     rand.New(rand.NewSource(rand.Int63())),
	}
}

// EncodeFrame wraps data in HTTP/2 DATA frame format
// Format: [Length:24][Type:8][Flags:8][StreamID:31][Payload:N][Padding:N]
func (h *HTTP2Obfuscator) EncodeFrame(data []byte) []byte {
	h.mutex.Lock()
	streamID := h.streamID
	h.streamID++
	if h.streamID > 0x7FFFFFFF {
		h.streamID = 1
	}
	h.mutex.Unlock()

	// Calculate padding (0-255 bytes, random for better obfuscation)
	paddingLen := h.rand.Intn(16) // Small padding for efficiency
	totalLen := len(data) + paddingLen

	// HTTP/2 frame header is 9 bytes
	frame := make([]byte, 9+len(data)+paddingLen)

	// Length (24 bits, big-endian)
	frame[0] = byte(totalLen >> 16)
	frame[1] = byte(totalLen >> 8)
	frame[2] = byte(totalLen)

	// Type: DATA frame
	frame[3] = FrameData

	// Flags: END_STREAM (for last frame) or 0
	flags := uint8(0)
	if len(data) < 1024 {
		flags = FlagEndStream // Mark as end for small frames
	}
	frame[4] = flags

	// Stream ID (31 bits, big-endian, must be odd for client-initiated)
	streamID |= 0x80000000 // Set highest bit to 1 (client stream)
	frame[5] = byte(streamID >> 24)
	frame[6] = byte(streamID >> 16)
	frame[7] = byte(streamID >> 8)
	frame[8] = byte(streamID)

	// Payload
	copy(frame[9:], data)

	// Padding (random bytes)
	if paddingLen > 0 {
		for i := 0; i < paddingLen; i++ {
			frame[9+len(data)+i] = byte(h.rand.Intn(256))
		}
	}

	return frame
}

// DecodeFrame extracts data from HTTP/2 DATA frame
func (h *HTTP2Obfuscator) DecodeFrame(frame []byte) ([]byte, error) {
	if len(frame) < 9 {
		return nil, ErrInvalidFrame
	}

	// Read frame header
	length := int(frame[0])<<16 | int(frame[1])<<8 | int(frame[2])
	frameType := frame[3]
	flags := frame[4]
	streamID := uint32(frame[5])<<24 | uint32(frame[6])<<16 | uint32(frame[7])<<8 | uint32(frame[8])

	// Validate frame
	if frameType != FrameData {
		return nil, ErrInvalidFrameType
	}

	// Check if frame has padding
	payloadStart := 9
	payloadLen := length

	if flags&FlagPadded != 0 {
		if len(frame) < 10 {
			return nil, ErrInvalidFrame
		}
		paddingLen := int(frame[9])
		payloadStart = 10
		payloadLen = length - paddingLen - 1
	}

	// Extract payload
	if len(frame) < payloadStart+payloadLen {
		return nil, ErrInvalidFrame
	}

	payload := make([]byte, payloadLen)
	copy(payload, frame[payloadStart:payloadStart+payloadLen])

	_ = streamID // Stream ID is tracked but not used for decoding

	return payload, nil
}

// EncodeHeaders creates HTTP/2 HEADERS frame for obfuscation
// Used for initial handshake to make connection look like HTTP/2
func (h *HTTP2Obfuscator) EncodeHeaders(headers map[string]string) []byte {
	// Simple header encoding (HPACK would be ideal but complex)
	// For obfuscation, we create a minimal valid HEADERS frame
	headerData := make([]byte, 0, 256)

	// Add pseudo-headers and regular headers
	for k, v := range headers {
		headerData = append(headerData, []byte(k)...)
		headerData = append(headerData, ':')
		headerData = append(headerData, []byte(v)...)
		headerData = append(headerData, '\r', '\n')
	}

	h.mutex.Lock()
	streamID := h.streamID
	h.streamID += 2 // HEADERS frames use even stream IDs
	if h.streamID > 0x7FFFFFFF {
		h.streamID = 2
	}
	h.mutex.Unlock()

	frame := make([]byte, 9+len(headerData))

	// Length
	length := len(headerData)
	frame[0] = byte(length >> 16)
	frame[1] = byte(length >> 8)
	frame[2] = byte(length)

	// Type: HEADERS
	frame[3] = FrameHeaders

	// Flags: END_HEADERS
	frame[4] = FlagEndHeaders

	// Stream ID (even for server-initiated)
	streamID &= 0x7FFFFFFF // Clear highest bit
	frame[5] = byte(streamID >> 24)
	frame[6] = byte(streamID >> 16)
	frame[7] = byte(streamID >> 8)
	frame[8] = byte(streamID)

	// Header data
	copy(frame[9:], headerData)

	return frame
}

// Errors
var (
	ErrInvalidFrame     = &FrameError{msg: "invalid HTTP/2 frame"}
	ErrInvalidFrameType = &FrameError{msg: "invalid HTTP/2 frame type"}
)

type FrameError struct {
	msg string
}

func (e *FrameError) Error() string {
	return e.msg
}
