package headers

import (
	"encoding/binary"
	"errors"
	"sync"
)

const (
	Version byte = 0x01

	FlagControl  byte = 1 << 0
	FlagFragment byte = 1 << 1
	FlagObfsPad  byte = 1 << 2 // payload framed: [2B realLen][data][pad]
)

const HeaderLen = 1 + 1 + 4 + 4 + 2

// Пул буферов для заголовков пакетов - критическая оптимизация производительности
var headerBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, HeaderLen)
	},
}

type PacketHeader struct {
	Version    byte
	Flags      byte
	SessionID  uint32
	Seq        uint32
	PayloadLen uint16
}

// MarshalBinary использует пул буферов для уменьшения аллокаций
func (h *PacketHeader) MarshalBinary() []byte {
	buf := headerBufferPool.Get().([]byte)
	buf[0] = h.Version
	buf[1] = h.Flags
	binary.BigEndian.PutUint32(buf[2:6], h.SessionID)
	binary.BigEndian.PutUint32(buf[6:10], h.Seq)
	binary.BigEndian.PutUint16(buf[10:12], h.PayloadLen)
	return buf
}

// MarshalBinaryTo записывает заголовок в предоставленный буфер (zero-copy вариант)
func (h *PacketHeader) MarshalBinaryTo(buf []byte) {
	if len(buf) < HeaderLen {
		return
	}
	buf[0] = h.Version
	buf[1] = h.Flags
	binary.BigEndian.PutUint32(buf[2:6], h.SessionID)
	binary.BigEndian.PutUint32(buf[6:10], h.Seq)
	binary.BigEndian.PutUint16(buf[10:12], h.PayloadLen)
}

// PutHeaderBuffer возвращает буфер заголовка в пул
func PutHeaderBuffer(buf []byte) {
	if cap(buf) >= HeaderLen {
		headerBufferPool.Put(buf[:HeaderLen])
	}
}

func (h *PacketHeader) UnmarshalBinary(b []byte) error {
	if len(b) < HeaderLen {
		return errors.New("short header")
	}
	h.Version = b[0]
	h.Flags = b[1]
	h.SessionID = binary.BigEndian.Uint32(b[2:6])
	h.Seq = binary.BigEndian.Uint32(b[6:10])
	h.PayloadLen = binary.BigEndian.Uint16(b[10:12])
	if h.Version != Version {
		return errors.New("version mismatch")
	}
	return nil
}
