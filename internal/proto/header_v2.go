package proto

import (
	"encoding/binary"
	"errors"
)

const (
	Version2 byte = 0x02 // Новая версия протокола

	// Flags для V2
	FlagControlV2    byte = 1 << 0 // Control packet
	FlagFragmentV2    byte = 1 << 1 // Fragmented packet
	FlagObfsPadV2    byte = 1 << 2 // Padding applied
	FlagStreamV2     byte = 1 << 3 // Stream multiplexing enabled
	FlagNoEncryptV2  byte = 1 << 4 // No encryption (for control packets)
	FlagBatchV2      byte = 1 << 5 // Batch packet (multiple packets in one)
)

// CompactHeaderV2 - компактный заголовок (8 bytes вместо 12)
type CompactHeaderV2 struct {
	Flags    byte   // 5 бит флагов (0..0x1F)
	StreamID uint16 // Stream ID для мультиплексирования (0 = default)
	Seq      uint32 // Sequence number (24-bit)
}

const CompactHeaderLenV2 = 1 + 2 + 3 // 6 bytes (Version в Flags)

// MarshalBinary сериализует компактный заголовок
func (h *CompactHeaderV2) MarshalBinary() []byte {
	buf := make([]byte, CompactHeaderLenV2)
	// Структура первого байта: [Version:3][Flags:5]
	flags := h.Flags & 0x1F
	buf[0] = (Version2 << 5) | flags

	// StreamID
	binary.BigEndian.PutUint16(buf[1:3], h.StreamID)
	
	// Seq (24 бита, три байта)
	buf[3] = byte(h.Seq >> 16)
	buf[4] = byte(h.Seq >> 8)
	buf[5] = byte(h.Seq)
	
	return buf
}

// UnmarshalBinary десериализует компактный заголовок
func (h *CompactHeaderV2) UnmarshalBinary(b []byte) error {
	if len(b) < CompactHeaderLenV2 {
		return errors.New("short compact header")
	}
	
	version := (b[0] >> 5) & 0x07
	if version != Version2 {
		return errors.New("version mismatch")
	}
	
	// Извлекаем данные из первого байта
	h.Flags = b[0] & 0x1F
	h.StreamID = binary.BigEndian.Uint16(b[1:3])
	
	// Восстанавливаем Seq из 3 байт
	h.Seq = uint32(b[3])<<16 | uint32(b[4])<<8 | uint32(b[5])
	
	return nil
}

// PacketHeaderV2 - полный заголовок с payload length (для больших пакетов)
type PacketHeaderV2 struct {
	CompactHeaderV2
	PayloadLen uint16 // Length только если нужно (variable length encoding)
}

const (
	// Variable length encoding для PayloadLen
	// Значение < 0xFF кодируем одним байтом.
	// 0xFF зарезервирован как маркер расширенной длины (ещё 2 байта).
	SmallPayloadThreshold byte = 0xFF
)

// MarshalBinaryV2 сериализует заголовок с переменной длиной
func (h *PacketHeaderV2) MarshalBinaryV2() []byte {
	compact := h.CompactHeaderV2.MarshalBinary()
	
	if h.PayloadLen < uint16(SmallPayloadThreshold) {
		// Маленький payload - 1 байт
		return append(compact, byte(h.PayloadLen))
	}
	// Большой payload - 2 байта (0xFF + uint16)
	buf := make([]byte, len(compact)+3)
	copy(buf, compact)
	buf[len(compact)] = 0xFF
	binary.BigEndian.PutUint16(buf[len(compact)+1:], h.PayloadLen)
	return buf
}

// UnmarshalBinaryV2 десериализует заголовок с переменной длиной
func (h *PacketHeaderV2) UnmarshalBinaryV2(b []byte) (int, error) {
	if len(b) < CompactHeaderLenV2 {
		return 0, errors.New("short header")
	}
	
	if err := h.CompactHeaderV2.UnmarshalBinary(b[:CompactHeaderLenV2]); err != nil {
		return 0, err
	}
	
	offset := CompactHeaderLenV2
	if len(b) < offset+1 {
		return 0, errors.New("short payload length")
	}
	
	if b[offset] == 0xFF {
		// Большой payload
		if len(b) < offset+3 {
			return 0, errors.New("short extended payload length")
		}
		h.PayloadLen = binary.BigEndian.Uint16(b[offset+1 : offset+3])
		return offset + 3, nil
	}
	// Маленький payload
	h.PayloadLen = uint16(b[offset])
	return offset + 1, nil
}

// BatchPacket - пакет с несколькими вложенными пакетами
type BatchPacket struct {
	Packets []BatchItem
}

type BatchItem struct {
	StreamID   uint16
	Seq        uint32
	Payload    []byte
	Control    bool
	NoEncrypt  bool
}

// MarshalBinary сериализует batch пакет
func (b *BatchPacket) MarshalBinary() ([]byte, error) {
	// Формат: [Count:1 byte][Items...]
	// Item: [StreamID:2][Seq:3][Flags:1][PayloadLen:1-2][Payload]
	buf := make([]byte, 0, 1024)
	buf = append(buf, byte(len(b.Packets)))
	
	for _, item := range b.Packets {
		// StreamID
		streamID := make([]byte, 2)
		binary.BigEndian.PutUint16(streamID, item.StreamID)
		buf = append(buf, streamID...)
		
		// Seq (3 bytes)
		buf = append(buf, byte(item.Seq>>16), byte(item.Seq>>8), byte(item.Seq))
		
		// Flags
		flags := byte(0)
		if item.Control {
			flags |= FlagControlV2
		}
		if item.NoEncrypt {
			flags |= FlagNoEncryptV2
		}
		buf = append(buf, flags)
		
		// PayloadLen (variable)
		payloadLen := len(item.Payload)
		if payloadLen < 255 {
			buf = append(buf, byte(payloadLen))
		} else {
			buf = append(buf, 0xFF)
			lenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBuf, uint16(payloadLen))
			buf = append(buf, lenBuf...)
		}
		
		// Payload
		buf = append(buf, item.Payload...)
	}
	
	return buf, nil
}

