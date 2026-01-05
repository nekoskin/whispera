package headers

import (
	"encoding/binary"
	"errors"
)

const (
	Version2 byte = 0x02 // Новая версия протокола

	// Flags для V2
	FlagControlV2   byte = 1 << 0 // Control packet
	FlagFragmentV2  byte = 1 << 1 // Fragmented packet
	FlagObfsPadV2   byte = 1 << 2 // Padding applied
	FlagStreamV2    byte = 1 << 3 // Stream multiplexing enabled
	FlagNoEncryptV2 byte = 1 << 4 // No encryption (for control packets)
	FlagBatchV2     byte = 1 << 5 // Batch packet (multiple packets in one)
)

const (
	HandshakeMagicV2 byte = 0x57 // 'W' for Whispera
	HandshakeLenV2   int  = 6
)

// HandshakeV2 - минимальный заголовок рукопожатия для V2 протокола
type HandshakeV2 struct {
	Magic     byte
	Version   byte
	SessionID uint32
}

func (h *HandshakeV2) MarshalBinary() []byte {
	buf := make([]byte, HandshakeLenV2)
	buf[0] = h.Magic
	buf[1] = h.Version
	binary.BigEndian.PutUint32(buf[2:6], h.SessionID)
	return buf
}

func (h *HandshakeV2) UnmarshalBinary(data []byte) error {
	if len(data) < HandshakeLenV2 {
		return errors.New("short handshake data")
	}
	h.Magic = data[0]
	h.Version = data[1]
	h.SessionID = binary.BigEndian.Uint32(data[2:6])
	if h.Magic != HandshakeMagicV2 {
		return errors.New("invalid handshake magic")
	}
	return nil
}

// CompactHeaderV2 - компактный заголовок (8 bytes вместо 12)
type CompactHeaderV2 struct {
	Flags    byte   // 5 бит флагов (0..0x1F)
	StreamID uint16 // Stream ID для мультиплексирования (0 = default)
	Seq      uint32 // Sequence number (24-bit)
}

const CompactHeaderLenV2 = 1 + 2 + 3 // 6 bytes (Version в Flags)

// MarshalBinaryTo сериализует компактный заголовок в предоставленный буфер
func (h *CompactHeaderV2) MarshalBinaryTo(buf []byte) {
	if len(buf) < CompactHeaderLenV2 {
		return
	}
	// Структура первого байта: [Version:3][Flags:5]
	flags := h.Flags & 0x1F
	buf[0] = (Version2 << 5) | flags

	// StreamID
	binary.BigEndian.PutUint16(buf[1:3], h.StreamID)

	// Seq (24 бита, три байта)
	buf[3] = byte(h.Seq >> 16)
	buf[4] = byte(h.Seq >> 8)
	buf[5] = byte(h.Seq)
}

// MarshalBinary сериализует компактный заголовок
func (h *CompactHeaderV2) MarshalBinary() []byte {
	buf := make([]byte, CompactHeaderLenV2)
	h.MarshalBinaryTo(buf)
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
	StreamID  uint16
	Seq       uint32
	Payload   []byte
	Control   bool
	NoEncrypt bool
}

// MarshalBinary сериализует batch пакет
// ОПТИМИЗИРОВАНО: Используем varint и дельта-кодирование Seq для уменьшения размера
func (b *BatchPacket) MarshalBinary() ([]byte, error) {
	// Формат: [Count:varint][Items...]
	// Item: [StreamID:varint][SeqDelta:varint][Flags:1][PayloadLen:varint][Payload]
	buf := make([]byte, 0, 1024)
	buf = appendVarInt(buf, uint64(len(b.Packets)))

	lastSeq := uint32(0)
	for _, item := range b.Packets {
		// StreamID (varint)
		buf = appendVarInt(buf, uint64(item.StreamID))

		// SeqDelta (varint)
		// Обычно пакеты в батче идут последовательно, поэтому дельта будет маленькой
		delta := int64(item.Seq) - int64(lastSeq)
		buf = appendVarInt(buf, uint64(encodeZigZag(delta)))
		lastSeq = item.Seq

		// Flags
		flags := byte(0)
		if item.Control {
			flags |= FlagControlV2
		}
		if item.NoEncrypt {
			flags |= FlagNoEncryptV2
		}
		buf = append(buf, flags)

		// PayloadLen (varint)
		buf = appendVarInt(buf, uint64(len(item.Payload)))

		// Payload
		buf = append(buf, item.Payload...)
	}

	return buf, nil
}

// UnmarshalBinary десериализует batch пакет
func (b *BatchPacket) UnmarshalBinary(data []byte) error {
	if len(data) < 1 {
		return errors.New("empty batch data")
	}

	count, n := decodeVarInt(data, 0)
	if n == 0 {
		return errors.New("invalid batch count")
	}
	offset := n

	b.Packets = make([]BatchItem, 0, int(count))
	lastSeq := uint32(0)

	for i := 0; i < int(count); i++ {
		if offset >= len(data) {
			break
		}

		item := BatchItem{}

		// StreamID
		streamID, n := decodeVarInt(data, offset)
		if n == 0 {
			return errors.New("invalid stream id in batch")
		}
		item.StreamID = uint16(streamID)
		offset += n

		// SeqDelta
		deltaZigZag, n := decodeVarInt(data, offset)
		if n == 0 {
			return errors.New("invalid seq delta in batch")
		}
		delta := decodeZigZag(deltaZigZag)
		item.Seq = uint32(int64(lastSeq) + delta)
		lastSeq = item.Seq
		offset += n

		// Flags
		if offset >= len(data) {
			return errors.New("short flags in batch")
		}
		flags := data[offset]
		item.Control = (flags & FlagControlV2) != 0
		item.NoEncrypt = (flags & FlagNoEncryptV2) != 0
		offset += 1

		// PayloadLen
		payloadLen, n := decodeVarInt(data, offset)
		if n == 0 {
			return errors.New("invalid payload len in batch")
		}
		offset += n

		if len(data) < offset+int(payloadLen) {
			return errors.New("short payload in batch item")
		}

		item.Payload = data[offset : offset+int(payloadLen)]
		offset += int(payloadLen)

		b.Packets = append(b.Packets, item)
	}

	return nil
}

// Вспомогательные функции для varint и ZigZag кодирования

func appendVarInt(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

func decodeVarInt(data []byte, off int) (uint64, int) {
	var v uint64
	var shift uint
	for i := off; i < len(data); i++ {
		b := data[i]
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v, i - off + 1
		}
		shift += 7
		if shift >= 64 {
			return 0, 0
		}
	}
	return 0, 0
}

func encodeZigZag(v int64) uint64 {
	return uint64((v << 1) ^ (v >> 63))
}

func decodeZigZag(v uint64) int64 {
	return int64(v>>1) ^ -int64(v&1)
}
