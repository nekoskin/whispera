package handler

import (
	"errors"

	"whispera/internal/proto/headers"
)

// ProtocolAdapter - адаптер для поддержки V1 и V2 протоколов
type ProtocolAdapter struct {
	UseV2 bool // Использовать V2 протокол
}

// NewProtocolAdapter создает адаптер протокола
func NewProtocolAdapter(useV2 bool) *ProtocolAdapter {
	return &ProtocolAdapter{UseV2: useV2}
}

// DetectVersion определяет версию протокола по первому байту
func DetectVersion(firstByte byte) (byte, error) {
	// Проверяем V2 (Version в верхних 3 битах)
	version := (firstByte >> 5) & 0x07
	if version == headers.Version2 {
		return headers.Version2, nil
	}

	// Проверяем V1 (Version = 0x01)
	if firstByte == headers.Version {
		return headers.Version, nil
	}

	return 0, errors.New("unknown protocol version")
}

// ParseHeader парсит заголовок с автоматическим определением версии
func ParseHeader(data []byte) (interface{}, int, error) {
	if len(data) < 1 {
		return nil, 0, errors.New("empty data")
	}

	version, err := DetectVersion(data[0])
	if err != nil {
		return nil, 0, err
	}

	switch version {
	case headers.Version2:
		// V2 протокол
		if len(data) < headers.CompactHeaderLenV2 {
			return nil, 0, errors.New("short V2 header")
		}

		var hdr headers.CompactHeaderV2
		if err := hdr.UnmarshalBinary(data[:headers.CompactHeaderLenV2]); err != nil {
			return nil, 0, err
		}

		// Проверяем, есть ли PayloadLen
		if len(data) > headers.CompactHeaderLenV2 {
			var hdrV2 headers.PacketHeaderV2
			hdrV2.CompactHeaderV2 = hdr
			offset, err := hdrV2.UnmarshalBinaryV2(data)
			if err != nil {
				// Если не удалось распарсить PayloadLen, возвращаем только CompactHeader
				return &hdr, headers.CompactHeaderLenV2, nil
			}
			return &hdrV2, offset, nil
		}

		return &hdr, headers.CompactHeaderLenV2, nil

	case headers.Version:
		// V1 протокол
		if len(data) < headers.HeaderLen {
			return nil, 0, errors.New("short V1 header")
		}

		var hdr headers.PacketHeader
		if err := hdr.UnmarshalBinary(data[:headers.HeaderLen]); err != nil {
			return nil, 0, err
		}

		return &hdr, headers.HeaderLen, nil

	default:
		return nil, 0, errors.New("unsupported protocol version")
	}
}

// GetSessionID извлекает SessionID из заголовка (V1 или V2)
func GetSessionID(header interface{}) (uint32, bool) {
	switch h := header.(type) {
	case *headers.PacketHeader:
		return h.SessionID, true
	case *headers.CompactHeaderV2:
		// В V2 нет SessionID в заголовке, используется StreamID
		// SessionID должен быть в контексте сессии
		return 0, false
	case *headers.PacketHeaderV2:
		return 0, false
	default:
		return 0, false
	}
}

// GetStreamID извлекает StreamID из заголовка (только V2)
func GetStreamID(header interface{}) (uint16, bool) {
	switch h := header.(type) {
	case *headers.CompactHeaderV2:
		return h.StreamID, true
	case *headers.PacketHeaderV2:
		return h.StreamID, true
	default:
		return 0, false
	}
}

// GetSeq извлекает Seq из заголовка (V1 или V2)
func GetSeq(header interface{}) (uint32, bool) {
	switch h := header.(type) {
	case *headers.PacketHeader:
		return h.Seq, true
	case *headers.CompactHeaderV2:
		return h.Seq, true
	case *headers.PacketHeaderV2:
		return h.Seq, true
	default:
		return 0, false
	}
}

// GetFlags извлекает Flags из заголовка (V1 или V2)
func GetFlags(header interface{}) (byte, bool) {
	switch h := header.(type) {
	case *headers.PacketHeader:
		return h.Flags, true
	case *headers.CompactHeaderV2:
		return h.Flags, true
	case *headers.PacketHeaderV2:
		return h.Flags, true
	default:
		return 0, false
	}
}

// GetPayloadLen извлекает PayloadLen из заголовка (V1 или V2)
func GetPayloadLen(header interface{}) (uint16, bool) {
	switch h := header.(type) {
	case *headers.PacketHeader:
		return h.PayloadLen, true
	case *headers.PacketHeaderV2:
		return h.PayloadLen, true
	case *headers.CompactHeaderV2:
		// В CompactHeaderV2 нет PayloadLen - он должен быть в payload
		return 0, false
	default:
		return 0, false
	}
}

// IsControlPacket проверяет, является ли пакет контрольным
func IsControlPacket(header interface{}) bool {
	flags, ok := GetFlags(header)
	if !ok {
		return false
	}

	// Проверяем V1 и V2 флаги
	if (flags&headers.FlagControl) != 0 || (flags&headers.FlagControlV2) != 0 {
		return true
	}

	return false
}

// IsBatchPacket проверяет, является ли пакет batch (только V2)
func IsBatchPacket(header interface{}) bool {
	flags, ok := GetFlags(header)
	if !ok {
		return false
	}

	return (flags & headers.FlagBatchV2) != 0
}

// IsStreamPacket проверяет, использует ли пакет stream multiplexing (только V2)
func IsStreamPacket(header interface{}) bool {
	flags, ok := GetFlags(header)
	if !ok {
		return false
	}

	return (flags & headers.FlagStreamV2) != 0
}
