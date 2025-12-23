package proto

import "errors"

// PacketBuilder создает пакеты V1 или V2 в зависимости от настроек
type PacketBuilder struct {
	UseV2     bool
	SessionID uint32 // Для V1
	StreamID  uint16 // Для V2 (0 = default stream)
}

// BuildHeader создает заголовок пакета (V1 или V2)
func (pb *PacketBuilder) BuildHeader(seq uint32, payloadLen uint16, flags byte) []byte {
	if pb.UseV2 {
		return pb.buildHeaderV2(seq, payloadLen, flags)
	}
	return pb.buildHeaderV1(seq, payloadLen, flags)
}

// buildHeaderV1 создает V1 заголовок
func (pb *PacketBuilder) buildHeaderV1(seq uint32, payloadLen uint16, flags byte) []byte {
	h := PacketHeader{
		Version:    Version,
		Flags:      flags,
		SessionID:  pb.SessionID,
		Seq:        seq,
		PayloadLen: payloadLen,
	}
	return h.MarshalBinary()
}

// buildHeaderV2 создает V2 заголовок
func (pb *PacketBuilder) buildHeaderV2(seq uint32, payloadLen uint16, flags byte) []byte {
	h2 := CompactHeaderV2{
		Flags:    flags,
		StreamID: pb.StreamID,
		Seq:      seq,
	}
	header := h2.MarshalBinary()

	// Добавляем PayloadLen (variable length encoding)
	if payloadLen < uint16(SmallPayloadThreshold) {
		header = append(header, byte(payloadLen))
	} else {
		header = append(header, 0xFF)
		header = append(header, byte(payloadLen>>8), byte(payloadLen))
	}

	return header
}

// GetHeaderSize возвращает размер заголовка для текущей версии
func (pb *PacketBuilder) GetHeaderSize(payloadLen uint16) int {
	if pb.UseV2 {
		size := CompactHeaderLenV2
		if payloadLen < uint16(SmallPayloadThreshold) {
			size += 1
		} else {
			size += 3
		}
		return size
	}
	return HeaderLen
}

// ParsePacketHeader парсит заголовок и определяет версию
func ParsePacketHeader(data []byte) (version byte, headerSize int, err error) {
	if len(data) < 1 {
		return 0, 0, errors.New("empty packet")
	}

	// Проверяем версию
	versionByte := (data[0] >> 5) & 0x07
	if versionByte == Version2 {
		// V2 протокол
		if len(data) < CompactHeaderLenV2 {
			return 0, 0, errors.New("short V2 header")
		}
		headerSize = CompactHeaderLenV2
		// Проверяем, есть ли PayloadLen
		if len(data) > CompactHeaderLenV2 {
			if data[CompactHeaderLenV2] == 0xFF {
				headerSize += 3
			} else {
				headerSize += 1
			}
		}
		return Version2, headerSize, nil
	}

	// V1 протокол (проверяем первый байт напрямую)
	if data[0] == Version {
		if len(data) < HeaderLen {
			return 0, 0, errors.New("short V1 header")
		}
		return Version, HeaderLen, nil
	}

	return 0, 0, errors.New("unknown version")
}

