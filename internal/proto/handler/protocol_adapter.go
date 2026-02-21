package handler

import (
	"errors"

	"whispera/internal/proto/headers"
)

type ProtocolAdapter struct {
	UseV2 bool
}

func NewProtocolAdapter(useV2 bool) *ProtocolAdapter {
	return &ProtocolAdapter{UseV2: useV2}
}

func DetectVersion(firstByte byte) (byte, error) {
	version := (firstByte >> 5) & 0x07
	if version == headers.Version2 {
		return headers.Version2, nil
	}

	if firstByte == headers.Version {
		return headers.Version, nil
	}

	return 0, errors.New("unknown protocol version")
}

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
		if len(data) < headers.CompactHeaderLenV2 {
			return nil, 0, errors.New("short V2 header")
		}

		var hdr headers.CompactHeaderV2
		if err := hdr.UnmarshalBinary(data[:headers.CompactHeaderLenV2]); err != nil {
			return nil, 0, err
		}

		if len(data) > headers.CompactHeaderLenV2 {
			var hdrV2 headers.PacketHeaderV2
			hdrV2.CompactHeaderV2 = hdr
			offset, err := hdrV2.UnmarshalBinaryV2(data)
			if err != nil {
				return &hdr, headers.CompactHeaderLenV2, nil
			}
			return &hdrV2, offset, nil
		}

		return &hdr, headers.CompactHeaderLenV2, nil

	case headers.Version:
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

func GetSessionID(header interface{}) (uint32, bool) {
	switch h := header.(type) {
	case *headers.PacketHeader:
		return h.SessionID, true
	case *headers.CompactHeaderV2:
		return 0, false
	case *headers.PacketHeaderV2:
		return 0, false
	default:
		return 0, false
	}
}

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

func GetPayloadLen(header interface{}) (uint16, bool) {
	switch h := header.(type) {
	case *headers.PacketHeader:
		return h.PayloadLen, true
	case *headers.PacketHeaderV2:
		return h.PayloadLen, true
	case *headers.CompactHeaderV2:
		return 0, false
	default:
		return 0, false
	}
}

func IsControlPacket(header interface{}) bool {
	flags, ok := GetFlags(header)
	if !ok {
		return false
	}

	if (flags&headers.FlagControl) != 0 || (flags&headers.FlagControlV2) != 0 {
		return true
	}

	return false
}

func IsBatchPacket(header interface{}) bool {
	flags, ok := GetFlags(header)
	if !ok {
		return false
	}

	return (flags & headers.FlagBatchV2) != 0
}

func IsStreamPacket(header interface{}) bool {
	flags, ok := GetFlags(header)
	if !ok {
		return false
	}

	return (flags & headers.FlagStreamV2) != 0
}
