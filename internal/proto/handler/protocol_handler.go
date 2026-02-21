package handler

import (
	"errors"

	"whispera/internal/proto/headers"
)

type ProtocolHandler struct {
	UseV2 bool
}

type PacketInfo struct {
	Version    byte
	IsV2       bool
	Header     *headers.PacketHeader
	HeaderV2   *headers.CompactHeaderV2
	Flags      byte
	StreamID   uint16
	Seq        uint32
	PayloadLen uint16
}

func (ph *ProtocolHandler) ParsePacket(data []byte) (*PacketInfo, error) {
	if len(data) < 1 {
		return nil, errors.New("empty packet")
	}

	version := (data[0] >> 5) & 0x07

	if version == headers.Version2 {
		if len(data) < headers.CompactHeaderLenV2 {
			return nil, errors.New("short V2 header")
		}

		var h2 headers.CompactHeaderV2
		if err := h2.UnmarshalBinary(data[:headers.CompactHeaderLenV2]); err != nil {
			return nil, err
		}

		offset := headers.CompactHeaderLenV2
		var payloadLen uint16
		if len(data) > offset {
			if data[offset] == 0xFF && len(data) > offset+2 {
				payloadLen = uint16(data[offset+1])<<8 | uint16(data[offset+2])
			} else {
				payloadLen = uint16(data[offset])
			}
		}

		return &PacketInfo{
			Version:    headers.Version2,
			IsV2:       true,
			HeaderV2:   &h2,
			Flags:      h2.Flags,
			StreamID:   h2.StreamID,
			Seq:        h2.Seq,
			PayloadLen: payloadLen,
		}, nil
	}

	if len(data) < headers.HeaderLen {
		return nil, errors.New("short V1 header")
	}

	var h headers.PacketHeader
	if err := h.UnmarshalBinary(data[:headers.HeaderLen]); err != nil {
		return nil, err
	}

	return &PacketInfo{
		Version:    headers.Version,
		IsV2:       false,
		Header:     &h,
		Flags:      h.Flags,
		StreamID:   0,
		Seq:        h.Seq,
		PayloadLen: h.PayloadLen,
	}, nil
}

func (ph *ProtocolHandler) CreatePacket(seq uint32, streamID uint16, payloadLen uint16, flags byte, useV2 bool) []byte {
	if useV2 && ph.UseV2 {
		h2 := headers.CompactHeaderV2{
			Flags:    flags,
			StreamID: streamID,
			Seq:      seq,
		}
		header := h2.MarshalBinary()

		if payloadLen > 0 {
			if payloadLen < uint16(headers.SmallPayloadThreshold) {
				header = append(header, byte(payloadLen))
			} else {
				header = append(header, 0xFF, byte(payloadLen>>8), byte(payloadLen))
			}
		}

		return header
	}

	h := headers.PacketHeader{
		Version:    headers.Version,
		Flags:      flags,
		SessionID:  0,
		Seq:        seq,
		PayloadLen: payloadLen,
	}
	return h.MarshalBinary()
}

func (ph *ProtocolHandler) GetHeaderSize(version byte, payloadLen uint16) int {
	if version == headers.Version2 {
		size := headers.CompactHeaderLenV2
		if payloadLen > 0 {
			if payloadLen < uint16(headers.SmallPayloadThreshold) {
				size += 1
			} else {
				size += 3
			}
		}
		return size
	}
	return headers.HeaderLen
}

func IsV2Packet(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	version := (data[0] >> 5) & 0x07
	return version == headers.Version2
}

func IsV1Packet(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	return data[0] == headers.Version
}
