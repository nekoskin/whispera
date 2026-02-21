package containers

import (
	"bytes"
	"errors"
	"fmt"
)

const (
	PacketSize  = 188
	SyncByte    = 0x47
	HeaderSize  = 4
	PayloadSize = PacketSize - HeaderSize
)

type Packer struct {
	PID               uint16
	ContinuityCounter uint8
}

func NewPacker(pid uint16) *Packer {
	return &Packer{
		PID: pid,
	}
}

func (p *Packer) WrapData(data []byte) []byte {
	numPackets := (len(data) + PayloadSize - 1) / PayloadSize

	tsBuffer := make([]byte, numPackets*PacketSize)

	for i := 0; i < numPackets; i++ {
		start := i * PayloadSize
		end := start + PayloadSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[start:end]

		tsBuffer[i*PacketSize] = SyncByte

		pusi := uint8(0)
		if i == 0 {
			pusi = 0x40
		}
		pidHigh := uint8((p.PID >> 8) & 0x1F)
		tsBuffer[i*PacketSize+1] = pusi | pidHigh

		tsBuffer[i*PacketSize+2] = uint8(p.PID & 0xFF)


		cc := p.ContinuityCounter & 0x0F
		p.ContinuityCounter++

		tsBuffer[i*PacketSize+3] = 0x10 | cc

		copy(tsBuffer[i*PacketSize+4:], chunk)

		if len(chunk) < PayloadSize {
			paddingStart := i*PacketSize + 4 + len(chunk)
			paddingEnd := (i + 1) * PacketSize
			for k := paddingStart; k < paddingEnd; k++ {
				tsBuffer[k] = 0xFF
			}
		}
	}

	return tsBuffer
}

type Parser struct {
	PID uint16
}

func NewParser(pid uint16) *Parser {
	return &Parser{
		PID: pid,
	}
}

func (p *Parser) UnwrapData(tsData []byte) ([]byte, error) {
	if len(tsData)%PacketSize != 0 {
		return nil, fmt.Errorf("invalid data length: %d is not a multiple of %d", len(tsData), PacketSize)
	}

	numPackets := len(tsData) / PacketSize
	var payloadBuf bytes.Buffer
	payloadBuf.Grow(numPackets * PayloadSize)

	for i := 0; i < numPackets; i++ {
		packetStart := i * PacketSize
		packet := tsData[packetStart : packetStart+PacketSize]

		if packet[0] != SyncByte {
			return nil, fmt.Errorf("invalid sync byte at offset %d: 0x%X", packetStart, packet[0])
		}

		pidHigh := packet[1] & 0x1F
		pidLow := packet[2]
		pid := (uint16(pidHigh) << 8) | uint16(pidLow)

		if pid != p.PID {
			continue
		}

		afc := (packet[3] >> 4) & 0x03
		hasPayload := (afc & 0x01) != 0
		hasAdaptation := (afc & 0x02) != 0

		if !hasPayload {
			continue
		}

		payloadOffset := 4
		if hasAdaptation {
			adaptLen := int(packet[4])
			if adaptLen > 183 {
				return nil, errors.New("invalid adaptation field length")
			}
			payloadOffset += 1 + adaptLen
		}

		if payloadOffset >= PacketSize {
			continue
		}

		rawPayload := packet[payloadOffset:]
		payloadBuf.Write(rawPayload)
	}

	return payloadBuf.Bytes(), nil
}
