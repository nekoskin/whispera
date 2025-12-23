package vless

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	Version = 0
)

type RequestCommand byte

const (
	CommandTCP RequestCommand = 1
	CommandUDP RequestCommand = 2
	CommandMux RequestCommand = 3
	CommandRvs RequestCommand = 4
)

type AddrType byte

const (
	AddrTypeIPv4   AddrType = 1
	AddrTypeDomain AddrType = 3
	AddrTypeIPv6   AddrType = 4
)

type RequestHeader struct {
	Version  byte
	UUID     [16]byte
	Addons   byte
	Command  RequestCommand
	Port     uint16
	AddrType AddrType
	Address  []byte
}

func ReadRequestHeader(conn io.Reader) (*RequestHeader, error) {
	var hdr RequestHeader

	// Read version byte first (VLESS spec requirement)
	var version [1]byte
	if _, err := io.ReadFull(conn, version[:]); err != nil {
		return nil, err
	}
	hdr.Version = version[0]

	// Validate version
	if hdr.Version != Version {
		return nil, errors.New("unsupported VLESS version")
	}

	if _, err := io.ReadFull(conn, hdr.UUID[:]); err != nil {
		return nil, err
	}

	var addonsLen [1]byte
	if _, err := io.ReadFull(conn, addonsLen[:]); err != nil {
		return nil, err
	}
	hdr.Addons = addonsLen[0]

	if hdr.Addons > 0 {
		addons := make([]byte, hdr.Addons)
		if _, err := io.ReadFull(conn, addons); err != nil {
			return nil, err
		}
	}

	var cmd [1]byte
	if _, err := io.ReadFull(conn, cmd[:]); err != nil {
		return nil, err
	}
	hdr.Command = RequestCommand(cmd[0])

	// Only TCP and UDP commands have address/port
	// Mux (0x03) and Rvs (0x04) commands don't have address/port
	if hdr.Command == CommandTCP || hdr.Command == CommandUDP {
		var port [2]byte
		if _, err := io.ReadFull(conn, port[:]); err != nil {
			return nil, err
		}
		hdr.Port = binary.BigEndian.Uint16(port[:])

		var addrType [1]byte
		if _, err := io.ReadFull(conn, addrType[:]); err != nil {
			return nil, err
		}
		hdr.AddrType = AddrType(addrType[0])

		switch hdr.AddrType {
		case AddrTypeIPv4:
			hdr.Address = make([]byte, 4)
			if _, err := io.ReadFull(conn, hdr.Address); err != nil {
				return nil, err
			}
		case AddrTypeIPv6:
			hdr.Address = make([]byte, 16)
			if _, err := io.ReadFull(conn, hdr.Address); err != nil {
				return nil, err
			}
		case AddrTypeDomain:
			var domainLen [1]byte
			if _, err := io.ReadFull(conn, domainLen[:]); err != nil {
				return nil, err
			}
			hdr.Address = make([]byte, domainLen[0])
			if _, err := io.ReadFull(conn, hdr.Address); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("invalid address type")
		}
	}

	return &hdr, nil
}

func WriteRequestHeader(conn io.Writer, hdr *RequestHeader) error {
	// Write version byte first (VLESS spec requirement)
	if _, err := conn.Write([]byte{hdr.Version}); err != nil {
		return err
	}

	if _, err := conn.Write(hdr.UUID[:]); err != nil {
		return err
	}

	if _, err := conn.Write([]byte{hdr.Addons}); err != nil {
		return err
	}

	if hdr.Addons > 0 {
		addons := make([]byte, hdr.Addons)
		if _, err := conn.Write(addons); err != nil {
			return err
		}
	}

	if _, err := conn.Write([]byte{byte(hdr.Command)}); err != nil {
		return err
	}

	// Only TCP and UDP commands have address/port
	// Mux (0x03) and Rvs (0x04) commands don't have address/port
	if hdr.Command == CommandTCP || hdr.Command == CommandUDP {
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, hdr.Port)
		if _, err := conn.Write(port); err != nil {
			return err
		}

		if _, err := conn.Write([]byte{byte(hdr.AddrType)}); err != nil {
			return err
		}

		if hdr.AddrType == AddrTypeDomain {
			if _, err := conn.Write([]byte{byte(len(hdr.Address))}); err != nil {
				return err
			}
		}

		if _, err := conn.Write(hdr.Address); err != nil {
			return err
		}
	}

	return nil
}

