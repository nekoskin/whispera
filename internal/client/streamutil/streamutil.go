// Package streamutil provides stream framing utilities
package streamutil

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// ReadFrame reads a length-prefixed frame from the connection
func ReadFrame(conn net.Conn) ([]byte, error) {
	// Read 4-byte length prefix
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lenBuf)
	if length == 0 {
		return []byte{}, nil
	}
	if length > 1<<20 { // 1MB max
		return nil, fmt.Errorf("frame too large: %d", length)
	}

	// Read frame data
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

// WriteFrame writes a length-prefixed frame to the connection
func WriteFrame(conn net.Conn, data []byte) error {
	// Write 4-byte length prefix
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}

	if len(data) > 0 {
		if _, err := conn.Write(data); err != nil {
			return err
		}
	}

	return nil
}

// SafeUint16 safely converts an int to uint16, returning (value, ok)
func SafeUint16(n int) (uint16, bool) {
	if n < 0 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}
