package xhttp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"

	"whispera/internal/obfuscation"
	"whispera/internal/obfuscation/core/evasion"
)

// ServerConfig represents XHTTP server configuration
// XHTTP is an obfuscation layer, NOT a transport protocol
// It uses two-layer obfuscation:
// 1. HTTP/2 frame obfuscation (primary - makes traffic look like HTTP/2)
// 2. Marionette obfuscation (mandatory additional layer - browser fingerprinting)
// According to Xray-core specification, XHTTP does NOT create TCP/TLS connections
type ServerConfig struct {
	PrivateKey  ed25519.PrivateKey
	ShortIDs    [][]byte
	ServerNames []string

	// Obfuscation/compat mode
	ObfuscationMode string // "marionette" (default) or "xray_compat"

	// Header codec used for header compression (HPACK or QPACK)
	HeaderCodec HeaderCodec

	// Marionette integration (MANDATORY for XHTTP)
	Marionette         *evasion.Marionette
	ObfuscationManager *obfuscation.IntegrationManager // Required - must not be nil
}

// getMarionetteFromManager extracts Marionette core from IntegrationManager
func getMarionetteFromManager(obfuscationManager *obfuscation.IntegrationManager) *evasion.Marionette {
	if obfuscationManager == nil {
		return nil
	}
	adapter := obfuscationManager.GetMarionetteAdapter()
	if adapter == nil {
		return nil
	}
	return adapter.GetCore()
}

// NewServerConfig creates a new XHTTP server config
// obfuscationManager is MANDATORY - XHTTP requires Marionette obfuscation
func NewServerConfig(serverNames []string, obfuscationManager *obfuscation.IntegrationManager) (*ServerConfig, error) {
	// Validate that Marionette is provided (mandatory)
	if obfuscationManager == nil {
		return nil, ErrMarionetteRequired
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	shortID := make([]byte, 8)
	if _, err := rand.Read(shortID); err != nil {
		return nil, err
	}

	return &ServerConfig{
		PrivateKey:         priv,
		ShortIDs:           [][]byte{shortID},
		ServerNames:        serverNames,
		ObfuscationMode:    "marionette",
		HeaderCodec:        nil,
		Marionette:         getMarionetteFromManager(obfuscationManager),
		ObfuscationManager: obfuscationManager,
	}, nil
}

// NewServerConfigWithKeys creates XHTTP server config with provided keys
// obfuscationManager is MANDATORY - XHTTP requires Marionette obfuscation
func NewServerConfigWithKeys(
	serverNames []string,
	privateKey ed25519.PrivateKey,
	shortIDs [][]byte,
	obfuscationManager *obfuscation.IntegrationManager,
) (*ServerConfig, error) {
	// Validate that Marionette is provided (mandatory)
	if obfuscationManager == nil {
		return nil, ErrMarionetteRequired
	}

	return &ServerConfig{
		PrivateKey:         privateKey,
		ShortIDs:           shortIDs,
		ServerNames:        serverNames,
		ObfuscationMode:    "marionette",
		HeaderCodec:        nil,
		Marionette:         getMarionetteFromManager(obfuscationManager),
		ObfuscationManager: obfuscationManager,
	}, nil
}

// SetObfuscationMode sets obfuscation compatibility mode and selects header codec
func (s *ServerConfig) SetObfuscationMode(mode string) error {
	if s == nil {
		return nil
	}
	switch mode {
	case "marionette":
		s.ObfuscationMode = "marionette"
		// default HPACK-based header codec
		s.HeaderCodec = NewHTTP2HeaderEncoder()
		return nil
	case "xray_compat":
		s.ObfuscationMode = "xray_compat"
		// Use QPACK adapter (skeleton for now)
		s.HeaderCodec = NewQPACKAdapter()
		return nil
	default:
		return ErrUnknownCodec
	}
}

// HandleConn handles incoming connection with XHTTP obfuscation layer
// XHTTP does NOT create connections - it wraps existing connections with obfuscation
// According to Xray-core specification, XHTTP is an obfuscation layer, not a transport
// XHTTP uses two-layer obfuscation: HTTP/2 frames (primary) + Marionette (mandatory)
func (s *ServerConfig) HandleConn(ctx context.Context, conn net.Conn) (net.Conn, error) {
	// Validate that Marionette is provided (mandatory)
	if s.ObfuscationManager == nil {
		return nil, ErrMarionetteRequired
	}

	// XHTTP wraps the existing connection with two-layer obfuscation:
	// 1. HTTP/2 frame obfuscation (primary - makes traffic look like HTTP/2)
	// 2. Marionette obfuscation (mandatory additional layer)
	return &ObfuscatedConn{
		Conn:               conn,
		ObfuscationManager: s.ObfuscationManager,
		Direction:          "inbound",
		http2Obf:           NewHTTP2Obfuscator(),
	}, nil
}

// GetPublicKey returns the public key
func (s *ServerConfig) GetPublicKey() []byte {
	return s.PrivateKey.Public().(ed25519.PublicKey)
}

// GetShortIDs returns short IDs
func (s *ServerConfig) GetShortIDs() [][]byte {
	return s.ShortIDs
}

// ObfuscatedConn wraps net.Conn with XHTTP obfuscation (HTTP/2 + Marionette)
// XHTTP uses two-layer obfuscation:
// 1. HTTP/2 frame obfuscation (primary layer - makes traffic look like HTTP/2)
// 2. Marionette obfuscation (mandatory additional layer - browser fingerprinting)
type ObfuscatedConn struct {
	net.Conn
	ObfuscationManager *obfuscation.IntegrationManager
	Direction          string
	http2Obf           *HTTP2Obfuscator
	readBuffer         []byte
	writeBuffer        []byte
}

// Read reads data and applies de-obfuscation (reverse order of Write)
// Order: TCP/TLS -> Marionette deobfuscation -> HTTP/2 frame deobfuscation -> data
func (oc *ObfuscatedConn) Read(b []byte) (n int, err error) {
	// If we have buffered decoded data, return from it first
	if len(oc.readBuffer) > 0 {
		n = copy(b, oc.readBuffer)
		oc.readBuffer = oc.readBuffer[n:]
		if n == len(b) {
			return n, nil
		}
		// continue to fill remaining
	}

	if oc.ObfuscationManager == nil {
		return 0, ErrMarionetteRequired
	}

	// Read loop: consume full HTTP/2 frames, skip non-DATA frames, return DATA payload
	for {
		// Read 9-byte HTTP/2 frame header
		header := make([]byte, 9)
		if _, err := io.ReadFull(oc.Conn, header); err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}

		length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		// Read payload
		payload := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(oc.Conn, payload); err != nil {
				if n > 0 {
					return n, nil
				}
				return 0, err
			}
		}

		// Reconstruct full frame bytes
		frame := append(header, payload...)

		// Apply Marionette de-obfuscation (frame-level)
		processed, _, err := oc.ObfuscationManager.ProcessTrafficWithML(frame, oc.Direction, "xhttp")
		if err != nil {
			// If deobfuscation fails, skip this frame and continue
			continue
		}

		// Ensure we have HTTP2 obfuscator
		if oc.http2Obf == nil {
			oc.http2Obf = NewHTTP2Obfuscator()
		}

		// Try to decode as DATA frame
		decoded, err := oc.http2Obf.DecodeFrame(processed)
		if err != nil {
			// Not a DATA frame or invalid - skip and continue to next frame
			continue
		}

		// Copy decoded payload into user buffer
		remaining := len(b) - n
		if remaining > 0 {
			copied := copy(b[n:], decoded)
			n += copied
			if copied < len(decoded) {
				oc.readBuffer = decoded[copied:]
			}
			return n, nil
		}

		// If we couldn't copy anything, stash decoded into buffer
		oc.readBuffer = append(oc.readBuffer, decoded...)
		// Try again in next iteration
		if len(oc.readBuffer) > 0 {
			copied := copy(b, oc.readBuffer)
			oc.readBuffer = oc.readBuffer[copied:]
			return copied, nil
		}
	}
}

// Write writes data and applies obfuscation
// Order: data -> HTTP/2 frame obfuscation -> Marionette obfuscation -> TCP/TLS
func (oc *ObfuscatedConn) Write(b []byte) (n int, err error) {
	// Layer 1: HTTP/2 frame obfuscation (primary XHTTP layer)
	if oc.http2Obf == nil {
		oc.http2Obf = NewHTTP2Obfuscator()
	}
	framed := oc.http2Obf.EncodeFrame(b)

	// Layer 2: Marionette obfuscation (mandatory additional layer)
	if oc.ObfuscationManager == nil {
		return 0, ErrMarionetteRequired
	}
	processed, _, err := oc.ObfuscationManager.ProcessTrafficWithML(framed, "outbound", "xhttp")
	if err != nil {
		return 0, err
	}

	// Write to connection
	_, err = oc.Conn.Write(processed)
	if err != nil {
		return 0, err
	}

	// Return original data length (not obfuscated length)
	return len(b), nil
}

// ErrMarionetteRequired indicates that Marionette is required but not provided
var ErrMarionetteRequired = &ObfuscationError{msg: "Marionette obfuscation is required for XHTTP"}

type ObfuscationError struct {
	msg string
}

func (e *ObfuscationError) Error() string {
	return e.msg
}
