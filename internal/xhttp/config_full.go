package xhttp

import (
	"crypto/ed25519"
	"time"
)

// Config represents complete XHTTP configuration
// Combines transport, obfuscation, and session management settings
type Config struct {
	// Transport layer
	Transport TransportConfig

	// Obfuscation layer
	Obfuscation ObfuscationConfig

	// Session management
	Session SessionConfig

	// Packet-up specific settings
	PacketUp PacketUpConfig

	// Stream-up specific settings
	StreamUp StreamUpConfig

	// Stream-one specific settings
	StreamOne StreamOneConfig

	// General settings
	Mode         string // "packet-up", "stream-up", "stream-one"
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// TransportConfig represents transport layer settings
type TransportConfig struct {
	// TCP/TLS settings
	ListenAddr  string
	TLSCertPath string
	TLSKeyPath  string

	// HTTP/2 settings
	HTTP2Enabled    bool
	HTTP2MaxStreams uint32

	// QUIC/HTTP3 settings
	QUIC3Enabled bool
	QUIC3Port    uint16
}

// ObfuscationConfig represents obfuscation settings
type ObfuscationConfig struct {
	// Marionette (mandatory for XHTTP)
	MarionetteEnabled bool
	MarionetteProfile string // "chrome", "firefox", etc.

	// HTTP/2 frame obfuscation
	HTTP2FrameObf     bool
	HTTP2PaddingBytes int // xPaddingBytes

	// Extra metadata
	ExtraEnabled bool
	ExtraJSON    string // Extra metadata as JSON

	// Private key and ShortIDs
	PrivateKey  ed25519.PrivateKey
	ShortIDs    [][]byte
	ServerNames []string
}

// SessionConfig represents session management settings
type SessionConfig struct {
	// Session lifecycle
	MaxSessions     int
	SessionTimeout  time.Duration
	CleanupInterval time.Duration

	// Connection limits
	MaxConnections      int
	MaxConnectionsPerIP int
}

// PacketUpConfig represents packet-up mode settings (HTTP POST/GET)
type PacketUpConfig struct {
	// Flow control - per Xray-core specification
	MaxPostSize     int64 // scMaxEachPostBytes - max size per POST (default: 1MB)
	MaxBufferedSize int64 // scMaxBufferedPosts - max buffered total (default: 100MB)

	// Padding
	PaddingBytes int // xPaddingBytes - random padding per request

	// HTTP settings
	KeepAlive         bool
	KeepAliveInterval time.Duration

	// Optional features
	CompressionEnabled bool
	ContentType        string // Default: "application/octet-stream"
}

// StreamUpConfig represents stream-up mode settings (long-lived connection)
type StreamUpConfig struct {
	// Packet framing
	PacketFraming string // "size-prefix" or "delimiter"
	FrameSize     int    // Max frame size

	// Flow control
	BufferSize int64

	// Timeouts
	ReadDeadline  time.Duration
	WriteDeadline time.Duration
}

// StreamOneConfig represents stream-one mode settings (single request-response)
type StreamOneConfig struct {
	// Request/Response settings
	MaxRequestSize  int64
	MaxResponseSize int64

	// Timeouts
	RequestTimeout time.Duration
}

// DefaultConfig returns default XHTTP configuration
func DefaultConfig() *Config {
	return &Config{
		Transport: TransportConfig{
			ListenAddr:      ":8443",
			HTTP2Enabled:    true,
			HTTP2MaxStreams: 100,
			QUIC3Enabled:    false,
		},
		Obfuscation: ObfuscationConfig{
			MarionetteEnabled: true,
			MarionetteProfile: "chrome",
			HTTP2FrameObf:     true,
			HTTP2PaddingBytes: 16,
			ExtraEnabled:      false,
		},
		Session: SessionConfig{
			MaxSessions:         10000,
			SessionTimeout:      10 * time.Minute,
			CleanupInterval:     30 * time.Second,
			MaxConnections:      100000,
			MaxConnectionsPerIP: 1000,
		},
		PacketUp: PacketUpConfig{
			MaxPostSize:        1000000,   // 1MB (default per Xray-core)
			MaxBufferedSize:    100000000, // 100MB (default per Xray-core)
			PaddingBytes:       16,
			KeepAlive:          true,
			KeepAliveInterval:  30 * time.Second,
			CompressionEnabled: false,
			ContentType:        "application/octet-stream",
		},
		StreamUp: StreamUpConfig{
			PacketFraming: "size-prefix",
			FrameSize:     65536,
			BufferSize:    1000000,
			ReadDeadline:  30 * time.Second,
			WriteDeadline: 30 * time.Second,
		},
		StreamOne: StreamOneConfig{
			MaxRequestSize:  10000000,
			MaxResponseSize: 10000000,
			RequestTimeout:  30 * time.Second,
		},
		Mode:         "packet-up",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// ProductionConfig returns production-ready XHTTP configuration
func ProductionConfig() *Config {
	cfg := DefaultConfig()
	cfg.Session.MaxSessions = 50000
	cfg.Session.SessionTimeout = 30 * time.Minute
	cfg.Session.MaxConnections = 500000
	cfg.Session.MaxConnectionsPerIP = 5000
	cfg.PacketUp.KeepAliveInterval = 60 * time.Second
	cfg.ReadTimeout = 30 * time.Second
	cfg.WriteTimeout = 30 * time.Second
	cfg.IdleTimeout = 120 * time.Second
	return cfg
}

// Validate validates configuration
func (c *Config) Validate() error {
	if c.Mode == "" {
		c.Mode = "packet-up"
	}

	if c.PacketUp.MaxPostSize <= 0 {
		c.PacketUp.MaxPostSize = 1000000
	}

	if c.PacketUp.MaxBufferedSize <= 0 {
		c.PacketUp.MaxBufferedSize = 100000000
	}

	if c.Session.MaxSessions <= 0 {
		c.Session.MaxSessions = 10000
	}

	if c.Session.SessionTimeout <= 0 {
		c.Session.SessionTimeout = 10 * time.Minute
	}

	return nil
}
