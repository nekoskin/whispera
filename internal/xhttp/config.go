package xhttp

import (
	"encoding/json"
)

// XHTTPConfig represents a minimal, compatible configuration structure
// inspired by Xray's xhttp configuration. This focuses on the most
// relevant fields for server-side behavior and compatibility toggles.
type XHTTPConfig struct {
	ServerNames     []string `json:"serverNames" yaml:"serverNames"`
	MaxPostSize     int64    `json:"maxPostSize,omitempty" yaml:"maxPostSize,omitempty"`
	MaxBufferedSize int64    `json:"maxBufferedSize,omitempty" yaml:"maxBufferedSize,omitempty"`
	PaddingBytes    int      `json:"paddingBytes,omitempty" yaml:"paddingBytes,omitempty"`
	ObfuscationMode string   `json:"obfuscationMode,omitempty" yaml:"obfuscationMode,omitempty"` // "marionette" | "xray_compat"
}

// LoadXHTTPConfigFromJSON loads XHTTP config from JSON bytes.
// Note: YAML support is intentionally left out to avoid adding a new
// dependency; the struct contains YAML tags for future use.
func LoadXHTTPConfigFromJSON(data []byte) (*XHTTPConfig, error) {
	var cfg XHTTPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ApplyToServerConfig applies values from XHTTPConfig to ServerConfig.
// It does not overwrite cryptographic keys or obfuscation manager.
func (c *XHTTPConfig) ApplyToServerConfig(s *ServerConfig) {
	if c == nil || s == nil {
		return
	}
	if len(c.ServerNames) > 0 {
		s.ServerNames = c.ServerNames
	}

	if c.ObfuscationMode != "" {
		_ = s.SetObfuscationMode(c.ObfuscationMode)
	}
}
