// Package crypto provides cryptographic operations module
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

const (
	ModuleName    = "crypto.provider"
	ModuleVersion = "1.0.0"

	// Key sizes
	KeySize   = 32
	NonceSize = 12
	SaltSize  = 32

	// HKDF info strings
	InfoSend = "whispera-send"
	InfoRecv = "whispera-recv"
)

// CipherType represents the type of AEAD cipher
type CipherType string

const (
	CipherChaCha20Poly1305 CipherType = "chacha20-poly1305"
	CipherAESGCM           CipherType = "aes-256-gcm"
)

// Config holds crypto provider configuration
type Config struct {
	DefaultCipher CipherType
	EnableKeyPool bool
	KeyPoolSize   int
}

// DefaultConfig returns default crypto configuration
func DefaultConfig() *Config {
	return &Config{
		DefaultCipher: CipherChaCha20Poly1305,
		EnableKeyPool: true,
		KeyPoolSize:   100,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	switch c.DefaultCipher {
	case CipherChaCha20Poly1305, CipherAESGCM:
		// Valid
	default:
		c.DefaultCipher = CipherChaCha20Poly1305
	}
	if c.KeyPoolSize <= 0 {
		c.KeyPoolSize = 100
	}
	return nil
}

// Provider implements interfaces.CryptoProvider
type Provider struct {
	*base.Module
	config *Config

	// Key pool for pre-generated keys
	keyPool     chan []byte
	keyPoolOnce sync.Once

	// Metrics
	mu              sync.RWMutex
	keysGenerated   uint64
	encryptOps      uint64
	decryptOps      uint64
	decryptFailures uint64
}

// New creates a new crypto provider
func New(cfg *Config) (*Provider, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	p := &Provider{
		Module:  base.NewModule(ModuleName, ModuleVersion, nil),
		config:  cfg,
		keyPool: make(chan []byte, cfg.KeyPoolSize),
	}

	return p, nil
}

// Init initializes the crypto provider
func (p *Provider) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := p.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if cryptoCfg, ok := cfg.(*Config); ok {
		p.config = cryptoCfg
	}

	return nil
}

// Start starts the crypto provider
func (p *Provider) Start() error {
	if err := p.Module.Start(); err != nil {
		return err
	}

	// Start key pool generator
	if p.config.EnableKeyPool {
		p.keyPoolOnce.Do(func() {
			go p.keyPoolGenerator()
		})
	}

	p.SetHealthy(true, "crypto provider running")
	p.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"cipher": string(p.config.DefaultCipher),
	})

	return nil
}

// Stop stops the crypto provider
func (p *Provider) Stop() error {
	p.PublishEvent(events.EventTypeModuleStopped, nil)
	return p.Module.Stop()
}

// keyPoolGenerator generates keys in background
func (p *Provider) keyPoolGenerator() {
	for p.IsRunning() {
		key := make([]byte, KeySize)
		if _, err := rand.Read(key); err != nil {
			continue
		}

		select {
		case p.keyPool <- key:
			p.mu.Lock()
			p.keysGenerated++
			p.mu.Unlock()
		default:
			// Pool full, discard key
		}
	}
}

// NewAEAD creates a new AEAD cipher
func (p *Provider) NewAEAD(key []byte) (interfaces.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", KeySize, len(key))
	}

	var aead cipher.AEAD
	var err error

	switch p.config.DefaultCipher {
	case CipherChaCha20Poly1305:
		aead, err = chacha20poly1305.New(key)
	case CipherAESGCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCM: %w", err)
		}
	default:
		aead, err = chacha20poly1305.New(key)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	return &aeadWrapper{
		aead:     aead,
		provider: p,
	}, nil
}

// DeriveKeys derives send and receive keys from a seed
func (p *Provider) DeriveKeys(seed []byte, isServer bool) (sendKey, recvKey []byte, err error) {
	if len(seed) < SaltSize {
		return nil, nil, fmt.Errorf("seed too short: expected at least %d bytes", SaltSize)
	}

	// Use HKDF to derive keys
	hash := sha256.New

	// Derive send key
	sendReader := hkdf.New(hash, seed, nil, []byte(InfoSend))
	sendKey = make([]byte, KeySize)
	if _, err := sendReader.Read(sendKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive send key: %w", err)
	}

	// Derive recv key
	recvReader := hkdf.New(hash, seed, nil, []byte(InfoRecv))
	recvKey = make([]byte, KeySize)
	if _, err := recvReader.Read(recvKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive recv key: %w", err)
	}

	// Swap keys for client/server
	if isServer {
		sendKey, recvKey = recvKey, sendKey
	}

	return sendKey, recvKey, nil
}

// GenerateSessionID generates a random session ID
func (p *Provider) GenerateSessionID() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("failed to generate session ID: %w", err)
	}

	id := binary.BigEndian.Uint32(buf[:])
	if id == 0 {
		id = 1 // Avoid zero session ID
	}

	return id, nil
}

// GenerateKey generates a random key
func (p *Provider) GenerateKey() ([]byte, error) {
	// Try to get from pool first
	if p.config.EnableKeyPool {
		select {
		case key := <-p.keyPool:
			return key, nil
		default:
			// Pool empty, generate new key
		}
	}

	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	p.mu.Lock()
	p.keysGenerated++
	p.mu.Unlock()

	return key, nil
}

// GenerateSeed generates a random seed for key derivation
func (p *Provider) GenerateSeed() ([]byte, error) {
	seed := make([]byte, SaltSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}
	return seed, nil
}

// DeriveKey derives a key from input material into output
func (p *Provider) DeriveKey(input, output []byte, length int) {
	hash := sha256.New
	reader := hkdf.New(hash, input, nil, []byte("whispera-derive"))
	reader.Read(output[:length])
}

// HealthCheck returns health status
func (p *Provider) HealthCheck() interfaces.HealthStatus {
	status := p.Module.HealthCheck()

	p.mu.RLock()
	status.Details["keys_generated"] = p.keysGenerated
	status.Details["encrypt_ops"] = p.encryptOps
	status.Details["decrypt_ops"] = p.decryptOps
	status.Details["decrypt_failures"] = p.decryptFailures
	status.Details["key_pool_size"] = len(p.keyPool)
	p.mu.RUnlock()

	status.Details["cipher"] = string(p.config.DefaultCipher)

	return status
}

// aeadWrapper wraps cipher.AEAD to implement interfaces.AEAD
type aeadWrapper struct {
	aead     cipher.AEAD
	provider *Provider
}

// Encrypt encrypts plaintext with the given sequence and AAD
func (a *aeadWrapper) Encrypt(seq uint32, aad, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, a.aead.NonceSize())
	binary.BigEndian.PutUint32(nonce[a.aead.NonceSize()-4:], seq)

	ciphertext := a.aead.Seal(nil, nonce, plaintext, aad)

	a.provider.mu.Lock()
	a.provider.encryptOps++
	a.provider.mu.Unlock()

	return ciphertext, nil
}

// Decrypt decrypts ciphertext with the given sequence and AAD
func (a *aeadWrapper) Decrypt(seq uint32, aad, ciphertext []byte) ([]byte, error) {
	nonce := make([]byte, a.aead.NonceSize())
	binary.BigEndian.PutUint32(nonce[a.aead.NonceSize()-4:], seq)

	plaintext, err := a.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		a.provider.mu.Lock()
		a.provider.decryptFailures++
		a.provider.mu.Unlock()
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	a.provider.mu.Lock()
	a.provider.decryptOps++
	a.provider.mu.Unlock()

	return plaintext, nil
}

// NonceSize returns the nonce size
func (a *aeadWrapper) NonceSize() int {
	return a.aead.NonceSize()
}

// Overhead returns the maximum overhead of sealing
func (a *aeadWrapper) Overhead() int {
	return a.aead.Overhead()
}

// DirectionalKeys holds send and receive keys
type DirectionalKeys struct {
	SendKey []byte
	RecvKey []byte
}

// AEADState holds AEAD state for a session
type AEADState struct {
	SendAEAD interfaces.AEAD
	RecvAEAD interfaces.AEAD
}

// NewAEADState creates a new AEAD state from directional keys
func (p *Provider) NewAEADState(sendKey, recvKey []byte) (*AEADState, error) {
	sendAEAD, err := p.NewAEAD(sendKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create send AEAD: %w", err)
	}

	recvAEAD, err := p.NewAEAD(recvKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create recv AEAD: %w", err)
	}

	return &AEADState{
		SendAEAD: sendAEAD,
		RecvAEAD: recvAEAD,
	}, nil
}

// Encrypt encrypts using the send AEAD
func (s *AEADState) Encrypt(seq uint32, aad, plaintext []byte) ([]byte, error) {
	return s.SendAEAD.Encrypt(seq, aad, plaintext)
}

// Decrypt decrypts using the recv AEAD
func (s *AEADState) Decrypt(seq uint32, aad, ciphertext []byte) ([]byte, error) {
	return s.RecvAEAD.Decrypt(seq, aad, ciphertext)
}

// Factory creates crypto provider modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
