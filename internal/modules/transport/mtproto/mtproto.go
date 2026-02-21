package mtproto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/logger"
)

var log = logger.Module("mtproto")

var handshakeBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 128)
	},
}

const (
	ModuleName    = "transport.mtproto"
	ModuleVersion = "1.0.0"

	dcIDOffset = 60
	nonceLen   = 64

	fakeTLSClientHello = 0x16
)

type Config struct {
	Secret string

	ListenAddr string

	DCAddresses map[int]string

	EnableFakeTLS bool

	EnableStats bool
}

func DefaultConfig() *Config {
	return &Config{
		DCAddresses: map[int]string{
			1: "149.154.175.50:443",
			2: "149.154.167.51:443",
			3: "149.154.175.100:443",
			4: "149.154.167.91:443",
			5: "91.108.56.100:443",
		},
		EnableFakeTLS: true,
		EnableStats:   true,
	}
}

func (c *Config) Validate() error {
	if c.Secret == "" {
		return fmt.Errorf("secret is required")
	}
	if len(c.Secret) < 32 {
		return fmt.Errorf("secret must be at least 32 characters")
	}
	return nil
}

type ParsedSecret struct {
	Type   string
	Secret []byte
	Tag    byte
	Domain string
}

func ParseSecret(secretHex string) (*ParsedSecret, error) {
	if len(secretHex) > 2 && (secretHex[:2] == "dd" || secretHex[:2] == "ee") {
		secretHex = secretHex[2:]
	}

	decoded, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex secret: %w", err)
	}

	secret := &ParsedSecret{}

	if len(decoded) == 16 {
		secret.Type = "simple"
		secret.Secret = decoded
	} else if len(decoded) == 17 {
		secret.Type = "secured"
		secret.Tag = decoded[0]
		secret.Secret = decoded[1:]
	} else if len(decoded) > 17 {
		secret.Type = "faketls"
		secret.Tag = decoded[0]
		secret.Secret = decoded[1:17]
		secret.Domain = string(decoded[17:])
	} else {
		return nil, fmt.Errorf("invalid secret length: %d", len(decoded))
	}

	return secret, nil
}

type Transport struct {
	*base.Module
	config *Config

	mu       sync.RWMutex
	listener net.Listener
	secret   *ParsedSecret

	totalConns  uint64
	activeConns int32
	bytesIn     uint64
	bytesOut    uint64
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	secret, err := ParseSecret(cfg.Secret)
	if err != nil {
		return nil, fmt.Errorf("invalid secret: %w", err)
	}

	t := &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		secret: secret,
	}

	return t, nil
}

func (t *Transport) Listen(ctx context.Context) error {
	listener, err := net.Listen("tcp", t.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	t.mu.Lock()
	t.listener = listener
	t.mu.Unlock()

	log.Info("MTProto listening on %s (type: %s)", t.config.ListenAddr, t.secret.Type)

	go t.acceptLoop(ctx)

	return nil
}

func (t *Transport) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := t.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("Accept error: %v", err)
			continue
		}

		atomic.AddUint64(&t.totalConns, 1)
		atomic.AddInt32(&t.activeConns, 1)

		go t.handleConnection(ctx, conn)
	}
}

func (t *Transport) handleConnection(ctx context.Context, clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		atomic.AddInt32(&t.activeConns, -1)
	}()

	clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	header := handshakeBufferPool.Get().([]byte)[:nonceLen]
	defer func() { handshakeBufferPool.Put(header) }()
	if _, err := io.ReadFull(clientConn, header); err != nil {
		log.Debug("Failed to read header: %v", err)
		return
	}

	var session *MTProtoSession
	var err error

	switch t.secret.Type {
	case "faketls":
		session, err = t.handleFakeTLS(clientConn, header)
	default:
		session, err = t.handleObfuscated(clientConn, header)
	}

	if err != nil {
		log.Debug("Handshake failed: %v", err)
		return
	}

	clientConn.SetDeadline(time.Time{})

	dcID := session.DCID
	dcAddr, ok := t.config.DCAddresses[dcID]
	if !ok {
		dcAddr = t.config.DCAddresses[2]
	}

	telegramConn, err := net.DialTimeout("tcp", dcAddr, 10*time.Second)
	if err != nil {
		log.Warn("Failed to connect to Telegram DC%d: %v", dcID, err)
		return
	}
	defer telegramConn.Close()

	if err := session.HandshakeWithServer(telegramConn); err != nil {
		log.Warn("Failed Telegram handshake: %v", err)
		return
	}

	log.Info("Proxying to Telegram DC%d (%s)", dcID, dcAddr)

	t.relay(ctx, session, clientConn, telegramConn)
}

func (t *Transport) handleObfuscated(_ net.Conn, header []byte) (*MTProtoSession, error) {
	session := NewMTProtoSession(t.secret.Secret)

	if err := session.DecryptHeader(header); err != nil {
		return nil, fmt.Errorf("failed to decrypt header: %w", err)
	}

	return session, nil
}

func (t *Transport) handleFakeTLS(conn net.Conn, header []byte) (*MTProtoSession, error) {
	if header[0] != fakeTLSClientHello {
		return nil, fmt.Errorf("invalid FakeTLS header")
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	tlsData := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, tlsData); err != nil {
		return nil, fmt.Errorf("failed to read TLS data: %w", err)
	}

	if len(tlsData) < 34 {
		return nil, fmt.Errorf("invalid ClientHello length")
	}
	random := tlsData[6:38]

	session := NewMTProtoSession(t.secret.Secret)
	if err := session.VerifyFakeTLS(random, t.secret.Domain); err != nil {
		return nil, fmt.Errorf("FakeTLS verification failed: %w", err)
	}

	if err := t.sendFakeServerHello(conn); err != nil {
		return nil, fmt.Errorf("failed to send ServerHello: %w", err)
	}

	return session, nil
}

func (t *Transport) sendFakeServerHello(conn net.Conn) error {
	serverHello := []byte{
		0x16, 0x03, 0x03,
		0x00, 0x3B,
		0x02,
		0x00, 0x00, 0x37,
		0x03, 0x03,
	}

	random := make([]byte, 32)
	rand.Read(random)
	serverHello = append(serverHello, random...)

	serverHello = append(serverHello, 0x00)

	serverHello = append(serverHello, 0x13, 0x01)

	serverHello = append(serverHello, 0x00)

	serverHello = append(serverHello, 0x00, 0x05)
	serverHello = append(serverHello, 0x00, 0x17, 0x00, 0x00, 0x00)

	_, err := conn.Write(serverHello)
	return err
}

func (t *Transport) relay(ctx context.Context, session *MTProtoSession, client, telegram net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := client.Read(buf)
			if err != nil {
				return
			}

			data := session.DecryptFromClient(buf[:n])

			if _, err := telegram.Write(data); err != nil {
				return
			}

			atomic.AddUint64(&t.bytesIn, uint64(n))
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := telegram.Read(buf)
			if err != nil {
				return
			}

			data := session.EncryptToClient(buf[:n])

			if _, err := client.Write(data); err != nil {
				return
			}

			atomic.AddUint64(&t.bytesOut, uint64(n))
		}
	}()

	<-done
}

type MTProtoSession struct {
	secret []byte
	DCID   int

	clientEncrypt cipher.Stream
	clientDecrypt cipher.Stream

	serverEncrypt cipher.Stream
	serverDecrypt cipher.Stream
}

func NewMTProtoSession(secret []byte) *MTProtoSession {
	return &MTProtoSession{
		secret: secret,
		DCID:   2,
	}
}

func (s *MTProtoSession) DecryptHeader(header []byte) error {
	if len(header) < nonceLen {
		return fmt.Errorf("header too short")
	}

	encKeyData := append(header[8:40], s.secret...)
	encKey := sha256.Sum256(encKeyData)
	encIV := header[40:56]

	reversed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		reversed[i] = header[39-i]
	}
	decKeyData := append(reversed, s.secret...)
	decKey := sha256.Sum256(decKeyData)
	decIV := make([]byte, 16)
	for i := 0; i < 16; i++ {
		decIV[i] = header[55-i]
	}

	encBlock, _ := aes.NewCipher(encKey[:])
	decBlock, _ := aes.NewCipher(decKey[:])

	s.clientDecrypt = cipher.NewCTR(encBlock, encIV)
	s.clientEncrypt = cipher.NewCTR(decBlock, decIV)

	decrypted := make([]byte, nonceLen)
	s.clientDecrypt.XORKeyStream(decrypted, header)

	dcID := int(binary.LittleEndian.Uint16(decrypted[dcIDOffset : dcIDOffset+2]))
	if dcID > 0 && dcID <= 5 {
		s.DCID = dcID
	}

	return nil
}

func (s *MTProtoSession) VerifyFakeTLS(random []byte, domain string) error {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(s.secret)
	expected := h.Sum(nil)

	for i := 0; i < 16 && i < len(random) && i < len(expected); i++ {
		if random[i] != expected[i] {
		}
	}

	block, _ := aes.NewCipher(s.secret)
	s.clientDecrypt = cipher.NewCTR(block, random[:16])
	s.clientEncrypt = cipher.NewCTR(block, random[:16])

	return nil
}

func (s *MTProtoSession) HandshakeWithServer(conn net.Conn) error {
	header := make([]byte, nonceLen)
	for {
		rand.Read(header)
		if header[0] != 0xef && header[0] != 0xdd && header[0] != 0xee {
			break
		}
	}

	dcBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(dcBytes, uint16(s.DCID))
	copy(header[dcIDOffset:], dcBytes)

	encKeyData := append(header[8:40], s.secret...)
	encKey := sha256.Sum256(encKeyData)
	encIV := header[40:56]

	reversed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		reversed[i] = header[39-i]
	}
	decKeyData := append(reversed, s.secret...)
	decKey := sha256.Sum256(decKeyData)
	decIV := make([]byte, 16)
	for i := 0; i < 16; i++ {
		decIV[i] = header[55-i]
	}

	encBlock, _ := aes.NewCipher(encKey[:])
	decBlock, _ := aes.NewCipher(decKey[:])

	s.serverEncrypt = cipher.NewCTR(encBlock, encIV)
	s.serverDecrypt = cipher.NewCTR(decBlock, decIV)

	encrypted := make([]byte, nonceLen)
	s.serverEncrypt.XORKeyStream(encrypted, header)

	_, err := conn.Write(encrypted)
	return err
}

func (s *MTProtoSession) DecryptFromClient(data []byte) []byte {
	if s.clientDecrypt == nil {
		return data
	}
	decrypted := make([]byte, len(data))
	s.clientDecrypt.XORKeyStream(decrypted, data)
	return decrypted
}

func (s *MTProtoSession) EncryptToClient(data []byte) []byte {
	if s.clientEncrypt == nil {
		return data
	}
	encrypted := make([]byte, len(data))
	s.clientEncrypt.XORKeyStream(encrypted, data)
	return encrypted
}


func (t *Transport) Init(ctx context.Context) error {
	return nil
}

func (t *Transport) Start(ctx context.Context) error {
	if t.config.ListenAddr != "" {
		return t.Listen(ctx)
	}
	return nil
}

func (t *Transport) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}

func (t *Transport) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_connections":  atomic.LoadUint64(&t.totalConns),
		"active_connections": atomic.LoadInt32(&t.activeConns),
		"bytes_in":           atomic.LoadUint64(&t.bytesIn),
		"bytes_out":          atomic.LoadUint64(&t.bytesOut),
		"secret_type":        t.secret.Type,
	}
}
