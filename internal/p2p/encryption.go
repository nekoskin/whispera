package p2p

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// P2PEncryption представляет систему шифрования P2P
type P2PEncryption struct { //nolint:revive // Name is part of public API
	mu             sync.RWMutex
	keys           map[string]*EncryptionKey
	sessions       map[string]*EncryptionSession
	keyRotation    time.Duration
	lastRotation   time.Time
	sessionCounter int64
}

// EncryptionKey представляет ключ шифрования
type EncryptionKey struct {
	ID        string    `json:"id"`
	Key       []byte    `json:"key"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	Algorithm string    `json:"algorithm"`
	Strength  int       `json:"strength"`
}

// EncryptionSession представляет сессию шифрования
type EncryptionSession struct {
	ID           string    `json:"id"`
	NodeID       string    `json:"node_id"`
	SendKey      []byte    `json:"send_key"`
	ReceiveKey   []byte    `json:"receive_key"`
	SendNonce    uint64    `json:"send_nonce"`
	ReceiveNonce uint64    `json:"receive_nonce"`
	Created      time.Time `json:"created"`
	LastUsed     time.Time `json:"last_used"`
	Algorithm    string    `json:"algorithm"`
}

// EncryptedMessage представляет зашифрованное сообщение
type EncryptedMessage struct {
	SessionID string `json:"session_id"`
	Nonce     []byte `json:"nonce"`
	Data      []byte `json:"data"`
	MAC       []byte `json:"mac"`
	Timestamp int64  `json:"timestamp"`
	FromNode  string `json:"from"`
}

// NewP2PEncryption создаёт новую систему шифрования
func NewP2PEncryption() *P2PEncryption {
	return &P2PEncryption{
		keys:         make(map[string]*EncryptionKey),
		sessions:     make(map[string]*EncryptionSession),
		keyRotation:  5 * time.Minute,
		lastRotation: time.Now(),
	}
}

// Start запускает систему шифрования
func (pe *P2PEncryption) Start(ctx context.Context) {
	// Starting P2P Encryption system

	// Запускаем ротацию ключей
	go pe.keyRotationLoop(ctx)

	// Запускаем очистку сессий
	go pe.sessionCleanupLoop(ctx)

	// Запускаем мониторинг безопасности
	go pe.securityMonitoringLoop(ctx)
}

// keyRotationLoop выполняет ротацию ключей
func (pe *P2PEncryption) keyRotationLoop(ctx context.Context) {
	ticker := time.NewTicker(pe.keyRotation)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pe.rotateKeys()
		}
	}
}

// sessionCleanupLoop очищает устаревшие сессии
func (pe *P2PEncryption) sessionCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pe.cleanupSessions()
		}
	}
}

// securityMonitoringLoop мониторит безопасность
func (pe *P2PEncryption) securityMonitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pe.monitorSecurity()
		}
	}
}

// CreateSession создаёт новую сессию шифрования
func (pe *P2PEncryption) CreateSession(nodeID string) (*EncryptionSession, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	// Генерируем ключи для сессии
	sendKey := make([]byte, 32)
	receiveKey := make([]byte, 32)

	if _, err := rand.Read(sendKey); err != nil {
		return nil, fmt.Errorf("ошибка генерации send key: %v", err)
	}

	if _, err := rand.Read(receiveKey); err != nil {
		return nil, fmt.Errorf("ошибка генерации receive key: %v", err)
	}

	// Создаём сессию с уникальным ID
	pe.sessionCounter++
	session := &EncryptionSession{
		ID:           fmt.Sprintf("session_%d_%d", time.Now().UnixNano(), pe.sessionCounter),
		NodeID:       nodeID,
		SendKey:      sendKey,
		ReceiveKey:   receiveKey,
		SendNonce:    0,
		ReceiveNonce: 0,
		Created:      time.Now(),
		LastUsed:     time.Now(),
		Algorithm:    "AES-256-GCM",
	}

	pe.sessions[session.ID] = session

	// Encryption session created
	return session, nil
}

// CreateECDHSessionForPeers создаёт сессию, используя общий секрет (например, X25519)
func (pe *P2PEncryption) CreateECDHSessionForPeers(
	myID, peerID string, sharedSecret []byte,
) (*EncryptionSession, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("empty shared secret")
	}
	// Дет. session ID от myID|peerID
	a, b := myID, peerID
	if a > b {
		a, b = b, a
	}
	sid := fmt.Sprintf("ecdh_%x", sha256.Sum256([]byte(a+":"+b)))
	if s, ok := pe.sessions[sid]; ok {
		s.LastUsed = time.Now()
		return s, nil
	}

	// Derive directional keys via HKDF-SHA256
	derive := func(info string) ([]byte, error) {
		r := hkdf.New(sha256.New, sharedSecret, nil, []byte(info))
		key := make([]byte, 32)
		if _, err := io.ReadFull(r, key); err != nil {
			return nil, err
		}
		return key, nil
	}
	// Direction depends on lexical order to ensure opposite mapping at the peer
	var sendKey, recvKey []byte
	var err error
	//nolint:nestif // Complex encryption key derivation
	if myID < peerID {
		sendKey, err = derive("send:" + a + "->" + b)
		if err != nil {
			return nil, err
		}
		recvKey, err = derive("recv:" + a + "<-" + b)
		if err != nil {
			return nil, err
		}
	} else {
		// inverse
		sendKey, err = derive("send:" + b + "->" + a)
		if err != nil {
			return nil, err
		}
		recvKey, err = derive("recv:" + b + "<-" + a)
		if err != nil {
			return nil, err
		}
	}

	pe.sessionCounter++
	s := &EncryptionSession{
		ID:           sid,
		NodeID:       peerID,
		SendKey:      sendKey,
		ReceiveKey:   recvKey,
		SendNonce:    0,
		ReceiveNonce: 0,
		Created:      time.Now(),
		LastUsed:     time.Now(),
		Algorithm:    "AES-256-GCM",
	}
	pe.sessions[s.ID] = s
	return s, nil
}

// EncryptMessage шифрует сообщение
func (pe *P2PEncryption) EncryptMessage(sessionID string, data []byte) (*EncryptedMessage, error) {
	pe.mu.RLock()
	session, exists := pe.sessions[sessionID]
	pe.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("сессия %s не найдена", sessionID)
	}

	// Создаём AES-GCM шифр
	block, err := aes.NewCipher(session.SendKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %v", err)
	}

	// Генерируем nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("ошибка генерации nonce: %v", err)
	}

	// Шифруем данные
	ciphertext := aesGCM.Seal(nil, nonce, data, nil)

	// Создаём зашифрованное сообщение
	encryptedMsg := &EncryptedMessage{
		SessionID: sessionID,
		Nonce:     nonce,
		Data:      ciphertext,
		MAC:       ciphertext[len(ciphertext)-aesGCM.Overhead():],
		Timestamp: time.Now().Unix(),
	}

	// Обновляем nonce и время использования
	pe.mu.Lock()
	session.SendNonce++
	session.LastUsed = time.Now()
	pe.mu.Unlock()

	// Message encrypted

	return encryptedMsg, nil
}

// DecryptMessage расшифровывает сообщение
func (pe *P2PEncryption) DecryptMessage(encryptedMsg *EncryptedMessage) ([]byte, error) {
	pe.mu.RLock()
	session, exists := pe.sessions[encryptedMsg.SessionID]
	pe.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("сессия %s не найдена", encryptedMsg.SessionID)
	}

	// Создаём AES-GCM шифр, используя ключ приёма для расшифровки
	block, err := aes.NewCipher(session.ReceiveKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %v", err)
	}

	// Расшифровываем данные
	plaintext, err := aesGCM.Open(nil, encryptedMsg.Nonce, encryptedMsg.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки: %v", err)
	}

	// Обновляем nonce и время использования
	pe.mu.Lock()
	session.ReceiveNonce++
	session.LastUsed = time.Now()
	pe.mu.Unlock()

	// Message decrypted

	return plaintext, nil
}

// rotateKeys выполняет ротацию ключей
func (pe *P2PEncryption) rotateKeys() {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	// Key rotation in progress

	// Генерируем новые ключи
	newKey := &EncryptionKey{
		ID:        fmt.Sprintf("key_%d", time.Now().UnixNano()),
		Key:       make([]byte, 32),
		Created:   time.Now(),
		Expires:   time.Now().Add(pe.keyRotation),
		Algorithm: "AES-256",
		Strength:  256,
	}

	if _, err := rand.Read(newKey.Key); err != nil {
		// New key generation error
		return
	}

	pe.keys[newKey.ID] = newKey
	pe.lastRotation = time.Now()

	// New encryption key created
}

// cleanupSessions очищает устаревшие сессии
func (pe *P2PEncryption) cleanupSessions() {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	// Cleaning up expired sessions

	now := time.Now()
	cleaned := 0

	for sessionID, session := range pe.sessions {
		if now.Sub(session.LastUsed) > 30*time.Minute {
			delete(pe.sessions, sessionID)
			cleaned++
		}
	}

	_ = cleaned // Suppress unused warning - cleanup performed
}

// monitorSecurity мониторит безопасность
func (pe *P2PEncryption) monitorSecurity() {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	// Encryption security monitoring

	// Статистика
	totalSessions := len(pe.sessions)
	totalKeys := len(pe.keys)

	// Проверяем активные сессии
	activeSessions := 0
	for _, session := range pe.sessions {
		if time.Since(session.LastUsed) < 5*time.Minute {
			activeSessions++
		}
	}

	// Encryption statistics
	_ = totalSessions
	_ = activeSessions
	_ = totalKeys

	// Проверяем время последней ротации
	timeSinceRotation := time.Since(pe.lastRotation)
	// Time since last rotation
	_ = timeSinceRotation
}

// GetEncryptionStats возвращает статистику шифрования
func (pe *P2PEncryption) GetEncryptionStats() map[string]interface{} {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	return map[string]interface{}{
		"total_sessions":    len(pe.sessions),
		"total_keys":        len(pe.keys),
		"key_rotation_time": pe.keyRotation.String(),
		"last_rotation":     pe.lastRotation,
		"algorithms":        []string{"AES-256-GCM", "ChaCha20-Poly1305"},
	}
}

// CreateSharedSessionForPeers создаёт (или возвращает) детерминированную общую сессию для пары узлов
func (pe *P2PEncryption) CreateSharedSessionForPeers(myID, peerID string) (*EncryptionSession, error) {
	// Детерминированный порядок
	a, b := myID, peerID
	if a > b {
		a, b = b, a
	}
	// Детерминированный sessionID и ключ
	sid := fmt.Sprintf("shared_%x", sha256.Sum256([]byte(a+":"+b)))
	key := sha256.Sum256([]byte("key:" + a + ":" + b))

	pe.mu.RLock()
	if s, ok := pe.sessions[sid]; ok {
		pe.mu.RUnlock()
		return s, nil
	}
	pe.mu.RUnlock()

	pe.mu.Lock()
	defer pe.mu.Unlock()
	if s, ok := pe.sessions[sid]; ok {
		return s, nil
	}
	s := &EncryptionSession{
		ID:           sid,
		NodeID:       peerID,
		SendKey:      key[:],
		ReceiveKey:   key[:],
		SendNonce:    0,
		ReceiveNonce: 0,
		Created:      time.Now(),
		LastUsed:     time.Now(),
		Algorithm:    "AES-256-GCM",
	}
	pe.sessions[sid] = s
	return s, nil
}

// GenerateSharedKey генерирует общий ключ для двух узлов
func (pe *P2PEncryption) GenerateSharedKey(node1ID, node2ID string) ([]byte, error) {
	// Используем SHA-256 для генерации общего ключа
	combined := fmt.Sprintf("%s:%s:%d", node1ID, node2ID, time.Now().Unix())
	hash := sha256.Sum256([]byte(combined))

	// Shared key generated
	return hash[:], nil
}

// ValidateSession проверяет валидность сессии
func (pe *P2PEncryption) ValidateSession(sessionID string) bool {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	session, exists := pe.sessions[sessionID]
	if !exists {
		return false
	}

	// Проверяем, не истекла ли сессия
	return time.Since(session.LastUsed) < 30*time.Minute
}

// GetSessionInfo возвращает информацию о сессии
func (pe *P2PEncryption) GetSessionInfo(sessionID string) (*EncryptionSession, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	session, exists := pe.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("сессия %s не найдена", sessionID)
	}

	return session, nil
}

// CloseSession закрывает сессию
func (pe *P2PEncryption) CloseSession(sessionID string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if _, exists := pe.sessions[sessionID]; !exists {
		return fmt.Errorf("сессия %s не найдена", sessionID)
	}

	delete(pe.sessions, sessionID)
	// Session closed

	return nil
}
