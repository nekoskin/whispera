package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

// KeyRotationManager управляет ротацией ключей
type KeyRotationManager struct {
	// Текущие ключи
	currentKeys  *KeySet
	previousKeys *KeySet
	nextKeys     *KeySet

	// Конфигурация
	config *RotationConfig

	// Состояние
	mu            sync.RWMutex
	isRunning     bool
	lastRotation  time.Time
	rotationCount int64

	// События
	rotationEvents []RotationEvent
}

// KeySet набор ключей
type KeySet struct {
	PSK         []byte
	ServerPriv  []byte
	ServerPub   []byte
	ClientPriv  []byte
	ClientPub   []byte
	GeneratedAt time.Time
	ExpiresAt   time.Time
	Version     int64
}

// RotationConfig конфигурация ротации
type RotationConfig struct {
	RotationInterval   time.Duration
	KeyLifetime        time.Duration
	PreRotationTime    time.Duration
	MaxKeyVersions     int
	EnableAutoRotation bool
	EnableAudit        bool
	AuditRetention     time.Duration
}

// RotationEvent событие ротации ключей
type RotationEvent struct {
	Timestamp   time.Time
	EventType   string // "generated", "activated", "expired", "revoked"
	KeyVersion  int64
	Description string
	Success     bool
}

// NewKeyRotationManager создает новый менеджер ротации ключей
func NewKeyRotationManager() *KeyRotationManager {
	return &KeyRotationManager{
		currentKeys:  nil,
		previousKeys: nil,
		nextKeys:     nil,
		config: &RotationConfig{
			RotationInterval:   24 * time.Hour,
			KeyLifetime:        48 * time.Hour,
			PreRotationTime:    2 * time.Hour,
			MaxKeyVersions:     10,
			EnableAutoRotation: true,
			EnableAudit:        true,
			AuditRetention:     30 * 24 * time.Hour,
		},
		rotationEvents: make([]RotationEvent, 0),
	}
}

// Start запускает автоматическую ротацию ключей
func (krm *KeyRotationManager) Start(ctx context.Context) error {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if krm.isRunning {
		return fmt.Errorf("key rotation manager is already running")
	}

	krm.isRunning = true

	// Генерируем начальный набор ключей
	if err := krm.generateInitialKeys(); err != nil {
		return fmt.Errorf("failed to generate initial keys: %v", err)
	}

	// Запускаем цикл ротации
	go krm.rotationLoop(ctx)

	log.Printf("Key rotation manager started")
	return nil
}

// Stop останавливает ротацию ключей
func (krm *KeyRotationManager) Stop() {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	krm.isRunning = false
	log.Printf("Key rotation manager stopped")
}

// rotationLoop основной цикл ротации ключей
func (krm *KeyRotationManager) rotationLoop(ctx context.Context) {
	ticker := time.NewTicker(krm.config.RotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if krm.config.EnableAutoRotation {
				krm.performRotation()
			}
		}
	}
}

// generateInitialKeys генерирует начальный набор ключей
func (krm *KeyRotationManager) generateInitialKeys() error {
	keys, err := krm.generateKeySet()
	if err != nil {
		return err
	}

	krm.currentKeys = keys
	krm.lastRotation = time.Now()
	krm.rotationCount = 1

	// Записываем событие
	krm.recordEvent("generated", keys.Version, "Initial key set generated", true)

	log.Printf("Initial key set generated (version %d)", keys.Version)
	return nil
}

// performRotation выполняет ротацию ключей
func (krm *KeyRotationManager) performRotation() {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	// Проверяем, нужна ли ротация
	if !krm.shouldRotate() {
		return
	}

	// Генерируем новый набор ключей
	newKeys, err := krm.generateKeySet()
	if err != nil {
		log.Printf("Failed to generate new keys: %v", err)
		krm.recordEvent("generated", 0, fmt.Sprintf("Failed to generate keys: %v", err), false)
		return
	}

	// Обновляем ключи
	krm.previousKeys = krm.currentKeys
	krm.currentKeys = newKeys
	krm.nextKeys = nil

	krm.lastRotation = time.Now()
	krm.rotationCount++

	// Записываем событие
	krm.recordEvent("activated", newKeys.Version, "Key rotation performed", true)

	// Очищаем старые ключи
	krm.cleanupOldKeys()

	log.Printf("Key rotation completed (version %d)", newKeys.Version)
}

// shouldRotate определяет, нужна ли ротация ключей
func (krm *KeyRotationManager) shouldRotate() bool {
	if krm.currentKeys == nil {
		return true
	}

	// Ротация нужна, если ключи скоро истекают
	if time.Until(krm.currentKeys.ExpiresAt) < krm.config.PreRotationTime {
		return true
	}

	// Ротация нужна, если ключи уже истекли
	if time.Now().After(krm.currentKeys.ExpiresAt) {
		return true
	}

	return false
}

// generateKeySet генерирует новый набор ключей
func (krm *KeyRotationManager) generateKeySet() (*KeySet, error) {
	// Генерируем PSK
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return nil, fmt.Errorf("failed to generate PSK: %v", err)
	}

	// Генерируем ключевую пару клиента
	clientPriv := make([]byte, 32)
	if _, err := rand.Read(clientPriv); err != nil {
		return nil, fmt.Errorf("failed to generate client private key: %v", err)
	}

	// Вычисляем публичный ключ клиента из приватного
	clientPub, err := curve25519.X25519(clientPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client public key: %v", err)
	}

	// Генерируем приватный ключ сервера
	serverPriv := make([]byte, 32)
	if _, err := rand.Read(serverPriv); err != nil {
		return nil, fmt.Errorf("failed to generate server private key: %v", err)
	}

	// Вычисляем публичный ключ сервера из приватного
	serverPub, err := curve25519.X25519(serverPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server public key: %v", err)
	}

	now := time.Now()
	keys := &KeySet{
		PSK:         psk,
		ServerPriv:  serverPriv,
		ServerPub:   serverPub,
		ClientPriv:  clientPriv,
		ClientPub:   clientPub,
		GeneratedAt: now,
		ExpiresAt:   now.Add(krm.config.KeyLifetime),
		Version:     krm.rotationCount + 1,
	}

	return keys, nil
}

// cleanupOldKeys очищает старые ключи
func (krm *KeyRotationManager) cleanupOldKeys() {
	// Очищаем предыдущие ключи, если они слишком старые
	if krm.previousKeys != nil && time.Since(krm.previousKeys.ExpiresAt) > krm.config.AuditRetention {
		krm.previousKeys = nil
		krm.recordEvent("revoked", krm.previousKeys.Version, "Old keys cleaned up", true)
	}

	// Ограничиваем количество версий ключей
	if krm.rotationCount > int64(krm.config.MaxKeyVersions) {
		// В реальной реализации здесь была бы более сложная логика очистки
		_ = krm.rotationCount // Suppress unused warning - cleanup logic placeholder
	}
}

// recordEvent записывает событие ротации
func (krm *KeyRotationManager) recordEvent(eventType string, keyVersion int64, description string, success bool) {
	if !krm.config.EnableAudit {
		return
	}

	event := RotationEvent{
		Timestamp:   time.Now(),
		EventType:   eventType,
		KeyVersion:  keyVersion,
		Description: description,
		Success:     success,
	}

	krm.rotationEvents = append(krm.rotationEvents, event)

	// Ограничиваем размер истории событий
	if len(krm.rotationEvents) > 1000 {
		krm.rotationEvents = krm.rotationEvents[1:]
	}
}

// GetCurrentKeys возвращает текущие ключи
func (krm *KeyRotationManager) GetCurrentKeys() *KeySet {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	if krm.currentKeys == nil {
		return nil
	}

	// Возвращаем копию
	keys := *krm.currentKeys
	return &keys
}

// GetPreviousKeys возвращает предыдущие ключи
func (krm *KeyRotationManager) GetPreviousKeys() *KeySet {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	if krm.previousKeys == nil {
		return nil
	}

	// Возвращаем копию
	keys := *krm.previousKeys
	return &keys
}

// GetNextKeys возвращает следующие ключи
func (krm *KeyRotationManager) GetNextKeys() *KeySet {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	if krm.nextKeys == nil {
		return nil
	}

	// Возвращаем копию
	keys := *krm.nextKeys
	return &keys
}

// ForceRotation принудительно выполняет ротацию ключей
func (krm *KeyRotationManager) ForceRotation() error {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if !krm.isRunning {
		return fmt.Errorf("key rotation manager is not running")
	}

	krm.performRotation()
	return nil
}

// GetRotationStatus возвращает статус ротации
func (krm *KeyRotationManager) GetRotationStatus() map[string]interface{} {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	status := map[string]interface{}{
		"is_running":      krm.isRunning,
		"last_rotation":   krm.lastRotation,
		"rotation_count":  krm.rotationCount,
		"current_version": 0,
		"next_rotation":   krm.lastRotation.Add(krm.config.RotationInterval),
	}

	if krm.currentKeys != nil {
		status["current_version"] = krm.currentKeys.Version
		status["expires_at"] = krm.currentKeys.ExpiresAt
		status["time_until_expiry"] = time.Until(krm.currentKeys.ExpiresAt)
	}

	return status
}

// GetRotationEvents возвращает события ротации
func (krm *KeyRotationManager) GetRotationEvents() []RotationEvent {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	events := make([]RotationEvent, len(krm.rotationEvents))
	copy(events, krm.rotationEvents)
	return events
}

// SetConfig обновляет конфигурацию ротации
func (krm *KeyRotationManager) SetConfig(config *RotationConfig) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	krm.config = config
}

// ExportKeys экспортирует ключи в безопасном формате
func (krm *KeyRotationManager) ExportKeys() (map[string]string, error) {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	if krm.currentKeys == nil {
		return nil, fmt.Errorf("no current keys available")
	}

	export := map[string]string{
		"psk_hex":         hex.EncodeToString(krm.currentKeys.PSK),
		"server_priv_hex": hex.EncodeToString(krm.currentKeys.ServerPriv),
		"server_pub_hex":  hex.EncodeToString(krm.currentKeys.ServerPub),
		"client_priv_hex": hex.EncodeToString(krm.currentKeys.ClientPriv),
		"client_pub_hex":  hex.EncodeToString(krm.currentKeys.ClientPub),
		"version":         fmt.Sprintf("%d", krm.currentKeys.Version),
		"generated_at":    krm.currentKeys.GeneratedAt.Format(time.RFC3339),
		"expires_at":      krm.currentKeys.ExpiresAt.Format(time.RFC3339),
	}

	return export, nil
}

// ImportKeys импортирует ключи из безопасного формата
func (krm *KeyRotationManager) ImportKeys(export map[string]string) error {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	// Валидируем обязательные поля
	requiredFields := []string{
		"psk_hex", "server_priv_hex", "server_pub_hex",
		"client_priv_hex", "client_pub_hex", "version",
	}
	for _, field := range requiredFields {
		if _, exists := export[field]; !exists {
			return fmt.Errorf("missing required field: %s", field)
		}
	}

	// Декодируем ключи
	psk, err := hex.DecodeString(export["psk_hex"])
	if err != nil {
		return fmt.Errorf("invalid PSK: %v", err)
	}

	serverPriv, err := hex.DecodeString(export["server_priv_hex"])
	if err != nil {
		return fmt.Errorf("invalid server private key: %v", err)
	}

	serverPub, err := hex.DecodeString(export["server_pub_hex"])
	if err != nil {
		return fmt.Errorf("invalid server public key: %v", err)
	}

	clientPriv, err := hex.DecodeString(export["client_priv_hex"])
	if err != nil {
		return fmt.Errorf("invalid client private key: %v", err)
	}

	clientPub, err := hex.DecodeString(export["client_pub_hex"])
	if err != nil {
		return fmt.Errorf("invalid client public key: %v", err)
	}

	// Парсим версию
	version := int64(0)
	if v, exists := export["version"]; exists {
		if _, err := fmt.Sscanf(v, "%d", &version); err != nil {
			return fmt.Errorf("invalid version: %v", err)
		}
	}

	// Создаем набор ключей
	keys := &KeySet{
		PSK:        psk,
		ServerPriv: serverPriv,
		ServerPub:  serverPub,
		ClientPriv: clientPriv,
		ClientPub:  clientPub,
		Version:    version,
	}

	// Парсим временные метки
	if generatedAt, exists := export["generated_at"]; exists {
		if t, err := time.Parse(time.RFC3339, generatedAt); err == nil {
			keys.GeneratedAt = t
		}
	}

	if expiresAt, exists := export["expires_at"]; exists {
		if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
			keys.ExpiresAt = t
		}
	}

	// Устанавливаем ключи
	krm.currentKeys = keys
	krm.lastRotation = time.Now()

	// Записываем событие
	krm.recordEvent("imported", version, "Keys imported from external source", true)

	log.Printf("Keys imported successfully (version %d)", version)
	return nil
}
