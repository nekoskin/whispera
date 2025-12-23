package security

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
)

// CertPinner управляет pinning сертификатов
type CertPinner struct {
	pins      map[string][]string // hostname -> []pinned hash
	mu        sync.RWMutex
	enabled   bool
	allowlist map[string]bool // hostname -> allow (игнорировать pinning для этих хостов)
}

// NewCertPinner создает новый CertPinner
func NewCertPinner() *CertPinner {
	return &CertPinner{
		pins:      make(map[string][]string),
		allowlist: make(map[string]bool),
		enabled:   true,
	}
}

// SetEnabled включает/выключает certificate pinning
func (cp *CertPinner) SetEnabled(enabled bool) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.enabled = enabled
}

// IsEnabled возвращает, включен ли certificate pinning
func (cp *CertPinner) IsEnabled() bool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.enabled
}

// AddPin добавляет pinned hash для хоста
func (cp *CertPinner) AddPin(hostname, hash string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	if cp.pins[hostname] == nil {
		cp.pins[hostname] = make([]string, 0)
	}
	
	// Проверяем, нет ли уже такого hash
	for _, existingHash := range cp.pins[hostname] {
		if existingHash == hash {
			return // Уже есть
		}
	}
	
	cp.pins[hostname] = append(cp.pins[hostname], hash)
}

// RemovePin удаляет pinned hash для хоста
func (cp *CertPinner) RemovePin(hostname, hash string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	pins := cp.pins[hostname]
	if pins == nil {
		return
	}
	
	// Удаляем hash из списка
	newPins := make([]string, 0, len(pins))
	for _, existingHash := range pins {
		if existingHash != hash {
			newPins = append(newPins, existingHash)
		}
	}
	
	if len(newPins) == 0 {
		delete(cp.pins, hostname)
	} else {
		cp.pins[hostname] = newPins
	}
}

// AddToAllowlist добавляет хост в allowlist (игнорировать pinning)
func (cp *CertPinner) AddToAllowlist(hostname string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.allowlist[hostname] = true
}

// RemoveFromAllowlist удаляет хост из allowlist
func (cp *CertPinner) RemoveFromAllowlist(hostname string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	delete(cp.allowlist, hostname)
}

// LoadPinsFromFile загружает pins из файла (формат: hostname:hash, по одной строке)
func (cp *CertPinner) LoadPinsFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open pinning file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Пропускаем пустые строки и комментарии
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Формат: hostname:hash или hostname hash (с пробелом)
		parts := strings.FieldsFunc(line, func(r rune) bool {
			return r == ':' || r == ' ' || r == '\t'
		})
		
		if len(parts) < 2 {
			return fmt.Errorf("invalid format at line %d: expected 'hostname:hash', got: %s", lineNum, line)
		}
		
		hostname := parts[0]
		hash := strings.Join(parts[1:], "") // Объединяем все части после hostname (на случай если hash содержит разделители)
		
		// Нормализуем hash (убираем пробелы, двоеточия)
		hash = normalizeHash(hash)
		
		cp.AddPin(hostname, hash)
	}
	
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading pinning file: %w", err)
	}
	
	return nil
}

// VerifyCertificate проверяет сертификат на соответствие pinned hash
func (cp *CertPinner) VerifyCertificate(hostname string, cert *x509.Certificate) error {
	cp.mu.RLock()
	enabled := cp.enabled
	allowlisted := cp.allowlist[hostname]
	pins := cp.pins[hostname]
	cp.mu.RUnlock()
	
	// Если pinning отключен или хост в allowlist, пропускаем проверку
	if !enabled || allowlisted {
		return nil
	}
	
	// Если нет pinned hash для этого хоста, пропускаем проверку
	if len(pins) == 0 {
		return nil
	}
	
	// Вычисляем SHA256 hash сертификата
	certHash := sha256.Sum256(cert.Raw)
	certHashHex := hex.EncodeToString(certHash[:])
	
	// Проверяем, совпадает ли hash с одним из pinned
	for _, pinnedHash := range pins {
		// Нормализуем hash (убираем пробелы, приводим к нижнему регистру)
		normalizedPinned := normalizeHash(pinnedHash)
		normalizedCert := normalizeHash(certHashHex)
		
		if normalizedCert == normalizedPinned {
			return nil // Hash совпадает
		}
	}
	
	// Hash не совпадает ни с одним pinned
	return fmt.Errorf("certificate pinning failed for %s: expected one of %v, got %s", hostname, pins, certHashHex)
}

// VerifyCertificateChain проверяет цепочку сертификатов
func (cp *CertPinner) VerifyCertificateChain(hostname string, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("no certificates provided")
	}
	
	// Проверяем leaf certificate (первый в цепочке)
	return cp.VerifyCertificate(hostname, certs[0])
}

// GetPins возвращает список pinned hash для хоста
func (cp *CertPinner) GetPins(hostname string) []string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	
	pins := cp.pins[hostname]
	if pins == nil {
		return nil
	}
	
	// Возвращаем копию
	result := make([]string, len(pins))
	copy(result, pins)
	return result
}

// GetAllPins возвращает все pinned hash для всех хостов
func (cp *CertPinner) GetAllPins() map[string][]string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	
	result := make(map[string][]string)
	for hostname, pins := range cp.pins {
		result[hostname] = make([]string, len(pins))
		copy(result[hostname], pins)
	}
	return result
}

// ClearPins очищает все pinned hash
func (cp *CertPinner) ClearPins() {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.pins = make(map[string][]string)
}

// normalizeHash нормализует hash (убирает пробелы, приводит к нижнему регистру)
func normalizeHash(hash string) string {
	// Убираем пробелы и двоеточия (формат "AA:BB:CC" -> "aabbcc")
	normalized := ""
	for _, char := range hash {
		if char != ' ' && char != ':' && char != '-' {
			// Приводим к нижнему регистру
			if char >= 'A' && char <= 'F' {
				char = char + ('a' - 'A')
			}
			normalized += string(char)
		}
	}
	return normalized
}

// CalculateCertHash вычисляет SHA256 hash сертификата
func CalculateCertHash(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// CalculateCertHashFormatted вычисляет SHA256 hash сертификата в формате "AA:BB:CC:..."
func CalculateCertHashFormatted(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	hexStr := hex.EncodeToString(hash[:])
	
	// Форматируем как "AA:BB:CC:..."
	formatted := ""
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			formatted += ":"
		}
		formatted += hexStr[i:i+2]
	}
	return formatted
}

// CreateTLSConfigWithPinning создает TLS конфигурацию с certificate pinning
func (cp *CertPinner) CreateTLSConfigWithPinning(hostname string, baseConfig *tls.Config) *tls.Config {
	if baseConfig == nil {
		baseConfig = &tls.Config{}
	}
	
	// Копируем базовую конфигурацию
	config := baseConfig.Clone()
	
	// Добавляем VerifyPeerCertificate для certificate pinning
	originalVerifyPeerCert := config.VerifyPeerCertificate
	config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// Сначала выполняем стандартную проверку если она была
		if originalVerifyPeerCert != nil {
			if err := originalVerifyPeerCert(rawCerts, verifiedChains); err != nil {
				return err
			}
		}
		
		// Затем проверяем certificate pinning
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificates provided")
		}
		
		// Парсим первый сертификат
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
		
		// Проверяем pinning
		return cp.VerifyCertificate(hostname, cert)
	}
	
	return config
}

// GetTLSConfigForHost возвращает TLS конфигурацию для хоста с certificate pinning
func (cp *CertPinner) GetTLSConfigForHost(hostname string) *tls.Config {
	baseConfig := &tls.Config{
		ServerName: hostname,
	}
	return cp.CreateTLSConfigWithPinning(hostname, baseConfig)
}

