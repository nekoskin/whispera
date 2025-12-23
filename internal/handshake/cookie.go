package handshake

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

const (
	cookieSecretSize = 32
	cookieSize       = 16
	cookieLifetime   = 120 * time.Second // 2 минуты
	cookieRotateInterval = 5 * time.Minute // Ротация секрета каждые 5 минут
)

// CookieSecret хранит секретный ключ для генерации cookies
type CookieSecret struct {
	secret    [cookieSecretSize]byte
	createdAt time.Time
	mu        sync.RWMutex
}

var (
	globalCookieSecret *CookieSecret
	cookieSecretOnce  sync.Once
)

func initCookieSecret() {
	globalCookieSecret = &CookieSecret{
		createdAt: time.Now(),
	}
	if _, err := rand.Read(globalCookieSecret.secret[:]); err != nil {
		panic("failed to initialize cookie secret: " + err.Error())
	}

	// Ротация секрета каждые 5 минут
	go func() {
		ticker := time.NewTicker(cookieRotateInterval)
		defer ticker.Stop()
		for range ticker.C {
			globalCookieSecret.rotate()
		}
	}()
}

func (cs *CookieSecret) rotate() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, err := rand.Read(cs.secret[:]); err != nil {
		// Логируем ошибку, но не паникуем - используем старый секрет
		return
	}
	cs.createdAt = time.Now()
}

// GenerateCookie генерирует cookie для клиента
// Cookie основан на IP адресе, порте и временном окне для защиты от replay
func GenerateCookie(clientAddr *net.UDPAddr) []byte {
	cookieSecretOnce.Do(initCookieSecret)
	
	globalCookieSecret.mu.RLock()
	defer globalCookieSecret.mu.RUnlock()

	// HMAC(secret, client_ip || client_port || timestamp_window)
	mac := hmac.New(sha256.New, globalCookieSecret.secret[:])

	// Добавляем IP адрес
	if clientAddr.IP.To4() != nil {
		// IPv4
		mac.Write(clientAddr.IP.To4())
	} else {
		// IPv6
		mac.Write(clientAddr.IP.To16())
	}

	// Добавляем порт
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(clientAddr.Port))
	mac.Write(portBytes)

	// Добавляем временное окно (обновляется каждые 2 минуты)
	timeWindow := uint32(time.Now().Unix() / int64(cookieLifetime.Seconds()))
	timeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(timeBytes, timeWindow)
	mac.Write(timeBytes)

	// Берем первые 16 байт HMAC
	sum := mac.Sum(nil)
	cookie := make([]byte, cookieSize)
	copy(cookie, sum[:cookieSize])

	return cookie
}

// VerifyCookie проверяет валидность cookie
// Использует constant-time сравнение для защиты от timing attacks
func VerifyCookie(cookie []byte, clientAddr *net.UDPAddr) bool {
	if len(cookie) != cookieSize {
		return false
	}

	expected := GenerateCookie(clientAddr)
	return hmac.Equal(cookie, expected)
}

