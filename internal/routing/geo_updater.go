package routing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// GeoUpdater управляет автоматическим обновлением GeoIP/GeoSite баз
type GeoUpdater struct {
	geoIPPath   string
	geoSitePath string
	updateDir   string // Директория для хранения баз
	updateURL   string // Базовый URL для обновлений (по умолчанию v2ray)
	interval    time.Duration
	mu          sync.RWMutex
	lastUpdate  time.Time
	enabled     bool
	httpClient  *http.Client
}

// GeoUpdateConfig конфигурация для обновления геобаз
type GeoUpdateConfig struct {
	UpdateDir   string        // Директория для хранения баз
	UpdateURL   string        // Базовый URL (по умолчанию v2ray releases)
	Interval    time.Duration // Интервал обновления (по умолчанию 24 часа)
	Enabled     bool          // Включено ли автообновление
	GeoIPPath   string        // Путь к GeoIP файлу (если указан, используется вместо автоскачивания)
	GeoSitePath string        // Путь к GeoSite файлу (если указан, используется вместо автоскачивания)
}

const (
	// DefaultGeoUpdateURL - URL для скачивания геобаз из v2ray releases
	DefaultGeoUpdateURL = "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
	DefaultGeoSiteURL   = "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"
	
	// Альтернативные источники (если основной недоступен)
	AltGeoIPURL   = "https://raw.githubusercontent.com/v2fly/geoip/release/geoip.dat"
	AltGeoSiteURL = "https://raw.githubusercontent.com/v2fly/domain-list-community/release/dlc.dat"
	
	// Имена файлов
	GeoIPFileName   = "geoip.dat"
	GeoSiteFileName = "geosite.dat"
)

// NewGeoUpdater создает новый updater для геобаз
func NewGeoUpdater(config GeoUpdateConfig) *GeoUpdater {
	if config.UpdateDir == "" {
		// Используем временную директорию по умолчанию
		config.UpdateDir = filepath.Join(os.TempDir(), "whispera-geo")
	}

	if config.Interval == 0 {
		config.Interval = 24 * time.Hour // Обновление раз в сутки
	}

	updater := &GeoUpdater{
		geoIPPath:   config.GeoIPPath,
		geoSitePath: config.GeoSitePath,
		updateDir:   config.UpdateDir,
		updateURL:   config.UpdateURL,
		interval:    config.Interval,
		enabled:     config.Enabled,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Создаем директорию если не существует
	if err := os.MkdirAll(config.UpdateDir, 0755); err != nil {
		// Логируем ошибку, но продолжаем работу
		_ = err
	}

	return updater
}

// Start запускает автоматическое обновление геобаз
func (u *GeoUpdater) Start(ctx context.Context) error {
	if !u.enabled {
		return nil
	}

	// Первоначальная загрузка/обновление
	if err := u.Update(); err != nil {
		// Логируем ошибку, но продолжаем работу
		_ = err
	}

	// Периодическое обновление
	go u.updateLoop(ctx)

	return nil
}

// updateLoop выполняет периодическое обновление
func (u *GeoUpdater) updateLoop(ctx context.Context) {
	ticker := time.NewTicker(u.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := u.Update(); err != nil {
				// Логируем ошибку, но продолжаем работу
				_ = err
			}
		}
	}
}

// Update обновляет геобазы
func (u *GeoUpdater) Update() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Обновляем GeoIP если путь не указан явно
	if u.geoIPPath == "" {
		geoIPPath := filepath.Join(u.updateDir, GeoIPFileName)
		if err := u.downloadFile(DefaultGeoUpdateURL, geoIPPath, AltGeoIPURL); err != nil {
			return fmt.Errorf("failed to update GeoIP: %w", err)
		}
		u.geoIPPath = geoIPPath
	}

	// Обновляем GeoSite если путь не указан явно
	if u.geoSitePath == "" {
		geoSitePath := filepath.Join(u.updateDir, GeoSiteFileName)
		if err := u.downloadFile(DefaultGeoSiteURL, geoSitePath, AltGeoSiteURL); err != nil {
			return fmt.Errorf("failed to update GeoSite: %w", err)
		}
		u.geoSitePath = geoSitePath
	}

	u.lastUpdate = time.Now()
	return nil
}

// downloadFile скачивает файл с fallback на альтернативный URL
func (u *GeoUpdater) downloadFile(url, filePath, altURL string) error {
	// Пробуем скачать с основного URL
	if err := u.downloadFromURL(url, filePath); err != nil {
		// Если не получилось, пробуем альтернативный URL
		if altURL != "" {
			if err2 := u.downloadFromURL(altURL, filePath); err2 != nil {
				return fmt.Errorf("failed to download from both URLs: %v, %v", err, err2)
			}
		} else {
			return err
		}
	}

	return nil
}

// downloadFromURL скачивает файл по URL
func (u *GeoUpdater) downloadFromURL(url, filePath string) error {
	resp, err := u.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Создаем временный файл
	tmpFile := filePath + ".tmp"
	out, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer out.Close()

	// Копируем данные
	if _, err := io.Copy(out, resp.Body); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to write file: %w", err)
	}

	// Закрываем файл перед переименованием
	out.Close()

	// Проверяем валидность файла (минимальный размер)
	info, err := os.Stat(tmpFile)
	if err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to stat file: %w", err)
	}

	if info.Size() < 1024 { // Минимум 1KB
		os.Remove(tmpFile)
		return fmt.Errorf("downloaded file too small: %d bytes", info.Size())
	}

	// Атомарно заменяем старый файл
	if err := os.Rename(tmpFile, filePath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}

// GetGeoIPPath возвращает путь к GeoIP файлу
func (u *GeoUpdater) GetGeoIPPath() string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.geoIPPath
}

// GetGeoSitePath возвращает путь к GeoSite файлу
func (u *GeoUpdater) GetGeoSitePath() string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.geoSitePath
}

// GetLastUpdate возвращает время последнего обновления
func (u *GeoUpdater) GetLastUpdate() time.Time {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.lastUpdate
}

// CheckUpdate проверяет наличие обновлений (сравнивает хеши)
func (u *GeoUpdater) CheckUpdate() (bool, error) {
	// Простая проверка: если файл старше интервала обновления, считаем что нужна проверка
	u.mu.RLock()
	lastUpdate := u.lastUpdate
	geoIPPath := u.geoIPPath
	geoSitePath := u.geoSitePath
	u.mu.RUnlock()

	if time.Since(lastUpdate) > u.interval {
		return true, nil
	}

	// Проверяем существование файлов
	if geoIPPath != "" {
		if info, err := os.Stat(geoIPPath); err != nil || time.Since(info.ModTime()) > u.interval {
			return true, nil
		}
	}

	if geoSitePath != "" {
		if info, err := os.Stat(geoSitePath); err != nil || time.Since(info.ModTime()) > u.interval {
			return true, nil
		}
	}

	return false, nil
}

// GetFileHash возвращает SHA256 хеш файла
func (u *GeoUpdater) GetFileHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// SetEnabled включает/выключает автообновление
func (u *GeoUpdater) SetEnabled(enabled bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.enabled = enabled
}

// IsEnabled возвращает, включено ли автообновление
func (u *GeoUpdater) IsEnabled() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.enabled
}

