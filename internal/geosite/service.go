package geosite

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"whispera/internal/logger"
)

// log is the module logger
var log = logger.Module("geosite")

// Service управляет GeoSite базой данных
type Service struct {
	db       *GeoSiteDatabase
	dbPath   string
	mu       sync.RWMutex
	autoLoad bool
}

// NewService создает новый GeoSite сервис
func NewService(dbPath string, autoLoad bool) *Service {
	service := &Service{
		db:       NewGeoSiteDatabase(),
		dbPath:   dbPath,
		autoLoad: autoLoad,
	}

	if autoLoad {
		if err := service.Load(); err != nil {
			log.Warn("Failed to load database: %v", err)
		}
	}

	return service
}

// Load загружает GeoSite базу из файла
func (s *Service) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dbPath == "" {
		return fmt.Errorf("database path not set")
	}

	if _, err := os.Stat(s.dbPath); os.IsNotExist(err) {
		return fmt.Errorf("geosite database file not found: %s", s.dbPath)
	}

	return s.db.LoadFromFile(s.dbPath)
}

// GetDomains возвращает домены для указанной страны
func (s *Service) GetDomains(countryCode string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.GetDomains(countryCode)
}

// IsDomainInCountry проверяет, принадлежит ли домен указанной стране
func (s *Service) IsDomainInCountry(domain, countryCode string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.IsDomainInCountry(domain, countryCode)
}

// DownloadDatabase загружает GeoSite базу с V2Ray репозитория
func (s *Service) DownloadDatabase() error {
	// V2Ray GeoSite репозиторий
	url := "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"

	// Создаем директорию, если не существует
	dir := filepath.Dir(s.dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	log.Info("Downloading database from %s...", url)
	if err := DownloadGeoSite(url, s.dbPath); err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}

	log.Info("Database downloaded successfully to %s", s.dbPath)

	// Перезагружаем базу
	return s.Load()
}

// EnsureDatabase проверяет наличие базы и загружает при необходимости
func (s *Service) EnsureDatabase() error {
	if _, err := os.Stat(s.dbPath); os.IsNotExist(err) {
		log.Info("Database not found, downloading...")
		return s.DownloadDatabase()
	}

	return s.Load()
}

// GetCategories возвращает список всех категорий для указанной страны
func (s *Service) GetCategories(countryCode string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.GetCategories(countryCode)
}

// IsDomainInCategory проверяет, принадлежит ли домен указанной категории
func (s *Service) IsDomainInCategory(domain, category string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.IsDomainInCategory(domain, category)
}
