package geoip

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// Service управляет GeoIP базой данных
type Service struct {
	db       *GeoIPDatabase
	dbPath   string
	mu       sync.RWMutex
	autoLoad bool
}

// NewService создает новый GeoIP сервис
func NewService(dbPath string, autoLoad bool) *Service {
	service := &Service{
		db:       NewGeoIPDatabase(),
		dbPath:   dbPath,
		autoLoad: autoLoad,
	}

	if autoLoad {
		if err := service.Load(); err != nil {
			log.Printf("[GeoIP] Warning: failed to load database: %v", err)
		}
	}

	return service
}

// Load загружает GeoIP базу из файла
func (s *Service) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dbPath == "" {
		return fmt.Errorf("database path not set")
	}

	if _, err := os.Stat(s.dbPath); os.IsNotExist(err) {
		return fmt.Errorf("geoip database file not found: %s", s.dbPath)
	}

	return s.db.LoadFromFile(s.dbPath)
}

// LookupCountry определяет страну по IP адресу
func (s *Service) LookupCountry(ipStr string) (string, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.LookupCountry(ip)
}

// LookupCountryByIP определяет страну по net.IP
func (s *Service) LookupCountryByIP(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.LookupCountry(ip)
}

// IsInCountry проверяет, принадлежит ли IP указанной стране
func (s *Service) IsInCountry(ipStr, countryCode string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.IsInCountry(ip, countryCode)
}

// GetCountryCIDRs возвращает CIDR для указанной страны
func (s *Service) GetCountryCIDRs(countryCode string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.GetCountryCIDRs(countryCode)
}

// DownloadDatabase загружает GeoIP базу с V2Ray репозитория
func (s *Service) DownloadDatabase() error {
	// V2Ray GeoIP репозиторий
	url := "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"

	// Создаем директорию, если не существует
	dir := filepath.Dir(s.dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	log.Printf("[GeoIP] Downloading database from %s...", url)
	if err := DownloadGeoIP(url, s.dbPath); err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}

	log.Printf("[GeoIP] Database downloaded successfully to %s", s.dbPath)

	// Перезагружаем базу
	return s.Load()
}

// EnsureDatabase проверяет наличие базы и загружает при необходимости
func (s *Service) EnsureDatabase() error {
	if _, err := os.Stat(s.dbPath); os.IsNotExist(err) {
		log.Printf("[GeoIP] Database not found, downloading...")
		return s.DownloadDatabase()
	}

	return s.Load()
}

