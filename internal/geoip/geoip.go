package geoip

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

// GeoIPDatabase представляет базу данных GeoIP
type GeoIPDatabase struct {
	ipv4CIDRs map[string]string // CIDR -> Country Code
	ipv6CIDRs map[string]string // CIDR -> Country Code
	mu        sync.RWMutex
}

// NewGeoIPDatabase создает новую базу данных GeoIP
func NewGeoIPDatabase() *GeoIPDatabase {
	return &GeoIPDatabase{
		ipv4CIDRs: make(map[string]string),
		ipv6CIDRs: make(map[string]string),
	}
}

// LoadFromFile загружает GeoIP базу из файла (V2Ray формат)
// Формат: binary format с заголовком и CIDR записями
// V2Ray формат: [4 bytes magic "v2rg"] [4 bytes version] [4 bytes count] [entries...]
// Entry: [1 byte cidr_len] [4/16 bytes IP] [1 byte country_code_len] [country_code bytes]
func (db *GeoIPDatabase) LoadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open geoip file: %w", err)
	}
	defer file.Close()

	db.mu.Lock()
	defer db.mu.Unlock()

	// Очищаем существующие данные
	db.ipv4CIDRs = make(map[string]string)
	db.ipv6CIDRs = make(map[string]string)

	// Читаем заголовок (первые 12 байт: magic + version + count)
	header := make([]byte, 12)
	if _, err := io.ReadFull(file, header); err != nil {
		if err == io.EOF {
			// Файл слишком короткий, пробуем простой формат
			return db.loadSimpleFormat(file)
		}
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Проверяем магическое число (V2Ray формат: "v2rg")
	magic := string(header[:4])
	if magic != "v2rg" {
		// Пробуем альтернативный формат или создаем простую базу
		return db.loadSimpleFormat(file)
	}

	// Читаем версию (не используется, но нужно пропустить)
	_ = binary.BigEndian.Uint32(header[4:8])

	// Читаем количество записей
	count := binary.BigEndian.Uint32(header[8:12])

	// Читаем записи
	loadedCount := 0
	for i := uint32(0); i < count; i++ {
		// Читаем длину CIDR префикса (1 байт)
		cidrLenBytes := make([]byte, 1)
		if _, err := io.ReadFull(file, cidrLenBytes); err != nil {
			if err == io.EOF {
				break
			}
			// Логируем ошибку, но продолжаем загрузку
			continue
		}
		cidrLen := int(cidrLenBytes[0])

		// Определяем размер IP адреса
		var ipBytes []byte
		if cidrLen <= 32 {
			ipBytes = make([]byte, 4)
		} else if cidrLen <= 128 {
			ipBytes = make([]byte, 16)
		} else {
			// Некорректная длина CIDR
			continue
		}

		if _, err := io.ReadFull(file, ipBytes); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		// Читаем длину country code (1 байт)
		ccLenBytes := make([]byte, 1)
		if _, err := io.ReadFull(file, ccLenBytes); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		ccLen := int(ccLenBytes[0])

		// Валидация длины country code (обычно 2 символа)
		if ccLen == 0 || ccLen > 10 {
			continue
		}

		// Читаем country code
		ccBytes := make([]byte, ccLen)
		if _, err := io.ReadFull(file, ccBytes); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		countryCode := string(ccBytes)
		ip := net.IP(ipBytes)

		// Формируем CIDR
		cidr := fmt.Sprintf("%s/%d", ip.String(), cidrLen)

		// Валидация CIDR
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		// Сохраняем в соответствующую карту
		if cidrLen <= 32 {
			db.ipv4CIDRs[network.String()] = countryCode
		} else {
			db.ipv6CIDRs[network.String()] = countryCode
		}
		loadedCount++
	}

	// Если не загрузили ни одной записи, пробуем простой формат
	if loadedCount == 0 {
		return db.loadSimpleFormat(file)
	}

	return nil
}

// loadSimpleFormat загружает простой текстовый формат (fallback)
func (db *GeoIPDatabase) loadSimpleFormat(file *os.File) error {
	// Простой формат: CIDR,CountryCode (по одной строке)
	file.Seek(0, 0) // Возвращаемся в начало
	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Парсим построчно
	lines := splitLines(string(data))
	loadedCount := 0
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// Формат: CIDR,CountryCode или CIDR CountryCode или CIDR\tCountryCode
		parts := splitByCommaOrSpace(line)
		if len(parts) < 2 {
			continue
		}

		cidr := strings.TrimSpace(parts[0])
		countryCode := strings.TrimSpace(parts[1])

		// Валидация country code (обычно 2 символа, но может быть и больше)
		if len(countryCode) == 0 || len(countryCode) > 10 {
			continue
		}

		// Парсим и нормализуем CIDR
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		normalizedCIDR := network.String()

		// Определяем IPv4 или IPv6
		if network.IP.To4() != nil {
			db.ipv4CIDRs[normalizedCIDR] = countryCode
		} else {
			db.ipv6CIDRs[normalizedCIDR] = countryCode
		}
		loadedCount++
	}

	if loadedCount == 0 {
		return fmt.Errorf("no valid entries found in file")
	}

	return nil
}

// LookupCountry определяет страну по IP адресу
func (db *GeoIPDatabase) LookupCountry(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}

	db.mu.RLock()
	defer db.mu.RUnlock()

	// Проверяем IPv4
	if ipv4 := ip.To4(); ipv4 != nil {
		// Ищем наиболее специфичный CIDR (самый длинный префикс)
		bestMatch := ""
		bestPrefixLen := -1

		for cidr, countryCode := range db.ipv4CIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}

			if network.Contains(ip) {
				ones, _ := network.Mask.Size()
				if ones > bestPrefixLen {
					bestPrefixLen = ones
					bestMatch = countryCode
				}
			}
		}

		if bestMatch != "" {
			return bestMatch, true
		}
	} else {
		// Проверяем IPv6
		bestMatch := ""
		bestPrefixLen := -1

		for cidr, countryCode := range db.ipv6CIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}

			if network.Contains(ip) {
				ones, _ := network.Mask.Size()
				if ones > bestPrefixLen {
					bestPrefixLen = ones
					bestMatch = countryCode
				}
			}
		}

		if bestMatch != "" {
			return bestMatch, true
		}
	}

	return "", false
}

// AddCIDR добавляет CIDR в базу данных
func (db *GeoIPDatabase) AddCIDR(cidr, countryCode string) error {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	if ip.To4() != nil {
		db.ipv4CIDRs[cidr] = countryCode
	} else {
		db.ipv6CIDRs[cidr] = countryCode
	}

	return nil
}

// GetCountryCIDRs возвращает все CIDR для указанной страны
func (db *GeoIPDatabase) GetCountryCIDRs(countryCode string) []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var result []string
	for cidr, cc := range db.ipv4CIDRs {
		if cc == countryCode {
			result = append(result, cidr)
		}
	}
	for cidr, cc := range db.ipv6CIDRs {
		if cc == countryCode {
			result = append(result, cidr)
		}
	}

	return result
}

// IsInCountry проверяет, принадлежит ли IP указанной стране
func (db *GeoIPDatabase) IsInCountry(ip net.IP, countryCode string) bool {
	cc, found := db.LookupCountry(ip)
	if !found {
		return false
	}
	return cc == countryCode
}

// GetAllCountries возвращает список всех стран в базе
func (db *GeoIPDatabase) GetAllCountries() []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	countriesSet := make(map[string]bool)
	for _, country := range db.ipv4CIDRs {
		countriesSet[country] = true
	}
	for _, country := range db.ipv6CIDRs {
		countriesSet[country] = true
	}

	countries := make([]string, 0, len(countriesSet))
	for country := range countriesSet {
		countries = append(countries, country)
	}
	return countries
}

// Helper functions
func splitLines(s string) []string {
	// Используем strings.Split для более эффективного разбиения
	lines := strings.Split(s, "\n")
	var result []string
	for _, line := range lines {
		// Убираем \r если есть
		line = strings.TrimRight(line, "\r")
		if len(line) > 0 {
			result = append(result, line)
		}
	}
	return result
}

func splitByCommaOrSpace(s string) []string {
	// Сначала пробуем разделить по запятой
	if strings.Contains(s, ",") {
		parts := strings.Split(s, ",")
		var result []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if len(p) > 0 {
				result = append(result, p)
			}
		}
		if len(result) >= 2 {
			return result
		}
	}
	
	// Если запятой нет, разделяем по пробелам/табам
	parts := strings.Fields(s)
	return parts
}

// DownloadGeoIP загружает GeoIP базу с V2Ray репозитория
func DownloadGeoIP(url string, outputPath string) error {
	// Используем стандартный HTTP клиент
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download geoip: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download geoip: status %d", resp.StatusCode)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

