package geosite

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

// GeoSiteDatabase представляет базу данных доменов по странам
type GeoSiteDatabase struct {
	domains map[string][]string // Country Code -> []Domain
	mu      sync.RWMutex
}

// NewGeoSiteDatabase создает новую базу данных GeoSite
func NewGeoSiteDatabase() *GeoSiteDatabase {
	return &GeoSiteDatabase{
		domains: make(map[string][]string),
	}
}

// LoadFromFile загружает GeoSite базу из файла (V2Ray формат)
// V2Ray формат: [4 bytes magic "v2rs"] [4 bytes version] [4 bytes count] [entries...]
// Entry: [1 byte country_code_len] [country_code bytes] [4 bytes domain_count] [domains...]
// Domain: [1 byte domain_len] [domain bytes]
func (db *GeoSiteDatabase) LoadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open geosite file: %w", err)
	}
	defer file.Close()

	db.mu.Lock()
	defer db.mu.Unlock()

	// Очищаем существующие данные
	db.domains = make(map[string][]string)

	// Читаем заголовок (первые 12 байт: magic + version + count)
	header := make([]byte, 12)
	if _, err := io.ReadFull(file, header); err != nil {
		if err == io.EOF {
			// Файл слишком короткий, пробуем простой формат
			return db.loadSimpleFormat(file)
		}
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Проверяем магическое число (V2Ray формат: "v2rs")
	magic := string(header[:4])
	if magic != "v2rs" {
		// Пробуем альтернативный формат
		return db.loadSimpleFormat(file)
	}

	// Читаем версию (не используется, но нужно пропустить)
	_ = binary.BigEndian.Uint32(header[4:8])

	// Читаем количество стран/категорий
	count := binary.BigEndian.Uint32(header[8:12])

	loadedCountries := 0
	for i := uint32(0); i < count; i++ {
		// Читаем длину country code или категории
		ccLenBytes := make([]byte, 1)
		if _, err := io.ReadFull(file, ccLenBytes); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		ccLen := int(ccLenBytes[0])

		// Валидация длины
		if ccLen == 0 || ccLen > 50 {
			continue
		}

		// Читаем country code или категорию (например, "cn:category:ads")
		ccBytes := make([]byte, ccLen)
		if _, err := io.ReadFull(file, ccBytes); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		countryCode := string(ccBytes)

		// Читаем количество доменов
		domainCountBytes := make([]byte, 4)
		if _, err := io.ReadFull(file, domainCountBytes); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		domainCount := binary.BigEndian.Uint32(domainCountBytes)

		var domains []string
		for j := uint32(0); j < domainCount; j++ {
			// Читаем длину домена
			domainLenBytes := make([]byte, 1)
			if _, err := io.ReadFull(file, domainLenBytes); err != nil {
				if err == io.EOF {
					break
				}
				continue
			}
			domainLen := int(domainLenBytes[0])

			// Валидация длины домена
			if domainLen == 0 || domainLen > 255 {
				continue
			}

			// Читаем домен
			domainBytes := make([]byte, domainLen)
			if _, err := io.ReadFull(file, domainBytes); err != nil {
				if err == io.EOF {
					break
				}
				continue
			}
			domain := string(domainBytes)

			// Нормализуем домен (lowercase, trim)
			domain = strings.ToLower(strings.TrimSpace(domain))
			if domain != "" {
				domains = append(domains, domain)
			}
		}

		if len(domains) > 0 {
			// Объединяем с существующими доменами для этой страны/категории
			if existing, ok := db.domains[countryCode]; ok {
				db.domains[countryCode] = append(existing, domains...)
			} else {
				db.domains[countryCode] = domains
			}
			loadedCountries++
		}
	}

	// Если не загрузили ни одной записи, пробуем простой формат
	if loadedCountries == 0 {
		return db.loadSimpleFormat(file)
	}

	return nil
}

// loadSimpleFormat загружает простой текстовый формат
func (db *GeoSiteDatabase) loadSimpleFormat(file *os.File) error {
	file.Seek(0, 0)
	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	currentCountry := ""
	loadedCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// Формат: country:domain или country:category:domain или domain (продолжение предыдущей страны)
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			currentCountry = strings.ToLower(strings.TrimSpace(parts[0]))
			if len(parts) > 1 {
				domain := strings.ToLower(strings.TrimSpace(parts[1]))
				if domain != "" && currentCountry != "" {
					if db.domains[currentCountry] == nil {
						db.domains[currentCountry] = []string{}
					}
					db.domains[currentCountry] = append(db.domains[currentCountry], domain)
					loadedCount++
				}
			}
		} else if currentCountry != "" {
			domain := strings.ToLower(strings.TrimSpace(line))
			if domain != "" {
				if db.domains[currentCountry] == nil {
					db.domains[currentCountry] = []string{}
				}
				db.domains[currentCountry] = append(db.domains[currentCountry], domain)
				loadedCount++
			}
		}
	}

	if loadedCount == 0 {
		return fmt.Errorf("no valid entries found in file")
	}

	return nil
}

// GetDomains возвращает домены для указанной страны или категории
func (db *GeoSiteDatabase) GetDomains(countryCode string) []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	countryCode = strings.ToLower(strings.TrimSpace(countryCode))
	domains, ok := db.domains[countryCode]
	if !ok {
		return nil
	}

	result := make([]string, len(domains))
	copy(result, domains)
	return result
}

// GetCategories возвращает список всех категорий для указанной страны
// Формат категории: "country:category:name" (например, "cn:category:ads")
func (db *GeoSiteDatabase) GetCategories(countryCode string) []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	countryCode = strings.ToLower(strings.TrimSpace(countryCode))
	prefix := countryCode + ":category:"
	
	var categories []string
	for key := range db.domains {
		if strings.HasPrefix(key, prefix) {
			// Извлекаем название категории
			category := strings.TrimPrefix(key, prefix)
			if category != "" {
				categories = append(categories, category)
			}
		}
	}
	
	return categories
}

// GetAllCountries возвращает список всех стран и категорий в базе
func (db *GeoSiteDatabase) GetAllCountries() []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	countries := make([]string, 0, len(db.domains))
	for country := range db.domains {
		countries = append(countries, country)
	}
	return countries
}

// IsDomainInCategory проверяет, принадлежит ли домен указанной категории
// category может быть в формате "country:category:name" или просто "category:name"
func (db *GeoSiteDatabase) IsDomainInCategory(domain, category string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()

	category = strings.ToLower(strings.TrimSpace(category))
	domains, ok := db.domains[category]
	if !ok {
		return false
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	domain = strings.TrimPrefix(domain, ".")

	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}

		if d == domain || strings.HasSuffix(domain, "."+d) {
			return true
		}

		if strings.HasPrefix(d, ".") {
			wildcard := d[1:]
			if domain == wildcard || strings.HasSuffix(domain, "."+wildcard) {
				return true
			}
		}
	}

	return false
}

// IsDomainInCountry проверяет, принадлежит ли домен указанной стране
func (db *GeoSiteDatabase) IsDomainInCountry(domain, countryCode string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()

	domains, ok := db.domains[countryCode]
	if !ok {
		return false
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	// Убираем ведущую точку если есть
	domain = strings.TrimPrefix(domain, ".")

	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}

		// Точное совпадение
		if d == domain {
			return true
		}

		// Проверка суффикса (поддомен)
		if strings.HasSuffix(domain, "."+d) {
			return true
		}

		// Поддержка wildcard доменов (начинающихся с ".")
		if strings.HasPrefix(d, ".") {
			wildcard := d[1:] // Убираем ведущую точку
			if domain == wildcard || strings.HasSuffix(domain, "."+wildcard) {
				return true
			}
		}

		// Поддержка доменов с ведущей точкой в базе
		if strings.HasPrefix(d, ".") {
			if strings.HasSuffix(domain, d) {
				return true
			}
		}
	}

	return false
}

// DownloadGeoSite загружает GeoSite базу с V2Ray репозитория
func DownloadGeoSite(url string, outputPath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download geosite: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download geosite: status %d", resp.StatusCode)
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

