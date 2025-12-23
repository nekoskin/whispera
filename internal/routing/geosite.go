package routing

import (
	"fmt"
	"os"
	"strings"
	"sync"

	geosite "whispera/internal/geosite"
)

// GeoSiteDatabase представляет базу данных GeoSite (домены по странам)
type GeoSiteDatabase struct {
	sites map[string][]string // country -> domains
	mu    sync.RWMutex
	loaded bool
}

// NewGeoSiteDatabase создает новую базу данных GeoSite
func NewGeoSiteDatabase() *GeoSiteDatabase {
	return &GeoSiteDatabase{
		sites: make(map[string][]string),
	}
}

// LoadFromFile загружает GeoSite базу из файла (формат v2ray/sing-box)
// Поддерживает как бинарный формат v2ray (magic "v2rs"), так и текстовый формат
func (g *GeoSiteDatabase) LoadFromFile(filename string) error {
	if filename == "" {
		return nil // Опциональная база
	}

	data, err := os.ReadFile(filename) //nolint:gosec // Filename validated by caller
	if err != nil {
		return fmt.Errorf("failed to read GeoSite file: %w", err)
	}

	// Проверяем, является ли файл бинарным форматом v2ray
	if len(data) >= 4 {
		magic := string(data[:4])
		if magic == "v2rs" {
			// Используем бинарный парсер из internal/geosite
			geoSiteDB := geosite.NewGeoSiteDatabase()
			if err := geoSiteDB.LoadFromFile(filename); err != nil {
				return fmt.Errorf("failed to load binary v2ray GeoSite: %w", err)
			}
			// Конвертируем в формат routing engine
			return g.loadFromGeoSiteDatabase(geoSiteDB)
		}
	}

	// Используем текстовый формат
	return g.LoadFromBytes(data)
}

// loadFromGeoSiteDatabase загружает данные из geosite.GeoSiteDatabase
func (g *GeoSiteDatabase) loadFromGeoSiteDatabase(source *geosite.GeoSiteDatabase) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Получаем все страны и категории из source через GetAllCountries()
	allCountries := source.GetAllCountries()
	if len(allCountries) == 0 {
		// Fallback на известные страны если метод не работает
		allCountries = []string{
			"cn", "ru", "us", "gb", "de", "fr", "jp", "kr", "in", "br",
			"ca", "au", "nl", "it", "es", "pl", "tr", "mx", "ar", "cl",
			"ads", "category-ads-all", "category-porn", "category-scholar-!cn",
			"geolocation-!cn", "geolocation-cn", "tld-cn", "tld-!cn",
		}
	}
	
	for _, country := range allCountries {
		domains := source.GetDomains(country)
		if len(domains) > 0 {
			countryUpper := strings.ToUpper(country)
			if g.sites[countryUpper] == nil {
				g.sites[countryUpper] = make([]string, 0)
			}
			g.sites[countryUpper] = append(g.sites[countryUpper], domains...)
		}
	}
	
	g.loaded = true
	return nil
}

// LoadFromBytes загружает GeoSite базу из байтов
func (g *GeoSiteDatabase) LoadFromBytes(data []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Простой парсер для формата v2ray GeoSite
	// Формат: "country_code:domain1,domain2,..."
	lines := strings.Split(string(data), "\n")

	currentCountry := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Проверяем, является ли строка заголовком страны
		if strings.HasSuffix(line, ":") {
			currentCountry = strings.ToUpper(strings.TrimSuffix(line, ":"))
			if g.sites[currentCountry] == nil {
				g.sites[currentCountry] = make([]string, 0)
			}
			continue
		}

		// Или формат "country:domain1,domain2"
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentCountry = strings.ToUpper(strings.TrimSpace(parts[0]))
				domainsStr := strings.TrimSpace(parts[1])
				if g.sites[currentCountry] == nil {
					g.sites[currentCountry] = make([]string, 0)
				}

				domains := strings.Split(domainsStr, ",")
				for _, domain := range domains {
					domain = strings.TrimSpace(domain)
					if domain != "" {
						g.sites[currentCountry] = append(g.sites[currentCountry], domain)
					}
				}
				continue
			}
		}

		// Добавляем домен к текущей стране
		if currentCountry != "" {
			domain := strings.TrimSpace(line)
			if domain != "" {
				g.sites[currentCountry] = append(g.sites[currentCountry], domain)
			}
		}
	}

	g.loaded = true
	return nil
}

// LookupCountry определяет страну по домену
func (g *GeoSiteDatabase) LookupCountry(domain string) []string {
	if !g.loaded {
		return nil
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	countries := make([]string, 0)

	for country, domains := range g.sites {
		for _, d := range domains {
			d = strings.ToLower(strings.TrimSuffix(d, "."))
			if g.matchDomain(d, domain) {
				countries = append(countries, country)
				break
			}
		}
	}

	return countries
}

// matchDomain проверяет соответствие домена правилу
func (g *GeoSiteDatabase) matchDomain(rule, domain string) bool {
	// Точное совпадение
	if rule == domain {
		return true
	}

	// Suffix match
	if strings.HasPrefix(rule, ".") {
		return strings.HasSuffix(domain, rule)
	}

	// Full match
	if strings.HasPrefix(rule, "full:") {
		fullDomain := strings.TrimPrefix(rule, "full:")
		return fullDomain == domain
	}

	// Keyword match
	if strings.HasPrefix(rule, "keyword:") {
		keyword := strings.TrimPrefix(rule, "keyword:")
		return strings.Contains(domain, keyword)
	}

	// Regex match (упрощенная версия)
	if strings.HasPrefix(rule, "regexp:") {
		// В реальной реализации нужно использовать regexp
		// Для простоты пропускаем
		return false
	}

	// Domain match (suffix)
	return strings.HasSuffix(domain, "."+rule) || domain == rule
}

// IsLoaded возвращает, загружена ли база
func (g *GeoSiteDatabase) IsLoaded() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.loaded
}

