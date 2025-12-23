package routing

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	geoip "whispera/internal/geoip"
)

// GeoIPDatabase представляет базу данных GeoIP
type GeoIPDatabase struct {
	ipv4Ranges map[string][]*IPRange // country -> IP ranges
	ipv6Ranges map[string][]*IPRange6
	mu         sync.RWMutex
	loaded     bool
}

// IPRange представляет диапазон IPv4 адресов
type IPRange struct {
	Start uint32
	End   uint32
}

// IPRange6 представляет диапазон IPv6 адресов
type IPRange6 struct {
	Start [16]byte
	End   [16]byte
}

// NewGeoIPDatabase создает новую базу данных GeoIP
func NewGeoIPDatabase() *GeoIPDatabase {
	return &GeoIPDatabase{
		ipv4Ranges: make(map[string][]*IPRange),
		ipv6Ranges: make(map[string][]*IPRange6),
	}
}

// LoadFromFile загружает GeoIP базу из файла (формат v2ray/sing-box)
// Поддерживает как бинарный формат v2ray (magic "v2rg"), так и текстовый формат
func (g *GeoIPDatabase) LoadFromFile(filename string) error {
	if filename == "" {
		return nil // Опциональная база
	}

	data, err := os.ReadFile(filename) //nolint:gosec // Filename validated by caller
	if err != nil {
		return fmt.Errorf("failed to read GeoIP file: %w", err)
	}

	// Проверяем, является ли файл бинарным форматом v2ray
	if len(data) >= 4 {
		magic := string(data[:4])
		if magic == "v2rg" {
			// Используем бинарный парсер из internal/geoip
			geoipDB := geoip.NewGeoIPDatabase()
			if err := geoipDB.LoadFromFile(filename); err != nil {
				return fmt.Errorf("failed to load binary v2ray GeoIP: %w", err)
			}
			// Конвертируем в формат routing engine
			return g.loadFromGeoIPDatabase(geoipDB)
		}
	}

	// Используем текстовый формат
	return g.LoadFromBytes(data)
}

// loadFromGeoIPDatabase загружает данные из geoip.GeoIPDatabase
// Конвертирует CIDR -> Country mapping в Country -> IP ranges mapping
// Использует метод GetCountryCIDRs для получения всех CIDR по стране
func (g *GeoIPDatabase) loadFromGeoIPDatabase(source *geoip.GeoIPDatabase) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Получаем все страны из source через GetAllCountries()
	allCountries := source.GetAllCountries()
	if len(allCountries) == 0 {
		// Fallback на известные страны если метод не работает
		allCountries = []string{"CN", "RU", "US", "GB", "DE", "FR", "JP", "KR", "IN", "BR", "CA", "AU", "NL", "IT", "ES", "PL", "TR", "MX", "AR", "CL"}
	}
	
	// Конвертируем CIDR в IP ranges для каждой страны
	for _, country := range allCountries {
		cidrs := source.GetCountryCIDRs(country)
		if len(cidrs) == 0 {
			continue
		}
		
		if g.ipv4Ranges[country] == nil {
			g.ipv4Ranges[country] = make([]*IPRange, 0)
		}
		if g.ipv6Ranges[country] == nil {
			g.ipv6Ranges[country] = make([]*IPRange6, 0)
		}
		
		for _, cidrStr := range cidrs {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				continue
			}
			
			if ipNet.IP.To4() != nil {
				start, end := cidrToRange(ipNet)
				g.ipv4Ranges[country] = append(g.ipv4Ranges[country], &IPRange{
					Start: start,
					End:   end,
				})
			} else {
				start, end := cidrToRange6(ipNet)
				g.ipv6Ranges[country] = append(g.ipv6Ranges[country], &IPRange6{
					Start: start,
					End:   end,
				})
			}
		}
	}
	
	g.loaded = true
	return nil
}

// LoadFromBytes загружает GeoIP базу из байтов
func (g *GeoIPDatabase) LoadFromBytes(data []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Простой парсер для формата v2ray GeoIP
	// Формат: "country_code:ip_range1,ip_range2,..."
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		country := strings.ToUpper(strings.TrimSpace(parts[0]))
		rangesStr := strings.TrimSpace(parts[1])

		ranges := strings.Split(rangesStr, ",")
		for _, rangeStr := range ranges {
			rangeStr = strings.TrimSpace(rangeStr)
			if rangeStr == "" {
				continue
			}

			// Парсим CIDR или IP range
			if strings.Contains(rangeStr, "/") {
				// CIDR notation
				_, ipNet, err := net.ParseCIDR(rangeStr)
				if err != nil {
					continue
				}

				if ipNet.IP.To4() != nil {
					// IPv4
					start, end := cidrToRange(ipNet)
					if g.ipv4Ranges[country] == nil {
						g.ipv4Ranges[country] = make([]*IPRange, 0)
					}
					g.ipv4Ranges[country] = append(g.ipv4Ranges[country], &IPRange{
						Start: start,
						End:   end,
					})
				} else {
					// IPv6
					start, end := cidrToRange6(ipNet)
					if g.ipv6Ranges[country] == nil {
						g.ipv6Ranges[country] = make([]*IPRange6, 0)
					}
					g.ipv6Ranges[country] = append(g.ipv6Ranges[country], &IPRange6{
						Start: start,
						End:   end,
					})
				}
			}
		}
	}

	g.loaded = true
	return nil
}

// cidrToRange конвертирует CIDR в диапазон IPv4
func cidrToRange(ipNet *net.IPNet) (start, end uint32) {
	ip := ipNet.IP.To4()
	if ip == nil {
		return 0, 0
	}

	ones, bits := ipNet.Mask.Size()
	mask := uint32((1 << (bits - ones)) - 1)

	start = binary.BigEndian.Uint32(ip)
	end = start | mask

	return start, end
}

// cidrToRange6 конвертирует CIDR в диапазон IPv6
func cidrToRange6(ipNet *net.IPNet) (start, end [16]byte) {
	ip := ipNet.IP.To16()
	if ip == nil {
		return
	}

	copy(start[:], ip)

	// Правильная обработка CIDR маски для IPv6
	ones, bits := ipNet.Mask.Size()
	if bits != 128 {
		// Неверная маска для IPv6
		copy(end[:], ip)
		return
	}

	// Вычисляем количество бит хоста
	hostBits := 128 - ones
	
	// Если все биты используются для сети (ones == 128), то start == end
	if ones == 128 {
		copy(end[:], ip)
		return
	}

	// Копируем начальный IP
	copy(end[:], ip)

	// Вычисляем маску хоста (все биты хоста установлены в 1)
	// Для IPv6 это сложнее, так как нужно работать с 128 битами
	// Используем побайтовую обработку
	bytesToSet := hostBits / 8
	bitsToSet := hostBits % 8

	// Устанавливаем байты хоста в 0xFF
	for i := 15; i >= 16-bytesToSet; i-- {
		end[i] = 0xFF
	}

	// Устанавливаем оставшиеся биты в последнем байте
	if bitsToSet > 0 {
		byteIndex := 16 - bytesToSet - 1
		if byteIndex >= 0 {
			mask := byte((1 << bitsToSet) - 1)
			end[byteIndex] |= mask
		}
	}

	// Применяем OR операцию для получения конечного адреса
	for i := 0; i < 16; i++ {
		end[i] = start[i] | end[i]
	}

	return start, end
}

// LookupCountry определяет страну по IP адресу
func (g *GeoIPDatabase) LookupCountry(ip net.IP) string {
	if !g.loaded {
		return ""
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if ip.To4() != nil {
		// IPv4
		ipUint := binary.BigEndian.Uint32(ip.To4())
		for country, ranges := range g.ipv4Ranges {
			for _, r := range ranges {
				if ipUint >= r.Start && ipUint <= r.End {
					return country
				}
			}
		}
	} else {
		// IPv6
		ipBytes := ip.To16()
		if ipBytes == nil {
			return ""
		}
		for country, ranges := range g.ipv6Ranges {
			for _, r := range ranges {
				if compareIPv6(ipBytes, r.Start[:]) >= 0 && compareIPv6(ipBytes, r.End[:]) <= 0 {
					return country
				}
			}
		}
	}

	return ""
}

// compareIPv6 сравнивает два IPv6 адреса
func compareIPv6(a, b []byte) int {
	for i := 0; i < 16; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// IsLoaded возвращает, загружена ли база
func (g *GeoIPDatabase) IsLoaded() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.loaded
}

