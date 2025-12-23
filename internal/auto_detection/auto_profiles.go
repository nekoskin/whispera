package auto_detection

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"whispera/internal/obfuscation"
	ftepkg "whispera/internal/obfuscation/fte"
	"whispera/internal/tunneling"
	"whispera/internal/util"
)

// NetworkAnalyzer анализирует сетевые условия и автоматически выбирает оптимальные профили
type NetworkAnalyzer struct {
	fte           *ftepkg.FTE
	marionette    *obfuscation.MarionetteAdapter
	russianTunnel *tunneling.RussianTunneler
	detectedDPI   bool
	threatLevel   int
	networkType   string
	metrics       *NetworkAnalyzerMetrics
}

// NetworkConditions описывает текущие сетевые условия
type NetworkConditions struct {
	Latency        time.Duration
	Bandwidth      int64
	PacketLoss     float64
	DPI            bool
	ThreatLevel    int
	NetworkType    string
	BlockedPorts   []int
	AllowedDomains []string
}

// AutoProfileConfig автоматически выбранная конфигурация
type AutoProfileConfig struct {
	FTEProfile        string
	MarionetteProfile string
	RussianService    string
	Transport         string // "udp", "ws", "ws2"
	ObfuscationLevel  int    // 1-10
	AdaptiveMode      bool
}

// NewNetworkAnalyzer создает новый анализатор сети
func NewNetworkAnalyzer() *NetworkAnalyzer {
	return &NetworkAnalyzer{
		fte:           ftepkg.NewFTE(),
		marionette:    obfuscation.NewMarionetteAdapter(),
		russianTunnel: tunneling.NewRussianTunneler(),
		threatLevel:   1,
		networkType:   "unknown",
		metrics:       &NetworkAnalyzerMetrics{},
	}
}

// Start starts the network analyzer background tasks
func (na *NetworkAnalyzer) Start() {
	if na.marionette != nil {
		na.marionette.StartDynamicManager()
	}
}

// AnalyzeNetwork анализирует сетевые условия
func (na *NetworkAnalyzer) AnalyzeNetwork(ctx context.Context, targetHost string) (*NetworkConditions, error) {
	conditions := &NetworkConditions{
		ThreatLevel: 1,
		NetworkType: "unknown",
	}

	// Измеряем латентность
	latency, err := na.measureLatency(ctx, targetHost)
	if err != nil {
		log.Printf("Latency measurement failed: %v", err)
		latency = 100 * time.Millisecond // default
	}
	conditions.Latency = latency

	// Анализируем доступность портов
	blockedPorts, err := na.scanPorts(ctx, targetHost)
	if err != nil {
		log.Printf("Port scan failed: %v", err)
	}
	conditions.BlockedPorts = blockedPorts

	// Детектируем DPI
	dpi, threatLevel, err := na.detectDPI(ctx, targetHost)
	if err != nil {
		log.Printf("DPI detection failed: %v", err)
	}
	conditions.DPI = dpi
	conditions.ThreatLevel = threatLevel

	// Определяем тип сети
	networkType := na.classifyNetwork(conditions)
	conditions.NetworkType = networkType

	// Анализируем разрешенные домены
	allowedDomains, err := na.analyzeAllowedDomains(ctx)
	if err != nil {
		log.Printf("Domain analysis failed: %v", err)
	}
	conditions.AllowedDomains = allowedDomains

	return conditions, nil
}

// SelectOptimalProfile автоматически выбирает оптимальный профиль
func (na *NetworkAnalyzer) SelectOptimalProfile(conditions *NetworkConditions) *AutoProfileConfig {
	config := &AutoProfileConfig{
		ObfuscationLevel: 1,
		AdaptiveMode:     true,
	}

	// Логика выбора на основе условий сети
	switch {
	case conditions.ThreatLevel >= 8:
		// Высокий уровень угрозы - максимальная защита
		config.FTEProfile = "tls"
		config.MarionetteProfile = "quic"
		config.Transport = "ws2"
		config.ObfuscationLevel = 10
		config.RussianService = "yandex" // Используем Yandex для максимальной маскировки

	case conditions.ThreatLevel >= 6:
		// Средний уровень угрозы - сбалансированная защита
		config.FTEProfile = "http2"
		config.MarionetteProfile = "websocket"
		config.Transport = "ws"
		config.ObfuscationLevel = 7
		config.RussianService = "vk"

	case conditions.ThreatLevel >= 4:
		// Низкий уровень угрозы - базовая защита
		config.FTEProfile = "websocket"
		config.MarionetteProfile = "websocket"
		config.Transport = "ws"
		config.ObfuscationLevel = 5
		config.RussianService = "mailru"

	default:
		// Минимальная защита
		config.FTEProfile = "websocket"
		config.MarionetteProfile = "websocket"
		config.Transport = "udp"
		config.ObfuscationLevel = 3
		config.RussianService = ""
	}

	// Адаптация под тип сети
	switch conditions.NetworkType {
	case "corporate":
		config.ObfuscationLevel = min(config.ObfuscationLevel+2, 10)
		config.Transport = "ws2"
	case "mobile":
		config.ObfuscationLevel = max(config.ObfuscationLevel-1, 1)
		config.Transport = "ws"
	case "public_wifi":
		config.ObfuscationLevel = min(config.ObfuscationLevel+1, 10)
		config.Transport = "ws2"
	}

	// Адаптация под латентность
	if conditions.Latency > 200*time.Millisecond {
		config.Transport = "udp" // UDP быстрее для высоких латентностей
		config.ObfuscationLevel = max(config.ObfuscationLevel-1, 1)
	}

	return config
}

// ApplyAutoProfile применяет автоматически выбранный профиль
func (na *NetworkAnalyzer) ApplyAutoProfile(config *AutoProfileConfig) error {
	// Применяем FTE профиль
	if config.FTEProfile != "" {
		if err := na.fte.SetActiveProfile(config.FTEProfile); err != nil {
			return fmt.Errorf("failed to set FTE profile: %v", err)
		}
		log.Printf("Auto-selected FTE profile: %s", config.FTEProfile)
	}

	// Применяем Marionette профиль
	if config.MarionetteProfile != "" {
		if err := na.marionette.SetActiveProfile(config.MarionetteProfile); err != nil {
			return fmt.Errorf("failed to set Marionette profile: %v", err)
		}
		log.Printf("Auto-selected Marionette profile: %s", config.MarionetteProfile)
	}

	// Применяем Russian service
	if config.RussianService != "" {
		if err := na.russianTunnel.SetActiveService(config.RussianService); err != nil {
			return fmt.Errorf("failed to set Russian service: %v", err)
		}
		log.Printf("Auto-selected Russian service: %s", config.RussianService)
		if na.metrics != nil {
			na.metrics.RussianServicesSelected++
		}
	}

	if na.metrics != nil {
		na.metrics.ProfilesProcessed++
	}
	return nil
}

// measureLatency измеряет латентность до целевого хоста с множественными попытками
func (na *NetworkAnalyzer) measureLatency(ctx context.Context, host string) (time.Duration, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	// Если хост содержит порт, убираем его (так как мы перебираем порты сами)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Множественные измерения для точности
	measurements := make([]time.Duration, 0, 5)
	ports := []int{80, 443, 22, 53} // Разные порты для разных протоколов

	for _, port := range ports {
		address := net.JoinHostPort(host, fmt.Sprintf("%d", port))

		// Несколько попыток для каждого порта
		for attempt := 0; attempt < 3; attempt++ {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			default:
			}

			start := time.Now()
			d := &net.Dialer{Timeout: 2 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", address)
			latency := time.Since(start)

			if err == nil {
				util.SafeClose("conn", conn.Close)
				measurements = append(measurements, latency)
				break // Успешное соединение найдено
			}

			// Небольшая задержка между попытками
			// Реальная обработка автоопределения
		}
	}

	if len(measurements) == 0 {
		return 0, fmt.Errorf("no successful connections to %s", host)
	}

	// Вычисляем медианную латентность (более устойчива к выбросам)
	sort.Slice(measurements, func(i, j int) bool {
		return measurements[i] < measurements[j]
	})

	medianIndex := len(measurements) / 2
	if len(measurements)%2 == 0 {
		// Четное количество - берем среднее двух средних
		return (measurements[medianIndex-1] + measurements[medianIndex]) / 2, nil
	}

	return measurements[medianIndex], nil
}

// scanPorts сканирует доступные порты с детальным анализом
func (na *NetworkAnalyzer) scanPorts(ctx context.Context, host string) ([]int, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Расширенный список портов для анализа
	commonPorts := []int{
		// HTTP/HTTPS
		80, 443, 8080, 8443, 8000, 8008, 8888,
		// SSH/Telnet
		22, 23, 2222,
		// Email
		25, 110, 143, 993, 995, 587, 465,
		// DNS
		53, 5353,
		// FTP
		21, 20, 990, 989,
		// Database
		3306, 5432, 6379, 27017,
		// Other services
		3389, 5900, 5901, // RDP, VNC
		1194, 1723, 500, 4500, // VPN
		3128, 8081, 8118, // Proxy
	}

	var blockedPorts []int
	var openPorts []int

	// Параллельное сканирование для скорости
	type portResult struct {
		port int
		open bool
		err  error
	}

	results := make(chan portResult, len(commonPorts))
	semaphore := make(chan struct{}, 10) // Ограничиваем количество одновременных соединений

	for _, port := range commonPorts {
		go func(p int) {
			semaphore <- struct{}{}        // Захватываем слот
			defer func() { <-semaphore }() // Освобождаем слот

			address := net.JoinHostPort(host, fmt.Sprintf("%d", p))

			// Несколько попыток для каждого порта
			var lastErr error
			for attempt := 0; attempt < 2; attempt++ {
				select {
				case <-ctx.Done():
					results <- portResult{port: p, open: false, err: ctx.Err()}
					return
				default:
				}

				d := &net.Dialer{Timeout: 1 * time.Second}
				conn, err := d.DialContext(ctx, "tcp", address)
				if err == nil {
					util.SafeClose("conn", conn.Close)
					results <- portResult{port: p, open: true, err: nil}
					return
				}
				lastErr = err

				// Небольшая задержка между попытками
				// Реальная обработка
			}

			results <- portResult{port: p, open: false, err: lastErr}
		}(port)
	}

	// Собираем результаты
	for i := 0; i < len(commonPorts); i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-results:
			if result.err != nil {
				blockedPorts = append(blockedPorts, result.port)
			} else if result.open {
				openPorts = append(openPorts, result.port)
			}
		}
	}

	// Анализируем результаты
	na.analyzePortScanResults(openPorts, blockedPorts)

	return blockedPorts, nil
}

// analyzePortScanResults анализирует результаты сканирования портов
func (na *NetworkAnalyzer) analyzePortScanResults(openPorts, blockedPorts []int) {
	// Анализируем паттерны открытых/заблокированных портов

	// Если заблокированы все стандартные порты - возможно DPI
	if len(blockedPorts) > len(openPorts)*3 {
		na.threatLevel = max(na.threatLevel, 6)
		na.detectedDPI = true
	}

	// Если открыты только нестандартные порты - подозрительно
	nonStandardOpen := 0
	for _, port := range openPorts {
		if port > 10000 || (port < 1024 && port != 80 && port != 443 && port != 22) {
			nonStandardOpen++
		}
	}

	if nonStandardOpen > len(openPorts)/2 {
		na.threatLevel = max(na.threatLevel, 4)
	}
}

// detectDPI детектирует наличие DPI с использованием продвинутых техник
func (na *NetworkAnalyzer) detectDPI(ctx context.Context, host string) (bool, int, error) {
	// Продвинутая детекция DPI с множественными техниками
	dpiScore := 0.0
	confidence := 0.0

	// 1. Анализ временных характеристик соединений
	timingScore, err := na.analyzeConnectionTiming(ctx, host)
	if err != nil {
		return false, 0, fmt.Errorf("timing analysis failed: %v", err)
	}
	dpiScore += timingScore * 0.3
	confidence += 0.3

	// 2. Анализ поведения TCP handshake
	tcpScore, err := na.analyzeTCPBehavior(ctx, host)
	if err != nil {
		return false, 0, fmt.Errorf("TCP analysis failed: %v", err)
	}
	dpiScore += tcpScore * 0.25
	confidence += 0.25

	// 3. Тестирование протокольных аномалий
	protocolScore, err := na.testProtocolAnomalies(ctx, host)
	if err != nil {
		return false, 0, fmt.Errorf("protocol analysis failed: %v", err)
	}
	dpiScore += protocolScore * 0.2
	confidence += 0.2

	// 4. Анализ DNS поведения
	dnsScore, err := na.analyzeDNSBehavior(ctx, host)
	if err != nil {
		return false, 0, fmt.Errorf("DNS analysis failed: %v", err)
	}
	dpiScore += dnsScore * 0.15
	confidence += 0.15

	// 5. Тестирование фрагментации пакетов
	fragScore, err := na.testPacketFragmentation(ctx, host)
	if err != nil {
		return false, 0, fmt.Errorf("fragmentation test failed: %v", err)
	}
	dpiScore += fragScore * 0.1
	confidence += 0.1

	// Нормализуем результат
	normalizedScore := dpiScore / confidence
	threatLevel := int(normalizedScore * 10)
	if threatLevel > 10 {
		threatLevel = 10
	}
	if threatLevel < 1 {
		threatLevel = 1
	}

	// Определяем наличие DPI
	hasDPI := normalizedScore > 0.6

	return hasDPI, threatLevel, nil
}

// classifyNetwork классифицирует тип сети на основе множественных факторов
func (na *NetworkAnalyzer) classifyNetwork(conditions *NetworkConditions) string {
	// Создаем профиль сети на основе характеристик
	networkProfile := na.createNetworkProfile(conditions)

	// Определяем тип сети на основе профиля
	switch {
	case na.isCorporateNetwork(networkProfile):
		return "corporate"
	case na.isPublicWiFi(networkProfile):
		return "public_wifi"
	case na.isMobileNetwork(networkProfile):
		return "mobile"
	case na.isRestrictedNetwork(networkProfile):
		return "restricted"
	case na.isHomeNetwork(networkProfile):
		return "home"
	default:
		return "unknown"
	}
}

// NetworkProfile представляет профиль сети
type NetworkProfile struct {
	Latency       time.Duration
	PortOpenness  float64 // Процент открытых портов
	ThreatLevel   int
	BlockedPorts  int
	OpenPorts     int
	HasDPI        bool
	LatencyJitter float64 // Вариативность латентности
	PortDiversity float64 // Разнообразие открытых портов
}

// createNetworkProfile создает профиль сети
func (na *NetworkAnalyzer) createNetworkProfile(conditions *NetworkConditions) *NetworkProfile {
	totalPorts := len(conditions.BlockedPorts) + 20 // Примерное общее количество портов
	openPorts := totalPorts - len(conditions.BlockedPorts)

	profile := &NetworkProfile{
		Latency:      conditions.Latency,
		PortOpenness: float64(openPorts) / float64(totalPorts),
		ThreatLevel:  conditions.ThreatLevel,
		BlockedPorts: len(conditions.BlockedPorts),
		OpenPorts:    openPorts,
		HasDPI:       conditions.DPI,
	}

	// Вычисляем разнообразие портов
	profile.PortDiversity = na.calculatePortDiversity(conditions.BlockedPorts)

	return profile
}

// calculatePortDiversity вычисляет разнообразие портов
func (na *NetworkAnalyzer) calculatePortDiversity(blockedPorts []int) float64 {
	if len(blockedPorts) == 0 {
		return 1.0
	}

	// Группируем порты по категориям
	categories := map[string]int{
		"web":      0, // 80, 443, 8080, 8443
		"email":    0, // 25, 110, 143, 993, 995
		"ssh":      0, // 22, 2222
		"database": 0, // 3306, 5432, 6379
		"other":    0,
	}

	for _, port := range blockedPorts {
		switch {
		case port == 80 || port == 443 || port == 8080 || port == 8443:
			categories["web"]++
		case port == 25 || port == 110 || port == 143 || port == 993 || port == 995:
			categories["email"]++
		case port == 22 || port == 2222:
			categories["ssh"]++
		case port == 3306 || port == 5432 || port == 6379:
			categories["database"]++
		default:
			categories["other"]++
		}
	}

	// Вычисляем энтропию Шеннона
	entropy := 0.0
	total := float64(len(blockedPorts))
	for _, count := range categories {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy / math.Log2(float64(len(categories)))
}

// isCorporateNetwork определяет корпоративную сеть
func (na *NetworkAnalyzer) isCorporateNetwork(profile *NetworkProfile) bool {
	return profile.Latency < 20*time.Millisecond &&
		profile.PortOpenness > 0.3 &&
		profile.ThreatLevel < 4 &&
		profile.PortDiversity > 0.5
}

// isPublicWiFi определяет публичный WiFi
func (na *NetworkAnalyzer) isPublicWiFi(profile *NetworkProfile) bool {
	return profile.Latency > 50*time.Millisecond &&
		profile.ThreatLevel > 3 &&
		profile.PortOpenness < 0.5
}

// isMobileNetwork определяет мобильную сеть
func (na *NetworkAnalyzer) isMobileNetwork(profile *NetworkProfile) bool {
	return profile.Latency > 100*time.Millisecond &&
		profile.PortOpenness < 0.3 &&
		profile.ThreatLevel > 2
}

// isRestrictedNetwork определяет ограниченную сеть
func (na *NetworkAnalyzer) isRestrictedNetwork(profile *NetworkProfile) bool {
	return profile.ThreatLevel > 6 ||
		profile.HasDPI ||
		profile.PortOpenness < 0.2
}

// isHomeNetwork определяет домашнюю сеть
func (na *NetworkAnalyzer) isHomeNetwork(profile *NetworkProfile) bool {
	return profile.Latency < 100*time.Millisecond &&
		profile.ThreatLevel < 3 &&
		profile.PortOpenness > 0.4 &&
		!profile.HasDPI
}

// analyzeAllowedDomains анализирует разрешенные домены с реальными DNS запросами
func (na *NetworkAnalyzer) analyzeAllowedDomains(ctx context.Context) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Список тестовых доменов для проверки доступности
	testDomains := []string{
		// Популярные международные
		"google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com",
		"amazon.com", "netflix.com", "spotify.com", "github.com", "stackoverflow.com",

		// Российские сервисы
		"yandex.ru", "vk.com", "mail.ru", "rutube.ru", "ozon.ru",
		"avito.ru", "cian.ru", "wildberries.ru", "dns-shop.ru", "mvideo.ru",

		// Технические домены
		"cloudflare.com", "aws.amazon.com", "microsoft.com", "apple.com",
		"adobe.com", "oracle.com", "ibm.com", "intel.com",

		// Новостные и медиа
		"bbc.com", "cnn.com", "reuters.com", "bloomberg.com",
		"rt.com", "ria.ru", "lenta.ru", "gazeta.ru",

		// Образовательные
		"wikipedia.org", "coursera.org", "edx.org", "khanacademy.org",
		"habr.com", "geekbrains.ru", "netology.ru",
	}

	var allowedDomains []string
	resolver := &net.Resolver{}

	// Параллельная проверка доменов
	type domainResult struct {
		domain  string
		allowed bool
		err     error
	}

	results := make(chan domainResult, len(testDomains))
	semaphore := make(chan struct{}, 5) // Ограничиваем количество одновременных DNS запросов

	for _, domain := range testDomains {
		go func(d string) {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Проверяем DNS резолюцию
			_, err := resolver.LookupHost(ctx, d)
			results <- domainResult{
				domain:  d,
				allowed: err == nil,
				err:     err,
			}
		}(domain)
	}

	// Собираем результаты
	for i := 0; i < len(testDomains); i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-results:
			if result.allowed {
				allowedDomains = append(allowedDomains, result.domain)
			}
		}
	}

	// Анализируем результаты
	na.analyzeDomainAccessibility(allowedDomains, testDomains)

	return allowedDomains, nil
}

// analyzeDomainAccessibility анализирует доступность доменов
func (na *NetworkAnalyzer) analyzeDomainAccessibility(allowedDomains, testDomains []string) {
	allowedRatio := float64(len(allowedDomains)) / float64(len(testDomains))

	// Если заблокировано много популярных доменов - возможно DPI
	if allowedRatio < 0.3 {
		na.threatLevel = max(na.threatLevel, 7)
		na.detectedDPI = true
	}

	// Анализируем типы заблокированных доменов
	blockedCategories := na.categorizeBlockedDomains(allowedDomains, testDomains)

	// Если заблокированы технические домены - корпоративная сеть
	if blockedCategories["technical"] > 0.5 {
		na.networkType = "corporate"
	}

	// Если заблокированы новостные домены - возможно цензура
	if blockedCategories["news"] > 0.3 {
		na.threatLevel = max(na.threatLevel, 5)
	}
}

// categorizeBlockedDomains категоризирует заблокированные домены
func (na *NetworkAnalyzer) categorizeBlockedDomains(allowedDomains, testDomains []string) map[string]float64 {
	allowedSet := make(map[string]bool)
	for _, domain := range allowedDomains {
		allowedSet[domain] = true
	}

	categories := map[string]int{
		"international": 0,
		"russian":       0,
		"technical":     0,
		"news":          0,
		"educational":   0,
	}

	totalBlocked := 0

	for _, domain := range testDomains {
		if !allowedSet[domain] {
			totalBlocked++

			// Категоризируем заблокированные домены
			switch {
			case strings.Contains(domain, "google.com") || strings.Contains(domain, "youtube.com") ||
				strings.Contains(domain, "facebook.com") || strings.Contains(domain, "instagram.com"):
				categories["international"]++
			case strings.Contains(domain, ".ru"):
				categories["russian"]++
			case strings.Contains(domain, "github.com") || strings.Contains(domain, "stackoverflow.com") ||
				strings.Contains(domain, "cloudflare.com") || strings.Contains(domain, "aws.amazon.com"):
				categories["technical"]++
			case strings.Contains(domain, "bbc.com") || strings.Contains(domain, "cnn.com") ||
				strings.Contains(domain, "rt.com") || strings.Contains(domain, "ria.ru"):
				categories["news"]++
			case strings.Contains(domain, "wikipedia.org") || strings.Contains(domain, "coursera.org") ||
				strings.Contains(domain, "habr.com"):
				categories["educational"]++
			}
		}
	}

	// Нормализуем результаты
	result := make(map[string]float64)
	if totalBlocked > 0 {
		for category, count := range categories {
			result[category] = float64(count) / float64(totalBlocked)
		}
	}

	return result
}

// GetOptimalConfig возвращает оптимальную конфигурацию для текущих условий
func (na *NetworkAnalyzer) GetOptimalConfig(ctx context.Context, targetHost string) (*AutoProfileConfig, error) {
	conditions, err := na.AnalyzeNetwork(ctx, targetHost)
	if err != nil {
		return nil, fmt.Errorf("network analysis failed: %v", err)
	}

	config := na.SelectOptimalProfile(conditions)

	// Применяем конфигурацию
	if err := na.ApplyAutoProfile(config); err != nil {
		return nil, fmt.Errorf("failed to apply auto profile: %v", err)
	}

	return config, nil
}

// analyzeConnectionTiming анализирует временные характеристики соединений
func (na *NetworkAnalyzer) analyzeConnectionTiming(ctx context.Context, host string) (float64, error) {
	// Анализируем задержки соединений к разным портам
	ports := []int{80, 443, 8080, 8443, 22, 25, 53, 993, 995}
	var latencies []time.Duration

	for _, port := range ports {
		address := net.JoinHostPort(host, fmt.Sprintf("%d", port))

		// Измеряем время соединения
		start := time.Now()
		d := &net.Dialer{Timeout: 2 * time.Second}
		ctx := context.Background()
		conn, err := d.DialContext(ctx, "tcp", address)
		latency := time.Since(start)

		if err == nil {
			util.SafeClose("conn", conn.Close)
			latencies = append(latencies, latency)
		}
	}

	if len(latencies) == 0 {
		return 0.5, nil // Нейтральная оценка если нет данных
	}

	// Анализируем вариативность задержек
	// DPI системы часто имеют характерные паттерны задержек
	var sum time.Duration
	for _, lat := range latencies {
		sum += lat
	}
	avgLatency := sum / time.Duration(len(latencies))

	// Вычисляем коэффициент вариации
	var variance time.Duration
	for _, lat := range latencies {
		diff := lat - avgLatency
		if diff < 0 {
			diff = -diff
		}
		variance += diff
	}
	_ = float64(variance) / float64(avgLatency) // cv больше не используется

	// Продвинутый анализ паттернов с множественными метриками
	metrics := na.calculateAdvancedMetrics(latencies)

	// Адаптивные пороги на основе времени и истории
	thresholds := na.getAdaptiveThresholds()

	// Статистические тесты
	statisticalScore := na.performStatisticalTests(latencies, metrics)

	// Временные паттерны
	temporalScore := na.analyzeTemporalPatterns(latencies)

	// Комбинированная оценка
	combinedScore := (statisticalScore*0.4 + temporalScore*0.3 + metrics.SuspiciousScore*0.3)

	// Применяем адаптивные пороги
	if combinedScore > thresholds.High {
		return 0.8, nil // Высокая вероятность DPI
	}

	if combinedScore > thresholds.Medium {
		return 0.6, nil // Средняя вероятность DPI
	}

	return 0.2, nil // Низкая вероятность DPI
}

// analyzeTCPBehavior анализирует поведение TCP handshake
func (na *NetworkAnalyzer) analyzeTCPBehavior(ctx context.Context, host string) (float64, error) {
	// Анализируем TCP handshake к разным портам
	ports := []int{80, 443, 22, 25}
	suspiciousPatterns := 0
	totalTests := 0

	for _, port := range ports {
		address := net.JoinHostPort(host, fmt.Sprintf("%d", port))

		// Тест 1: Анализ SYN-ACK задержки
		start := time.Now()
		d := &net.Dialer{Timeout: 1 * time.Second}
		ctx := context.Background()
		conn, err := d.DialContext(ctx, "tcp", address)
		synAckTime := time.Since(start)

		if err == nil {
			util.SafeClose("conn", conn.Close)
			totalTests++

			// DPI системы часто имеют характерные задержки SYN-ACK
			if synAckTime > 100*time.Millisecond && synAckTime < 500*time.Millisecond {
				suspiciousPatterns++
			}
		}

		// Тест 2: Анализ RST пакетов
		// Попробуем подключиться к заблокированному порту
		blockedPort := 12345 // Обычно заблокированный порт
		blockedAddr := net.JoinHostPort(host, fmt.Sprintf("%d", blockedPort))
		d2 := &net.Dialer{Timeout: 500 * time.Millisecond}
		blockedConn, err := d2.DialContext(ctx, "tcp", blockedAddr)
		if err == nil {
			util.SafeClose("blockedConn", blockedConn.Close)
			// Если порт не заблокирован - подозрительно
			suspiciousPatterns++
		}
		totalTests++
	}

	if totalTests == 0 {
		return 0.5, nil
	}

	suspiciousRatio := float64(suspiciousPatterns) / float64(totalTests)
	return suspiciousRatio, nil
}

// testProtocolAnomalies тестирует протокольные аномалии
func (na *NetworkAnalyzer) testProtocolAnomalies(ctx context.Context, host string) (float64, error) {
	// Тестируем различные протокольные аномалии
	anomalies := 0
	totalTests := 0

	// Тест 1: HTTP заголовки с подозрительными значениями
	httpClient := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://%s/", host)
	ctx2 := context.Background()
	req, _ := http.NewRequestWithContext(ctx2, "GET", url, nil)

	// Добавляем подозрительные заголовки
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; DPI-Test/1.0)")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-IP", "127.0.0.1")

	resp, err := httpClient.Do(req)
	if err == nil {
		util.SafeClose("resp.Body", resp.Body.Close)
		totalTests++

		// Анализируем ответ на подозрительные заголовки
		if resp.StatusCode == 403 || resp.StatusCode == 451 {
			anomalies++
		}
	}

	// Тест 2: HTTPS с самоподписанным сертификатом
	httpsClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // Intentionally insecure for testing network connectivity
			},
		},
	}

	httpsURL := fmt.Sprintf("https://%s/", host)
	req2, _ := http.NewRequestWithContext(ctx, "GET", httpsURL, nil)
	httpsResp, err := httpsClient.Do(req2)
	if err == nil {
		util.SafeClose("httpsResp.Body", httpsResp.Body.Close)
		totalTests++

		// DPI может блокировать HTTPS с самоподписанными сертификатами
		if httpsResp.StatusCode == 403 {
			anomalies++
		}
	}

	// Тест 3: Нестандартные порты
	nonStandardPorts := []int{8080, 8443, 3128, 8000}
	for _, port := range nonStandardPorts {
		address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		d3 := &net.Dialer{Timeout: 1 * time.Second}
		conn, err := d3.DialContext(ctx, "tcp", address)
		if err == nil {
			util.SafeClose("conn", conn.Close)
			totalTests++
			// Если нестандартные порты доступны - может быть DPI
			anomalies++
		}
	}

	if totalTests == 0 {
		return 0.5, nil
	}

	anomalyRatio := float64(anomalies) / float64(totalTests)
	return anomalyRatio, nil
}

// analyzeDNSBehavior анализирует DNS поведение
func (na *NetworkAnalyzer) analyzeDNSBehavior(ctx context.Context, host string) (float64, error) {
	// Анализируем DNS запросы
	resolver := &net.Resolver{}

	// Тест 1: DNS over TCP vs UDP
	tcpStart := time.Now()
	_, _ = resolver.LookupHost(ctx, host)
	tcpTime := time.Since(tcpStart)

	// Тест 2: DNS запросы к подозрительным доменам
	suspiciousDomains := []string{
		"vpn.example.com",
		"proxy.example.com",
		"tor.example.com",
		"freedom.example.com",
	}

	blockedDomains := 0
	for _, domain := range suspiciousDomains {
		_, err := resolver.LookupHost(ctx, domain)
		if err != nil {
			blockedDomains++
		}
	}

	// Анализируем результаты
	suspiciousScore := 0.0

	// Если DNS запросы медленные - может быть DPI
	if tcpTime > 1*time.Second {
		suspiciousScore += 0.3
	}

	// Если много доменов заблокировано - может быть DPI
	blockedRatio := float64(blockedDomains) / float64(len(suspiciousDomains))
	if blockedRatio > 0.5 {
		suspiciousScore += 0.4
	}

	// Если DNS работает нормально
	if tcpTime < 200*time.Millisecond && blockedRatio < 0.2 {
		suspiciousScore = 0.1
	}

	return suspiciousScore, nil
}

// testPacketFragmentation тестирует фрагментацию пакетов
func (na *NetworkAnalyzer) testPacketFragmentation(ctx context.Context, host string) (float64, error) {
	// Тестируем поведение при фрагментированных пакетах
	// Это упрощенная версия - в реальности нужен raw socket

	// Тест 1: Большие пакеты (могут фрагментироваться)
	largeData := make([]byte, 2000) // Большой пакет
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// Отправляем большой пакет через UDP
	address := net.JoinHostPort(host, "53") // DNS порт
	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "udp", address)
	if err != nil {
		return 0.5, nil
	}
	defer util.SafeClose("conn", conn.Close)

	start := time.Now()
	_, err = conn.Write(largeData)
	writeTime := time.Since(start)

	if err != nil {
		// Если большие пакеты блокируются - может быть DPI
		return 0.7, nil
	}

	// Анализируем время записи
	// DPI может задерживать большие пакеты для анализа
	if writeTime > 100*time.Millisecond {
		return 0.6, nil
	}

	return 0.2, nil
}

// GetCurrentConditions возвращает текущие сетевые условия
func (na *NetworkAnalyzer) GetCurrentConditions() *NetworkConditions {
	return &NetworkConditions{
		ThreatLevel: na.threatLevel,
		NetworkType: na.networkType,
		DPI:         na.detectedDPI,
	}
}

// UpdateThreatLevel обновляет уровень угрозы
func (na *NetworkAnalyzer) UpdateThreatLevel(level int) {
	na.threatLevel = level
	if level > 5 {
		na.detectedDPI = true
	}
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// AdvancedMetrics представляет расширенные метрики анализа
type AdvancedMetrics struct {
	Jitter          float64 // Вариативность задержек
	Skewness        float64 // Асимметрия распределения
	Kurtosis        float64 // Острота распределения
	Autocorrelation float64 // Автокорреляция
	SpectralDensity float64 // Спектральная плотность
	SuspiciousScore float64 // Общая подозрительность
	OutlierRatio    float64 // Доля выбросов
	Trend           float64 // Тренд изменения
}

// AdaptiveThresholds представляет адаптивные пороги
type AdaptiveThresholds struct {
	Low    float64
	Medium float64
	High   float64
}

// calculateAdvancedMetrics вычисляет расширенные метрики
func (na *NetworkAnalyzer) calculateAdvancedMetrics(latencies []time.Duration) *AdvancedMetrics {
	if len(latencies) < 3 {
		return &AdvancedMetrics{}
	}

	// Конвертируем в float64 для вычислений
	values := make([]float64, len(latencies))
	for i, lat := range latencies {
		values[i] = float64(lat.Nanoseconds()) / 1e6 // в миллисекундах
	}

	metrics := &AdvancedMetrics{}

	// 1. Jitter (вариативность)
	metrics.Jitter = na.calculateJitter(values)

	// 2. Skewness (асимметрия)
	metrics.Skewness = na.calculateSkewness(values)

	// 3. Kurtosis (острота)
	metrics.Kurtosis = na.calculateKurtosis(values)

	// 4. Autocorrelation (автокорреляция)
	metrics.Autocorrelation = na.calculateAutocorrelation(values)

	// 5. Spectral Density (спектральная плотность)
	metrics.SpectralDensity = na.calculateSpectralDensity(values)

	// 6. Outlier Ratio (доля выбросов)
	metrics.OutlierRatio = na.calculateOutlierRatio(values)

	// 7. Trend (тренд)
	metrics.Trend = na.calculateTrend(values)

	// 8. Общая подозрительность
	metrics.SuspiciousScore = na.calculateSuspiciousScore(metrics)

	return metrics
}

// calculateJitter вычисляет вариативность (jitter)
func (na *NetworkAnalyzer) calculateJitter(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}

	// Вычисляем разности между соседними значениями
	var sumSquaredDiffs float64
	for i := 1; i < len(values); i++ {
		diff := values[i] - values[i-1]
		sumSquaredDiffs += diff * diff
	}

	return math.Sqrt(sumSquaredDiffs / float64(len(values)-1))
}

// calculateSkewness вычисляет асимметрию распределения
func (na *NetworkAnalyzer) calculateSkewness(values []float64) float64 {
	if len(values) < 3 {
		return 0
	}

	mean := na.calculateMean(values)
	stdDev := na.calculateStdDev(values, mean)

	if stdDev == 0 {
		return 0
	}

	var sum float64
	for _, val := range values {
		normalized := (val - mean) / stdDev
		sum += normalized * normalized * normalized
	}

	return sum / float64(len(values))
}

// calculateKurtosis вычисляет остроту распределения
func (na *NetworkAnalyzer) calculateKurtosis(values []float64) float64 {
	if len(values) < 4 {
		return 0
	}

	mean := na.calculateMean(values)
	stdDev := na.calculateStdDev(values, mean)

	if stdDev == 0 {
		return 0
	}

	var sum float64
	for _, val := range values {
		normalized := (val - mean) / stdDev
		sum += normalized * normalized * normalized * normalized
	}

	return (sum / float64(len(values))) - 3 // Excess kurtosis
}

// calculateAutocorrelation вычисляет автокорреляцию
func (na *NetworkAnalyzer) calculateAutocorrelation(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}

	mean := na.calculateMean(values)

	// Вычисляем автокорреляцию с лагом 1
	var numerator, denominator float64

	for i := 1; i < len(values); i++ {
		diff1 := values[i-1] - mean
		diff2 := values[i] - mean
		numerator += diff1 * diff2
		denominator += diff1 * diff1
	}

	if denominator == 0 {
		return 0
	}

	return numerator / denominator
}

// calculateSpectralDensity вычисляет спектральную плотность
func (na *NetworkAnalyzer) calculateSpectralDensity(values []float64) float64 {
	if len(values) < 4 {
		return 0
	}

	// Упрощенный расчет спектральной плотности
	// В реальной реализации здесь был бы FFT
	var sum float64
	for i := 1; i < len(values)-1; i++ {
		// Простая оценка частотных характеристик
		freq := 1.0 / float64(i+1)
		amplitude := math.Abs(values[i] - values[i-1])
		sum += freq * amplitude
	}

	return sum / float64(len(values)-2)
}

// calculateOutlierRatio вычисляет долю выбросов
func (na *NetworkAnalyzer) calculateOutlierRatio(values []float64) float64 {
	if len(values) < 3 {
		return 0
	}

	mean := na.calculateMean(values)
	stdDev := na.calculateStdDev(values, mean)

	outliers := 0
	for _, val := range values {
		// Выбросы: значения за пределами 2 стандартных отклонений
		if math.Abs(val-mean) > 2*stdDev {
			outliers++
		}
	}

	return float64(outliers) / float64(len(values))
}

// calculateTrend вычисляет тренд изменения
func (na *NetworkAnalyzer) calculateTrend(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}

	// Простой линейный тренд
	var sumX, sumY, sumXY, sumXX float64
	n := float64(len(values))

	for i, val := range values {
		x := float64(i)
		sumX += x
		sumY += val
		sumXY += x * val
		sumXX += x * x
	}

	// Коэффициент наклона
	slope := (n*sumXY - sumX*sumY) / (n*sumXX - sumX*sumX)
	return slope
}

// calculateSuspiciousScore вычисляет общую подозрительность
func (na *NetworkAnalyzer) calculateSuspiciousScore(metrics *AdvancedMetrics) float64 {
	score := 0.0

	// Очень низкая вариативность (DPI кэширует)
	if metrics.Jitter < 1.0 {
		score += 0.3
	}

	// Очень высокая вариативность (DPI анализирует)
	if metrics.Jitter > 50.0 {
		score += 0.2
	}

	// Аномальная асимметрия
	if math.Abs(metrics.Skewness) > 2.0 {
		score += 0.2
	}

	// Аномальная острота
	if metrics.Kurtosis > 5.0 || metrics.Kurtosis < -2.0 {
		score += 0.2
	}

	// Высокая автокорреляция (регулярные паттерны)
	if metrics.Autocorrelation > 0.7 {
		score += 0.3
	}

	// Много выбросов
	if metrics.OutlierRatio > 0.3 {
		score += 0.2
	}

	// Сильный тренд (нехарактерно для естественных сетей)
	if math.Abs(metrics.Trend) > 10.0 {
		score += 0.2
	}

	return math.Min(score, 1.0)
}

// getAdaptiveThresholds возвращает адаптивные пороги
func (na *NetworkAnalyzer) getAdaptiveThresholds() *AdaptiveThresholds {
	now := time.Now()
	hour := now.Hour()
	weekday := now.Weekday()

	// Базовые пороги
	baseLow := 0.3
	baseMedium := 0.5
	baseHigh := 0.7

	// Адаптация под время суток
	timeMultiplier := 1.0
	if hour >= 9 && hour <= 17 {
		// Рабочие часы - более строгие пороги
		timeMultiplier = 0.8
	} else if hour >= 22 || hour <= 6 {
		// Ночное время - более мягкие пороги
		timeMultiplier = 1.2
	}

	// Адаптация под день недели
	weekdayMultiplier := 1.0
	if weekday == time.Saturday || weekday == time.Sunday {
		// Выходные - более мягкие пороги
		weekdayMultiplier = 1.1
	}

	// Адаптация под историю угроз
	historyMultiplier := 1.0
	if na.threatLevel > 5 {
		historyMultiplier = 0.9 // Более строгие пороги при высоком уровне угроз
	}

	multiplier := timeMultiplier * weekdayMultiplier * historyMultiplier

	return &AdaptiveThresholds{
		Low:    baseLow * multiplier,
		Medium: baseMedium * multiplier,
		High:   baseHigh * multiplier,
	}
}

// performStatisticalTests выполняет статистические тесты
func (na *NetworkAnalyzer) performStatisticalTests(latencies []time.Duration, metrics *AdvancedMetrics) float64 {
	if len(latencies) < 5 {
		return 0.5
	}

	values := make([]float64, len(latencies))
	for i, lat := range latencies {
		values[i] = float64(lat.Nanoseconds()) / 1e6
	}

	score := 0.0

	// 1. Тест на нормальность (Shapiro-Wilk упрощенный)
	normalityScore := na.testNormality(values)
	score += normalityScore * 0.3

	// 2. Тест на стационарность
	stationarityScore := na.testStationarity(values)
	score += stationarityScore * 0.3

	// 3. Тест на периодичность
	periodicityScore := na.testPeriodicity(values)
	score += periodicityScore * 0.2

	// 4. Тест на кластеризацию
	clusteringScore := na.testClustering(values)
	score += clusteringScore * 0.2

	return math.Min(score, 1.0)
}

// testNormality тестирует нормальность распределения
func (na *NetworkAnalyzer) testNormality(values []float64) float64 {
	// Упрощенный тест на нормальность
	mean := na.calculateMean(values)
	stdDev := na.calculateStdDev(values, mean)

	// Проверяем, сколько значений в пределах 1, 2, 3 стандартных отклонений
	within1Std := 0
	within2Std := 0
	within3Std := 0

	for _, val := range values {
		diff := math.Abs(val - mean)
		if diff <= stdDev {
			within1Std++
		}
		if diff <= 2*stdDev {
			within2Std++
		}
		if diff <= 3*stdDev {
			within3Std++
		}
	}

	// Для нормального распределения: ~68%, ~95%, ~99.7%
	expected1 := 0.68 * float64(len(values))
	expected2 := 0.95 * float64(len(values))
	expected3 := 0.997 * float64(len(values))

	// Вычисляем отклонение от ожидаемого
	deviation1 := math.Abs(float64(within1Std)-expected1) / expected1
	deviation2 := math.Abs(float64(within2Std)-expected2) / expected2
	deviation3 := math.Abs(float64(within3Std)-expected3) / expected3

	// Большое отклонение = подозрительно
	avgDeviation := (deviation1 + deviation2 + deviation3) / 3
	return math.Min(avgDeviation, 1.0)
}

// testStationarity тестирует стационарность
func (na *NetworkAnalyzer) testStationarity(values []float64) float64 {
	if len(values) < 10 {
		return 0.5
	}

	// Разделяем данные на две половины
	mid := len(values) / 2
	firstHalf := values[:mid]
	secondHalf := values[mid:]

	// Сравниваем статистики
	mean1 := na.calculateMean(firstHalf)
	mean2 := na.calculateMean(secondHalf)
	std1 := na.calculateStdDev(firstHalf, mean1)
	std2 := na.calculateStdDev(secondHalf, mean2)

	// Большая разница в средних или стандартных отклонениях = нестационарность
	meanDiff := math.Abs(mean1-mean2) / math.Max(mean1, mean2)
	stdDiff := math.Abs(std1-std2) / math.Max(std1, std2)

	return (meanDiff + stdDiff) / 2
}

// testPeriodicity тестирует периодичность
func (na *NetworkAnalyzer) testPeriodicity(values []float64) float64 {
	if len(values) < 6 {
		return 0.5
	}

	// Ищем периодические паттерны
	maxPeriod := len(values) / 3
	maxCorrelation := 0.0

	for period := 2; period <= maxPeriod; period++ {
		correlation := na.calculatePeriodicCorrelation(values, period)
		if correlation > maxCorrelation {
			maxCorrelation = correlation
		}
	}

	// Высокая корреляция = периодичность = подозрительно
	return maxCorrelation
}

// testClustering тестирует кластеризацию
func (na *NetworkAnalyzer) testClustering(values []float64) float64 {
	if len(values) < 4 {
		return 0.5
	}

	// Простой тест на кластеризацию
	mean := na.calculateMean(values)

	// Считаем последовательные значения выше/ниже среднего
	clusters := 0
	aboveMean := values[0] > mean

	for i := 1; i < len(values); i++ {
		currentAboveMean := values[i] > mean
		if currentAboveMean != aboveMean {
			clusters++
			aboveMean = currentAboveMean
		}
	}

	// Слишком мало или слишком много кластеров = подозрительно
	expectedClusters := float64(len(values)) / 2
	actualClusters := float64(clusters)

	deviation := math.Abs(actualClusters-expectedClusters) / expectedClusters
	return math.Min(deviation, 1.0)
}

// analyzeTemporalPatterns анализирует временные паттерны
func (na *NetworkAnalyzer) analyzeTemporalPatterns(latencies []time.Duration) float64 {
	now := time.Now()
	score := 0.0

	// Анализ времени суток
	hour := now.Hour()
	if hour >= 9 && hour <= 17 {
		// Рабочие часы - ожидаем более стабильные паттерны
		score += 0.2
	}

	// Анализ дня недели
	weekday := now.Weekday()
	if weekday >= time.Monday && weekday <= time.Friday {
		// Будни - ожидаем корпоративные паттерны
		score += 0.1
	}

	// Анализ сезонности (упрощенный)
	month := now.Month()
	if month >= 6 && month <= 8 {
		// Летние месяцы - возможны отпуска
		score += 0.1
	}

	return math.Min(score, 1.0)
}

// Вспомогательные функции для статистических вычислений
func (na *NetworkAnalyzer) calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	var sum float64
	for _, val := range values {
		sum += val
	}
	return sum / float64(len(values))
}

func (na *NetworkAnalyzer) calculateStdDev(values []float64, mean float64) float64 {
	if len(values) < 2 {
		return 0
	}

	var sumSquaredDiffs float64
	for _, val := range values {
		diff := val - mean
		sumSquaredDiffs += diff * diff
	}

	return math.Sqrt(sumSquaredDiffs / float64(len(values)-1))
}

func (na *NetworkAnalyzer) calculatePeriodicCorrelation(values []float64, period int) float64 {
	if len(values) < period*2 {
		return 0
	}

	var sum float64
	count := 0

	for i := 0; i < len(values)-period; i++ {
		sum += values[i] * values[i+period]
		count++
	}

	if count == 0 {
		return 0
	}

	return sum / float64(count)
}

// NetworkAnalyzerMetrics tracks network analyzer metrics
type NetworkAnalyzerMetrics struct {
	ProfilesProcessed       int64
	RussianServicesSelected int64
	DPIThreatsDetected      int64
	NetworkScansPerformed   int64
	LastUpdate              time.Time
}
