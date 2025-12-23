package adblock

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"whispera/internal/obfuscation"
	"whispera/internal/obfuscation/core/types"
)

// AdBlocker - блокировщик рекламы с ML поддержкой
type AdBlocker struct {
	mu              sync.RWMutex
	enabled         bool
	dnsEnabled      bool
	httpsEnabled    bool
	mlEnabled       bool
	
	// DNS блокировка
	dnsBlockList    map[string]bool
	dnsRegexList    []*regexp.Regexp
	
	// HTTPS блокировка
	httpsBlockList  map[string]bool
	httpsRegexList  []*regexp.Regexp
	
	// ML система для обнаружения рекламы
	mlSystem        *MLAdDetector
	
	// Статистика
	stats           *AdBlockerStats
	
	// Кастомные правила
	customRules     []BlockRule
}

// BlockRule - правило блокировки
type BlockRule struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain,omitempty"`
	URL       string    `json:"url,omitempty"`
	Pattern   string    `json:"pattern,omitempty"`
	Type      string    `json:"type"` // "dns", "https", "both"
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// AdBlockerStats - статистика блокировщика
type AdBlockerStats struct {
	TotalBlocked     int64     `json:"total_blocked"`
	DNSBlocked       int64     `json:"dns_blocked"`
	HTTPSBlocked     int64     `json:"https_blocked"`
	MLBlocked        int64     `json:"ml_blocked"`
	LastBlocked      time.Time `json:"last_blocked"`
	BlockedDomains   map[string]int64 `json:"blocked_domains"`
	mu               sync.RWMutex
}

// MLAdDetector - ML детектор рекламы
type MLAdDetector struct {
	enabled     bool
	mlClient    *obfuscation.UnifiedMLSystem
	confidence  float64 // Порог уверенности (0.0-1.0)
	mu          sync.RWMutex
}

// NewAdBlocker создает новый блокировщик рекламы
func NewAdBlocker() *AdBlocker {
	ab := &AdBlocker{
		enabled:        true,
		dnsEnabled:     true,
		httpsEnabled:   true,
		mlEnabled:      true,
		dnsBlockList:   make(map[string]bool),
		httpsBlockList: make(map[string]bool),
		customRules:    make([]BlockRule, 0),
		stats: &AdBlockerStats{
			BlockedDomains: make(map[string]int64),
		},
		mlSystem: &MLAdDetector{
			enabled:    true,
			confidence: 0.7, // 70% уверенности
		},
	}
	
	// Загружаем базовые списки рекламы
	ab.loadDefaultLists()
	
	return ab
}

// Enable включает/выключает блокировщик
func (ab *AdBlocker) Enable(enabled bool) {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	ab.enabled = enabled
}

// SetDNSBlocking включает/выключает DNS блокировку
func (ab *AdBlocker) SetDNSBlocking(enabled bool) {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	ab.dnsEnabled = enabled
}

// SetHTTPSBlocking включает/выключает HTTPS блокировку
func (ab *AdBlocker) SetHTTPSBlocking(enabled bool) {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	ab.httpsEnabled = enabled
}

// SetMLBlocking включает/выключает ML блокировку
func (ab *AdBlocker) SetMLBlocking(enabled bool) {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	ab.mlEnabled = enabled
	ab.mlSystem.enabled = enabled
}

// ShouldBlockDNS проверяет нужно ли блокировать DNS запрос
func (ab *AdBlocker) ShouldBlockDNS(domain string) bool {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	
	if !ab.enabled || !ab.dnsEnabled {
		return false
	}
	
	domain = strings.ToLower(strings.TrimSpace(domain))
	
	// Проверка точного совпадения
	if ab.dnsBlockList[domain] {
		return true
	}
	
	// Проверка поддоменов
	for blockedDomain := range ab.dnsBlockList {
		if strings.HasSuffix(domain, "."+blockedDomain) || domain == blockedDomain {
			return true
		}
	}
	
	// Проверка regex
	for _, regex := range ab.dnsRegexList {
		if regex.MatchString(domain) {
			return true
		}
	}
	
	// Проверка кастомных правил
	for _, rule := range ab.customRules {
		if rule.Enabled && (rule.Type == "dns" || rule.Type == "both") {
			if rule.Domain != "" && (domain == rule.Domain || strings.HasSuffix(domain, "."+rule.Domain)) {
				return true
			}
			if rule.Pattern != "" {
				if matched, _ := regexp.MatchString(rule.Pattern, domain); matched {
					return true
				}
			}
		}
	}
	
	return false
}

// ShouldBlockHTTPS проверяет нужно ли блокировать HTTPS запрос
func (ab *AdBlocker) ShouldBlockHTTPS(urlStr string, headers http.Header, body []byte) bool {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	
	if !ab.enabled || !ab.httpsEnabled {
		return false
	}
	
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	
	host := strings.ToLower(parsedURL.Hostname())
	path := parsedURL.Path
	
	// Проверка DNS блокировки (домен)
	if ab.ShouldBlockDNS(host) {
		return true
	}
	
	// Проверка HTTPS блокировки
	if ab.httpsBlockList[host] {
		return true
	}
	
	// Проверка URL паттернов
	fullURL := strings.ToLower(urlStr)
	for blockedDomain := range ab.httpsBlockList {
		if strings.Contains(fullURL, blockedDomain) {
			return true
		}
	}
	
	// Проверка regex для URL
	for _, regex := range ab.httpsRegexList {
		if regex.MatchString(fullURL) || regex.MatchString(path) {
			return true
		}
	}
	
	// Проверка кастомных правил
	for _, rule := range ab.customRules {
		if rule.Enabled && (rule.Type == "https" || rule.Type == "both") {
			if rule.URL != "" && strings.Contains(fullURL, rule.URL) {
				return true
			}
			if rule.Pattern != "" {
				if matched, _ := regexp.MatchString(rule.Pattern, fullURL); matched {
					return true
				}
			}
		}
	}
	
	// ML проверка рекламы
	if ab.mlEnabled && ab.mlSystem.enabled {
		if ab.mlSystem.IsAd(urlStr, headers, body) {
			return true
		}
	}
	
	return false
}

// BlockDNS блокирует DNS запрос
func (ab *AdBlocker) BlockDNS(domain string) {
	ab.stats.mu.Lock()
	ab.stats.TotalBlocked++
	ab.stats.DNSBlocked++
	ab.stats.LastBlocked = time.Now()
	ab.stats.BlockedDomains[domain]++
	ab.stats.mu.Unlock()
	
	log.Printf("[AdBlocker] Blocked DNS: %s", domain)
}

// BlockHTTPS блокирует HTTPS запрос
func (ab *AdBlocker) BlockHTTPS(urlStr string, reason string) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return
	}
	domain := parsedURL.Hostname()
	
	ab.stats.mu.Lock()
	ab.stats.TotalBlocked++
	ab.stats.HTTPSBlocked++
	ab.stats.LastBlocked = time.Now()
	ab.stats.BlockedDomains[domain]++
	ab.stats.mu.Unlock()
	
	log.Printf("[AdBlocker] Blocked HTTPS: %s (reason: %s)", urlStr, reason)
}

// AddCustomRule добавляет кастомное правило
func (ab *AdBlocker) AddCustomRule(rule BlockRule) error {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	
	if rule.ID == "" {
		rule.ID = fmt.Sprintf("rule_%d", time.Now().UnixNano())
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now()
	}
	
	ab.customRules = append(ab.customRules, rule)
	return nil
}

// RemoveCustomRule удаляет кастомное правило
func (ab *AdBlocker) RemoveCustomRule(ruleID string) error {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	
	for i, rule := range ab.customRules {
		if rule.ID == ruleID {
			ab.customRules = append(ab.customRules[:i], ab.customRules[i+1:]...)
			return nil
		}
	}
	
	return fmt.Errorf("rule not found: %s", ruleID)
}

// GetStats возвращает статистику
func (ab *AdBlocker) GetStats() *AdBlockerStats {
	ab.stats.mu.RLock()
	defer ab.stats.mu.RUnlock()
	
	// Создаем копию для безопасного возврата
	statsCopy := &AdBlockerStats{
		TotalBlocked:   ab.stats.TotalBlocked,
		DNSBlocked:     ab.stats.DNSBlocked,
		HTTPSBlocked:   ab.stats.HTTPSBlocked,
		MLBlocked:      ab.stats.MLBlocked,
		LastBlocked:    ab.stats.LastBlocked,
		BlockedDomains: make(map[string]int64),
	}
	
	for k, v := range ab.stats.BlockedDomains {
		statsCopy.BlockedDomains[k] = v
	}
	
	return statsCopy
}

// loadDefaultLists загружает базовые списки рекламы
func (ab *AdBlocker) loadDefaultLists() {
	// Популярные рекламные домены
	defaultAdDomains := []string{
		"doubleclick.net",
		"googleadservices.com",
		"googlesyndication.com",
		"googletagmanager.com",
		"google-analytics.com",
		"facebook.com",
		"facebook.net",
		"ads.yahoo.com",
		"advertising.com",
		"adnxs.com",
		"rubiconproject.com",
		"openx.net",
		"pubmatic.com",
		"criteo.com",
		"outbrain.com",
		"taboola.com",
		"adform.com",
		"media.net",
		"adtech.com",
		"yandex.ru",
		"yandexadexchange.net",
		"mycdn.me",
		"vk.com",
		"vk.ru",
		"ok.ru",
		"mail.ru",
		"adfox.ru",
		"begun.ru",
		"adriver.ru",
		"tns-counter.ru",
		"top100.ru",
		"adriver.ru",
		"adnium.com",
		"amazon-adsystem.com",
		"amazon-adsystem.com",
		"adsrvr.org",
		"advertising.com",
		"adtechus.com",
		"advertising.com",
		"advertising.com",
		"adtechus.com",
		"advertising.com",
		"advertising.com",
	}
	
	for _, domain := range defaultAdDomains {
		ab.dnsBlockList[domain] = true
		ab.httpsBlockList[domain] = true
	}
	
	// Регулярные выражения для рекламных паттернов
	adPatterns := []string{
		`.*\.ads?\..*`,
		`.*ad[s]?[0-9]*\..*`,
		`.*advertising\..*`,
		`.*banner\..*`,
		`.*promo\..*`,
		`.*tracking\..*`,
		`.*analytics\..*`,
		`.*pixel\..*`,
		`.*tracker\..*`,
		`.*/ads?/.*`,
		`.*/advertising/.*`,
		`.*/banner/.*`,
		`.*/promo/.*`,
		`.*\.gif.*`,
		`.*\.swf.*`,
		`.*/tracking/.*`,
	}
	
	for _, pattern := range adPatterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			ab.dnsRegexList = append(ab.dnsRegexList, regex)
			ab.httpsRegexList = append(ab.httpsRegexList, regex)
		}
	}
	
	log.Printf("[AdBlocker] Loaded %d domains and %d patterns", len(ab.dnsBlockList), len(ab.dnsRegexList))
}

// LoadListFromFile загружает список из файла (EasyList формат)
func (ab *AdBlocker) LoadListFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	ab.mu.Lock()
	defer ab.mu.Unlock()
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Пропускаем комментарии и пустые строки
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}
		
		// EasyList формат: ||domain.com^
		if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
			domain := strings.TrimPrefix(line, "||")
			domain = strings.TrimSuffix(domain, "^")
			domain = strings.TrimSpace(domain)
			if domain != "" {
				ab.dnsBlockList[domain] = true
				ab.httpsBlockList[domain] = true
			}
			continue
		}
		
		// Простой формат: domain.com
		if !strings.Contains(line, "/") && !strings.Contains(line, "*") {
			ab.dnsBlockList[line] = true
			ab.httpsBlockList[line] = true
			continue
		}
		
		// Regex паттерн
		if strings.Contains(line, "*") || strings.Contains(line, "^") {
			pattern := line
			pattern = strings.ReplaceAll(pattern, "*", ".*")
			pattern = strings.ReplaceAll(pattern, "^", "$")
			if regex, err := regexp.Compile(pattern); err == nil {
				ab.dnsRegexList = append(ab.dnsRegexList, regex)
				ab.httpsRegexList = append(ab.httpsRegexList, regex)
			}
		}
	}
	
	if err := scanner.Err(); err != nil {
		return err
	}
	
	log.Printf("[AdBlocker] Loaded list from %s", filePath)
	return nil
}

// IsAd проверяет является ли запрос рекламой через ML
func (ml *MLAdDetector) IsAd(urlStr string, headers http.Header, body []byte) bool {
	ml.mu.RLock()
	defer ml.mu.RUnlock()
	
	if !ml.enabled || ml.mlClient == nil {
		return false
	}
	
	// Анализируем URL
	adIndicators := 0
	
	// Индикаторы в URL
	adKeywords := []string{"ad", "ads", "advertising", "banner", "promo", "tracking", "analytics", "pixel", "tracker"}
	urlLower := strings.ToLower(urlStr)
	for _, keyword := range adKeywords {
		if strings.Contains(urlLower, keyword) {
			adIndicators++
		}
	}
	
	// Анализируем заголовки
	if contentType := headers.Get("Content-Type"); contentType != "" {
		if strings.Contains(contentType, "image") || strings.Contains(contentType, "javascript") {
			// Проверяем размер - маленькие изображения часто реклама
			if len(body) > 0 && len(body) < 50000 {
				adIndicators++
			}
		}
	}
	
	// Анализируем User-Agent
	if ua := headers.Get("User-Agent"); ua != "" {
		uaLower := strings.ToLower(ua)
		if strings.Contains(uaLower, "ad") || strings.Contains(uaLower, "tracker") {
			adIndicators++
		}
	}
	
	// Если есть несколько индикаторов - считаем рекламой
	if adIndicators >= 2 {
		return true
	}
	
	// Используем ML систему если доступна
	if ml.mlClient != nil {
		context := &types.UnifiedTrafficContext{
			Direction: "inbound",
			Protocol:  "https",
			Size:      len(body),
			Timestamp: time.Now(),
		}
		
		// Анализируем трафик через ML
		processed, err := ml.mlClient.ProcessTraffic(body, context)
		if err == nil && processed != nil {
			// Если ML изменил трафик - вероятно это реклама
			if len(processed) < len(body) {
				return true
			}
		}
	}
	
	return false
}

// SetMLSystem устанавливает ML систему
func (ab *AdBlocker) SetMLSystem(mlSystem *obfuscation.UnifiedMLSystem) {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	ab.mlSystem.mlClient = mlSystem
}

// GetCustomRules возвращает кастомные правила
func (ab *AdBlocker) GetCustomRules() []BlockRule {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	
	rules := make([]BlockRule, len(ab.customRules))
	copy(rules, ab.customRules)
	return rules
}

