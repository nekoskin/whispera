package adblock

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Rule представляет правило блокировки AdBlock
type Rule struct {
	Raw      string         // Оригинальная строка правила
	Pattern  *regexp.Regexp // Скомпилированный паттерн
	Type     RuleType       // Тип правила
	Options  []string       // Опции правила (domain, etc.)
	Exception bool          // Является ли это исключением
}

// RuleType определяет тип правила блокировки
type RuleType int

const (
	RuleTypeDomain RuleType = iota // Блокировка по домену
	RuleTypeURL                    // Блокировка по URL
	RuleTypeElement                // Блокировка элементов (CSS)
)

// Engine представляет движок блокировки рекламы
type Engine struct {
	rules      []*Rule
	mu         sync.RWMutex
	enabled    bool
	blocked    int64 // Счетчик заблокированных запросов
	allowed    int64 // Счетчик разрешенных запросов
	lastUpdate time.Time
}

// NewEngine создает новый движок AdBlock
func NewEngine() *Engine {
	return &Engine{
		rules:   make([]*Rule, 0),
		enabled: true,
	}
}

// Enable включает/выключает блокировку
func (e *Engine) Enable(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = enabled
}

// IsEnabled возвращает статус блокировки
func (e *Engine) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// AddRule добавляет правило блокировки
func (e *Engine) AddRule(rawRule string) error {
	rule, err := parseRule(rawRule)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
	return nil
}

// RemoveRule удаляет правило блокировки
func (e *Engine) RemoveRule(rawRule string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	for i, rule := range e.rules {
		if rule.Raw == rawRule {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return
		}
	}
}

// LoadRulesFromURL загружает правила из URL (EasyList, EasyPrivacy, etc.)
func (e *Engine) LoadRulesFromURL(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch rules: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return e.LoadRulesFromReader(resp.Body)
}

// LoadRulesFromReader загружает правила из io.Reader
func (e *Engine) LoadRulesFromReader(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	loaded := 0
	skipped := 0

	e.mu.Lock()
	defer e.mu.Unlock()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Пропускаем пустые строки и комментарии
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			skipped++
			continue
		}

		rule, err := parseRule(line)
		if err != nil {
			skipped++
			continue
		}

		e.rules = append(e.rules, rule)
		loaded++
	}

	e.lastUpdate = time.Now()
	log.Printf("[AdBlock] Loaded %d rules, skipped %d lines", loaded, skipped)
	return scanner.Err()
}

// ShouldBlock проверяет, должен ли быть заблокирован запрос
func (e *Engine) ShouldBlock(domain, url string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.enabled {
		return false
	}

	// Проверяем правила в обратном порядке (последние добавленные имеют приоритет)
	for i := len(e.rules) - 1; i >= 0; i-- {
		rule := e.rules[i]
		
		// Исключения имеют приоритет
		if rule.Exception {
			if matchesRule(rule, domain, url) {
				e.allowed++
				return false
			}
			continue
		}

		// Проверяем правило блокировки
		if matchesRule(rule, domain, url) {
			e.blocked++
			return true
		}
	}

	e.allowed++
	return false
}

// matchesRule проверяет, соответствует ли запрос правилу
func matchesRule(rule *Rule, domain, url string) bool {
	if rule.Pattern == nil {
		return false
	}

	switch rule.Type {
	case RuleTypeDomain:
		// Проверяем домен
		if rule.Pattern.MatchString(domain) {
			// Проверяем опции domain, если есть
			if len(rule.Options) > 0 {
				return checkDomainOptions(rule.Options, domain)
			}
			return true
		}
		return false

	case RuleTypeURL:
		// Проверяем URL
		return rule.Pattern.MatchString(url)

	case RuleTypeElement:
		// Для элементов нужен полный URL
		return rule.Pattern.MatchString(url)
	}

	return false
}

// checkDomainOptions проверяет опции домена
func checkDomainOptions(options []string, domain string) bool {
	for _, opt := range options {
		if strings.HasPrefix(opt, "domain=") {
			domains := strings.TrimPrefix(opt, "domain=")
			domainList := strings.Split(domains, "|")
			for _, d := range domainList {
				if strings.HasSuffix(domain, d) || domain == d {
					return true
				}
			}
		}
	}
	return true // Если опций нет, разрешаем
}

// parseRule парсит строку правила AdBlock
func parseRule(raw string) (*Rule, error) {
	rule := &Rule{
		Raw: raw,
	}

	// Проверяем, является ли это исключением
	if strings.HasPrefix(raw, "@@") {
		rule.Exception = true
		raw = strings.TrimPrefix(raw, "@@")
	}

	// Удаляем опции из правила
	parts := strings.Split(raw, "$")
	patternStr := parts[0]
	if len(parts) > 1 {
		rule.Options = strings.Split(parts[1], ",")
	}

	// Определяем тип правила
	if strings.Contains(patternStr, "||") {
		// Доменное правило: ||example.com^
		rule.Type = RuleTypeDomain
		patternStr = strings.TrimPrefix(patternStr, "||")
		patternStr = strings.TrimSuffix(patternStr, "^")
		patternStr = regexp.QuoteMeta(patternStr)
		patternStr = "^" + patternStr
	} else if strings.HasPrefix(patternStr, "|") && strings.HasSuffix(patternStr, "|") {
		// Точное совпадение URL: |http://example.com|
		rule.Type = RuleTypeURL
		patternStr = strings.Trim(patternStr, "|")
		patternStr = regexp.QuoteMeta(patternStr)
		patternStr = "^" + patternStr + "$"
	} else if strings.HasPrefix(patternStr, "|") {
		// Начало URL: |http://example.com
		rule.Type = RuleTypeURL
		patternStr = strings.TrimPrefix(patternStr, "|")
		patternStr = regexp.QuoteMeta(patternStr)
		patternStr = "^" + patternStr
	} else if strings.HasSuffix(patternStr, "|") {
		// Конец URL: example.com|
		rule.Type = RuleTypeURL
		patternStr = strings.TrimSuffix(patternStr, "|")
		patternStr = regexp.QuoteMeta(patternStr)
		patternStr = patternStr + "$"
	} else {
		// Обычный паттерн
		rule.Type = RuleTypeURL
		// Конвертируем AdBlock wildcards в regex
		patternStr = convertAdBlockToRegex(patternStr)
	}

	// Компилируем regex
	pattern, err := regexp.Compile(patternStr)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}
	rule.Pattern = pattern

	return rule, nil
}

// convertAdBlockToRegex конвертирует AdBlock паттерн в regex
func convertAdBlockToRegex(pattern string) string {
	// Экранируем специальные символы
	pattern = regexp.QuoteMeta(pattern)
	
	// Конвертируем AdBlock wildcards
	pattern = strings.ReplaceAll(pattern, "\\*", ".*")
	pattern = strings.ReplaceAll(pattern, "\\^", "[^a-zA-Z0-9_.%-]")
	
	return pattern
}

// GetStats возвращает статистику блокировки
func (e *Engine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"enabled":     e.enabled,
		"rules_count": len(e.rules),
		"blocked":     e.blocked,
		"allowed":     e.allowed,
		"last_update": e.lastUpdate,
	}
}

// GetRules возвращает список всех правил
func (e *Engine) GetRules() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]string, len(e.rules))
	for i, rule := range e.rules {
		rules[i] = rule.Raw
	}
	return rules
}

// ClearRules очищает все правила
func (e *Engine) ClearRules() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = make([]*Rule, 0)
	e.blocked = 0
	e.allowed = 0
}

