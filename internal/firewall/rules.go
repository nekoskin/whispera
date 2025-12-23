package firewall

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

// FirewallEngine - движок файрвола для применения правил
type FirewallEngine struct {
	rules []*Rule
	mu    sync.RWMutex
}

// Rule - правило файрвола
type Rule struct {
	ID        string
	Action    string   // "allow", "deny", "reject"
	Direction string   // "inbound", "outbound", "both"
	Protocol  string   // "tcp", "udp", "icmp", "all"
	Port      string   // "80", "443", "80,443", "1000-2000"
	SourceIP  []string // IP или CIDR как строки
	DestIP    []string // IP или CIDR как строки
	Enabled   bool
	Priority  int
}

// NewFirewallEngine создает новый движок файрвола
func NewFirewallEngine() *FirewallEngine {
	return &FirewallEngine{
		rules: make([]*Rule, 0),
	}
}

// AddRule добавляет правило
func (fe *FirewallEngine) AddRule(rule *Rule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}
	
	// Парсим IP сети (валидация)
	for _, ipStr := range rule.SourceIP {
		_, _, err := net.ParseCIDR(ipStr)
		if err != nil {
			// Попробуем как IP без маски
			if ip := net.ParseIP(ipStr); ip == nil {
				return fmt.Errorf("invalid source IP: %s", ipStr)
			}
		}
	}
	
	for _, ipStr := range rule.DestIP {
		_, _, err := net.ParseCIDR(ipStr)
		if err != nil {
			if ip := net.ParseIP(ipStr); ip == nil {
				return fmt.Errorf("invalid dest IP: %s", ipStr)
			}
		}
	}
	
	fe.mu.Lock()
	defer fe.mu.Unlock()
	
	fe.rules = append(fe.rules, rule)
	
	// Сортируем по приоритету (высокий приоритет = больше число)
	for i := len(fe.rules) - 1; i > 0; i-- {
		if fe.rules[i].Priority > fe.rules[i-1].Priority {
			fe.rules[i], fe.rules[i-1] = fe.rules[i-1], fe.rules[i]
		}
	}
	
	return nil
}

// RemoveRule удаляет правило
func (fe *FirewallEngine) RemoveRule(id string) error {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	
	for i, rule := range fe.rules {
		if rule.ID == id {
			fe.rules = append(fe.rules[:i], fe.rules[i+1:]...)
			return nil
		}
	}
	
	return fmt.Errorf("rule not found: %s", id)
}

// CheckPacket проверяет пакет на соответствие правилам
func (fe *FirewallEngine) CheckPacket(direction, protocol string, srcIP, dstIP net.IP, port int) (bool, error) {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	
	// Проходим по правилам в порядке приоритета
	for _, rule := range fe.rules {
		if !rule.Enabled {
			continue
		}
		
		// Проверяем направление
		if rule.Direction != "both" && rule.Direction != direction {
			continue
		}
		
		// Проверяем протокол
		if rule.Protocol != "all" && rule.Protocol != protocol {
			continue
		}
		
		// Проверяем порт
		if rule.Port != "" && !fe.matchPort(port, rule.Port) {
			continue
		}
		
		// Проверяем IP адреса
		if len(rule.SourceIP) > 0 && !fe.matchIP(srcIP, rule.SourceIP) {
			continue
		}
		
		if len(rule.DestIP) > 0 && !fe.matchIP(dstIP, rule.DestIP) {
			continue
		}
		
		// Правило совпало - применяем действие
		switch rule.Action {
		case "allow":
			return true, nil
		case "deny", "reject":
			return false, fmt.Errorf("blocked by rule %s", rule.ID)
		default:
			continue
		}
	}
	
	// По умолчанию разрешаем (default allow)
	return true, nil
}

// matchPort проверяет совпадение порта
func (fe *FirewallEngine) matchPort(port int, rulePort string) bool {
	// Поддержка форматов: "80", "80,443", "1000-2000"
	
	// Список портов через запятую
	if strings.Contains(rulePort, ",") {
		ports := strings.Split(rulePort, ",")
		for _, p := range ports {
			p = strings.TrimSpace(p)
			if parsed, err := strconv.Atoi(p); err == nil && parsed == port {
				return true
			}
		}
		return false
	}
	
	// Диапазон портов
	if strings.Contains(rulePort, "-") {
		parts := strings.Split(rulePort, "-")
		if len(parts) == 2 {
			min, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			max, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && port >= min && port <= max {
				return true
			}
		}
		return false
	}
	
	// Один порт
	if parsed, err := strconv.Atoi(rulePort); err == nil {
		return parsed == port
	}
	
	return false
}

// matchIP проверяет совпадение IP адреса с сетями (из строк)
func (fe *FirewallEngine) matchIP(ip net.IP, ipStrings []string) bool {
	for _, ipStr := range ipStrings {
		// Попробуем как CIDR
		_, network, err := net.ParseCIDR(ipStr)
		if err == nil {
			if network.Contains(ip) {
				return true
			}
			continue
		}
		
		// Попробуем как прямой IP
		if parsedIP := net.ParseIP(ipStr); parsedIP != nil {
			if ip.Equal(parsedIP) {
				return true
			}
		}
	}
	return false
}

// GetRules возвращает все правила
func (fe *FirewallEngine) GetRules() []*Rule {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	
	rules := make([]*Rule, len(fe.rules))
	copy(rules, fe.rules)
	return rules
}

