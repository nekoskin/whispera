package routing

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Engine - полноценный движок маршрутизации для TUN dataplane
type Engine struct {
	rules          []*Rule
	rulesMu        sync.RWMutex
	domainCache    map[string]net.IP // domain -> IP cache для быстрого lookup
	fakeIPMap      map[string]string // Fake-IP -> domain маппинг (синхронизируется с клиентом)
	fakeIPMu       sync.RWMutex
	cacheMu        sync.RWMutex
	cacheTTL       time.Duration
	geoIP          *GeoIPDatabase
	geoSite        *GeoSiteDatabase
	geoUpdater     *GeoUpdater
	outboundMgr    *OutboundManager
	outboundGroups *OutboundGroupManager
	serverMgr      *ServerManager
	subscriptionMgr *SubscriptionManager
}

// Rule представляет одно правило маршрутизации
type Rule struct {
	Type        string   // "field", "logical", "default"
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	Network     string   `json:"network,omitempty"` // "tcp", "udp", "tcp,udp"
	Source      []string `json:"source,omitempty"`
	PortRange   string   `json:"port_range,omitempty"` // "1000-2000"
	GeoIP       []string `json:"geoip,omitempty"`      // Список стран (например, ["CN", "RU"])
	GeoSite     []string `json:"geosite,omitempty"`    // Список стран для доменов
	OutboundTag string   `json:"outbound_tag"`
	BalancerTag string   `json:"balancer_tag,omitempty"`
	Enabled     bool     `json:"enabled"`
	Priority    int      `json:"priority"` // Чем выше, тем раньше проверяется
}

// PacketInfo содержит информацию о пакете для маршрутизации
type PacketInfo struct {
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	Protocol   string // "tcp", "udp", "icmp"
	Domain     string // Если известен домен (из DNS или SNI)
	UserID     string // ID пользователя (если есть)
	InboundTag string // Тег inbound соединения
}

// NewEngine создает новый routing engine
func NewEngine() *Engine {
	serverMgr := NewServerManager()
	outboundGroups := NewOutboundGroupManager()
	outboundGroups.Start() // Запускаем фоновое обновление задержек для url-test
	
	return &Engine{
		rules:          make([]*Rule, 0),
		domainCache:    make(map[string]net.IP),
		fakeIPMap:      make(map[string]string), // Fake-IP -> domain
		cacheTTL:       5 * time.Minute,
		geoIP:          NewGeoIPDatabase(),
		geoSite:        NewGeoSiteDatabase(),
		outboundMgr:    NewOutboundManager(),
		outboundGroups: outboundGroups,
		serverMgr:      serverMgr,
		subscriptionMgr: NewSubscriptionManager(serverMgr),
	}
}

// SetGeoUpdater устанавливает geo updater для автоматического обновления баз
func (e *Engine) SetGeoUpdater(updater *GeoUpdater) {
	e.geoUpdater = updater
}

// GetGeoUpdater возвращает geo updater
func (e *Engine) GetGeoUpdater() *GeoUpdater {
	return e.geoUpdater
}

// LoadGeoIP загружает GeoIP базу данных
func (e *Engine) LoadGeoIP(filename string) error {
	return e.geoIP.LoadFromFile(filename)
}

// LoadGeoSite загружает GeoSite базу данных
func (e *Engine) LoadGeoSite(filename string) error {
	return e.geoSite.LoadFromFile(filename)
}

// ReloadGeoBases перезагружает геобазы (используется после обновления)
func (e *Engine) ReloadGeoBases() error {
	if e.geoUpdater == nil {
		return nil
	}

	geoIPPath := e.geoUpdater.GetGeoIPPath()
	geoSitePath := e.geoUpdater.GetGeoSitePath()

	if geoIPPath != "" {
		if err := e.LoadGeoIP(geoIPPath); err != nil {
			return fmt.Errorf("failed to reload GeoIP: %w", err)
		}
	}

	if geoSitePath != "" {
		if err := e.LoadGeoSite(geoSitePath); err != nil {
			return fmt.Errorf("failed to reload GeoSite: %w", err)
		}
	}

	return nil
}

// APIRule представляет правило из API (для избежания циклического импорта)
type APIRule struct {
	Type        string   `json:"type"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	Network     string   `json:"network,omitempty"`
	Source      []string `json:"source,omitempty"`
	OutboundTag string   `json:"outboundTag"`
	BalancerTag string   `json:"balancerTag,omitempty"`
	Enabled     bool     `json:"enabled"`
	Priority    int      `json:"priority"`
}

// LoadRules загружает правила из API
func (e *Engine) LoadRules(apiRules []APIRule) error {
	e.rulesMu.Lock()
	defer e.rulesMu.Unlock()

	e.rules = make([]*Rule, 0, len(apiRules))

	for _, apiRule := range apiRules {
		if !apiRule.Enabled {
			continue
		}

		rule := &Rule{
			Type:        apiRule.Type,
			Domain:      apiRule.Domain,
			IP:          apiRule.IP,
			Port:        apiRule.Port,
			Network:     apiRule.Network,
			Source:      apiRule.Source,
			OutboundTag: apiRule.OutboundTag,
			BalancerTag: apiRule.BalancerTag,
			Enabled:     apiRule.Enabled,
			Priority:    apiRule.Priority,
		}

		// Парсим port range если есть
		if strings.Contains(apiRule.Port, "-") {
			rule.PortRange = apiRule.Port
		}

		e.rules = append(e.rules, rule)
	}

	// Сортируем по приоритету (высокий приоритет = раньше проверяется)
	e.sortRulesByPriority()

	return nil
}

// AddRule добавляет правило маршрутизации
func (e *Engine) AddRule(rule *Rule) {
	e.rulesMu.Lock()
	defer e.rulesMu.Unlock()

	e.rules = append(e.rules, rule)
	e.sortRulesByPriority()
}

// RemoveRule удаляет правило по индексу
func (e *Engine) RemoveRule(index int) bool {
	e.rulesMu.Lock()
	defer e.rulesMu.Unlock()

	if index < 0 || index >= len(e.rules) {
		return false
	}

	e.rules = append(e.rules[:index], e.rules[index+1:]...)
	return true
}

// GetRules возвращает все правила
func (e *Engine) GetRules() []*Rule {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	rules := make([]*Rule, len(e.rules))
	copy(rules, e.rules)
	return rules
}

// sortRulesByPriority сортирует правила по приоритету (внутри мьютекса)
func (e *Engine) sortRulesByPriority() {
	// ОПТИМИЗАЦИЯ: Используем более эффективную сортировку вставками для небольших списков
	// Для больших списков (>20) можно использовать sort.Slice, но для правил обычно немного
	n := len(e.rules)
	if n <= 1 {
		return
	}
	// ОПТИМИЗАЦИЯ: Сортировка вставками O(n²) в худшем случае, но быстрее для почти отсортированных списков
	for i := 1; i < n; i++ {
		key := e.rules[i]
		j := i - 1
		for j >= 0 && e.rules[j].Priority < key.Priority {
			e.rules[j+1] = e.rules[j]
			j--
		}
		e.rules[j+1] = key
	}
}

// Match определяет, соответствует ли пакет правилу
func (r *Rule) Match(info *PacketInfo, engine *Engine) bool {
	// Проверка по доменам
	if len(r.Domain) > 0 {
		if info.Domain == "" {
			return false // Нет домена для сравнения
		}
		matched := false
		for _, domain := range r.Domain {
			if engine.matchDomain(domain, info.Domain) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Проверка по IP
	if len(r.IP) > 0 {
		matched := false
		for _, ipRule := range r.IP {
			if engine.matchIP(ipRule, info.DstIP) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Проверка по порту
	if r.Port != "" {
		if !engine.matchPort(r.Port, info.DstPort) {
			return false
		}
	}

	// Проверка по порту (range)
	if r.PortRange != "" {
		if !engine.matchPortRange(r.PortRange, info.DstPort) {
			return false
		}
	}

	// Проверка по протоколу/сети
	if r.Network != "" {
		// ОПТИМИЗАЦИЯ: Для одного протокола проверяем напрямую без Split
		if !strings.Contains(r.Network, ",") {
			if strings.TrimSpace(r.Network) != info.Protocol {
				return false
			}
		} else {
			networks := strings.Split(r.Network, ",")
			matched := false
			for _, net := range networks {
				if strings.TrimSpace(net) == info.Protocol {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	// Проверка по source IP
	if len(r.Source) > 0 {
		matched := false
		for _, srcRule := range r.Source {
			if engine.matchIP(srcRule, info.SrcIP) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Проверка по GeoIP
	if len(r.GeoIP) > 0 {
		if !engine.geoIP.IsLoaded() {
			return false // База не загружена
		}
		country := engine.geoIP.LookupCountry(info.DstIP)
		if country == "" {
			return false
		}
		matched := false
		for _, geoCountry := range r.GeoIP {
			if strings.EqualFold(country, geoCountry) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Проверка по GeoSite
	if len(r.GeoSite) > 0 {
		if info.Domain == "" {
			return false // Нет домена для проверки
		}
		if !engine.geoSite.IsLoaded() {
			return false // База не загружена
		}
		countries := engine.geoSite.LookupCountry(info.Domain)
		if len(countries) == 0 {
			return false
		}
		matched := false
		for _, geoCountry := range r.GeoSite {
			for _, country := range countries {
				if strings.EqualFold(country, geoCountry) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// matchDomain проверяет соответствие домена правилу (поддержка wildcard и suffix)
func (e *Engine) matchDomain(rule, domain string) bool {
	// ОПТИМИЗАЦИЯ: Кэшируем результаты ToLower для часто используемых доменов
	// Для начала просто оптимизируем операции со строками
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	rule = strings.ToLower(strings.TrimSuffix(rule, "."))

	// Точное совпадение
	if rule == domain {
		return true
	}

	// Suffix match (например, ".google.com" соответствует "www.google.com")
	if strings.HasPrefix(rule, ".") {
		return strings.HasSuffix(domain, rule)
	}

	// Prefix match (например, "google" соответствует "google.com")
	if strings.HasSuffix(rule, ".") {
		return strings.HasPrefix(domain, strings.TrimSuffix(rule, "."))
	}

	// Wildcard match (например, "*.google.com")
	if strings.HasPrefix(rule, "*.") {
		suffix := rule[2:]
		return strings.HasSuffix(domain, suffix)
	}

	return false
}

// matchIP проверяет соответствие IP правилу (поддержка CIDR, IPv4 и IPv6)
func (e *Engine) matchIP(rule string, ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Нормализуем IP (конвертируем IPv4-mapped IPv6 в IPv4)
	ip = NormalizeIP(ip)

	// ОПТИМИЗАЦИЯ: Сначала проверяем CIDR (самый частый случай), потом ParseIP, и только потом String()
	// CIDR match (поддержка IPv4 и IPv6)
	if strings.Contains(rule, "/") {
		_, network, err := net.ParseCIDR(rule)
		if err != nil {
			return false
		}
		// Используем улучшенную функцию для проверки
		return IPContains(network, ip)
	}

	// Пробуем парсить как IP адрес (для точного совпадения) - быстрее чем String()
	if parsedIP := net.ParseIP(rule); parsedIP != nil {
		parsedIP = NormalizeIP(parsedIP)
		return parsedIP.Equal(ip)
	}

	// Прямое совпадение через String() (только если не удалось распарсить)
	// ОПТИМИЗАЦИЯ: Это медленнее, поэтому проверяем в последнюю очередь
	if rule == ip.String() {
		return true
	}

	return false
}

// matchPort проверяет соответствие порта правилу
func (e *Engine) matchPort(rule string, port uint16) bool {
	// ОПТИМИЗАЦИЯ: Для одного порта проверяем напрямую без Split
	if !strings.Contains(rule, ",") {
		// Одиночный порт
		if p, err := strconv.ParseUint(strings.TrimSpace(rule), 10, 16); err == nil {
			return uint16(p) == port
		}
		return false
	}
	
	// Список портов через запятую
	ports := strings.Split(rule, ",")
	for _, p := range ports {
		if e.matchPort(strings.TrimSpace(p), port) {
			return true
		}
	}
	return false
}

// matchPortRange проверяет соответствие порта диапазону
func (e *Engine) matchPortRange(rule string, port uint16) bool {
	parts := strings.Split(rule, "-")
	if len(parts) != 2 {
		return false
	}

	min, err1 := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	max, err2 := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)

	if err1 != nil || err2 != nil {
		return false
	}

	return port >= uint16(min) && port <= uint16(max)
}

// Route определяет outbound tag для пакета
func (e *Engine) Route(info *PacketInfo) (outboundTag string, balancerTag string, matched bool) {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	// Проверяем правила по порядку (уже отсортированы по приоритету)
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		if rule.Match(info, e) {
			outboundTag = rule.OutboundTag
			balancerTag = rule.BalancerTag
			
			// Если указан balancer tag, выбираем outbound из группы
			if balancerTag != "" && e.outboundGroups != nil {
				group, exists := e.outboundGroups.GetGroup(balancerTag)
				if exists {
					var selected string
					var err error
					
					// Для load-balance используем weighted selection если доступен server manager
					if group.Type == GroupTypeLoadBalance && e.serverMgr != nil {
						selected, err = e.outboundGroups.SelectOutboundWithServerMgr(balancerTag, e.outboundMgr, e.serverMgr)
					} else {
						selected, err = e.outboundGroups.SelectOutbound(balancerTag, e.outboundMgr)
					}
					
					if err == nil {
						outboundTag = selected
					}
				}
			}
			
			return outboundTag, balancerTag, true
		}
	}

	return "", "", false
}

// GetOutboundManager возвращает outbound manager
func (e *Engine) GetOutboundManager() *OutboundManager {
	return e.outboundMgr
}

// GetOutboundGroupManager возвращает менеджер групп outbound'ов
func (e *Engine) GetOutboundGroupManager() *OutboundGroupManager {
	return e.outboundGroups
}

// GetServerManager возвращает менеджер серверов
func (e *Engine) GetServerManager() *ServerManager {
	return e.serverMgr
}

// GetSessionIDForOutbound возвращает session ID для outbound tag
func (e *Engine) GetSessionIDForOutbound(outboundTag string) (uint32, bool) {
	if e.outboundMgr == nil {
		return 0, false
	}
	return e.outboundMgr.GetSessionID(outboundTag)
}

// SetDomainCache устанавливает домен в кэш
func (e *Engine) SetDomainCache(domain string, ip net.IP) {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()

	e.domainCache[domain] = ip
}

// GetDomainCache получает IP из кэша домена
func (e *Engine) GetDomainCache(domain string) (net.IP, bool) {
	e.cacheMu.RLock()
	defer e.cacheMu.RUnlock()

	ip, ok := e.domainCache[domain]
	return ip, ok
}

// ClearDomainCache очищает кэш доменов
func (e *Engine) ClearDomainCache() {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()

	e.domainCache = make(map[string]net.IP)
}

// CacheDomain сохраняет домен в кэш для обратного lookup по IP
func (e *Engine) CacheDomain(domain string, ip net.IP) {
	if domain == "" || ip == nil {
		return
	}
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	e.domainCache[domain] = ip
}

// GetDomainFromCache возвращает домен из кэша по IP (обратный lookup)
func (e *Engine) GetDomainFromCache(ip net.IP) string {
	if ip == nil {
		return ""
	}
	e.cacheMu.RLock()
	defer e.cacheMu.RUnlock()
	// Ищем домен по IP (обратный lookup)
	for domain, cachedIP := range e.domainCache {
		if cachedIP.Equal(ip) {
			return domain
		}
	}
	return ""
}

// LookupFakeIP проверяет, является ли IP Fake-IP и возвращает домен
// Это используется для обратного lookup Fake-IP -> domain на сервере
// Поддерживает IPv4 (198.18.0.0/15) и IPv6 (fc00::/7)
func (e *Engine) LookupFakeIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	
	// Проверяем, является ли IP Fake-IP (IPv4 или IPv6)
	if !IsFakeIP(ip) {
		return ""
	}
	
	// Это Fake-IP - ищем домен в маппинге
	e.fakeIPMu.RLock()
	defer e.fakeIPMu.RUnlock()
	ipStr := ip.String()
	if domain, ok := e.fakeIPMap[ipStr]; ok {
		return domain
	}
	// Домен не найден - будет определен через SNI/HTTP sniffing
	return ""
}

// SyncFakeIPMapping синхронизирует маппинг Fake-IP -> domain с клиента
// Вызывается при получении домена из пакетов или через API
// Поддерживает IPv4 (198.18.0.0/15) и IPv6 (fc00::/7)
func (e *Engine) SyncFakeIPMapping(ip net.IP, domain string) {
	if ip == nil || domain == "" {
		return
	}
	
	// Проверяем, что это Fake-IP (IPv4 или IPv6)
	if !IsFakeIP(ip) {
		return
	}
	
	e.fakeIPMu.Lock()
	defer e.fakeIPMu.Unlock()
	ipStr := ip.String()
	e.fakeIPMap[ipStr] = domain
	// Также обновляем domainCache для обратной совместимости
	e.cacheMu.Lock()
	e.domainCache[domain] = ip
	e.cacheMu.Unlock()
}

// GetSubscriptionManager возвращает менеджер подписок
func (e *Engine) GetSubscriptionManager() *SubscriptionManager {
	return e.subscriptionMgr
}

// StartSubscriptions запускает автоматическое обновление подписок
func (e *Engine) StartSubscriptions() {
	if e.subscriptionMgr != nil {
		e.subscriptionMgr.Start()
	}
}

// StopSubscriptions останавливает автоматическое обновление подписок
func (e *Engine) StopSubscriptions() {
	if e.subscriptionMgr != nil {
		e.subscriptionMgr.Stop()
	}
}

