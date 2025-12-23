package routing

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// OutboundGroupType тип группы outbound
type OutboundGroupType string

const (
	GroupTypeSelect    OutboundGroupType = "select"     // Ручной выбор
	GroupTypeURLTest   OutboundGroupType = "url-test"   // Выбор по задержке
	GroupTypeFallback  OutboundGroupType = "fallback"   // Failover
	GroupTypeLoadBalance OutboundGroupType = "load-balance" // Балансировка нагрузки
)

// OutboundGroup представляет группу outbound'ов
type OutboundGroup struct {
	Tag            string           `json:"tag"`
	Type           OutboundGroupType `json:"type"`
	Outbounds      []string          `json:"outbounds"` // Список тегов outbound'ов в группе
	Interval       time.Duration     `json:"interval,omitempty"` // Интервал проверки для url-test
	Timeout        time.Duration     `json:"timeout,omitempty"`  // Таймаут для url-test
	URL            string            `json:"url,omitempty"`      // URL для проверки (url-test)
	Tolerance      int               `json:"tolerance,omitempty"` // Допустимая разница в задержке (ms) для url-test
	roundRobinIndex int              // Индекс для round-robin
	mu             sync.RWMutex
}

// OutboundGroupManager управляет группами outbound'ов
type OutboundGroupManager struct {
	groups      map[string]*OutboundGroup
	mu          sync.RWMutex
	stopCh      chan struct{}
	latencyCache map[string]time.Duration // tag -> latency cache
	latencyMu   sync.RWMutex
}

// NewOutboundGroupManager создает новый менеджер групп
func NewOutboundGroupManager() *OutboundGroupManager {
	return &OutboundGroupManager{
		groups:       make(map[string]*OutboundGroup),
		stopCh:       make(chan struct{}),
		latencyCache: make(map[string]time.Duration),
	}
}

// Start запускает фоновые процессы (например, периодическое обновление задержек для url-test)
func (ogm *OutboundGroupManager) Start() {
	go ogm.updateLatenciesLoop()
}

// Stop останавливает фоновые процессы
func (ogm *OutboundGroupManager) Stop() {
	close(ogm.stopCh)
}

// updateLatenciesLoop периодически обновляет задержки для url-test групп
func (ogm *OutboundGroupManager) updateLatenciesLoop() {
	ticker := time.NewTicker(30 * time.Second) // Обновляем каждые 30 секунд
	defer ticker.Stop()

	for {
		select {
		case <-ogm.stopCh:
			return
		case <-ticker.C:
			ogm.updateAllLatencies()
		}
	}
}

// updateAllLatencies обновляет задержки для всех url-test групп
func (ogm *OutboundGroupManager) updateAllLatencies() {
	ogm.mu.RLock()
	groups := make([]*OutboundGroup, 0, len(ogm.groups))
	for _, group := range ogm.groups {
		if group.Type == GroupTypeURLTest {
			groups = append(groups, group)
		}
	}
	ogm.mu.RUnlock()

	// Обновляем задержки для каждой группы
	for _, group := range groups {
		ogm.updateGroupLatencies(group)
	}
}

// updateGroupLatencies обновляет задержки для всех outbound'ов в группе
func (ogm *OutboundGroupManager) updateGroupLatencies(group *OutboundGroup) {
	group.mu.RLock()
	outbounds := make([]string, len(group.Outbounds))
	copy(outbounds, group.Outbounds)
	url := group.URL
	timeout := group.Timeout
	group.mu.RUnlock()

	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if url == "" {
		url = "https://www.google.com/generate_204"
	}

	// Обновляем задержки параллельно
	type latencyUpdate struct {
		tag     string
		latency time.Duration
		err     error
	}
	updates := make(chan latencyUpdate, len(outbounds))

	for _, tag := range outbounds {
		go func(t string) {
			latency, err := ogm.measureLatency(t, url, timeout)
			updates <- latencyUpdate{tag: t, latency: latency, err: err}
		}(tag)
	}

	// Собираем результаты с таймаутом
	ogm.latencyMu.Lock()
	deadline := time.After(timeout + 2*time.Second)
	collected := 0
	for collected < len(outbounds) {
		select {
		case update := <-updates:
			if update.err == nil {
				ogm.latencyCache[update.tag] = update.latency
			} else {
				// При ошибке удаляем из кэша или оставляем старое значение
				// Можно удалить: delete(ogm.latencyCache, update.tag)
			}
			collected++
		case <-deadline:
			// Таймаут - выходим
			ogm.latencyMu.Unlock()
			return
		}
	}
	ogm.latencyMu.Unlock()
}

// getCachedLatency возвращает кэшированную задержку для outbound
func (ogm *OutboundGroupManager) getCachedLatency(tag string) (time.Duration, bool) {
	ogm.latencyMu.RLock()
	defer ogm.latencyMu.RUnlock()
	latency, ok := ogm.latencyCache[tag]
	return latency, ok
}

// AddGroup добавляет группу outbound'ов
func (ogm *OutboundGroupManager) AddGroup(group *OutboundGroup) {
	ogm.mu.Lock()
	defer ogm.mu.Unlock()
	ogm.groups[group.Tag] = group
}

// GetGroup возвращает группу по тегу
func (ogm *OutboundGroupManager) GetGroup(tag string) (*OutboundGroup, bool) {
	ogm.mu.RLock()
	defer ogm.mu.RUnlock()
	group, exists := ogm.groups[tag]
	return group, exists
}

// RemoveGroup удаляет группу
func (ogm *OutboundGroupManager) RemoveGroup(tag string) {
	ogm.mu.Lock()
	defer ogm.mu.Unlock()
	delete(ogm.groups, tag)
}

// SelectOutbound выбирает outbound из группы
func (ogm *OutboundGroupManager) SelectOutbound(groupTag string, outboundMgr *OutboundManager) (string, error) {
	group, exists := ogm.GetGroup(groupTag)
	if !exists {
		return "", fmt.Errorf("group %s not found", groupTag)
	}

	group.mu.RLock()
	defer group.mu.RUnlock()

	switch group.Type {
	case GroupTypeSelect:
		// Ручной выбор - возвращаем первый доступный
		return ogm.selectFirstAvailable(group.Outbounds, outboundMgr)
	
	case GroupTypeURLTest:
		// Выбор по задержке - возвращаем самый быстрый
		return ogm.selectFastest(group.Outbounds, group.URL, group.Timeout, outboundMgr)
	
	case GroupTypeFallback:
		// Failover - возвращаем первый доступный
		return ogm.selectFirstAvailable(group.Outbounds, outboundMgr)
	
	case GroupTypeLoadBalance:
		// Балансировка нагрузки - round-robin
		return ogm.selectRoundRobin(group.Outbounds, outboundMgr)
	
	default:
		return "", fmt.Errorf("unknown group type: %s", group.Type)
	}
}

// selectFirstAvailable выбирает первый доступный outbound
func (ogm *OutboundGroupManager) selectFirstAvailable(outbounds []string, outboundMgr *OutboundManager) (string, error) {
	for _, tag := range outbounds {
		if _, exists := outboundMgr.GetSessionID(tag); exists {
			return tag, nil
		}
	}
	return "", fmt.Errorf("no available outbound in group")
}

// selectFastest выбирает самый быстрый outbound на основе измеренной задержки
func (ogm *OutboundGroupManager) selectFastest(outbounds []string, url string, timeout time.Duration, outboundMgr *OutboundManager) (string, error) {
	// Сначала пробуем использовать кэшированные задержки
	type latencyResult struct {
		tag     string
		latency time.Duration
		fromCache bool
		err     error
	}

	results := make([]latencyResult, 0)
	for _, tag := range outbounds {
		if _, exists := outboundMgr.GetSessionID(tag); !exists {
			continue // Пропускаем недоступные
		}

		// Пробуем получить из кэша
		if cachedLatency, ok := ogm.getCachedLatency(tag); ok && cachedLatency > 0 {
			results = append(results, latencyResult{
				tag:        tag,
				latency:    cachedLatency,
				fromCache:  true,
				err:        nil,
			})
		} else {
			// Если нет в кэше или кэш пустой, измеряем синхронно
			// Это может быть медленно, но нужно для первого измерения
			latency, err := ogm.measureLatency(tag, url, timeout)
			if err == nil {
				// Сохраняем в кэш при успешном измерении
				ogm.latencyMu.Lock()
				ogm.latencyCache[tag] = latency
				ogm.latencyMu.Unlock()
			}
			results = append(results, latencyResult{
				tag:        tag,
				latency:    latency,
				fromCache:  false,
				err:        err,
			})
		}
	}

	if len(results) == 0 {
		return "", fmt.Errorf("no available outbounds in group")
	}

	// Находим самый быстрый (минимальная задержка)
	fastest := results[0]
	for _, result := range results[1:] {
		if result.err == nil && (fastest.err != nil || result.latency < fastest.latency) {
			fastest = result
		}
	}

	if fastest.err != nil {
		// Если все failed, возвращаем первый доступный
		return ogm.selectFirstAvailable(outbounds, outboundMgr)
	}

	return fastest.tag, nil
}

// measureLatency измеряет задержку для outbound через HTTP запрос
func (ogm *OutboundGroupManager) measureLatency(tag string, url string, timeout time.Duration) (time.Duration, error) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	// Создаем контекст с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Создаем HTTP клиент с коротким таймаутом
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Используем стандартный dialer
				// В будущем здесь можно добавить маршрутизацию через конкретный outbound
				dialer := &net.Dialer{
					Timeout:   timeout,
					KeepAlive: 30 * time.Second,
				}
				return dialer.DialContext(ctx, network, addr)
			},
			DisableKeepAlives:     true, // Отключаем keep-alive для точного измерения
			MaxIdleConns:          0,
			IdleConnTimeout:       0,
			TLSHandshakeTimeout:   timeout / 2,
			ResponseHeaderTimeout: timeout / 2,
		},
	}

	// Создаем HEAD запрос (меньше данных передается)
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Устанавливаем User-Agent
	req.Header.Set("User-Agent", "Whispera-Latency-Test/1.0")

	// Измеряем время выполнения запроса
	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)

	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Проверяем статус код (2xx и 3xx считаем успешными)
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	return latency, nil
}

// selectRoundRobin выбирает outbound по round-robin алгоритму
func (ogm *OutboundGroupManager) selectRoundRobin(outbounds []string, outboundMgr *OutboundManager) (string, error) {
	// Получаем доступные outbounds
	available := make([]string, 0)
	for _, tag := range outbounds {
		if _, exists := outboundMgr.GetSessionID(tag); exists {
			available = append(available, tag)
		}
	}

	if len(available) == 0 {
		return "", fmt.Errorf("no available outbounds in group")
	}

	// Используем hash от времени для round-robin (упрощенная версия)
	// В полной реализации нужно хранить индекс в структуре группы
	index := int(time.Now().UnixNano() % int64(len(available)))
	return available[index], nil
}

// selectRoundRobinWithGroup выбирает outbound по round-robin с использованием индекса группы
func (ogm *OutboundGroupManager) selectRoundRobinWithGroup(group *OutboundGroup, outboundMgr *OutboundManager) (string, error) {
	group.mu.Lock()
	defer group.mu.Unlock()

	// Получаем доступные outbounds
	available := make([]string, 0)
	for _, tag := range group.Outbounds {
		if _, exists := outboundMgr.GetSessionID(tag); exists {
			available = append(available, tag)
		}
	}

	if len(available) == 0 {
		return "", fmt.Errorf("no available outbounds in group")
	}

	// Используем индекс группы для round-robin
	selected := available[group.roundRobinIndex%len(available)]
	group.roundRobinIndex = (group.roundRobinIndex + 1) % len(available)
	
	return selected, nil
}

// selectWeighted выбирает outbound по весам (weighted load-balance)
func (ogm *OutboundGroupManager) selectWeighted(outbounds []string, outboundMgr *OutboundManager, serverMgr *ServerManager) (string, error) {
	if serverMgr == nil {
		return ogm.selectRoundRobin(outbounds, outboundMgr)
	}

	// Получаем доступные outbounds с весами
	type weightedOutbound struct {
		tag    string
		weight int
	}
	weighted := make([]weightedOutbound, 0)
	totalWeight := 0

	for _, tag := range outbounds {
		if _, exists := outboundMgr.GetSessionID(tag); !exists {
			continue
		}

		server, exists := serverMgr.GetServer(tag)
		if !exists {
			continue
		}

		weight := server.Weight
		if weight <= 0 {
			weight = 1 // Дефолтный вес
		}

		weighted = append(weighted, weightedOutbound{
			tag:    tag,
			weight: weight,
		})
		totalWeight += weight
	}

	if len(weighted) == 0 {
		return "", fmt.Errorf("no available outbounds in group")
	}

	// Выбираем случайный outbound с учетом весов
	// Используем простой алгоритм: генерируем случайное число от 0 до totalWeight
	// и выбираем outbound, в диапазон которого попадает это число
	random := int(time.Now().UnixNano() % int64(totalWeight))
	current := 0

	for _, w := range weighted {
		current += w.weight
		if random < current {
			return w.tag, nil
		}
	}

	// Fallback на первый доступный
	return weighted[0].tag, nil
}

// SelectOutboundWithServerMgr выбирает outbound из группы с использованием server manager
func (ogm *OutboundGroupManager) SelectOutboundWithServerMgr(groupTag string, outboundMgr *OutboundManager, serverMgr *ServerManager) (string, error) {
	group, exists := ogm.GetGroup(groupTag)
	if !exists {
		return "", fmt.Errorf("group %s not found", groupTag)
	}

	group.mu.RLock()
	defer group.mu.RUnlock()

	switch group.Type {
	case GroupTypeLoadBalance:
		// Балансировка нагрузки - weighted round-robin
		return ogm.selectWeighted(group.Outbounds, outboundMgr, serverMgr)
	
	default:
		// Для других типов используем обычный SelectOutbound
		return ogm.SelectOutbound(groupTag, outboundMgr)
	}
}

// GetAllGroups возвращает все группы
func (ogm *OutboundGroupManager) GetAllGroups() []*OutboundGroup {
	ogm.mu.RLock()
	defer ogm.mu.RUnlock()

	groups := make([]*OutboundGroup, 0, len(ogm.groups))
	for _, group := range ogm.groups {
		groups = append(groups, group)
	}
	return groups
}

