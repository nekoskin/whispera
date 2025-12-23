package routing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Subscription представляет подписку на серверы
type Subscription struct {
	ID          string        `json:"id"`          // Уникальный ID подписки
	Name        string        `json:"name"`        // Имя подписки
	URL         string        `json:"url"`         // URL подписки
	Enabled     bool          `json:"enabled"`     // Включена ли подписка
	Interval    time.Duration `json:"interval"`    // Интервал обновления
	LastUpdate  time.Time     `json:"last_update"` // Время последнего обновления
	LastError   string        `json:"last_error"`  // Последняя ошибка
	Servers     []*ServerConfig `json:"servers"`   // Список серверов из подписки
	mu          sync.RWMutex
}

// SubscriptionManager управляет подписками
type SubscriptionManager struct {
	subscriptions map[string]*Subscription // id -> subscription
	serverManager *ServerManager           // Менеджер серверов для обновления
	httpClient    *http.Client             // HTTP клиент для загрузки
	stop          chan struct{}             // Канал для остановки
	wg            sync.WaitGroup            // WaitGroup для горутин
	mu            sync.RWMutex
}

// NewSubscriptionManager создает новый менеджер подписок
func NewSubscriptionManager(serverManager *ServerManager) *SubscriptionManager {
	return &SubscriptionManager{
		subscriptions: make(map[string]*Subscription),
		serverManager: serverManager,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		stop: make(chan struct{}),
	}
}

// AddSubscription добавляет подписку
func (sm *SubscriptionManager) AddSubscription(sub *Subscription) error {
	if sub.ID == "" {
		return fmt.Errorf("subscription ID cannot be empty")
	}
	if sub.URL == "" {
		return fmt.Errorf("subscription URL cannot be empty")
	}

	// Валидация URL
	if _, err := url.Parse(sub.URL); err != nil {
		return fmt.Errorf("invalid subscription URL: %w", err)
	}

	// Устанавливаем дефолтный интервал если не указан
	if sub.Interval == 0 {
		sub.Interval = 1 * time.Hour
	}

	sm.mu.Lock()
	sm.subscriptions[sub.ID] = sub
	sm.mu.Unlock()

	// Если подписка включена, сразу обновляем
	if sub.Enabled {
		go sm.updateSubscription(sub.ID)
	}

	return nil
}

// RemoveSubscription удаляет подписку
func (sm *SubscriptionManager) RemoveSubscription(id string) {
	sm.mu.Lock()
	delete(sm.subscriptions, id)
	sm.mu.Unlock()
}

// GetSubscription возвращает подписку по ID
func (sm *SubscriptionManager) GetSubscription(id string) (*Subscription, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sub, exists := sm.subscriptions[id]
	return sub, exists
}

// GetAllSubscriptions возвращает все подписки
func (sm *SubscriptionManager) GetAllSubscriptions() []*Subscription {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	subs := make([]*Subscription, 0, len(sm.subscriptions))
	for _, sub := range sm.subscriptions {
		subs = append(subs, sub)
	}
	return subs
}

// UpdateSubscription обновляет подписку
func (sm *SubscriptionManager) UpdateSubscription(sub *Subscription) error {
	sm.mu.RLock()
	existing, exists := sm.subscriptions[sub.ID]
	sm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("subscription not found: %s", sub.ID)
	}

	// Сохраняем существующие данные
	sub.mu.RLock()
	sub.Servers = existing.Servers
	sub.LastUpdate = existing.LastUpdate
	sub.mu.RUnlock()

	sm.mu.Lock()
	sm.subscriptions[sub.ID] = sub
	sm.mu.Unlock()

	// Если подписка включена, обновляем
	if sub.Enabled {
		go sm.updateSubscription(sub.ID)
	}

	return nil
}

// EnableSubscription включает/выключает подписку
func (sm *SubscriptionManager) EnableSubscription(id string, enabled bool) error {
	sm.mu.RLock()
	sub, exists := sm.subscriptions[id]
	sm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("subscription not found: %s", id)
	}

	sub.mu.Lock()
	sub.Enabled = enabled
	sub.mu.Unlock()

	if enabled {
		go sm.updateSubscription(id)
	}

	return nil
}

// Start запускает периодическое обновление подписок
func (sm *SubscriptionManager) Start() {
	sm.wg.Add(1)
	go sm.updateLoop()
}

// Stop останавливает обновление подписок
func (sm *SubscriptionManager) Stop() {
	close(sm.stop)
	sm.wg.Wait()
}

// updateLoop периодически обновляет все включенные подписки
func (sm *SubscriptionManager) updateLoop() {
	defer sm.wg.Done()

	ticker := time.NewTicker(5 * time.Minute) // Проверяем каждые 5 минут
	defer ticker.Stop()

	for {
		select {
		case <-sm.stop:
			return
		case <-ticker.C:
			sm.mu.RLock()
			subs := make([]*Subscription, 0, len(sm.subscriptions))
			for _, sub := range sm.subscriptions {
				sub.mu.RLock()
				if sub.Enabled {
					// Проверяем, нужно ли обновление
					if time.Since(sub.LastUpdate) >= sub.Interval {
						subs = append(subs, sub)
					}
				}
				sub.mu.RUnlock()
			}
			sm.mu.RUnlock()

			// Обновляем все подписки параллельно
			for _, sub := range subs {
				go sm.updateSubscription(sub.ID)
			}
		}
	}
}

// updateSubscription обновляет конкретную подписку
func (sm *SubscriptionManager) updateSubscription(id string) {
	sm.mu.RLock()
	sub, exists := sm.subscriptions[id]
	sm.mu.RUnlock()

	if !exists {
		return
	}

	sub.mu.RLock()
	subURL := sub.URL
	sub.mu.RUnlock()

	log.Printf("[Subscription] Updating subscription %s: %s", id, subURL)

	servers, err := sm.fetchServers(subURL)
	if err != nil {
		sub.mu.Lock()
		sub.LastError = err.Error()
		sub.mu.Unlock()
		log.Printf("[Subscription] Failed to update subscription %s: %v", id, err)
		return
	}

	// Обновляем подписку
	sub.mu.Lock()
	sub.Servers = servers
	sub.LastUpdate = time.Now()
	sub.LastError = ""
	sub.mu.Unlock()

	// Обновляем серверы в ServerManager
	sm.updateServersFromSubscription(id, servers)

	log.Printf("[Subscription] Successfully updated subscription %s: %d servers", id, len(servers))
}

// fetchServers загружает серверы из URL подписки
func (sm *SubscriptionManager) fetchServers(subURL string) ([]*ServerConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Whispera-Subscription-Client/1.0")

	resp, err := sm.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch subscription: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Пробуем декодировать как base64
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err == nil {
		body = decoded
	}

	// Парсим JSON
	var servers []*ServerConfig
	if err := json.Unmarshal(body, &servers); err != nil {
		// Пробуем парсить как объект с полем servers
		var wrapper struct {
			Servers []*ServerConfig `json:"servers"`
		}
		if err2 := json.Unmarshal(body, &wrapper); err2 != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w (also tried wrapper: %v)", err, err2)
		}
		servers = wrapper.Servers
	}

	// Валидация и нормализация серверов
	validServers := make([]*ServerConfig, 0, len(servers))
	for _, server := range servers {
		if server == nil {
			continue
		}

		// Генерируем tag если не указан
		if server.Tag == "" {
			server.Tag = fmt.Sprintf("sub_%s_%d", subURL, len(validServers))
		}

		// Устанавливаем дефолтные значения
		if server.Protocol == "" {
			server.Protocol = "udp"
		}
		if !server.Enabled {
			server.Enabled = true // По умолчанию включаем
		}
		if server.Priority == 0 {
			server.Priority = 100
		}
		if server.Weight == 0 {
			server.Weight = 1
		}

		// Валидация адреса
		if server.Address == "" {
			log.Printf("[Subscription] Skipping server with empty address (tag: %s)", server.Tag)
			continue
		}

		validServers = append(validServers, server)
	}

	return validServers, nil
}

// updateServersFromSubscription обновляет серверы в ServerManager из подписки
func (sm *SubscriptionManager) updateServersFromSubscription(subID string, servers []*ServerConfig) {
	// Получаем старые серверы из этой подписки
	sm.mu.RLock()
	sub, exists := sm.subscriptions[subID]
	sm.mu.RUnlock()

	if !exists {
		return
	}

	sub.mu.RLock()
	oldServers := sub.Servers
	sub.mu.RUnlock()

	// Создаем map старых серверов для быстрого поиска
	oldServerMap := make(map[string]*ServerConfig)
	for _, server := range oldServers {
		if server != nil {
			oldServerMap[server.Tag] = server
		}
	}

	// Обновляем или добавляем новые серверы
	for _, server := range servers {
		if server == nil {
			continue
		}

		// Добавляем префикс подписки к tag для уникальности
		originalTag := server.Tag
		server.Tag = fmt.Sprintf("%s_%s", subID, originalTag)

		// Проверяем, существует ли сервер
		if oldServer, exists := oldServerMap[originalTag]; exists {
			// Сохраняем состояние (enabled, priority, weight) если они были изменены вручную
			server.mu.Lock()
			oldServer.mu.RLock()
			// Если сервер был отключен вручную, не включаем его обратно
			if !oldServer.Enabled {
				server.Enabled = false
			}
			// Сохраняем приоритет и вес если они были изменены
			if oldServer.Priority != 100 {
				server.Priority = oldServer.Priority
			}
			if oldServer.Weight != 1 {
				server.Weight = oldServer.Weight
			}
			oldServer.mu.RUnlock()
			server.mu.Unlock()
		}

		// Добавляем или обновляем сервер
		if err := sm.serverManager.AddServer(server); err != nil {
			log.Printf("[Subscription] Failed to add server %s: %v", server.Tag, err)
		}
	}

	// Удаляем серверы, которых больше нет в подписке
	for tag := range oldServerMap {
		found := false
		for _, server := range servers {
			if server != nil && server.Tag == tag {
				found = true
				break
			}
		}
		if !found {
			// Удаляем сервер только если он начинается с префикса подписки
			fullTag := fmt.Sprintf("%s_%s", subID, tag)
			sm.serverManager.RemoveServer(fullTag)
			log.Printf("[Subscription] Removed server %s (no longer in subscription)", fullTag)
		}
	}
}

// ForceUpdate принудительно обновляет все включенные подписки
func (sm *SubscriptionManager) ForceUpdate() {
	sm.mu.RLock()
	subs := make([]*Subscription, 0, len(sm.subscriptions))
	for _, sub := range sm.subscriptions {
		sub.mu.RLock()
		if sub.Enabled {
			subs = append(subs, sub)
		}
		sub.mu.RUnlock()
	}
	sm.mu.RUnlock()

	for _, sub := range subs {
		go sm.updateSubscription(sub.ID)
	}
}

// GetSubscriptionServers возвращает серверы из конкретной подписки
func (sm *SubscriptionManager) GetSubscriptionServers(subID string) ([]*ServerConfig, error) {
	sm.mu.RLock()
	sub, exists := sm.subscriptions[subID]
	sm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("subscription not found: %s", subID)
	}

	sub.mu.RLock()
	defer sub.mu.RUnlock()
	return sub.Servers, nil
}

