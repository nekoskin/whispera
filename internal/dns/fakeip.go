package dns

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// fakeIPEntry хранит информацию о маппинге Fake-IP
type fakeIPEntry struct {
	Domain    string
	IP        uint32
	LastUsed  time.Time
	CreatedAt time.Time
}

// FakeIPPool manages the mapping between domains and fake IP addresses.
// It uses the 198.18.0.0/15 range (RFC 2544) typically used for benchmarking
// but widely adopted by Clash/Mihomo for Fake-IP.
type FakeIPPool struct {
	mu sync.RWMutex

	// ipToDomain maps uint32 (IPv4) to domain string
	ipToDomain map[uint32]string
	// domainToIP maps domain string to uint32 (IPv4)
	domainToIP map[string]uint32
	
	// LRU tracking: список IP в порядке использования (most recent at end)
	lruList []uint32
	lruMap  map[uint32]int // IP -> index in lruList
	
	// TTL management
	entries map[uint32]*fakeIPEntry // IP -> entry with TTL info
	
	minIP uint32
	maxIP uint32
	cursor uint32
	
	// TTL для маппингов (0 = без ограничения)
	defaultTTL time.Duration
	// Интервал очистки устаревших записей
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

func NewFakeIPPool() *FakeIPPool {
	// 198.18.0.1 to 198.19.255.254
	// 198.18.0.0 = 0xC6120000
	min := binary.BigEndian.Uint32(net.ParseIP("198.18.0.1").To4())
	max := binary.BigEndian.Uint32(net.ParseIP("198.19.255.254").To4())

	pool := &FakeIPPool{
		ipToDomain:      make(map[uint32]string),
		domainToIP:      make(map[string]uint32),
		lruList:         make([]uint32, 0),
		lruMap:          make(map[uint32]int),
		entries:         make(map[uint32]*fakeIPEntry),
		minIP:           min,
		maxIP:           max,
		cursor:          min,
		defaultTTL:      24 * time.Hour, // 24 часа по умолчанию
		cleanupInterval: 1 * time.Hour,  // Очистка каждый час
		stopCleanup:     make(chan struct{}),
	}
	
	// Запускаем фоновую очистку
	go pool.cleanupLoop()
	
	return pool
}

// Stop останавливает фоновую очистку
func (p *FakeIPPool) Stop() {
	close(p.stopCleanup)
}

// cleanupLoop периодически очищает устаревшие записи
func (p *FakeIPPool) cleanupLoop() {
	ticker := time.NewTicker(p.cleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			p.cleanupExpired()
		case <-p.stopCleanup:
			return
		}
	}
}

// cleanupExpired удаляет записи с истекшим TTL
func (p *FakeIPPool) cleanupExpired() {
	if p.defaultTTL == 0 {
		return // TTL отключен
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	now := time.Now()
	expiredIPs := make([]uint32, 0)
	
	for ip, entry := range p.entries {
		if now.Sub(entry.CreatedAt) > p.defaultTTL {
			expiredIPs = append(expiredIPs, ip)
		}
	}
	
	for _, ip := range expiredIPs {
		p.removeIP(ip)
	}
	
	if len(expiredIPs) > 0 {
		// log.Printf("[FakeIP] Cleaned up %d expired entries", len(expiredIPs))
	}
}

// removeIP удаляет IP из всех маппингов
func (p *FakeIPPool) removeIP(ip uint32) {
	if domain, ok := p.ipToDomain[ip]; ok {
		delete(p.domainToIP, domain)
	}
	delete(p.ipToDomain, ip)
	delete(p.entries, ip)
	
	// Удаляем из LRU
	if idx, ok := p.lruMap[ip]; ok {
		p.lruList = append(p.lruList[:idx], p.lruList[idx+1:]...)
		delete(p.lruMap, ip)
		// Обновляем индексы
		for i := idx; i < len(p.lruList); i++ {
			p.lruMap[p.lruList[i]] = i
		}
	}
}

// LookupIP returns the domain associated with the given fake IP.
// Returns empty string if not found.
func (p *FakeIPPool) Lookup(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	val := binary.BigEndian.Uint32(ip4)

	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.ipToDomain[val]
}

// GetIP returns a fake IP for the given domain.
// If the domain already has an IP, it returns it and updates LRU.
// Otherwise, it allocates a new one using LRU algorithm.
func (p *FakeIPPool) Get(domain string) net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Проверяем, есть ли уже IP для этого домена
	if ipVal, ok := p.domainToIP[domain]; ok {
		// Обновляем LRU (перемещаем в конец)
		p.updateLRU(ipVal)
		// Обновляем время последнего использования
		if entry, exists := p.entries[ipVal]; exists {
			entry.LastUsed = time.Now()
		}
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, ipVal)
		return ip
	}

	// Нужно выделить новый IP
	var ipVal uint32
	
	// Пробуем найти свободный IP (который не используется)
	startCursor := p.cursor
	for {
		ipVal = p.cursor
		p.cursor++
		if p.cursor > p.maxIP {
			p.cursor = p.minIP
		}
		
		// Если IP не используется, берем его
		if _, exists := p.ipToDomain[ipVal]; !exists {
			break
		}
		
		// Если прошли полный круг, используем LRU (самый старый)
		if p.cursor == startCursor {
			if len(p.lruList) > 0 {
				ipVal = p.lruList[0] // Самый старый (least recently used)
				// Удаляем старый маппинг
				if oldDomain, exists := p.ipToDomain[ipVal]; exists {
					delete(p.domainToIP, oldDomain)
				}
				// Удаляем из LRU
				p.removeFromLRU(ipVal)
			}
			break
		}
	}

	// Создаем новый маппинг
	p.ipToDomain[ipVal] = domain
	p.domainToIP[domain] = ipVal
	
	// Добавляем в LRU (в конец = most recent)
	p.addToLRU(ipVal)
	
	// Создаем entry с TTL
	p.entries[ipVal] = &fakeIPEntry{
		Domain:    domain,
		IP:        ipVal,
		LastUsed:  time.Now(),
		CreatedAt: time.Now(),
	}

	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipVal)
	return ip
}

// updateLRU перемещает IP в конец списка (most recent)
func (p *FakeIPPool) updateLRU(ip uint32) {
	if idx, ok := p.lruMap[ip]; ok {
		// Удаляем из текущей позиции
		p.lruList = append(p.lruList[:idx], p.lruList[idx+1:]...)
		// Обновляем индексы
		for i := idx; i < len(p.lruList); i++ {
			p.lruMap[p.lruList[i]] = i
		}
	}
	// Добавляем в конец
	p.lruList = append(p.lruList, ip)
	p.lruMap[ip] = len(p.lruList) - 1
}

// addToLRU добавляет IP в конец списка
func (p *FakeIPPool) addToLRU(ip uint32) {
	if _, exists := p.lruMap[ip]; !exists {
		p.lruList = append(p.lruList, ip)
		p.lruMap[ip] = len(p.lruList) - 1
	}
}

// removeFromLRU удаляет IP из списка
func (p *FakeIPPool) removeFromLRU(ip uint32) {
	if idx, ok := p.lruMap[ip]; ok {
		p.lruList = append(p.lruList[:idx], p.lruList[idx+1:]...)
		delete(p.lruMap, ip)
		// Обновляем индексы
		for i := idx; i < len(p.lruList); i++ {
			p.lruMap[p.lruList[i]] = i
		}
	}
}

// IsFakeIP checks if the IP is within the fake IP range.
func (p *FakeIPPool) IsFakeIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	val := binary.BigEndian.Uint32(ip4)
	return val >= p.minIP && val <= p.maxIP
}

