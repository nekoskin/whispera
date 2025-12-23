package server

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"sync"
	"time"

	aeadpkg "whispera/internal/crypto"
	metr "whispera/internal/metrics"
	networkpkg "whispera/internal/network"
)

// SessionState - состояние сессии клиента
type SessionState struct {
	SessionID    uint32
	ClientAddr   *net.UDPAddr
	AEADState    *aeadpkg.AEADState
	RecvWin      *aeadpkg.SlidingWindow
	SeqSend      uint32
	Seed         []byte
	LastActivity time.Time
	OutboundTag  string // Outbound tag для routing (опционально)
	UserID       string // User ID для связи с политиками (опционально)

	// Stream-level mux: сопоставление StreamID -> поток (5‑tuple) и состояние.
	Streams map[uint16]*StreamStateEntry
	
	// Network components для полноценного протокола
	PacketBuffer  *networkpkg.PacketBuffer
	Retransmit    *networkpkg.RetransmissionManager
	MTU           *networkpkg.MTUDiscovery
	Congestion    *networkpkg.CongestionController
	RateLimit     *networkpkg.RateLimiter
	
	// Статистика отправленных данных (для server-initiated rekeying)
	SentBytes    int64
	SentPkts     int64
	
	// Защита от replay атак при rekey
	usedRekeySalts map[string]time.Time // salt (hex) -> timestamp использования
	
	// Защита от дублирования ACK
	processedAcks map[uint32]time.Time // seq -> timestamp обработки ACK
	
	Mu           sync.RWMutex // Экспортировано для использования в main.go
}

// StreamStateEntry хранит метаданные логического потока внутри сессии.
// Помимо 5‑tuple и временных меток, здесь могут храниться режимы обработки
// (например, UseNetstackTCP) и связанные сетевые ресурсы (TargetConn).
type StreamStateEntry struct {
	Proto      uint8
	SrcIP      net.IP
	SrcPort    uint16
	DstIP      net.IP
	DstPort    uint16
	CreatedAt  time.Time
	LastActive time.Time
	Closed     bool

	// UseNetstackTCP включает режим "байтового" TCP‑моста для этого потока:
	// вместо IP‑пакетов сервер принимает/отправляет чистый TCP‑payload через TargetConn.
	UseNetstackTCP bool
	// TargetConn — исходящее TCP‑соединение к целевому серверу для этого потока
	// (используется, когда UseNetstackTCP == true).
	TargetConn net.Conn
}

// SessionManager - менеджер множественных сессий
type SessionManager struct {
	sessions            map[uint32]*SessionState
	mu                  sync.RWMutex
	timeout             time.Duration
	maxSessions         int           // Максимальное количество сессий (0 = без ограничений)
	maxStreamsPerSession int          // Максимальное количество потоков на сессию (0 = без ограничений)
	streamIdleTimeout    time.Duration // Таймаут неактивности потока (0 = как timeout сессии)
	onSessionRemoved    SessionRemovedCallback // Callback для удаления сессии
}

// SessionRemovedCallback вызывается при удалении сессии
type SessionRemovedCallback func(sessionID uint32, outboundTag string)

// SetSessionRemovedCallback устанавливает callback для удаления сессии
func (sm *SessionManager) SetSessionRemovedCallback(callback SessionRemovedCallback) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.onSessionRemoved = callback
}

// RegisterStream регистрирует или обновляет stream‑поток внутри сессии.
func (sm *SessionManager) RegisterStream(sessionID uint32, streamID uint16, protoByte uint8, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) {
	session := sm.GetSession(sessionID)
	if session == nil {
		return
	}

	session.Mu.Lock()
	defer session.Mu.Unlock()

	if session.Streams == nil {
		session.Streams = make(map[uint16]*StreamStateEntry)
	}

	// Лимит потоков на сессию: при превышении дропаем регистрацию новых потоков.
	if sm.maxStreamsPerSession > 0 && len(session.Streams) >= sm.maxStreamsPerSession {
		log.Printf("[STREAM] Max streams per session reached (session=%d, limit=%d), dropping new stream %d",
			sessionID, sm.maxStreamsPerSession, streamID)
		return
	}

	entry, exists := session.Streams[streamID]
	now := time.Now()
	if !exists {
		entry = &StreamStateEntry{
			Proto:      protoByte,
			SrcIP:      append(net.IP(nil), srcIP...),
			SrcPort:    srcPort,
			DstIP:      append(net.IP(nil), dstIP...),
			DstPort:    dstPort,
			CreatedAt:  now,
			LastActive: now,
			Closed:     false,
		}
		session.Streams[streamID] = entry
	} else {
		entry.LastActive = now
		entry.Closed = false
	}
}

// GetStream возвращает метаданные потока по StreamID в рамках сессии.
func (sm *SessionManager) GetStream(sessionID uint32, streamID uint16) *StreamStateEntry {
	session := sm.GetSession(sessionID)
	if session == nil {
		return nil
	}

	session.Mu.RLock()
	defer session.Mu.RUnlock()

	if session.Streams == nil {
		return nil
	}
	return session.Streams[streamID]
}

// CloseStream помечает поток как закрытый и может использоваться для явного STREAM_CLOSE.
func (sm *SessionManager) CloseStream(sessionID uint32, streamID uint16) {
	session := sm.GetSession(sessionID)
	if session == nil {
		return
	}

	session.Mu.Lock()
	defer session.Mu.Unlock()

	if session.Streams == nil {
		return
	}
	if entry, ok := session.Streams[streamID]; ok {
		entry.Closed = true
		entry.LastActive = time.Now()
	}
}

// NewSessionManager создает менеджер сессий
func NewSessionManager(timeout time.Duration) *SessionManager {
	return NewSessionManagerWithLimit(timeout, 0) // По умолчанию без ограничений по сессиям
}

// NewSessionManagerWithLimit создает менеджер сессий с лимитом
func NewSessionManagerWithLimit(timeout time.Duration, maxSessions int) *SessionManager {
	sm := &SessionManager{
		sessions:             make(map[uint32]*SessionState),
		timeout:              timeout,
		maxSessions:          maxSessions,
		maxStreamsPerSession: 0,            // 0 = без ограничений по потокам
		streamIdleTimeout:    timeout / 2, // по умолчанию потоки живут в 2 раза меньше, чем сессия
	}
	
	// Запускаем очистку неактивных сессий
	go sm.cleanupLoop()
	
	return sm
}

// SetTimeout обновляет таймаут сессий и (если streamIdleTimeout не переопределен) таймаут потоков.
// Используется для live‑reload конфигурации (напр. когда меняется keepalive/профиль).
func (sm *SessionManager) SetTimeout(timeout time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if timeout <= 0 {
		return
	}
	sm.timeout = timeout
	// Если streamIdleTimeout не настраивался отдельно, держим его пропорциональным.
	if sm.streamIdleTimeout <= 0 || sm.streamIdleTimeout == sm.timeout/2 {
		sm.streamIdleTimeout = timeout / 2
	}
}

// generateCollisionFreeSessionID генерирует новый sessionID без коллизий
// SECURITY: Использует криптографически стойкий RNG и проверяет на коллизии
// В будущем рекомендуется перейти на 64-bit sessionID для уменьшения вероятности коллизий
func (sm *SessionManager) generateCollisionFreeSessionID() uint32 {
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			log.Printf("[SECURITY] Failed to generate sessionID: %v", err)
			continue
		}
		sessionID := binary.BigEndian.Uint32(b[:])
		
		// Проверяем, что sessionID не равен 0 и не существует
		if sessionID != 0 && sm.sessions[sessionID] == nil {
			return sessionID
		}
	}
	
	// Если не удалось сгенерировать за maxRetries попыток, возвращаем 0
	// Вызывающий код должен обработать это
	return 0
}

// GetOrCreateSession получает или создает сессию
func (sm *SessionManager) GetOrCreateSession(sessionID uint32) *SessionState {
	// Валидация SessionID
	if sessionID == 0 {
		return nil // SessionID не может быть 0
	}
	
	// ОПТИМИЗАЦИЯ: Используем RLock для быстрого пути
	sm.mu.RLock()
	if session, exists := sm.sessions[sessionID]; exists {
		sm.mu.RUnlock()
		// ОПТИМИЗАЦИЯ: Обновляем активность без блокировки если возможно
		session.Mu.Lock()
		session.LastActivity = time.Now()
		session.Mu.Unlock()
		return session
	}
	sm.mu.RUnlock()
	
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	// Double-check после блокировки на запись
	if session, exists := sm.sessions[sessionID]; exists {
		session.Mu.Lock()
		session.LastActivity = time.Now()
		session.Mu.Unlock()
		return session
	}
	
	// SECURITY: Проверка на коллизию sessionID
	// Если sessionID уже существует (что не должно было произойти после double-check выше),
	// это коллизия - генерируем новый
	// В будущем рекомендуется перейти на 64-bit sessionID для уменьшения вероятности коллизий
	originalSessionID := sessionID
	if _, exists := sm.sessions[sessionID]; exists && sessionID != 0 {
		log.Printf("[SECURITY] SessionID collision detected: %d (after double-check), generating new sessionID", sessionID)
		// Генерируем новый sessionID до 10 раз
		for retries := 0; retries < 10; retries++ {
			newSessionID := sm.generateCollisionFreeSessionID()
			if newSessionID != 0 {
				sessionID = newSessionID
				log.Printf("[SECURITY] Generated new collision-free sessionID: %d (was %d)", sessionID, originalSessionID)
				break
			}
		}
		if sessionID == originalSessionID {
			log.Printf("[SECURITY] WARNING: Failed to generate collision-free sessionID after retries, collision may occur")
			// В крайнем случае продолжаем с оригинальным sessionID
			// Это не идеально, но вероятность коллизии очень мала
		}
	}
	
	// Проверяем лимит на количество сессий
	if sm.maxSessions > 0 && len(sm.sessions) >= sm.maxSessions {
		// Достигнут лимит - пытаемся удалить самую старую неактивную сессию
		sm.forceCleanupOldest()
		// Проверяем снова
		if len(sm.sessions) >= sm.maxSessions {
			return nil // Все еще достигнут лимит
		}
	}
	
	// Создаем новую сессию с полной интеграцией network компонентов
	session := &SessionState{
		SessionID:      sessionID,
		SeqSend:        1,
		LastActivity:   time.Now(),
		RecvWin:        aeadpkg.NewSlidingWindow(),
		PacketBuffer:   networkpkg.NewPacketBuffer(100, 5*time.Second),
		MTU:            networkpkg.NewMTUDiscovery(1200, 576, 1500),
		Congestion:     networkpkg.NewCongestionController(10, 100, 2, 1000),
		RateLimit:      networkpkg.NewRateLimiter(10*1024*1024, 100*1024), // 10 MB/s, burst 100 KB
		usedRekeySalts: make(map[string]time.Time),                        // Защита от replay атак
		processedAcks:  make(map[uint32]time.Time),                        // Защита от дублирования ACK
		Streams:        make(map[uint16]*StreamStateEntry),
	}
	
	// RetransmissionManager будет инициализирован после создания сессии с правильным callback
	// Пока оставляем nil - callback будет установлен в UpdateSession или при handshake
	session.Retransmit = nil
	
	sm.sessions[sessionID] = session
	
	// Обновляем метрики
	metr.SessionsCreated.Inc()
	metr.SessionsActive.Set(float64(len(sm.sessions)))
	
	return session
}

// UpdateSession обновляет адрес и состояние шифрования сессии
func (sm *SessionManager) UpdateSession(sessionID uint32, clientAddr *net.UDPAddr, aeadState *aeadpkg.AEADState, seed []byte) {
	// ОПТИМИЗАЦИЯ: Используем RLock для чтения
	sm.mu.RLock()
	session, exists := sm.sessions[sessionID]
	sm.mu.RUnlock()
	
	if !exists {
		session = sm.GetOrCreateSession(sessionID)
	}
	
	// ОПТИМИЗАЦИЯ: Обновляем все поля в одной блокировке
	session.Mu.Lock()
	if clientAddr != nil {
		session.ClientAddr = clientAddr
		// Обновляем Retransmit callback если адрес изменился
		if session.Retransmit != nil && session.AEADState != nil {
			// Callback будет установлен извне при необходимости
		}
	}
	if aeadState != nil {
		session.AEADState = aeadState
	}
	if seed != nil {
		// ОПТИМИЗАЦИЯ: Переиспользуем память если размер не изменился
		if len(session.Seed) != len(seed) {
			session.Seed = make([]byte, len(seed))
		}
		copy(session.Seed, seed)
	}
	session.LastActivity = time.Now()
	session.Mu.Unlock()
}

// SetOutboundTag устанавливает outbound tag для сессии
func (sm *SessionManager) SetOutboundTag(sessionID uint32, outboundTag string) {
	session := sm.GetSession(sessionID)
	if session == nil {
		return
	}
	
	session.Mu.Lock()
	session.OutboundTag = outboundTag
	session.Mu.Unlock()
}

// SetUserID устанавливает userID для сессии
func (sm *SessionManager) SetUserID(sessionID uint32, userID string) {
	session := sm.GetSession(sessionID)
	if session == nil {
		return
	}
	
	session.Mu.Lock()
	session.UserID = userID
	session.Mu.Unlock()
}

// SetRetransmitCallback устанавливает callback для повторной передачи пакетов
func (sm *SessionManager) SetRetransmitCallback(sessionID uint32, callback func(seq uint32, data []byte) error) {
	session := sm.GetSession(sessionID)
	if session != nil && session.Retransmit != nil {
		session.Mu.Lock()
		defer session.Mu.Unlock()
		// RetransmissionManager требует пересоздания для установки callback
		// Пока оставляем как есть, callback устанавливается при создании
	}
}

// GetSession получает сессию
func (sm *SessionManager) GetSession(sessionID uint32) *SessionState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	return sm.sessions[sessionID]
}

// RemoveSession удаляет сессию и очищает все ресурсы
func (sm *SessionManager) RemoveSession(sessionID uint32) {
	sm.mu.Lock()
	session := sm.sessions[sessionID]
	delete(sm.sessions, sessionID)
	sessionCount := len(sm.sessions)
	sm.mu.Unlock()
	
	// Обновляем метрики
	metr.SessionsClosed.Inc()
	metr.SessionsActive.Set(float64(sessionCount))
	
	// Cleanup ресурсов сессии
	if session != nil {
		session.Mu.Lock()
		
		// Вычисляем длительность сессии для метрики
		sessionDuration := time.Since(session.LastActivity)
		if !session.LastActivity.IsZero() {
			metr.SessionDuration.Observe(sessionDuration.Seconds())
		}
		
		// Удаляем outbound tag из routing engine
		outboundTag := session.OutboundTag
		session.Mu.Unlock()
		
		// Вызываем callback для удаления из routing engine (если установлен)
		if sm.onSessionRemoved != nil {
			sm.onSessionRemoved(sessionID, outboundTag)
		}
		
		// Удаление connection из connection enforcer выполняется в вызывающем коде
		
		session.Mu.Lock()
		
		// Останавливаем RetransmissionManager
		if session.Retransmit != nil {
			session.Retransmit.Stop()
		}
		
		// Очищаем PacketBuffer
		if session.PacketBuffer != nil {
			session.PacketBuffer = nil
		}
		
		session.Mu.Unlock()
	}
}

// GetAllSessions возвращает все активные сессии
func (sm *SessionManager) GetAllSessions() []*SessionState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	sessions := make([]*SessionState, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// cleanupLoop периодически очищает неактивные сессии
func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	// Используем context.Background() так как это долгоживущий процесс
	// В будущем можно добавить контекст в SessionManager для graceful shutdown
	ctx := context.Background()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.mu.Lock()
			now := time.Now()
			for sessionID, session := range sm.sessions {
				// Сначала чистим неактивные потоки внутри сессии
				session.Mu.Lock()
				if session.Streams != nil {
					streamTimeout := sm.streamIdleTimeout
					if streamTimeout <= 0 {
						streamTimeout = sm.timeout
					}
					for sid, st := range session.Streams {
						if now.Sub(st.LastActive) > streamTimeout {
							st.Closed = true
							delete(session.Streams, sid)
						}
					}
				}
				inactive := now.Sub(session.LastActivity) > sm.timeout
				session.Mu.Unlock()

				// Затем, при необходимости, удаляем саму сессию
				if inactive {
					delete(sm.sessions, sessionID)
					// Обновляем метрики при удалении неактивной сессии
					metr.SessionsClosed.Inc()
					metr.SessionsActive.Set(float64(len(sm.sessions)))
				}
			}
			sm.mu.Unlock()
		}
	}
}

// forceCleanupOldest удаляет самую старую неактивную сессию (используется при достижении лимита)
// ВНИМАНИЕ: вызывается внутри Lock(), не блокирует повторно
func (sm *SessionManager) forceCleanupOldest() {
	if len(sm.sessions) == 0 {
		return
	}
	
	var oldestSessionID uint32
	var oldestTime time.Time
	first := true
	
	now := time.Now()
	minInactiveTime := 1 * time.Minute // Минимум 1 минута неактивности
	
	for sessionID, session := range sm.sessions {
		session.Mu.RLock()
		lastActivity := session.LastActivity
		inactiveDuration := now.Sub(lastActivity)
		session.Mu.RUnlock()
		
		// Ищем самую старую неактивную сессию
		if inactiveDuration > minInactiveTime {
			if first || lastActivity.Before(oldestTime) {
				oldestSessionID = sessionID
				oldestTime = lastActivity
				first = false
			}
		}
	}
	
	// Удаляем самую старую неактивную сессию
	if !first {
		delete(sm.sessions, oldestSessionID)
	}
}

// GetSessionCount возвращает текущее количество активных сессий
func (sm *SessionManager) GetSessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// GetMaxSessions возвращает максимальное количество сессий (0 = без ограничений)
func (sm *SessionManager) GetMaxSessions() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.maxSessions
}

// IncrementSeqSend инкрементирует seqSend для сессии
func (sm *SessionManager) IncrementSeqSend(sessionID uint32) uint32 {
	session := sm.GetSession(sessionID)
	if session == nil {
		return 1
	}
	
	session.Mu.Lock()
	defer session.Mu.Unlock()
	
	session.SeqSend++
	session.LastActivity = time.Now()
	return session.SeqSend
}

// UpdateSessionAEAD обновляет AEAD state в сессии (для rekey)
func (sm *SessionManager) UpdateSessionAEAD(sessionID uint32, newAead *aeadpkg.AEADState) {
	session := sm.GetSession(sessionID)
	if session == nil {
		return
	}
	
	session.Mu.Lock()
	defer session.Mu.Unlock()
	
	session.AEADState = newAead
	session.RecvWin = aeadpkg.NewSlidingWindow()
	session.SeqSend = 1
	session.LastActivity = time.Now()
}

// AddSession добавляет новую сессию (alias для UpdateSession с новыми данными)
func (sm *SessionManager) AddSession(
	sessionID uint32,
	clientAddr *net.UDPAddr,
	aeadState *aeadpkg.AEADState,
	seed []byte,
) *SessionState {
	sm.UpdateSession(sessionID, clientAddr, aeadState, seed)
	return sm.GetSession(sessionID)
}

// UpdateActivity обновляет время последней активности
func (sm *SessionManager) UpdateActivity(sessionID uint32) {
	session := sm.GetSession(sessionID)
	if session != nil {
		session.Mu.Lock()
		session.LastActivity = time.Now()
		session.Mu.Unlock()
	}
}

// GetSeqSend возвращает текущий seqSend
func (sm *SessionManager) GetSeqSend(sessionID uint32) uint32 {
	session := sm.GetSession(sessionID)
	if session == nil {
		return 1
	}
	
	session.Mu.RLock()
	defer session.Mu.RUnlock()
	
	return session.SeqSend
}

// GetSessionByClientAddr возвращает сессию по адресу клиента
func (sm *SessionManager) GetSessionByClientAddr(addr *net.UDPAddr) *SessionState {
	// ОПТИМИЗАЦИЯ: Кэшируем строковое представление адреса
	addrStr := addr.String()
	
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	// ОПТИМИЗАЦИЯ: Используем RLock для чтения, минимизируем блокировки
	for _, session := range sm.sessions {
		session.Mu.RLock()
		if session.ClientAddr != nil && session.ClientAddr.String() == addrStr {
			session.Mu.RUnlock()
			return session
		}
		session.Mu.RUnlock()
	}
	return nil
}

// AddRoute добавляет маршрут IP -> sessionID
func (sm *SessionManager) AddRoute(destIP net.IP, sessionID uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	// Сохраняем маршрут в сессии
	if session := sm.sessions[sessionID]; session != nil {
		session.Mu.Lock()
		// Можно добавить поле Routes в SessionState если нужно
		session.Mu.Unlock()
	}
}

// FindSessionByDestinationIP ищет сессию по destination IP из TUN пакета
// Использует таблицу маршрутизации RouteTable если доступна, иначе fallback на первую активную сессию
func (sm *SessionManager) FindSessionByDestinationIP(destIP net.IP, routeTable *RouteTable) *SessionState {
	if destIP == nil {
		return nil
	}

	// Если есть таблица маршрутизации, используем её
	if routeTable != nil {
		if sessionID, found := routeTable.FindRoute(destIP); found && sessionID != 0 {
			session := sm.GetSession(sessionID)
			if session != nil && session.AEADState != nil && session.ClientAddr != nil {
				return session
			}
		}
	}

	// Fallback: ищем сессию по IP клиента (если destination IP совпадает с IP клиента)
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	destIPStr := destIP.String()
	
	// Сначала пробуем найти точное совпадение с IP клиента
	for _, session := range sm.sessions {
		if session != nil && session.AEADState != nil && session.ClientAddr != nil {
			if session.ClientAddr.IP.String() == destIPStr {
				return session
			}
		}
	}
	
	// Если не найдено, возвращаем первую активную сессию (старое поведение для совместимости)
	// ОПТИМИЗАЦИЯ: Всегда возвращаем активную сессию если есть хотя бы одна
	for _, session := range sm.sessions {
		if session != nil {
			session.Mu.RLock()
			hasAEAD := session.AEADState != nil
			hasAddr := session.ClientAddr != nil
			session.Mu.RUnlock()
			if hasAEAD && hasAddr {
				return session
			}
		}
	}
	
	return nil
}

// GetFirstActiveSession возвращает первую активную сессию (для fallback маршрутизации)
// КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Этот метод гарантирует, что если есть хотя бы одна активная сессия,
// она будет возвращена, что необходимо для работы с Fake-IP и когда маршрутизация не настроена
// Соответствует подходу Clash Verge Rev и Prizrak-Box (Mihomo) - всегда есть default outbound
func (sm *SessionManager) GetFirstActiveSession() *SessionState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	for _, session := range sm.sessions {
		if session != nil {
			session.Mu.RLock()
			hasAEAD := session.AEADState != nil
			hasAddr := session.ClientAddr != nil
			session.Mu.RUnlock()
			if hasAEAD && hasAddr {
				return session
			}
		}
	}
	
	return nil
}

// SetSeqSend устанавливает seqSend
func (sm *SessionManager) SetSeqSend(sessionID uint32, seq uint32) {
	session := sm.GetSession(sessionID)
	if session == nil {
		return
	}
	
	session.Mu.Lock()
	defer session.Mu.Unlock()
	
	session.SeqSend = seq
}

// CheckAndRegisterRekeySalt проверяет и регистрирует salt для rekey
// Возвращает true если salt уже использовался (replay attack попытка)
func (sm *SessionManager) CheckAndRegisterRekeySalt(sessionID uint32, salt []byte) bool {
	session := sm.GetSession(sessionID)
	if session == nil {
		return false // Сессия не найдена, разрешаем (проверка будет в другом месте)
	}
	
	session.Mu.Lock()
	defer session.Mu.Unlock()
	
	// Инициализация если не инициализировано
	if session.usedRekeySalts == nil {
		session.usedRekeySalts = make(map[string]time.Time)
	}
	
	// Преобразуем salt в строку для использования в качестве ключа
	saltKey := hex.EncodeToString(salt)
	
	// Проверяем, использовался ли этот salt ранее
	if usedTime, exists := session.usedRekeySalts[saltKey]; exists {
		log.Printf("REPLAY ATTACK DETECTED: Salt %s already used at %v for session %d", 
			saltKey[:16], usedTime, sessionID)
		return true // Salt уже использовался - возможная replay атака
	}
	
	// КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Защита от утечки памяти - лимит на количество сохраненных salt
	maxSalts := 1000 // Максимальное количество сохраненных salt на сессию
	if len(session.usedRekeySalts) >= maxSalts {
		// Удаляем 10% самых старых записей
		type saltTime struct {
			key  string
			time time.Time
		}
		salts := make([]saltTime, 0, len(session.usedRekeySalts))
		for k, t := range session.usedRekeySalts {
			salts = append(salts, saltTime{k, t})
		}
		// Сортируем по времени (старые сначала)
		for i := 0; i < len(salts)-1; i++ {
			for j := i + 1; j < len(salts); j++ {
				if salts[i].time.After(salts[j].time) {
					salts[i], salts[j] = salts[j], salts[i]
				}
			}
		}
		// Удаляем 10% самых старых
		toDelete := len(salts) / 10
		if toDelete < 1 {
			toDelete = 1
		}
		for i := 0; i < toDelete && i < len(salts); i++ {
			delete(session.usedRekeySalts, salts[i].key)
		}
	}
	
	// Регистрируем новый salt
	session.usedRekeySalts[saltKey] = time.Now()
	
	// Очищаем старые salt (старше 1 часа) чтобы избежать утечки памяти
	now := time.Now()
	maxAge := 1 * time.Hour
	for key, usedTime := range session.usedRekeySalts {
		if now.Sub(usedTime) > maxAge {
			delete(session.usedRekeySalts, key)
		}
	}
	
	return false // Salt новый и зарегистрирован
}

// CleanupOldRekeySalts очищает старые salt (вызывается периодически)
func (sm *SessionManager) CleanupOldRekeySalts(maxAge time.Duration) {
	sm.mu.RLock()
	sessions := make([]*SessionState, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	sm.mu.RUnlock()
	
	now := time.Now()
	for _, session := range sessions {
		session.Mu.Lock()
		if session.usedRekeySalts != nil {
			for key, usedTime := range session.usedRekeySalts {
				if now.Sub(usedTime) > maxAge {
					delete(session.usedRekeySalts, key)
				}
			}
		}
		// Очищаем старые processed ACKs
		if session.processedAcks != nil {
			for seq, processedTime := range session.processedAcks {
				if now.Sub(processedTime) > maxAge {
					delete(session.processedAcks, seq)
				}
			}
		}
		session.Mu.Unlock()
	}
}

// CheckAndRegisterAck проверяет и регистрирует обработанный ACK
// Возвращает true если ACK уже был обработан ранее (дубликат)
func (sm *SessionManager) CheckAndRegisterAck(sessionID uint32, ackedSeq uint32) bool {
	session := sm.GetSession(sessionID)
	if session == nil {
		return false // Сессия не найдена, разрешаем (обработка будет в другом месте)
	}
	
	session.Mu.Lock()
	defer session.Mu.Unlock()
	
	// Инициализация если не инициализировано
	if session.processedAcks == nil {
		session.processedAcks = make(map[uint32]time.Time)
	}
	
	// Проверяем, был ли этот ACK уже обработан
	if processedTime, exists := session.processedAcks[ackedSeq]; exists {
		// ACK уже был обработан - возможный дубликат или replay
		// Логируем только если прошло достаточно времени (не банальный дубликат от сети)
		if time.Since(processedTime) > 1*time.Second {
			log.Printf("Duplicate ACK detected: seq %d for session %d (first processed at %v)", 
				ackedSeq, sessionID, processedTime)
		}
		return true // ACK уже был обработан
	}
	
	// КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Защита от утечки памяти - лимит на количество сохраненных ACK
	maxAcks := 5000 // Максимальное количество сохраненных ACK на сессию
	if len(session.processedAcks) >= maxAcks {
		// Удаляем 10% самых старых записей
		type ackTime struct {
			seq  uint32
			time time.Time
		}
		acks := make([]ackTime, 0, len(session.processedAcks))
		for s, t := range session.processedAcks {
			acks = append(acks, ackTime{s, t})
		}
		// Сортируем по времени (старые сначала)
		for i := 0; i < len(acks)-1; i++ {
			for j := i + 1; j < len(acks); j++ {
				if acks[i].time.After(acks[j].time) {
					acks[i], acks[j] = acks[j], acks[i]
				}
			}
		}
		// Удаляем 10% самых старых
		toDelete := len(acks) / 10
		if toDelete < 1 {
			toDelete = 1
		}
		for i := 0; i < toDelete && i < len(acks); i++ {
			delete(session.processedAcks, acks[i].seq)
		}
	}
	
	// Регистрируем новый ACK
	session.processedAcks[ackedSeq] = time.Now()
	
	// Очищаем старые ACK (старше 1 часа) чтобы избежать утечки памяти
	now := time.Now()
	maxAge := 1 * time.Hour
	for seq, processedTime := range session.processedAcks {
		if now.Sub(processedTime) > maxAge {
			delete(session.processedAcks, seq)
		}
	}
	
	return false // ACK новый и зарегистрирован
}

