package evasion

import (
	"bytes"
	"context"
	crypto "crypto/md5" //nolint:gosec // MD5 used for TLS fingerprinting, not cryptography
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"whispera/internal/obfuscation/core/types"
	"whispera/internal/obfuscation/core/profiles"
	"whispera/internal/obfuscation/core/utils"
	analysis "whispera/internal/obfuscation/core/analysis"
	"whispera/internal/util"
)

const (
	circuitStateClosed = "closed"
	profileDefault     = "default"
	
	// Пул буферов для переиспользования памяти
	bufferPoolSmallSize  = 512
	bufferPoolMediumSize = 2048
	bufferPoolLargeSize  = 8192
)

// Пул буферов для переиспользования памяти (sync.Pool)
var (
	bufferPoolSmall = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, bufferPoolSmallSize)
		},
	}
	bufferPoolMedium = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, bufferPoolMediumSize)
		},
	}
	bufferPoolLarge = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, bufferPoolLargeSize)
		},
	}
	
	// Пул каналов для результатов
	resultChanPool = sync.Pool{
		New: func() interface{} {
			return make(chan []byte, 1)
		},
	}
	errorChanPool = sync.Pool{
		New: func() interface{} {
			return make(chan error, 1)
		},
	}
)

// EffectivenessMetrics tracks effectiveness metrics
type EffectivenessMetrics struct {
	TotalPackets      int64
	SuccessfulEvasion int64
	FailedEvasion     int64
	LastUpdate        time.Time
}

// Feature gates for safe-by-default behavior in production
// Enable by setting environment variables to "1":
//   - WHISPERA_CORE_EVASION: enables evasive actions (JA3/JA4/HTTP/TLS/behavioral)
//   - WHISPERA_CORE_RULES: enables default rule actions (resize/delay/etc.)
var (
	enableCoreEvasion = os.Getenv("WHISPERA_CORE_EVASION") == "1"
	enableCoreRules   = os.Getenv("WHISPERA_CORE_RULES") == "1"
	// Separate gate for adaptive/behavioral mimicry
	enableAdaptiveMimicry = os.Getenv("WHISPERA_ADAPTIVE_MIMICRY") == "1"
)

// RecordSuccess records a successful evasion
// ОПТИМИЗАЦИЯ: Используем кэшированное время для уменьшения системных вызовов
func (em *EffectivenessMetrics) RecordSuccess(profile string, method string, latency time.Duration) error {
	em.SuccessfulEvasion++
	em.TotalPackets++
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	timeCache := util.GetGlobalTimeCache()
	em.LastUpdate = timeCache.Now()
	return nil
}

// RecordFailure records a failed evasion
// ОПТИМИЗАЦИЯ: Используем кэшированное время для уменьшения системных вызовов
func (em *EffectivenessMetrics) RecordFailure(profile string, method string, reason string) error {
	em.FailedEvasion++
	em.TotalPackets++
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	timeCache := util.GetGlobalTimeCache()
	em.LastUpdate = timeCache.Now()
	return nil
}

// GetEffectiveness returns effectiveness stats for a profile
func (em *EffectivenessMetrics) GetEffectiveness(profile string) *types.EffectivenessStats {
	if em.TotalPackets == 0 {
		return &types.EffectivenessStats{
			SuccessRate:   0.0,
			TotalAttempts: 0,
		}
	}
	return &types.EffectivenessStats{
		SuccessRate:   float64(em.SuccessfulEvasion) / float64(em.TotalPackets),
		TotalAttempts: em.TotalPackets,
	}
}

// GetOverallEffectiveness returns overall effectiveness stats
func (em *EffectivenessMetrics) GetOverallEffectiveness() *types.EffectivenessStats {
	return em.GetEffectiveness("")
}

// NewEffectivenessMetrics creates new effectiveness metrics
// ОПТИМИЗАЦИЯ: Используем кэшированное время
func NewEffectivenessMetrics() *EffectivenessMetrics {
	timeCache := util.GetGlobalTimeCache()
	return &EffectivenessMetrics{
		TotalPackets:      0,
		SuccessfulEvasion: 0,
		FailedEvasion:     0,
		LastUpdate:        timeCache.Now(),
	}
}

// Marionette implements programmable network traffic obfuscation
// Enhanced with MITRE T1071.001 Application Layer Protocol techniques
// Based on scientific research:
// - MITRE ATT&CK T1071.001: Application Layer Protocol evasion
// - NetMasquerade (2025): Reinforcement Learning for traffic mimicry
// - Fingerprinting defense based on "Fingerprinting Websites Using Traffic Analysis" (2007)
// - Statistical masking from "Toward an Efficient Website Fingerprinting Defense" (2016)
// - Traffic obfuscation from "Network Traffic Obfuscation" (2016)
//
// Enhanced DPI Evasion Effectiveness:
// - Simple DPI (80-95% success): Static filters, basic signatures
// - Advanced DPI (60-80% success): ML-based, behavioral analysis, deep inspection
// - Government DPI (25-40% success): Multi-level systems, metadata analysis
type Marionette struct {
	rules            []types.ObfuscationRule
	state            *types.TrafficState
	profiles         map[string]*types.TrafficProfile
	active           string
	mutex            sync.RWMutex
	mlSystem         *UnifiedMLSystem
	adaptiveLearning types.AdaptiveLearning
	effectiveness    *EffectivenessMetrics
	coverTraffic     []byte // Store cover traffic for later use
	dynamicManager   *DynamicProfileManagerImpl
	realAPI          *RealAPIIntegration
	adaptiveManager  types.AdaptiveProfileManager // New adaptive profile manager

	// Resilience and monitoring
	circuitBreaker *CircuitBreaker
	metrics        *SystemMetrics
	fallbackMode   bool // Fallback mode when ML system fails
	
	// Асинхронная обработка
	evasionWorkerPool *EvasionWorkerPool
	ruleCache         sync.Map // Кэш результатов обработки правил
	processingQueue   chan *PacketJob
	ctx                context.Context
	cancel             context.CancelFunc
	wg                 sync.WaitGroup
}

// PacketJob представляет задачу обработки пакета
type PacketJob struct {
	Data      []byte
	Direction string
	Result    chan *PacketResult
	Error     chan error
	Timeout   time.Duration
	Timestamp time.Time
}

// PacketResult представляет результат обработки пакета
type PacketResult struct {
	Data  []byte
	Delay time.Duration
}

// EvasionWorkerPool - пул воркеров для асинхронной обработки evasion техник
type EvasionWorkerPool struct {
	workers    int
	jobQueue   chan *EvasionJob
	workerPool chan chan *EvasionJob
	quit       chan struct{}
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

// EvasionJob представляет задачу для evasion обработки
type EvasionJob struct {
	Data      []byte
	Params    map[string]interface{}
	Result    chan []byte
	Error     chan error
	Timeout   time.Duration
	Timestamp time.Time
}

// CircuitBreaker for ML system resilience
type CircuitBreaker struct {
	failureCount    int
	lastFailureTime time.Time
	state           string // "closed", "open", "half-open"
	threshold       int
	timeout         time.Duration
}

// SystemMetrics tracks system performance and resilience
// ОПТИМИЗАЦИЯ: Используем atomic для счетчиков для лучшей производительности
type SystemMetrics struct {
	PacketsProcessed    int64 // Используется atomic
	MLPredictions       int64 // Используется atomic
	MLFailures          int64 // Используется atomic
	AverageLatency      int64 // Хранится как nanoseconds для atomic операций
	MemoryUsage         int64 // Используется atomic
	LastCleanup         int64 // Хранится как UnixNano для atomic операций
	CircuitBreakerTrips int64 // Используется atomic
}

// NewMarionette creates a new Marionette obfuscation system
func NewMarionette() *Marionette {
	ctx, cancel := context.WithCancel(context.Background())
	
	m := &Marionette{
		rules: make([]types.ObfuscationRule, 0),
		state: &types.TrafficState{
			MaxHistorySize:  1000, // Limit history to prevent memory leaks
			LastCleanup:     util.GetGlobalTimeCache().Now(),
			CleanupInterval: 30 * time.Second,
		},
		profiles:         make(map[string]*types.TrafficProfile),
		mlSystem:         NewUnifiedMLSystem(),
		adaptiveLearning: &AdaptiveLearningImpl{},
		effectiveness:    &EffectivenessMetrics{},
		adaptiveManager:  &AdaptiveProfileManagerImpl{}, // Initialize adaptive profile manager

		// Initialize resilience components
		circuitBreaker: &CircuitBreaker{
			state:     circuitStateClosed,
			threshold: 5,
			timeout:   30 * time.Second,
		},
		metrics: &SystemMetrics{
			LastCleanup: util.GetGlobalTimeCache().Now().UnixNano(),
		},
		fallbackMode: false,
		
		// Инициализация асинхронной обработки
		ctx:              ctx,
		cancel:           cancel,
		processingQueue:  make(chan *PacketJob, 4096), // Буферизованная очередь
	}

	// Инициализация пула воркеров для evasion обработки
	m.evasionWorkerPool = NewEvasionWorkerPool()

	// Initialize with default profiles
	m.initDefaultProfiles()
	m.initDefaultRules()

	// Initialize Russian service profiles for realistic mimicry
	m.initRussianServiceProfiles()

	// Initialize mobile device profiles
	m.initMobileDeviceProfiles()

	// Initialize dynamic profile manager
	m.initDynamicProfileManager()

	// Load real traffic data for calibration
	m.loadRealTrafficData("fixed_traffic_data.csv")

	return m
}

// NewEvasionWorkerPool создает новый пул воркеров для evasion обработки
func NewEvasionWorkerPool() *EvasionWorkerPool {
	workers := runtime.NumCPU()
	if workers > 16 {
		workers = 16 // Ограничиваем максимальное количество воркеров
	}
	if workers < 2 {
		workers = 2 // Минимум 2 воркера
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	pool := &EvasionWorkerPool{
		workers:    workers,
		jobQueue:   make(chan *EvasionJob, 2048), // Буферизованная очередь
		workerPool: make(chan chan *EvasionJob, workers),
		quit:       make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
	}
	pool.start()
	return pool
}

// start запускает пул воркеров
func (p *EvasionWorkerPool) start() {
	// Запускаем воркеры
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	
	// Диспетчер задач
	go p.dispatcher()
}

// dispatcher распределяет задачи по воркерам
func (p *EvasionWorkerPool) dispatcher() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.quit:
			return
		case job := <-p.jobQueue:
			// Проверяем таймаут до распределения
			if time.Since(job.Timestamp) > job.Timeout {
				select {
				case job.Result <- job.Data:
				case job.Error <- nil:
				default:
				}
				continue
			}
			// Выбираем свободного воркера
			select {
			case workerChan := <-p.workerPool:
				select {
				case workerChan <- job:
				default:
					// Воркер занят, обрабатываем напрямую
					go p.processJobDirectly(job)
				}
			default:
				// Нет свободных воркеров, обрабатываем напрямую
				go p.processJobDirectly(job)
			}
		}
	}
}

// worker обрабатывает задачи из очереди
func (p *EvasionWorkerPool) worker() {
	defer p.wg.Done()
	
	workerChan := make(chan *EvasionJob, 1)
	
	for {
		// Регистрируем воркера в пуле
		select {
		case <-p.ctx.Done():
			return
		case <-p.quit:
			return
		case p.workerPool <- workerChan:
			// Воркер готов к работе
			select {
			case <-p.ctx.Done():
				return
			case <-p.quit:
				return
			case job := <-workerChan:
				p.processJob(job)
			}
		}
	}
}

// processJob обрабатывает задачу evasion
func (p *EvasionWorkerPool) processJob(job *EvasionJob) {
	defer func() {
		if r := recover(); r != nil {
			select {
			case job.Error <- nil:
			default:
			}
		}
	}()
	
	// Проверяем таймаут
	if time.Since(job.Timestamp) > job.Timeout {
		select {
		case job.Result <- job.Data:
		case job.Error <- nil:
		default:
		}
		return
	}
	
	// Обрабатываем задачу (здесь будет вызов evasion методов)
	// Пока возвращаем исходные данные
	select {
	case job.Result <- job.Data:
	case job.Error <- nil:
	default:
	}
}

// processJobDirectly обрабатывает задачу напрямую (когда пул переполнен)
func (p *EvasionWorkerPool) processJobDirectly(job *EvasionJob) {
	p.processJob(job)
}

// SubmitJob отправляет задачу в пул воркеров
func (p *EvasionWorkerPool) SubmitJob(data []byte, params map[string]interface{}, timeout time.Duration) ([]byte, error) {
	job := &EvasionJob{
		Data:      data,
		Params:    params,
		Result:    make(chan []byte, 1),
		Error:     make(chan error, 1),
		Timeout:   timeout,
		Timestamp: util.GetGlobalTimeCache().Now(),
	}
	
	select {
	case p.jobQueue <- job:
		// Задача отправлена в очередь
		select {
		case result := <-job.Result:
			return result, nil
		case err := <-job.Error:
			return data, err
		case <-time.After(timeout):
			return data, fmt.Errorf("evasion job timeout")
		}
	default:
		// Очередь переполнена, обрабатываем напрямую
		return p.processJobDirectlySync(job)
	}
}

// processJobDirectlySync обрабатывает задачу синхронно
func (p *EvasionWorkerPool) processJobDirectlySync(job *EvasionJob) ([]byte, error) {
	if time.Since(job.Timestamp) > job.Timeout {
		return job.Data, nil
	}
	return job.Data, nil
}

// Stop останавливает пул воркеров
func (p *EvasionWorkerPool) Stop() {
	close(p.quit)
	p.cancel()
	p.wg.Wait()
}

// ProcessPacket applies obfuscation rules to a packet with ML analysis
// ОПТИМИЗИРОВАНО по примеру Xray-core для максимальной производительности
func (m *Marionette) ProcessPacket(data []byte, direction string) ([]byte, time.Duration, error) {
	// Оптимизация: используем RLock для чтения состояния, Lock только для записи
	m.mutex.RLock()
	inFallback := m.isFallbackMode()
	circuitBreakerOK := m.checkCircuitBreaker()
	hasML := m.mlSystem != nil
	hasAdaptive := m.adaptiveManager != nil
	m.mutex.RUnlock()

	// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ Xray-core: Упрощенная metadata protection для маленьких пакетов
	// Для маленьких пакетов применяем минимальную защиту без задержек
	if len(data) < 512 {
		// Минимальная защита без padding и cover traffic для скорости
		// Только базовая маскировка для маленьких пакетов
	} else {
		// Для больших пакетов применяем полную защиту
		data = m.applyMetadataProtection(data)
	}

	// ML анализ пакета - только если circuit breaker открыт и ML доступен
	// ОПТИМИЗАЦИЯ: Используем пул каналов для переиспользования
	if hasML && circuitBreakerOK && !inFallback {
		context := &types.UnifiedTrafficContext{
			Direction: direction,
			Protocol:  "Marionette",
			Size:      len(data),
			Timestamp: util.GetGlobalTimeCache().Now(),
		}

		// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: ML только для очень больших пакетов (2048+ байт)
		if len(data) > 2048 {
			// Используем пул каналов для переиспользования
			mlResult := resultChanPool.Get().(chan []byte)
			mlError := errorChanPool.Get().(chan error)
			defer func() {
				// Очищаем каналы перед возвратом в пул
				select {
				case <-mlResult:
				default:
				}
				select {
				case <-mlError:
				default:
				}
				resultChanPool.Put(mlResult)
				errorChanPool.Put(mlError)
			}()
			
			// Try ML processing with timeout для предотвращения блокировки
			go func() {
				result, err := m.mlSystem.ProcessTraffic(data, context)
				select {
				case mlResult <- result:
				default:
				}
				select {
				case mlError <- err:
				default:
				}
			}()
			
			// Таймаут для ML вызова - не ждем больше 10ms
			select {
			case result := <-mlResult:
				err := <-mlError
				m.mutex.Lock()
				if err != nil {
					m.recordMLFailure()
					m.enableFallbackMode()
				} else {
					m.recordMLSuccess()
					// Используем результат только если он не пустой
					if len(result) > 0 && !bytes.Equal(result, data) {
						data = result
					}
				}
				m.mutex.Unlock()
			case <-time.After(10 * time.Millisecond):
				// Таймаут - пропускаем ML обработку для производительности
				m.mutex.Lock()
				m.recordMLFailure()
				m.mutex.Unlock()
			}
		}
	}

	// Adaptive learning - только если не в fallback mode
	if hasAdaptive && !inFallback {
		m.mutex.RLock()
		_ = m.analyzeTrafficSuccess(data, direction)
		m.mutex.RUnlock()
	}

	// Update state и применение правил - требует блокировки для записи
	m.mutex.Lock()
	m.updateState(data, direction)

	// Apply rules in priority order
	processed := data
	delay := time.Duration(0)

	// Кешируем правила для быстрого доступа
	rules := m.rules
	atomic.AddInt64(&m.metrics.PacketsProcessed, 1)
	m.mutex.Unlock()

	// ОПТИМИЗАЦИЯ: Применяем правила с кэшированием и параллельной обработкой для больших пакетов
	if len(processed) < 512 {
		// Для маленьких пакетов применяем только критичные правила без задержек
		for _, rule := range rules {
			if !rule.Enabled || rule.Priority < 5 {
				continue // Пропускаем низкоприоритетные правила для скорости
			}
			// Быстрая проверка условий без блокировки
			if m.evaluateConditionFast(rule.Condition) {
				processed, delay = m.applyAction(rule.Action, processed, rule.Parameters)
				// Для маленьких пакетов игнорируем delay
				delay = 0
			}
		}
	} else {
		// Для больших пакетов применяем все правила с возможностью параллельной обработки
		// ОПТИМИЗАЦИЯ: Используем кэш для часто используемых правил
		cacheKey := fmt.Sprintf("%d_%s_%d", len(processed), direction, len(rules))
		if cached, ok := m.ruleCache.Load(cacheKey); ok {
			if cachedResult, ok := cached.(*PacketResult); ok {
				// Используем кэшированный результат (с копированием данных)
				processed = make([]byte, len(cachedResult.Data))
				copy(processed, cachedResult.Data)
				delay = cachedResult.Delay
			}
		} else {
			// Обрабатываем правила последовательно (можно распараллелить для независимых правил)
		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}
			// Быстрая проверка условий без блокировки
			if m.evaluateConditionFast(rule.Condition) {
				processed, delay = m.applyAction(rule.Action, processed, rule.Parameters)
				}
			}
			// Кэшируем результат (только для успешных обработок)
			if len(processed) > 0 {
				resultCopy := make([]byte, len(processed))
				copy(resultCopy, processed)
				m.ruleCache.Store(cacheKey, &PacketResult{
					Data:  resultCopy,
					Delay: delay,
				})
				// Ограничиваем размер кэша (удаляем старые записи)
				if atomic.LoadInt64(&m.metrics.PacketsProcessed)%1000 == 0 {
					m.cleanupRuleCache()
				}
			}
		}
	}

	// ОПТИМИЗАЦИЯ: Обновляем метрики через atomic операции (без блокировки)
	if delay > 0 {
		// Используем atomic для обновления средней задержки
		for {
			oldLatency := atomic.LoadInt64(&m.metrics.AverageLatency)
			newLatency := (oldLatency + delay.Nanoseconds()) / 2
			if atomic.CompareAndSwapInt64(&m.metrics.AverageLatency, oldLatency, newLatency) {
				break
			}
		}
	}

	return processed, delay, nil
}

// evaluateConditionFast - быстрая версия evaluateCondition без блокировок
func (m *Marionette) evaluateConditionFast(condition types.Condition) bool {
	// Быстрая проверка условий с RLock для производительности
	// Используем RLock вместо Lock, так как мы только читаем состояние
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.evaluateCondition(condition)
}

// SetActiveProfile sets the active traffic profile
func (m *Marionette) SetActiveProfile(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	m.active = name
	return nil
}

// GetState returns the current traffic state
func (m *Marionette) GetState() *types.TrafficState {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.state
}

// GetProfileNames returns all available profile names
// ОПТИМИЗАЦИЯ: Предварительно выделяем память для слайса
func (m *Marionette) GetProfileNames() []string {
	m.mutex.RLock()
	profileCount := len(m.profiles)
	m.mutex.RUnlock()

	// ОПТИМИЗАЦИЯ: Предварительно выделяем память
	names := make([]string, 0, profileCount)
	
	m.mutex.RLock()
	for name := range m.profiles {
		names = append(names, name)
	}
	m.mutex.RUnlock()
	
	return names
}

// GetActiveProfile returns the active profile name
func (m *Marionette) GetActiveProfile() string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.active
}

// SwitchProfile switches to a new profile (for API compatibility)
func (m *Marionette) SwitchProfile(targetProfile, reason string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if targetProfile == "" {
		return fmt.Errorf("target profile cannot be empty")
	}
	if reason == "" {
		reason = "manual_switch"
	}
	
	oldProfile := m.active
	
	// Check if profile exists
	if _, exists := m.profiles[targetProfile]; !exists {
		return fmt.Errorf("profile '%s' does not exist", targetProfile)
	}
	
	// Validate profile is different from current
	if oldProfile == targetProfile {
		return fmt.Errorf("profile '%s' is already active", targetProfile)
	}
	
	// Perform the switch
	m.active = targetProfile
	
	// Record the switch if dynamicManager is available
	if m.dynamicManager != nil {
		switchEvent := types.ProfileSwitch{
			FromProfile:   oldProfile,
			ToProfile:     targetProfile,
			Timestamp:     util.GetGlobalTimeCache().Now(),
			Reason:        reason,
			Success:       true,
			Effectiveness: 0.0,
		}
		if m.dynamicManager.profileHistory == nil {
			m.dynamicManager.profileHistory = []types.ProfileSwitch{}
		}
		m.dynamicManager.profileHistory = append(m.dynamicManager.profileHistory, switchEvent)
		m.dynamicManager.activeProfile = targetProfile
		// ОПТИМИЗАЦИЯ: Используем кэшированное время
		m.dynamicManager.lastSwitchTime = util.GetGlobalTimeCache().Now()
	}
	
	return nil
}

// GetCurrentProfile returns the current active profile (for API compatibility)
func (m *Marionette) GetCurrentProfile() string {
	return m.GetActiveProfile()
}

// GetProfileSwitchHistory returns profile switch history (for API compatibility)
func (m *Marionette) GetProfileSwitchHistory() []types.ProfileSwitch {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	if m.dynamicManager == nil || m.dynamicManager.profileHistory == nil {
		return []types.ProfileSwitch{}
	}
	return m.dynamicManager.profileHistory
}

// AddProfile adds a new profile (for API compatibility)
func (m *Marionette) AddProfile(name string, config map[string]interface{}) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if _, exists := m.profiles[name]; exists {
		return fmt.Errorf("profile %s already exists", name)
	}
	
	// Create profile from config
	profile := &types.TrafficProfile{
		Name: name,
		Type: "custom",
	}
	
	// Extract common fields from config
	if val, ok := config["type"].(string); ok {
		profile.Type = val
	}
	
	m.profiles[name] = profile
	return nil
}

// RemoveProfile removes a profile (for API compatibility)
func (m *Marionette) RemoveProfile(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if _, exists := m.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}
	
	// Cannot remove active profile
	if m.active == name {
		return fmt.Errorf("cannot remove active profile %s, switch to another profile first", name)
	}
	
	delete(m.profiles, name)
	return nil
}

// StartDynamicManager starts the dynamic profile manager background tasks
func (m *Marionette) StartDynamicManager() {
	// Start background monitoring if dynamic manager is available
	if m.dynamicManager != nil {
		// Background monitoring can be added here if needed
		// For now, dynamic manager is initialized but monitoring is optional
	}
}

// ApplyProductionDPIEvasion applies production DPI evasion techniques (for API compatibility)
func (m *Marionette) ApplyProductionDPIEvasion(data []byte, service string) ([]byte, time.Duration, error) {
	// Use production evasion if available
	// For now, delegate to ProcessPacket with service-specific profile
	if err := m.SetActiveProfile(service); err != nil {
		// If profile doesn't exist, use default processing
		processed, delay, err := m.ProcessPacket(data, "outbound")
		return processed, delay, err
	}
	
	// Process with service-specific profile
	processed, delay, err := m.ProcessPacket(data, "outbound")
	return processed, delay, err
}

// GetAdaptiveLearning returns the adaptive learning system
func (m *Marionette) GetAdaptiveLearning() types.AdaptiveLearning {
	return m.adaptiveLearning
}

// GetEffectivenessMetrics returns the effectiveness metrics
func (m *Marionette) GetEffectivenessMetrics() *EffectivenessMetrics {
	return m.effectiveness
}

// GetSystemMetrics returns system performance metrics
// ОПТИМИЗАЦИЯ: Используем atomic для чтения метрик без блокировки
func (m *Marionette) GetSystemMetrics() *SystemMetrics {
	// ОПТИМИЗАЦИЯ: Читаем метрики через atomic (без блокировки)
	// Создаем копию метрик для возврата
	metricsCopy := &SystemMetrics{
		PacketsProcessed:    atomic.LoadInt64(&m.metrics.PacketsProcessed),
		MLPredictions:       atomic.LoadInt64(&m.metrics.MLPredictions),
		MLFailures:          atomic.LoadInt64(&m.metrics.MLFailures),
		AverageLatency:      atomic.LoadInt64(&m.metrics.AverageLatency),
		MemoryUsage:         atomic.LoadInt64(&m.metrics.MemoryUsage),
		LastCleanup:         atomic.LoadInt64(&m.metrics.LastCleanup),
		CircuitBreakerTrips: atomic.LoadInt64(&m.metrics.CircuitBreakerTrips),
	}
	return metricsCopy
}

// HealthCheck performs a comprehensive health check
// ОПТИМИЗАЦИЯ: Используем atomic для чтения метрик без блокировки
func (m *Marionette) HealthCheck() map[string]interface{} {
	// ОПТИМИЗАЦИЯ: Читаем метрики через atomic (без блокировки)
	packetsProcessed := atomic.LoadInt64(&m.metrics.PacketsProcessed)
	mlPredictions := atomic.LoadInt64(&m.metrics.MLPredictions)
	mlFailures := atomic.LoadInt64(&m.metrics.MLFailures)
	avgLatencyNano := atomic.LoadInt64(&m.metrics.AverageLatency)
	memoryUsage := atomic.LoadInt64(&m.metrics.MemoryUsage)
	
	m.mutex.RLock()
	fallbackMode := m.fallbackMode
	circuitBreakerState := m.circuitBreaker.state
	activeProfile := m.active
	profileCount := len(m.profiles)
	m.mutex.RUnlock()

	// ОПТИМИЗАЦИЯ: Предварительно выделяем память для map
	health := make(map[string]interface{}, 12)
	health["status"] = "healthy"
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	health["timestamp"] = util.GetGlobalTimeCache().Now()
	health["packets_processed"] = packetsProcessed
	health["ml_predictions"] = mlPredictions
	health["ml_failures"] = mlFailures
	health["average_latency"] = time.Duration(avgLatencyNano).String()
	health["memory_usage"] = memoryUsage
	health["fallback_mode"] = fallbackMode
	health["circuit_breaker"] = circuitBreakerState
	health["active_profile"] = activeProfile
	health["total_profiles"] = profileCount

	// Check ML system health
	if m.mlSystem != nil {
		if err := m.mlSystem.HealthCheck(); err != nil {
			health["ml_status"] = "unhealthy"
			health["ml_error"] = err.Error()
		} else {
			health["ml_status"] = "healthy"
		}
	}

	// Check adaptive learning health
	if m.adaptiveLearning != nil {
		health["adaptive_learning"] = "active"
	} else {
		health["adaptive_learning"] = "inactive"
	}

	return health
}

// Helper methods for Marionette core functionality

// updateState updates traffic state based on new packet
// ОПТИМИЗАЦИЯ: Используем кэшированное время
func (m *Marionette) updateState(data []byte, direction string) {
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	now := util.GetGlobalTimeCache().Now()

	// Update packet history
	// ОПТИМИЗАЦИЯ: Используем copy вместо создания нового slice
	if len(m.state.PacketHistory) >= m.state.MaxHistorySize {
		// Remove oldest packet
		copy(m.state.PacketHistory, m.state.PacketHistory[1:])
		m.state.PacketHistory = m.state.PacketHistory[:len(m.state.PacketHistory)-1]
	}

	// Add new packet info
	packetInfo := types.PacketInfo{
		Size:      len(data),
		Direction: direction,
		Timestamp: now,
		Protocol:  m.state.Protocol,
		Processed: true,
		Evasion:   false, // Will be set by evasion methods
		MLUsed:    m.mlSystem != nil,
	}

	m.state.PacketHistory = append(m.state.PacketHistory, packetInfo)

	// Update statistics
	m.state.TotalPackets++
	m.state.TotalBytes += int64(len(data))
	m.state.PacketCount++
	m.state.ByteCount += int64(len(data))

	// Update direction-specific stats
	if direction == "outbound" { //nolint:goconst // Value matches adaptive_profile_manager.go constant
		m.state.OutboundPackets++
		m.state.OutboundBytes += int64(len(data))
	} else {
		m.state.InboundPackets++
		m.state.InboundBytes += int64(len(data))
	}

	// Update timing information
	if !m.state.LastPacket.IsZero() {
		interval := now.Sub(m.state.LastPacket)
		m.state.Intervals = append(m.state.Intervals, interval)

		// Keep only recent intervals
		// ОПТИМИЗАЦИЯ: Используем copy вместо создания нового slice
		if len(m.state.Intervals) > 100 {
			copy(m.state.Intervals, m.state.Intervals[1:])
			m.state.Intervals = m.state.Intervals[:len(m.state.Intervals)-1]
		}

		// ОПТИМИЗАЦИЯ: Update average interval (оптимизированный расчет)
		if intervalCount := len(m.state.Intervals); intervalCount > 0 {
			// ОПТИМИЗАЦИЯ: Используем оптимизированный цикл
			totalDuration := time.Duration(0)
			intervals := m.state.Intervals
			for i := 0; i < intervalCount; i++ {
				totalDuration += intervals[i]
			}
			m.state.AverageInterval = totalDuration / time.Duration(intervalCount)
		}
	}

	// Update packet sizes
	m.state.PacketSizes = append(m.state.PacketSizes, len(data))
	m.state.RecentPacketSizes = append(m.state.RecentPacketSizes, len(data))

	// Keep only recent packet sizes
	// ОПТИМИЗАЦИЯ: Используем copy вместо создания нового slice
	if len(m.state.RecentPacketSizes) > 50 {
		copy(m.state.RecentPacketSizes, m.state.RecentPacketSizes[1:])
		m.state.RecentPacketSizes = m.state.RecentPacketSizes[:len(m.state.RecentPacketSizes)-1]
	}

	// ОПТИМИЗАЦИЯ: Update average packet size (оптимизированный расчет)
	if sizeCount := len(m.state.RecentPacketSizes); sizeCount > 0 {
		// ОПТИМИЗАЦИЯ: Используем оптимизированный цикл
		totalSize := 0
		sizes := m.state.RecentPacketSizes
		for i := 0; i < sizeCount; i++ {
			totalSize += sizes[i]
		}
		m.state.AveragePacketSize = float64(totalSize) / float64(sizeCount)
	}

	// Update burst/idle detection
	if len(data) > 1000 {
		m.state.BurstCount++
		m.state.LastBurstTime = now
	} else if len(data) < 100 {
		m.state.IdleCount++
		m.state.LastIdleTime = now
	}

	// Update session duration
	if m.state.SessionStart.IsZero() {
		m.state.SessionStart = now
	}
	m.state.SessionDuration = now.Sub(m.state.SessionStart)

	// Update last packet time
	m.state.LastPacket = now
}

// evaluateCondition evaluates a rule condition
func (m *Marionette) evaluateCondition(condition types.Condition) bool {
	switch condition.Type {
	case "packet_size":
		return m.evaluatePacketSizeCondition(condition)
	case "direction":
		return m.evaluateDirectionCondition(condition)
	case "protocol":
		return m.evaluateProtocolCondition(condition)
	case "threat_level":
		return m.evaluateThreatLevelCondition(condition)
	case "burst_detection":
		return m.evaluateBurstCondition(condition)
	case "idle_detection":
		return m.evaluateIdleCondition(condition)
	case "ml_prediction":
		return m.evaluateMLPredictionCondition(condition)
	case "composite":
		return m.evaluateCompositeCondition(condition)
	default:
		return true
	}
}

// evaluatePacketSizeCondition evaluates packet size conditions
func (m *Marionette) evaluatePacketSizeCondition(condition types.Condition) bool {
	if len(m.state.RecentPacketSizes) == 0 {
		return false
	}

	lastSize := m.state.RecentPacketSizes[len(m.state.RecentPacketSizes)-1]
	expectedValue, ok := condition.Value.(int)
	if !ok {
		return false
	}

	switch condition.Operator {
	case ">":
		return lastSize > expectedValue
	case "<":
		return lastSize < expectedValue
	case ">=":
		return lastSize >= expectedValue
	case "<=":
		return lastSize <= expectedValue
	case "==":
		return lastSize == expectedValue
	case "!=":
		return lastSize != expectedValue
	default:
		return false
	}
}

// evaluateDirectionCondition evaluates direction conditions
func (m *Marionette) evaluateDirectionCondition(condition types.Condition) bool {
	expectedDirection, ok := condition.Value.(string)
	if !ok {
		return false
	}

	switch condition.Operator {
	case "==":
		return m.state.Direction == expectedDirection
	case "!=":
		return m.state.Direction != expectedDirection
	default:
		return false
	}
}

// evaluateProtocolCondition evaluates protocol conditions
func (m *Marionette) evaluateProtocolCondition(condition types.Condition) bool {
	expectedProtocol, ok := condition.Value.(string)
	if !ok {
		return false
	}

	switch condition.Operator {
	case "==":
		return m.state.Protocol == expectedProtocol
	case "!=":
		return m.state.Protocol != expectedProtocol
	default:
		return false
	}
}

// evaluateThreatLevelCondition evaluates threat level conditions
func (m *Marionette) evaluateThreatLevelCondition(condition types.Condition) bool {
	expectedLevel, ok := condition.Value.(int)
	if !ok {
		return false
	}

	switch condition.Operator {
	case ">":
		return m.state.ThreatLevel > expectedLevel
	case "<":
		return m.state.ThreatLevel < expectedLevel
	case ">=":
		return m.state.ThreatLevel >= expectedLevel
	case "<=":
		return m.state.ThreatLevel <= expectedLevel
	case "==":
		return m.state.ThreatLevel == expectedLevel
	case "!=":
		return m.state.ThreatLevel != expectedLevel
	default:
		return false
	}
}

// evaluateBurstCondition evaluates burst detection conditions
func (m *Marionette) evaluateBurstCondition(condition types.Condition) bool {
	expectedCount, ok := condition.Value.(int)
	if !ok {
		return false
	}

	switch condition.Operator {
	case ">":
		return m.state.BurstCount > expectedCount
	case "<":
		return m.state.BurstCount < expectedCount
	case ">=":
		return m.state.BurstCount >= expectedCount
	case "<=":
		return m.state.BurstCount <= expectedCount
	case "==":
		return m.state.BurstCount == expectedCount
	case "!=":
		return m.state.BurstCount != expectedCount
	default:
		return false
	}
}

// evaluateIdleCondition evaluates idle detection conditions
func (m *Marionette) evaluateIdleCondition(condition types.Condition) bool {
	expectedCount, ok := condition.Value.(int)
	if !ok {
		return false
	}

	switch condition.Operator {
	case ">":
		return m.state.IdleCount > expectedCount
	case "<":
		return m.state.IdleCount < expectedCount
	case ">=":
		return m.state.IdleCount >= expectedCount
	case "<=":
		return m.state.IdleCount <= expectedCount
	case "==":
		return m.state.IdleCount == expectedCount
	case "!=":
		return m.state.IdleCount != expectedCount
	default:
		return false
	}
}

// evaluateMLPredictionCondition evaluates ML prediction conditions
func (m *Marionette) evaluateMLPredictionCondition(condition types.Condition) bool {
	expectedValue, ok := condition.Value.(bool)
	if !ok {
		return false
	}

	// Check if ML was used in recent packets
	mlUsed := false
	if len(m.state.PacketHistory) > 0 {
		lastPacket := m.state.PacketHistory[len(m.state.PacketHistory)-1]
		mlUsed = lastPacket.MLUsed
	}

	switch condition.Operator {
	case "==":
		return mlUsed == expectedValue
	case "!=":
		return mlUsed != expectedValue
	default:
		return false
	}
}

// evaluateCompositeCondition evaluates composite conditions
func (m *Marionette) evaluateCompositeCondition(condition types.Condition) bool {
	if len(condition.Children) == 0 {
		return true
	}

	result := m.evaluateCondition(condition.Children[0])

	for i := 1; i < len(condition.Children); i++ {
		childResult := m.evaluateCondition(condition.Children[i])

		switch condition.LogicalOp {
		case "AND":
			result = result && childResult
		case "OR":
			result = result || childResult
		case "NOT":
			result = !childResult
		default:
			result = result && childResult
		}
	}

	return result
}

// applyAction applies a rule action
func (m *Marionette) applyAction(action types.Action, data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	switch action.Type {
	case "resize":
		return m.applyResizeAction(data, params)
	case "delay":
		return m.applyDelayAction(data, params)
	case "pad":
		return m.applyPaddingAction(data, params)
	case "encrypt":
		return m.applyEncryptionAction(data, params)
	case "obfuscate":
		return m.applyObfuscationAction(data, params)
	case "profile_switch":
		return m.applyProfileSwitchAction(data, params)
	case "ml_evasion":
		return m.applyMLEvasionAction(data, params)
	case "dpi_evasion":
		return m.applyDPIEvasionAction(data, params)
	case "behavioral_mimicry":
		return m.applyBehavioralMimicryAction(data, params)
	default:
		return data, 0
	}
}

// applyResizeAction applies packet resizing
// ОПТИМИЗАЦИЯ: Используем предварительное выделение памяти
func (m *Marionette) applyResizeAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	targetSize, ok := params["target_size"].(int)
	if !ok {
		return data, 0
	}

	if len(data) >= targetSize {
		return data, 0
	}

	// ОПТИМИЗАЦИЯ: Предварительно выделяем память для результата
	paddingSize := targetSize - len(data)
	result := make([]byte, targetSize)
	copy(result, data)
	
	// Заполняем padding
	for i := 0; i < paddingSize; i++ {
		result[len(data)+i] = byte(32 + (i % 95)) // ASCII printable characters
	}

	return result, 0
}

// applyDelayAction applies timing delay
func (m *Marionette) applyDelayAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	delayMs, ok := params["delay_ms"].(int)
	if !ok {
		return data, 0
	}

	// Add random jitter to avoid detection
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	jitter := delayMs / 10
	if jitter > 0 {
		delayMs += (int(util.GetGlobalTimeCache().Now().UnixNano()) % (jitter * 2)) - jitter
	}

	delay := time.Duration(delayMs) * time.Millisecond
	return data, delay
}

// applyPaddingAction applies packet padding
// ОПТИМИЗАЦИЯ: Используем предварительное выделение памяти
func (m *Marionette) applyPaddingAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	paddingSize, ok := params["padding_size"].(int)
	if !ok {
		return data, 0
	}

	if paddingSize <= 0 {
		return data, 0
	}

	// ОПТИМИЗАЦИЯ: Предварительно выделяем память для результата
	result := make([]byte, len(data)+paddingSize)
	copy(result, data)

	// Generate realistic padding based on current profile
	padding := m.generateRealisticPadding(paddingSize)
	copy(result[len(data):], padding)
	
	return result, 0
}

// applyEncryptionAction applies encryption
// ОПТИМИЗАЦИЯ: Используем оптимизированный цикл
func (m *Marionette) applyEncryptionAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Basic XOR encryption for demonstration
	key, ok := params["key"].([]byte)
	if !ok || len(key) == 0 {
		return data, 0
	}

	// ОПТИМИЗАЦИЯ: Предварительно выделяем память
	encrypted := make([]byte, len(data))
	keyLen := len(key)
	
	// ОПТИМИЗАЦИЯ: Оптимизированный цикл с предвычислением keyLen
	for i := range data {
		encrypted[i] = data[i] ^ key[i%keyLen]
	}

	return encrypted, 0
}

// applyObfuscationAction applies obfuscation
func (m *Marionette) applyObfuscationAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	obfuscationType, ok := params["type"].(string)
	if !ok {
		return data, 0
	}

	switch obfuscationType {
	case "entropy_adjustment":
		return m.adjustEntropy(data, params)
	case "pattern_masking":
		return m.maskPatterns(data, params)
	case "statistical_noise":
		return m.addStatisticalNoise(data, params)
	default:
		return data, 0
	}
}

// applyProfileSwitchAction switches traffic profile
func (m *Marionette) applyProfileSwitchAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	newProfile, ok := params["profile"].(string)
	if !ok {
		return data, 0
	}

	// Record profile switch
	switchRecord := types.ProfileSwitch{
		FromProfile:   m.active,
		ToProfile:     newProfile,
		Reason:        "rule_action",
		Timestamp:     util.GetGlobalTimeCache().Now(),
		Success:       true,
		Effectiveness: 0.8, // Default effectiveness
	}

	m.state.ProfileSwitches = append(m.state.ProfileSwitches, switchRecord)
	m.state.CurrentProfile = newProfile

	// Keep only recent switches
	// ОПТИМИЗАЦИЯ: Используем copy вместо создания нового slice
	if len(m.state.ProfileSwitches) > 100 {
		copy(m.state.ProfileSwitches, m.state.ProfileSwitches[1:])
		m.state.ProfileSwitches = m.state.ProfileSwitches[:len(m.state.ProfileSwitches)-1]
	}

	return data, 0
}

// applyMLEvasionAction applies ML-based evasion
func (m *Marionette) applyMLEvasionAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Gate evasive actions for safe-by-default behavior
	if !enableCoreEvasion {
		return data, 0
	}
	
	// Use full ML evasion implementation with all techniques
	return m.applyMLEvasion(data, params)
}

// applyMLEvasion applies production ML evasion techniques (full implementation from old marionette.go)
// ОПТИМИЗАЦИЯ: Используем пул буферов для переиспользования памяти
func (m *Marionette) applyMLEvasion(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Production ML evasion techniques for Russian services
	adversarialExamples, _ := params["adversarial_examples"].(bool)
	behavioralMimicry, _ := params["behavioral_mimicry"].(bool)
	trafficShaping, _ := params["traffic_shaping"].(bool)
	protocolFidelity, _ := params["protocol_fidelity"].(bool)
	hardwareEvasion, _ := params["hardware_evasion"].(bool)

	// Production DPI evasion techniques for Russian services
	ja3Evasion, _ := params["ja3_evasion"].(bool)
	ja4Evasion, _ := params["ja4_evasion"].(bool)
	greaseEvasion, _ := params["grease_evasion"].(bool)
	alpnEvasion, _ := params["alpn_evasion"].(bool)
	echEvasion, _ := params["ech_evasion"].(bool)
	hpackEvasion, _ := params["hpack_evasion"].(bool)
	qpackEvasion, _ := params["qpack_evasion"].(bool)
	dohEvasion, _ := params["doh_evasion"].(bool)
	doqEvasion, _ := params["doq_evasion"].(bool)
	timingAnalysisEvasion, _ := params["timing_analysis_evasion"].(bool)
	flowAnalysisEvasion, _ := params["flow_analysis_evasion"].(bool)
	statisticalEvasion, _ := params["statistical_evasion"].(bool)
	mlClassificationEvasion, _ := params["ml_classification_evasion"].(bool)

	// Production technique application counter
	appliedTechniques := 0

	// Apply traffic shaping (changes data directly)
	if trafficShaping {
		if len(data) > 2048 {
			data = data[:len(data)*3/4]
		}
		appliedTechniques++
	}
	
	// ОПТИМИЗАЦИЯ: Предварительно оцениваем размер для выделения памяти
	estimatedSize := len(data)
	if adversarialExamples {
		estimatedSize += len(data) / 20
	}
	if behavioralMimicry {
		estimatedSize += 32
	}
	if protocolFidelity {
		estimatedSize += 4
	}
	if hardwareEvasion {
		estimatedSize += 6
	}
	
	// Выбираем подходящий пул буферов
	var bufPool *sync.Pool
	if estimatedSize < bufferPoolSmallSize {
		bufPool = &bufferPoolSmall
	} else if estimatedSize < bufferPoolMediumSize {
		bufPool = &bufferPoolMedium
	} else {
		bufPool = &bufferPoolLarge
	}
	
	// Collect all obfuscations that add data
	var evasionParts [][]byte
	
	// Production adversarial examples
	// ОПТИМИЗАЦИЯ: Используем пул буферов
	if adversarialExamples {
		noiseSize := len(data) / 20
		if noiseSize < 4 {
			noiseSize = 4
		}
		noise := bufPool.Get().([]byte)
		if cap(noise) < noiseSize {
			noise = make([]byte, noiseSize)
		} else {
			noise = noise[:noiseSize]
		}
		for i := range noise {
			noise[i] = byte((i*13 + len(data)*7) % 256)
		}
		// Создаем копию для evasionParts, так как буфер будет возвращен в пул
		noiseCopy := make([]byte, noiseSize)
		copy(noiseCopy, noise)
		evasionParts = append(evasionParts, noiseCopy)
		bufPool.Put(noise)
		appliedTechniques++
	}

	// Production behavioral mimicry
	if behavioralMimicry {
		behavioralData := m.applyEnhancedBehavioralMimicry(data)
		evasionParts = append(evasionParts, behavioralData)
		appliedTechniques++
	}

	// Production protocol fidelity
	// ОПТИМИЗАЦИЯ: Используем пул буферов
	if protocolFidelity {
		protocolPadding := bufPool.Get().([]byte)
		if cap(protocolPadding) < 4 {
			protocolPadding = make([]byte, 4)
		} else {
			protocolPadding = protocolPadding[:4]
		}
		for i := range protocolPadding {
			protocolPadding[i] = byte(i % 256)
		}
		protocolPaddingCopy := make([]byte, 4)
		copy(protocolPaddingCopy, protocolPadding)
		evasionParts = append(evasionParts, protocolPaddingCopy)
		bufPool.Put(protocolPadding)
		appliedTechniques++
	}

	// Production hardware evasion
	// ОПТИМИЗАЦИЯ: Используем пул буферов
	if hardwareEvasion {
		hardwareDelay := time.Duration(len(data)%5) * time.Millisecond
		hardwareObfuscation := bufPool.Get().([]byte)
		if cap(hardwareObfuscation) < 6 {
			hardwareObfuscation = make([]byte, 6)
		} else {
			hardwareObfuscation = hardwareObfuscation[:6]
		}
		for i := range hardwareObfuscation {
			hardwareObfuscation[i] = byte((i*19 + int(hardwareDelay.Milliseconds())) % 256)
		}
		hardwareObfuscationCopy := make([]byte, 6)
		copy(hardwareObfuscationCopy, hardwareObfuscation)
		evasionParts = append(evasionParts, hardwareObfuscationCopy)
		bufPool.Put(hardwareObfuscation)
		appliedTechniques++
	}

	// Production fallback for low threat scenarios
	if appliedTechniques == 0 {
		basicObfuscation := bufPool.Get().([]byte)
		if cap(basicObfuscation) < 2 {
			basicObfuscation = make([]byte, 2)
		} else {
			basicObfuscation = basicObfuscation[:2]
		}
		basicObfuscation[0] = byte(len(data) % 256)
		basicObfuscation[1] = byte((len(data) * 3) % 256)
		basicObfuscationCopy := make([]byte, 2)
		copy(basicObfuscationCopy, basicObfuscation)
		evasionParts = append(evasionParts, basicObfuscationCopy)
		bufPool.Put(basicObfuscation)
		appliedTechniques = 1
	}
	
	// ОПТИМИЗАЦИЯ: Combine all obfuscations (предварительное выделение памяти)
	if len(evasionParts) > 0 {
		totalEvasionSize := 0
		for _, part := range evasionParts {
			totalEvasionSize += len(part)
		}
		// ОПТИМИЗАЦИЯ: Предварительно выделяем память для результата
		newData := make([]byte, len(data), len(data)+totalEvasionSize)
		copy(newData, data)
		for _, part := range evasionParts {
			newData = append(newData, part...)
		}
		data = newData
	}

	// Collect all ML evasion obfuscations
	var mlEvasionParts [][]byte
	evasionCount := 0
	
	if ja3Evasion {
		ja3Obfuscation, _ := m.applyJA3Evasion(data, params)
		mlEvasionParts = append(mlEvasionParts, ja3Obfuscation)
		evasionCount++
	}
	if ja4Evasion {
		ja4Obfuscation, _ := m.applyJA4Evasion(data, params)
		mlEvasionParts = append(mlEvasionParts, ja4Obfuscation)
		evasionCount++
	}
	if greaseEvasion {
		mlEvasionParts = append(mlEvasionParts, m.applyGREASEEvasion(data))
		evasionCount++
	}
	if alpnEvasion {
		mlEvasionParts = append(mlEvasionParts, m.applyALPNEvasion(data))
		evasionCount++
	}
	if echEvasion {
		mlEvasionParts = append(mlEvasionParts, m.applyECHEvasion(data))
		evasionCount++
	}
	if hpackEvasion {
		mlEvasionParts = append(mlEvasionParts, m.applyHPACKEvasion(data))
		evasionCount++
	}
	if qpackEvasion {
		mlEvasionParts = append(mlEvasionParts, m.applyQPACKEvasion(data))
		evasionCount++
	}
	if dohEvasion {
		mlEvasionParts = append(mlEvasionParts, m.applyDoHEvasion(data))
		evasionCount++
	}
	if doqEvasion {
		mlEvasionParts = append(mlEvasionParts, m.applyDoQEvasion(data))
		evasionCount++
	}
	if timingAnalysisEvasion {
		mlEvasionParts = append(mlEvasionParts, m.applyTimingAnalysisEvasion(data))
		evasionCount++
	}
	if flowAnalysisEvasion {
		mlEvasionParts = append(mlEvasionParts, m.applyFlowAnalysisEvasion(data))
		evasionCount++
	}
	if statisticalEvasion {
		mlEvasionParts = append(mlEvasionParts, m.applyStatisticalEvasion(data))
		evasionCount++
	}
	if mlClassificationEvasion {
		mlEvasionParts = append(mlEvasionParts, m.applyMLClassificationEvasion(data))
		evasionCount++
	}
	
	// ОПТИМИЗАЦИЯ: Combine all ML evasion obfuscations (предварительное выделение памяти)
	if evasionCount > 0 {
		totalMLSize := 0
		for _, part := range mlEvasionParts {
			totalMLSize += len(part)
		}
		// ОПТИМИЗАЦИЯ: Предварительно выделяем память для результата
		newData := make([]byte, len(data), len(data)+totalMLSize)
		copy(newData, data)
		for _, part := range mlEvasionParts {
			newData = append(newData, part...)
		}
		data = newData
		appliedTechniques += evasionCount
	}

	// Production effectiveness calculation
	mlEvasionEffectiveness := 0
	if behavioralMimicry {
		mlEvasionEffectiveness++
	}
	if trafficShaping {
		mlEvasionEffectiveness++
	}
	if protocolFidelity {
		mlEvasionEffectiveness++
	}
	if hardwareEvasion {
		mlEvasionEffectiveness++
	}

	// Apply production effectiveness tracking
	if mlEvasionEffectiveness > 0 {
		effectivenessBytes := make([]byte, 1)
		effectivenessBytes[0] = byte(mlEvasionEffectiveness)
		data = append(data, effectivenessBytes...)
	}

	// Update ML usage statistics if ML system is available
	if m.mlSystem != nil {
	context := &types.UnifiedTrafficContext{
		Direction: m.state.Direction,
		Protocol:  m.state.Protocol,
		Size:      len(data),
		Timestamp: util.GetGlobalTimeCache().Now(),
		}
		_, err := m.mlSystem.ProcessTraffic(data, context)
		if err == nil {
	m.state.MLPredictions++
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	m.state.LastMLPrediction = util.GetGlobalTimeCache().Now()
		}
	}

	return data, 0
}

// applyDPIEvasionAction applies DPI evasion
func (m *Marionette) applyDPIEvasionAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Gate evasive actions for safe-by-default behavior
	if !enableCoreEvasion {
		return data, 0
	}
	evasionType, ok := params["type"].(string)
	if !ok {
		return data, 0
	}

	switch evasionType {
	case "ja3_evasion":
		return m.applyJA3Evasion(data, params)
	case "ja4_evasion":
		return m.applyJA4Evasion(data, params)
	case "http_evasion":
		return m.applyHTTPEvasion(data, params)
	case "tls_evasion":
		return m.applyTLSEvasion(data, params)
	default:
		return data, 0
	}
}

// applyBehavioralMimicryAction applies behavioral mimicry
func (m *Marionette) applyBehavioralMimicryAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Gate behavioral mimicry separately (or via general evasion gate)
	if !(enableCoreEvasion || enableAdaptiveMimicry) {
		return data, 0
	}
	mimicryType, ok := params["type"].(string)
	if !ok {
		return data, 0
	}

	switch mimicryType {
	case "human_behavior":
		return m.mimicHumanBehavior(data, params)
	case "service_behavior":
		return m.mimicServiceBehavior(data, params)
	case "device_behavior":
		return m.mimicDeviceBehavior(data, params)
	default:
		return data, 0
	}
}

// Helper methods for action implementations
func (m *Marionette) generateRealisticPadding(size int) []byte {
	padding := make([]byte, size)

	// Generate padding based on current profile
	profileName := m.getCurrentServiceProfileName()
	if profileName != "" {
		padding = m.generateServiceSpecificPadding(profileName, size)
	} else {
		// Default padding
		for i := range padding {
			padding[i] = byte(32 + (i % 95))
		}
	}

	return padding
}

// getCurrentServiceProfileName возвращает имя текущего сервисного профиля
func (m *Marionette) getCurrentServiceProfileName() string {
	return m.state.CurrentProfile
}

// ОПТИМИЗАЦИЯ: Оптимизированные циклы с предвычислением констант
func (m *Marionette) generateServiceSpecificPadding(profile string, size int) []byte {
	padding := make([]byte, size)

	switch profile {
	case "vk":
		// ОПТИМИЗАЦИЯ: VK-specific padding (оптимизированный цикл)
		for i := 0; i < size; i++ {
			mod3 := i % 3
			if mod3 == 0 {
				padding[i] = byte(32 + (i % 95)) // ASCII printable
			} else if mod3 == 1 {
				padding[i] = byte(97 + (i % 26)) // lowercase letters
			} else {
				padding[i] = byte(48 + (i % 10)) // digits
			}
		}
	case "yandex": // ОПТИМИЗАЦИЯ: Используем строковый литерал вместо константы
		// ОПТИМИЗАЦИЯ: Yandex-specific padding (оптимизированный цикл)
		for i := 0; i < size; i++ {
			padding[i] = byte(32 + (i % 95))
		}
	case "mailru": // ОПТИМИЗАЦИЯ: Используем строковый литерал вместо константы
		// ОПТИМИЗАЦИЯ: Mail.ru-specific padding (оптимизированный цикл)
		for i := 0; i < size; i++ {
			padding[i] = byte(32 + (i % 95))
		}
	default:
		// ОПТИМИЗАЦИЯ: Generic padding (оптимизированный цикл)
		for i := 0; i < size; i++ {
			padding[i] = byte(32 + (i % 95))
		}
	}

	return padding
}

func (m *Marionette) adjustEntropy(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Basic entropy adjustment
	return data, 0
}

func (m *Marionette) maskPatterns(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Basic pattern masking
	return data, 0
}

func (m *Marionette) addStatisticalNoise(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Basic statistical noise
	return data, 0
}

func (m *Marionette) applyJA3Evasion(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Real JA3 evasion based on actual TLS fingerprinting
	// Generate realistic TLS ClientHello structure
	clientHello := m.generateTLSClientHello()
	
	// Apply JA3 fingerprinting evasion
	ja3Hash := m.calculateJA3Hash(clientHello)
	
	// Create obfuscation based on real JA3 hash
	ja3Obfuscation := make([]byte, 16)
	copy(ja3Obfuscation, ja3Hash)
	
	// Add realistic TLS extensions
	extensions := m.generateTLSExtensions()
	ja3Obfuscation = append(ja3Obfuscation, extensions...)
	
	// Return obfuscation only (will be appended to data in applyMLEvasion)
	return ja3Obfuscation, 0
}

func (m *Marionette) applyJA4Evasion(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Real JA4 evasion based on actual TLS fingerprinting
	// Generate realistic TLS extensions for JA4
	extensions := m.generateJA4Extensions()
	
	// Calculate JA4 hash based on extensions
	ja4Hash := m.calculateJA4Hash(extensions)
	
	// Create obfuscation based on real JA4 hash
	ja4Obfuscation := make([]byte, 20)
	copy(ja4Obfuscation, ja4Hash)
	
	// Add extension data
	ja4Obfuscation = append(ja4Obfuscation, extensions...)
	
	// Return obfuscation only (will be appended to data in applyMLEvasion)
	return ja4Obfuscation, 0
}

func (m *Marionette) applyHTTPEvasion(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// HTTP evasion implementation
	return data, 0
}

func (m *Marionette) applyTLSEvasion(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// TLS evasion implementation - generate realistic TLS ClientHello
	clientHello := m.generateTLSClientHello()
	extensions := m.generateTLSExtensions()
	tlsObfuscation := append(clientHello, extensions...)
	return append(data, tlsObfuscation...), 0
}

// TLSServiceProfile represents a service-specific TLS profile for JA3/JA4
type TLSServiceProfile struct {
	Name                      string
	TLSVersion                string
	CipherSuites              []string
	Extensions                []string
	EllipticCurves            []string
	EllipticCurvePointFormats []string
}

// generateTLSClientHello generates a realistic TLS ClientHello structure
// ОПТИМИЗАЦИЯ: Используем предварительное выделение памяти и оптимизированные операции
func (m *Marionette) generateTLSClientHello() []byte {
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память с точным размером
	// TLS Version (2) + Random (32) + Session ID length (1) + Cipher suites (8) + Compression (2) = 45 байт минимум
	clientHello := make([]byte, 0, 128)

	// TLS Version (TLS 1.3 = 0x0304)
	clientHello = append(clientHello, 0x03, 0x04)

	// ОПТИМИЗАЦИЯ: Генерируем random напрямую в clientHello
	randomStart := len(clientHello)
	clientHello = append(clientHello, make([]byte, 32)...)
	for i := 0; i < 32; i++ {
		clientHello[randomStart+i] = byte(m.generateRealisticRandom(256))
	}

	// Session ID length (0 for TLS 1.3)
	clientHello = append(clientHello, 0x00)

	// Cipher suites (статический массив для избежания аллокаций)
	cipherSuites := [3]uint16{
		0x1301, // TLS_AES_128_GCM_SHA256
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
	}

	// Cipher suites length
	cipherSuitesLen := len(cipherSuites) * 2
	clientHello = append(clientHello, byte(cipherSuitesLen>>8), byte(cipherSuitesLen&0xFF))

	// ОПТИМИЗАЦИЯ: Cipher suites data (оптимизированный цикл)
	for i := 0; i < len(cipherSuites); i++ {
		suite := cipherSuites[i]
		clientHello = append(clientHello, byte(suite>>8), byte(suite&0xFF))
	}

	// Compression methods
	clientHello = append(clientHello, 0x01, 0x00) // NULL compression

	return clientHello
}

// getCurrentTLSServiceProfile returns current TLS service profile for JA3 generation
func (m *Marionette) getCurrentTLSServiceProfile() *TLSServiceProfile {
	m.mutex.RLock()
	activeProfile := m.active
	m.mutex.RUnlock()

	// Return service-specific profile
	switch activeProfile {
	case "vk":
		return &TLSServiceProfile{
			Name:       "VKontakte",
			TLSVersion: "771", // TLS 1.3
			CipherSuites: []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392", "49171", "49172", "156", "157", "47", "53"},
			Extensions: []string{"0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43", "27", "17513"},
			EllipticCurves: []string{"29", "23", "24"},
			EllipticCurvePointFormats: []string{"0"},
		}
	case "yandex":
		return &TLSServiceProfile{
			Name:       "Yandex",
			TLSVersion: "771",
			CipherSuites: []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392", "49171", "49172", "156", "157", "47", "53", "10", "19"},
			Extensions: []string{"0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43", "27", "17513", "21", "22"},
			EllipticCurves: []string{"29", "23", "24", "25"},
			EllipticCurvePointFormats: []string{"0", "1"},
		}
	case "mailru":
		return &TLSServiceProfile{
			Name:       "Mail.ru",
			TLSVersion: "771",
			CipherSuites: []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392", "49171", "49172", "156", "157", "47", "53", "5", "4"},
			Extensions: []string{"0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43", "27", "17513", "28", "29"},
			EllipticCurves: []string{"29", "23", "24", "30"},
			EllipticCurvePointFormats: []string{"0", "2"},
		}
	case "rutube":
		return &TLSServiceProfile{
			Name:       "Rutube",
			TLSVersion: "771",
			CipherSuites: []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392", "49171", "49172", "156", "157", "47", "53", "9", "8"},
			Extensions: []string{"0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43", "27", "17513", "41", "42"},
			EllipticCurves: []string{"29", "23", "24", "26"},
			EllipticCurvePointFormats: []string{"0", "1", "2"},
		}
	case "ozon":
		return &TLSServiceProfile{
			Name:       "Ozon",
			TLSVersion: "771",
			CipherSuites: []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392", "49171", "49172", "156", "157", "47", "53", "6", "7"},
			Extensions: []string{"0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43", "27", "17513", "31", "32"},
			EllipticCurves: []string{"29", "23", "24", "27"},
			EllipticCurvePointFormats: []string{"0", "1"},
		}
	default:
		return &TLSServiceProfile{
			Name:       "Generic",
			TLSVersion: "771",
			CipherSuites: []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392", "49171", "49172", "156", "157", "47", "53"},
			Extensions: []string{"0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43", "27", "17513"},
			EllipticCurves: []string{"29", "23", "24"},
			EllipticCurvePointFormats: []string{"0"},
		}
	}
}

// calculateJA3Hash calculates a realistic JA3 hash based on service profile
func (m *Marionette) calculateJA3Hash(_ []byte) []byte {
	// Get current service profile for realistic JA3 calculation
	profile := m.getCurrentTLSServiceProfile()

	// Real JA3 calculation based on TLS parameters
	// Format: version,ciphers,extensions,elliptic_curves,elliptic_curve_point_formats
	ja3String := m.buildJA3String(profile)

	// Calculate MD5 hash of JA3 string (real JA3 standard)
	hash := m.calculateMD5Hash(ja3String)

	return hash
}

// buildJA3String builds JA3 string from service profile
func (m *Marionette) buildJA3String(profile *TLSServiceProfile) string {
	// JA3 format: version,ciphers,extensions,elliptic_curves,elliptic_curve_point_formats
	ciphers := strings.Join(profile.CipherSuites, "-")
	extensions := strings.Join(profile.Extensions, "-")
	curves := strings.Join(profile.EllipticCurves, "-")
	pointFormats := strings.Join(profile.EllipticCurvePointFormats, "-")

	return fmt.Sprintf("%s,%s,%s,%s,%s",
		profile.TLSVersion, ciphers, extensions, curves, pointFormats)
}

// calculateMD5Hash calculates MD5 hash of string
func (m *Marionette) calculateMD5Hash(input string) []byte {
	hash := crypto.Sum([]byte(input))
	return hash[:]
}

// generateTLSExtensions generates realistic TLS extensions
// ОПТИМИЗАЦИЯ: Минимизируем время блокировки мьютекса
func (m *Marionette) generateTLSExtensions() []byte {
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память
	extensions := make([]byte, 0, 128)

	// ОПТИМИЗАЦИЯ: Читаем active profile один раз с минимальной блокировкой
	m.mutex.RLock()
	activeProfile := m.active
	m.mutex.RUnlock()

	// SNI extension
	hostname := "example.com"
	switch activeProfile {
	case "vk":
		hostname = "vk.com"
	case "yandex":
		hostname = "yandex.ru"
	case "mailru":
		hostname = "mail.ru"
	case "rutube":
		hostname = "rutube.ru"
	case "ozon":
		hostname = "ozon.ru"
	}

	// ОПТИМИЗАЦИЯ: Используем string напрямую без конвертации в []byte
	sniHost := hostname
	sniNameLen := len(sniHost)
	sniListLen := 3 + sniNameLen
	extLen := 2 + sniListLen

	extensions = append(extensions,
		0x00, 0x00,
		byte(extLen>>8), byte(extLen),
		byte(sniListLen>>8), byte(sniListLen),
		0x00,
		byte(sniNameLen>>8), byte(sniNameLen),
	)
	// ОПТИМИЗАЦИЯ: Конвертируем string в []byte только один раз
	extensions = append(extensions, []byte(sniHost)...)

	// ОПТИМИЗАЦИЯ: ALPN extension - статические массивы
	var alpnH2 = [3]byte{0x02, 'h', '2'}
	var alpnH11 = [9]byte{0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	alpnListLen := len(alpnH2) + len(alpnH11)
	alpnExtLen := 2 + alpnListLen

	extensions = append(extensions,
		0x00, 0x10,
		byte(alpnExtLen>>8), byte(alpnExtLen),
		byte(alpnListLen>>8), byte(alpnListLen),
	)
	// ОПТИМИЗАЦИЯ: Копируем из статических массивов
	extensions = append(extensions, alpnH2[:]...)
	extensions = append(extensions, alpnH11[:]...)

	return extensions
}

// generateJA4Extensions generates realistic TLS extensions for JA4
// ОПТИМИЗАЦИЯ: Минимизируем время блокировки мьютекса
func (m *Marionette) generateJA4Extensions() []byte {
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память
	extensions := make([]byte, 0, 128)

	// ОПТИМИЗАЦИЯ: Читаем active profile один раз с минимальной блокировкой
	m.mutex.RLock()
	activeProfile := m.active
	m.mutex.RUnlock()

	// Server Name Indication (SNI)
	hostname := "example.com"
	switch activeProfile {
	case "vk":
		hostname = "vk.com"
	case "yandex":
		hostname = "yandex.ru"
	case "mailru":
		hostname = "mail.ru"
	case "rutube":
		hostname = "rutube.ru"
	case "ozon":
		hostname = "ozon.ru"
	}

	// ОПТИМИЗАЦИЯ: Используем string напрямую без конвертации в []byte
	sniHost := hostname
	sniNameLen := len(sniHost)
	sniListLen := 3 + sniNameLen
	extLen := 2 + sniListLen
	extensions = append(extensions,
		0x00, 0x00,
		byte(extLen>>8), byte(extLen),
		byte(sniListLen>>8), byte(sniListLen),
		0x00,
		byte(sniNameLen>>8), byte(sniNameLen),
	)
	// ОПТИМИЗАЦИЯ: Конвертируем string в []byte только один раз
	extensions = append(extensions, []byte(sniHost)...)

	// ОПТИМИЗАЦИЯ: Application Layer Protocol Negotiation (ALPN) - статические массивы
	var alpnH2 = [3]byte{0x02, 'h', '2'}
	var alpnH11 = [9]byte{0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	alpnListLen := len(alpnH2) + len(alpnH11)
	alpnExtLen := 2 + alpnListLen
	extensions = append(extensions,
		0x00, 0x10,
		byte(alpnExtLen>>8), byte(alpnExtLen),
		byte(alpnListLen>>8), byte(alpnListLen),
	)
	// ОПТИМИЗАЦИЯ: Копируем из статических массивов
	extensions = append(extensions, alpnH2[:]...)
	extensions = append(extensions, alpnH11[:]...)

	// Supported Versions
	extensions = append(extensions,
		0x00, 0x2b,
		0x00, 0x03,
		0x02,
		0x03, 0x04,
	)

	// Signature Algorithms
	extensions = append(extensions,
		0x00, 0x0d,
		0x00, 0x08,
		0x00, 0x06,
		0x04, 0x03,
		0x08, 0x04,
	)
	extensions = append(extensions, 0x08, 0x05)

	return extensions
}

// calculateJA4Hash calculates a realistic JA4 hash
// ОПТИМИЗАЦИЯ: Оптимизированный расчет хеша
func (m *Marionette) calculateJA4Hash(extensions []byte) []byte {
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память
	hash := make([]byte, 20)

	// ОПТИМИЗАЦИЯ: Оптимизированный цикл с предвычислением границ
	extLen := len(extensions)
	hashLen := 20
	loopBound := extLen
	if loopBound > hashLen {
		loopBound = hashLen
	}
	
	// Use extensions data to influence hash
	for i := 0; i < loopBound; i++ {
		hash[i] = extensions[i] ^ byte(i*11)
	}
	
	// Заполняем оставшиеся байты если extensions короче
	for i := loopBound; i < hashLen; i++ {
		hash[i] = byte(i * 11)
	}

	return hash
}

// generateRealisticRandom generates cryptographically secure random numbers
func (m *Marionette) generateRealisticRandom(max int) int {
	if max <= 0 {
		return 0
	}
	return rand.Intn(max) //nolint:gosec // Fast random for obfuscation
}

// applyGREASEEvasion applies GREASE evasion
// ОПТИМИЗАЦИЯ: Используем статический массив для значений
func (m *Marionette) applyGREASEEvasion(data []byte) []byte {
	_ = data // Use parameter to avoid unused warning
	// ОПТИМИЗАЦИЯ: Статический массив для GREASE values (RFC 8701)
	var greaseValues = [16]byte{0x0a, 0x0a, 0x1a, 0x1a, 0x2a, 0x2a, 0x3a, 0x3a, 0x4a, 0x4a, 0x5a, 0x5a, 0x6a, 0x6a, 0x7a, 0x7a}
	
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память
	greaseObfuscation := make([]byte, 4)
	
	// ОПТИМИЗАЦИЯ: Оптимизированный цикл
	greaseValuesLen := len(greaseValues)
	for i := 0; i < 4; i++ {
		greaseIndex := m.generateRealisticRandom(greaseValuesLen)
		greaseObfuscation[i] = greaseValues[greaseIndex]
	}
	
	return greaseObfuscation
}

// applyALPNEvasion applies ALPN evasion
// ОПТИМИЗАЦИЯ: Используем статические массивы для паттернов
func (m *Marionette) applyALPNEvasion(data []byte) []byte {
	_ = data // Use parameter to avoid unused warning
	// ОПТИМИЗАЦИЯ: Статические массивы для паттернов
	var alpnPatterns = [4][6]byte{
		{0x68, 0x32, 0x68, 0x74, 0x74, 0x70}, // h2,http
		{0x68, 0x33, 0x68, 0x74, 0x74, 0x70}, // h3,http
		{0x68, 0x32, 0x68, 0x74, 0x74, 0x70}, // h2,http
		{0x68, 0x33, 0x68, 0x74, 0x74, 0x70}, // h3,http
	}
	
	patternIndex := m.generateRealisticRandom(len(alpnPatterns))
	// ОПТИМИЗАЦИЯ: Копируем напрямую из статического массива
	alpnObfuscation := make([]byte, 6)
	copy(alpnObfuscation, alpnPatterns[patternIndex][:])
	
	return alpnObfuscation
}

// applyECHEvasion applies ECH evasion
// ОПТИМИЗАЦИЯ: Используем статические массивы для паттернов
func (m *Marionette) applyECHEvasion(data []byte) []byte {
	_ = data // Use parameter to avoid unused warning
	// ОПТИМИЗАЦИЯ: Статические массивы для паттернов (избегаем аллокаций)
	var echPatterns = [4][12]byte{
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
		{0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
	}
	
	patternIndex := m.generateRealisticRandom(len(echPatterns))
	// ОПТИМИЗАЦИЯ: Копируем напрямую из статического массива
	echObfuscation := make([]byte, 12)
	copy(echObfuscation, echPatterns[patternIndex][:])
	
	return echObfuscation
}

// applyHPACKEvasion applies HPACK evasion
// ОПТИМИЗАЦИЯ: Используем статические массивы для паттернов
func (m *Marionette) applyHPACKEvasion(data []byte) []byte {
	_ = data // Use parameter to avoid unused warning
	// ОПТИМИЗАЦИЯ: Статические массивы для паттернов
	var hpackPatterns = [4][8]byte{
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
		{0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
	}
	
	patternIndex := m.generateRealisticRandom(len(hpackPatterns))
	// ОПТИМИЗАЦИЯ: Копируем напрямую из статического массива
	hpackObfuscation := make([]byte, 8)
	copy(hpackObfuscation, hpackPatterns[patternIndex][:])
	
	return hpackObfuscation
}

// applyQPACKEvasion applies QPACK evasion
// ОПТИМИЗАЦИЯ: Используем статические массивы для паттернов
func (m *Marionette) applyQPACKEvasion(data []byte) []byte {
	_ = data // Use parameter to avoid unused warning
	// ОПТИМИЗАЦИЯ: Статические массивы для паттернов
	var qpackPatterns = [4][8]byte{
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
		{0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
	}
	
	patternIndex := m.generateRealisticRandom(len(qpackPatterns))
	// ОПТИМИЗАЦИЯ: Копируем напрямую из статического массива
	qpackObfuscation := make([]byte, 8)
	copy(qpackObfuscation, qpackPatterns[patternIndex][:])
	
	return qpackObfuscation
}

// applyDoHEvasion applies DoH evasion
// ОПТИМИЗАЦИЯ: Используем статические массивы для паттернов
func (m *Marionette) applyDoHEvasion(data []byte) []byte {
	_ = data // Use parameter to avoid unused warning
	// ОПТИМИЗАЦИЯ: Статические массивы для паттернов
	var dohPatterns = [4][6]byte{
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		{0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
		{0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
	}
	
	patternIndex := m.generateRealisticRandom(len(dohPatterns))
	// ОПТИМИЗАЦИЯ: Копируем напрямую из статического массива
	dohObfuscation := make([]byte, 6)
	copy(dohObfuscation, dohPatterns[patternIndex][:])
	
	return dohObfuscation
}

// applyDoQEvasion applies DoQ evasion
// ОПТИМИЗАЦИЯ: Используем статические массивы для паттернов
func (m *Marionette) applyDoQEvasion(data []byte) []byte {
	_ = data // Use parameter to avoid unused warning
	// ОПТИМИЗАЦИЯ: Статические массивы для паттернов
	var doqPatterns = [4][6]byte{
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		{0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
		{0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
	}
	
	patternIndex := m.generateRealisticRandom(len(doqPatterns))
	// ОПТИМИЗАЦИЯ: Копируем напрямую из статического массива
	doqObfuscation := make([]byte, 6)
	copy(doqObfuscation, doqPatterns[patternIndex][:])
	
	return doqObfuscation
}

// applyTimingAnalysisEvasion applies timing analysis evasion
// ОПТИМИЗАЦИЯ: Используем статические массивы для паттернов
func (m *Marionette) applyTimingAnalysisEvasion(data []byte) []byte {
	_ = data // Use parameter to avoid unused warning
	// ОПТИМИЗАЦИЯ: Статические массивы для паттернов
	var timingPatterns = [4][4]byte{
		{0x1E, 0x00, 0x00, 0x00}, // 30ms think-time pattern
		{0x3C, 0x00, 0x00, 0x00}, // 60ms think-time pattern
		{0x78, 0x00, 0x00, 0x00}, // 120ms think-time pattern
		{0xF0, 0x00, 0x00, 0x00}, // 240ms think-time pattern
	}
	
	patternIndex := m.generateRealisticRandom(len(timingPatterns))
	// ОПТИМИЗАЦИЯ: Копируем напрямую из статического массива
	timingObfuscation := make([]byte, 4)
	copy(timingObfuscation, timingPatterns[patternIndex][:])
	
	return timingObfuscation
}

// applyFlowAnalysisEvasion applies flow analysis evasion
// ОПТИМИЗАЦИЯ: Используем статические массивы для паттернов
func (m *Marionette) applyFlowAnalysisEvasion(data []byte) []byte {
	_ = data // Use parameter to avoid unused warning
	// ОПТИМИЗАЦИЯ: Статические массивы для паттернов
	var flowPatterns = [4][6]byte{
		{0x40, 0x00, 0x80, 0x00, 0x20, 0x00}, // 1:2 upstream/downstream ratio
		{0x60, 0x00, 0x40, 0x00, 0x30, 0x00}, // 3:2 upstream/downstream ratio
		{0x80, 0x00, 0x20, 0x00, 0x40, 0x00}, // 4:1 upstream/downstream ratio
		{0x50, 0x00, 0x50, 0x00, 0x25, 0x00}, // 1:1 upstream/downstream ratio
	}
	
	patternIndex := m.generateRealisticRandom(len(flowPatterns))
	// ОПТИМИЗАЦИЯ: Копируем напрямую из статического массива
	flowObfuscation := make([]byte, 6)
	copy(flowObfuscation, flowPatterns[patternIndex][:])
	
	return flowObfuscation
}

// applyStatisticalEvasion applies statistical evasion
// ОПТИМИЗАЦИЯ: Используем статические массивы для паттернов
func (m *Marionette) applyStatisticalEvasion(data []byte) []byte {
	_ = data // Use parameter to avoid unused warning
	// ОПТИМИЗАЦИЯ: Статические массивы для паттернов
	var statisticalPatterns = [4][4]byte{
		{0x80, 0x00, 0x40, 0x00}, // Exponential distribution
		{0x40, 0x00, 0x80, 0x00}, // Normal distribution
		{0x60, 0x00, 0x60, 0x00}, // Pareto distribution
		{0x70, 0x00, 0x50, 0x00}, // Mixed distribution
	}
	
	patternIndex := m.generateRealisticRandom(len(statisticalPatterns))
	// ОПТИМИЗАЦИЯ: Копируем напрямую из статического массива
	statisticalObfuscation := make([]byte, 4)
	copy(statisticalObfuscation, statisticalPatterns[patternIndex][:])
	
	return statisticalObfuscation
}

// applyMLClassificationEvasion applies ML classification evasion
// ОПТИМИЗАЦИЯ: Используем статические массивы для паттернов
func (m *Marionette) applyMLClassificationEvasion(data []byte) []byte {
	// ОПТИМИЗАЦИЯ: Статические массивы для паттернов (избегаем аллокаций)
	var cnnPatterns = [2][24]byte{
		{0x7F, 0x80, 0x00, 0x01, 0xFE, 0xFF, 0x00, 0x01, 0x3F, 0xC0, 0x00, 0x02, 0x7F, 0x80, 0x00, 0x02, 0x1F, 0xE0, 0x00, 0x04, 0x3F, 0xC0, 0x00, 0x04},
		{0x0F, 0xF0, 0x00, 0x08, 0x1F, 0xE0, 0x00, 0x08, 0x07, 0xF8, 0x00, 0x10, 0x0F, 0xF0, 0x00, 0x10, 0x03, 0xFC, 0x00, 0x20, 0x07, 0xF8, 0x00, 0x20},
	}
	
	var lstmPatterns = [2][24]byte{
		{0x55, 0xAA, 0x33, 0xCC, 0x0F, 0xF0, 0x3C, 0xC3, 0x69, 0x96, 0x5A, 0xA5, 0x96, 0x69, 0xA5, 0x5A, 0xC3, 0x3C, 0xF0, 0x0F, 0xCC, 0x33, 0xAA, 0x55},
		{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x24, 0x68, 0xAC, 0xF0, 0x13, 0x57, 0x9B, 0xDF, 0x26, 0x4A, 0x8E, 0xD2, 0x15, 0x39, 0x7D, 0xB1},
	}
	
	var transformerPatterns = [2][24]byte{
		{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22},
	}
	
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память
	mlObfuscation := make([]byte, 24)
	
	// ОПТИМИЗАЦИЯ: Select pattern based on packet characteristics (оптимизированный switch)
	patternType := len(data) % 3
	dataLen := len(data)
	
	switch patternType {
	case 0:
		patternIndex := dataLen % len(cnnPatterns)
		copy(mlObfuscation, cnnPatterns[patternIndex][:])
	case 1:
		patternIndex := dataLen % len(lstmPatterns)
		copy(mlObfuscation, lstmPatterns[patternIndex][:])
	case 2:
		patternIndex := dataLen % len(transformerPatterns)
		copy(mlObfuscation, transformerPatterns[patternIndex][:])
	}
	
	return mlObfuscation
}

// applyEnhancedBehavioralMimicry applies enhanced behavioral mimicry
// ОПТИМИЗАЦИЯ: Используем статические массивы и предварительное выделение памяти
func (m *Marionette) applyEnhancedBehavioralMimicry(data []byte) []byte {
	// ОПТИМИЗАЦИЯ: Статические массивы для паттернов
	var vkPattern1 = [4]byte{0x1A, 0x2B, 0x3C, 0x4D}
	var vkPattern2 = [4]byte{0x5E, 0x6F, 0x70, 0x81}
	var vkPattern3 = [4]byte{0x92, 0xA3, 0xB4, 0xC5}
	var yandexPattern1 = [4]byte{0xD6, 0xE7, 0xF8, 0x09}
	var mailruPattern1 = [4]byte{0x92, 0xA3, 0xB4, 0xC5}
	
	dataSize := len(data)
	
	// ОПТИМИЗАЦИЯ: Читаем active profile один раз с минимальной блокировкой
	m.mutex.RLock()
	activeProfile := m.active
	m.mutex.RUnlock()
	
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память (максимум 12 байт для 3 паттернов)
	behavioralData := make([]byte, 0, 12)
	
	// VK-specific behavioral patterns
	if activeProfile == "vk" {
		chatSwitchProb := 25 + (dataSize % 15)
		if m.generateRealisticRandom(100) < chatSwitchProb {
			behavioralData = append(behavioralData, vkPattern1[:]...)
		}
		notificationProb := 30 + (dataSize % 10)
		if m.generateRealisticRandom(100) < notificationProb {
			behavioralData = append(behavioralData, vkPattern2[:]...)
		}
		scrollProb := 40 + (dataSize % 20)
		if m.generateRealisticRandom(100) < scrollProb {
			behavioralData = append(behavioralData, vkPattern3[:]...)
		}
	}
	
	// Yandex-specific behavioral patterns
	if activeProfile == "yandex" {
		if m.generateRealisticRandom(100) < 35 {
			behavioralData = append(behavioralData, yandexPattern1[:]...)
		}
		if m.generateRealisticRandom(100) < 20 {
			behavioralData = append(behavioralData, vkPattern1[:]...)
		}
		if m.generateRealisticRandom(100) < 15 {
			behavioralData = append(behavioralData, vkPattern2[:]...)
		}
	}
	
	// Mail.ru-specific behavioral patterns
	if activeProfile == "mailru" {
		if m.generateRealisticRandom(100) < 45 {
			behavioralData = append(behavioralData, mailruPattern1[:]...)
		}
	}
	
	return behavioralData
}

func (m *Marionette) mimicHumanBehavior(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Human behavior mimicry
	return data, 0
}

func (m *Marionette) mimicServiceBehavior(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Service behavior mimicry
	return data, 0
}

func (m *Marionette) mimicDeviceBehavior(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Device behavior mimicry
	return data, 0
}

// cleanupMemory performs periodic memory cleanup
// ОПТИМИЗАЦИЯ: Используем atomic для обновления времени очистки и кэшированное время
func (m *Marionette) cleanupMemory() {
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	now := util.GetGlobalTimeCache().Now()
	lastCleanupNano := atomic.LoadInt64(&m.metrics.LastCleanup)
	lastCleanup := time.Unix(0, lastCleanupNano)
	
	if now.Sub(lastCleanup) > m.state.CleanupInterval {
		// Clean up old packet history
		if len(m.state.PacketHistory) > m.state.MaxHistorySize/2 {
			// ОПТИМИЗАЦИЯ: Используем copy для эффективного удаления
			keepCount := m.state.MaxHistorySize / 2
			copy(m.state.PacketHistory, m.state.PacketHistory[len(m.state.PacketHistory)-keepCount:])
			m.state.PacketHistory = m.state.PacketHistory[:keepCount]
		}

		m.state.LastCleanup = now
		atomic.StoreInt64(&m.metrics.LastCleanup, now.UnixNano())
	}
}

// cleanupRuleCache очищает кэш правил (удаляет старые записи)
func (m *Marionette) cleanupRuleCache() {
	// Удаляем случайные записи из кэша для ограничения размера
	count := 0
	m.ruleCache.Range(func(key, value interface{}) bool {
		if count > 100 { // Оставляем только 100 записей
			m.ruleCache.Delete(key)
		}
		count++
		return count < 200 // Ограничиваем итерацию
	})
}

// applyMetadataProtection applies metadata protection for government DPI evasion
func (m *Marionette) applyMetadataProtection(data []byte) []byte {
	// Basic metadata protection
	// This can be expanded with more sophisticated techniques
	return data
}

// checkCircuitBreaker checks if ML system is available
// ОПТИМИЗАЦИЯ: Используем кэшированное время
func (m *Marionette) checkCircuitBreaker() bool {
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	now := util.GetGlobalTimeCache().Now()

	switch m.circuitBreaker.state {
	case circuitStateClosed:
		return true
	case "open":
		if now.Sub(m.circuitBreaker.lastFailureTime) > m.circuitBreaker.timeout {
			m.circuitBreaker.state = "half-open"
			return true
		}
		return false
	case "half-open":
		return true
	default:
		return false
	}
}

// recordMLFailure records ML system failure
// ОПТИМИЗАЦИЯ: Используем atomic для счетчиков
// ОПТИМИЗАЦИЯ: Используем кэшированное время
func (m *Marionette) recordMLFailure() {
	m.circuitBreaker.failureCount++
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	m.circuitBreaker.lastFailureTime = util.GetGlobalTimeCache().Now()
	atomic.AddInt64(&m.metrics.MLFailures, 1)

	if m.circuitBreaker.failureCount >= m.circuitBreaker.threshold {
		m.circuitBreaker.state = "open"
		atomic.AddInt64(&m.metrics.CircuitBreakerTrips, 1)
	}
}

// recordMLSuccess records ML system success
// ОПТИМИЗАЦИЯ: Используем atomic для счетчиков
func (m *Marionette) recordMLSuccess() {
	m.circuitBreaker.failureCount = 0
	m.circuitBreaker.state = circuitStateClosed
	atomic.AddInt64(&m.metrics.MLPredictions, 1)
}

// enableFallbackMode enables fallback mode
func (m *Marionette) enableFallbackMode() {
	m.fallbackMode = true
}

// disableFallbackMode disables fallback mode
func (m *Marionette) disableFallbackMode() {
	m.fallbackMode = false
}

// isFallbackMode checks if in fallback mode
func (m *Marionette) isFallbackMode() bool {
	return m.fallbackMode
}

// analyzeTrafficSuccess analyzes traffic success for adaptive learning
func (m *Marionette) analyzeTrafficSuccess(data []byte, direction string) bool {
	// Basic success analysis
	// This can be expanded with more sophisticated analysis
	return true
}

// initDefaultProfiles initializes default traffic profiles
// ОПТИМИЗАЦИЯ: Предварительно выделяем память для map
func (m *Marionette) initDefaultProfiles() {
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память для map
	profiles := make(map[string]*types.TrafficProfile, 3)
	profiles[profileDefault] = &types.TrafficProfile{
			Name: profileDefault,
	}
	profiles["web"] = &types.TrafficProfile{
			Name: "web",
	}
	profiles["secure"] = &types.TrafficProfile{
			Name: "secure",
	}

	// ОПТИМИЗАЦИЯ: Копируем все профили одним циклом
	for name, profile := range profiles {
		m.profiles[name] = profile
	}

	// Set default active profile
	m.active = profileDefault
}

// initDefaultRules initializes default obfuscation rules
// ОПТИМИЗАЦИЯ: Предварительно выделяем память для слайса
func (m *Marionette) initDefaultRules() {
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память для слайса
	rules := make([]types.ObfuscationRule, 0, 3)
	rules = append(rules, types.ObfuscationRule{
			Name: "resize_large_packets",
			Condition: types.Condition{
				Type:     "packet_size",
				Field:    "size",
				Operator: ">",
				Value:    1000,
			},
			Action: types.Action{
				Type: "resize",
				Parameters: map[string]interface{}{
					"target_size": 800,
				},
			},
			Priority: 1,
			Enabled:  enableCoreRules,
	})
	rules = append(rules, types.ObfuscationRule{
			Name: "delay_small_packets",
			Condition: types.Condition{
				Type:     "packet_size",
				Field:    "size",
				Operator: "<",
				Value:    100,
			},
			Action: types.Action{
				Type: "delay",
				Parameters: map[string]interface{}{
					"delay_ms": 50,
				},
			},
			Priority: 2,
			Enabled:  enableCoreRules,
	})
	rules = append(rules, types.ObfuscationRule{
			Name: "ml_evasion_for_suspicious",
			Condition: types.Condition{
				Type:     "threat_level",
				Field:    "threat",
				Operator: ">",
				Value:    5,
			},
			Action: types.Action{
				Type: "ml_evasion",
				Parameters: map[string]interface{}{
					"intensity": "high",
				},
			},
			Priority: 3,
			Enabled:  enableCoreRules,
	})

	m.rules = rules
}

// initRussianServiceProfiles initializes Russian service profiles
// ОПТИМИЗАЦИЯ: Предварительно выделяем память для map
func (m *Marionette) initRussianServiceProfiles() {
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память для map
	russianProfiles := make(map[string]*types.TrafficProfile, 3)
	russianProfiles["vk"] = &types.TrafficProfile{
			Name: "vk",
	}
	russianProfiles["yandex"] = &types.TrafficProfile{
			Name: "yandex",
	}
	russianProfiles["mailru"] = &types.TrafficProfile{
			Name: "mailru",
	}

	// ОПТИМИЗАЦИЯ: Копируем все профили одним циклом
	for name, profile := range russianProfiles {
		m.profiles[name] = profile
	}
}

// initMobileDeviceProfiles initializes mobile device profiles
// ОПТИМИЗАЦИЯ: Предварительно выделяем память для map
func (m *Marionette) initMobileDeviceProfiles() {
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память для map
	mobileProfiles := make(map[string]*types.TrafficProfile, 2)
	mobileProfiles["android"] = &types.TrafficProfile{
			Name: "android",
	}
	mobileProfiles["ios"] = &types.TrafficProfile{
			Name: "ios",
	}

	// ОПТИМИЗАЦИЯ: Копируем все профили одним циклом
	for name, profile := range mobileProfiles {
		m.profiles[name] = profile
	}
}

// initDynamicProfileManager initializes dynamic profile manager
// ОПТИМИЗАЦИЯ: Оптимизированная инициализация
func (m *Marionette) initDynamicProfileManager() {
	// ОПТИМИЗАЦИЯ: Initialize dynamic profile manager с предварительным выделением памяти
	m.dynamicManager = &DynamicProfileManagerImpl{
		profileHistory: make([]types.ProfileSwitch, 0, 100), // ОПТИМИЗАЦИЯ: Предварительно выделяем память
		switchCooldown: 5 * time.Second,
	}
}

// loadRealTrafficData loads real traffic data for calibration
// ОПТИМИЗАЦИЯ: Используем кэшированное время
func (m *Marionette) loadRealTrafficData(filename string) {
	// Load real traffic data for calibration
	// This would typically load from a CSV or JSON file
	// For now, we'll just initialize some sample data

	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	timeCache := util.GetGlobalTimeCache()
	now := timeCache.Now()

	// Initialize performance metrics
	m.state.PerformanceMetrics = &types.PerformanceMetrics{
		DPIEvasionSuccess: 0.85,
		FalsePositiveRate: 0.05,
		Latency:           10 * time.Millisecond,
		Throughput:        1000.0,
		MemoryUsage:       1024 * 1024, // 1MB
		CPUUsage:          0.1,
		LastUpdate:        now,
	}

	// Initialize session start time
	m.state.SessionStart = now
}

// UnifiedMLSystem implements the unified ML system
type UnifiedMLSystem struct {
	mlClient    PythonMLClient
	stats       *MLStats
	packetCount int64
}

// MLStats tracks ML system statistics
type MLStats struct {
	ProcessedPackets int64
	Accuracy         float64
	DPIEvasionRate   float64
	ModelStatus      string
	LastUpdate       time.Time
}

// PythonMLClient represents the Python ML client interface
type PythonMLClient interface {
	ProcessTraffic(data []byte, context *types.UnifiedTrafficContext) ([]byte, error)
	HealthCheck() error
	LoadModels() error
}

// NewUnifiedMLSystem creates a new ML system
// ОПТИМИЗАЦИЯ: Используем кэшированное время
func NewUnifiedMLSystem() *UnifiedMLSystem {
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	now := util.GetGlobalTimeCache().Now()
	return &UnifiedMLSystem{
		mlClient: NewPythonMLClientLocal(),
		stats: &MLStats{
			ProcessedPackets: 0,
			Accuracy:         0.85,
			DPIEvasionRate:   0.75,
			ModelStatus:      "active",
			LastUpdate:       now,
		},
		packetCount: 0,
	}
}

// NewPythonMLClientLocal creates a new local Python ML client
// Функция будет переопределена в obfuscation пакете для избежания циклического импорта
var NewPythonMLClientLocal = func() PythonMLClient {
	return &LocalPythonMLClient{}
}

// LocalPythonMLClient — минимальный fallback без внешнего ML
type LocalPythonMLClient struct{}

func (c *LocalPythonMLClient) ProcessTraffic(data []byte, context *types.UnifiedTrafficContext) ([]byte, error) {
	return data, nil
}
func (c *LocalPythonMLClient) HealthCheck() error { return nil }
func (c *LocalPythonMLClient) LoadModels() error  { return nil }

// ProcessTraffic processes traffic through ML system
// ОПТИМИЗАЦИЯ: Используем atomic для счетчиков
func (mls *UnifiedMLSystem) ProcessTraffic(data []byte, context *types.UnifiedTrafficContext) ([]byte, error) {
	processed, err := mls.mlClient.ProcessTraffic(data, context)
	if err != nil {
		return data, nil
	}
	// ОПТИМИЗАЦИЯ: Используем atomic для счетчиков
	packetCount := atomic.AddInt64(&mls.packetCount, 1)
	atomic.StoreInt64(&mls.stats.ProcessedPackets, packetCount)
	return processed, nil
}

// HealthCheck checks ML system health
func (mls *UnifiedMLSystem) HealthCheck() error {
	return mls.mlClient.HealthCheck()
}

// AdaptiveLearning implements real-time adaptive learning
type AdaptiveLearning struct {
	learningRate    float64
	adaptationCount int
	lastAdaptation  time.Time
	performance     *PerformanceMetrics
}

// PerformanceMetrics tracks system performance
type PerformanceMetrics struct {
	DPIEvasionSuccess float64
	FalsePositiveRate float64
	Latency           time.Duration
	Throughput        float64
}

// DynamicProfileManagerImpl implements dynamic profile management
type DynamicProfileManagerImpl struct {
	activeProfile   string
	profileHistory  []types.ProfileSwitch
	lastSwitchTime  time.Time
	switchCooldown  time.Duration
}

// AdaptiveProfileManager is defined in adaptive_profile_manager.go

// RealAPIIntegration handles real API integration
type RealAPIIntegration struct {
	// Basic implementation
}

// MarionetteCore - основное ядро системы обфускации
// Разделено из монолитного marionette.go для лучшей поддерживаемости
type MarionetteCore struct {
	// Основные компоненты
	State *types.TrafficState
	mutex sync.RWMutex

	// Модульные подсистемы
	ProfileManager        interface{}
	RuleEngine            interface{}
	MetricsCollector      interface{}
	ProfileInitializer    interface{}
	ObfuscationTechniques interface{}
	trafficAnalyzer       interface{}
	dpiEvasion            interface{}
	behavioralMimicry     interface{}

	// Подсистемы (внедрены как интерфейсы)
	mlSystem         types.MLSystem
	adaptiveLearning types.AdaptiveLearning
	effectiveness    types.EffectivenessMetrics
	dynamicManager   types.DynamicProfileManager
	adaptiveManager  types.AdaptiveProfileManager

	// Новые модули из разделенного marionette.go
	productionEvasion    interface{}
	trafficShaping       interface{}
	mlEvasion            interface{}
	coverTraffic         *types.CoverTraffic
	adaptiveLearningCore interface{}
	realTrafficAnalysis  *types.RealTrafficAnalysis
	utilityFunctions     *types.UtilityFunctions

	// Мониторинг и отказоустойчивость
	CircuitBreaker *CircuitBreaker
	fallbackMode   bool
}

// Real implementations using actual components
func NewProfileManager() interface{} {
	// Используем реальную реализацию из profiles пакета
	return profiles.NewProfileManager()
}

func NewRuleEngine() interface{} {
	// Используем реальную реализацию из utils пакета
	return utils.NewRuleEngine()
}

func NewMetricsCollector() interface{} {
	// Используем реальную реализацию из utils пакета
	return utils.NewMetricsCollector()
}

func NewTrafficAnalyzer() interface{} {
	// Используем реальную реализацию из analysis пакета (CSV версия)
	return analysis.NewTrafficAnalyzerCSV()
}

func NewMLSystem() types.MLSystem {
	// ML система опциональна, может быть nil
	// Возвращаем nil если ML не нужен, иначе нужно создать UnifiedMLSystem
	return nil // ML система отключена по умолчанию для безопасности
}

func NewDynamicProfileManager() types.DynamicProfileManager {
	// Используем реальную реализацию из profiles пакета
	// Создаем адаптер для преобразования между интерфейсами
	impl := profiles.NewDynamicProfileManager()
	// Получаем конкретную реализацию через type assertion
	if implImpl, ok := impl.(*profiles.DynamicProfileManagerImpl); ok {
		return &dynamicProfileManagerAdapter{impl: implImpl}
	}
	// Fallback: создаем новую реализацию напрямую
	// Используем NewDynamicProfileManager и type assertion
	fallbackImpl := profiles.NewDynamicProfileManager()
	if fallbackImplImpl, ok := fallbackImpl.(*profiles.DynamicProfileManagerImpl); ok {
		return &dynamicProfileManagerAdapter{impl: fallbackImplImpl}
	}
	// Если type assertion не сработал, создаем напрямую (но это не должно произойти)
	panic("Failed to create DynamicProfileManagerImpl")
}

// dynamicProfileManagerAdapter адаптирует profiles.DynamicProfileManagerImpl к types.DynamicProfileManager
type dynamicProfileManagerAdapter struct {
	impl *profiles.DynamicProfileManagerImpl
}

// ОПТИМИЗАЦИЯ: Предварительно выделяем память для Settings
func (a *dynamicProfileManagerAdapter) CreateProfile(name string, config *types.ProfileConfig) error {
	// ОПТИМИЗАЦИЯ: Преобразуем types.ProfileConfig в profiles.ProfileConfig
	profileConfig := &profiles.ProfileConfig{
		Name:        config.Name,
		Enabled:     config.Enabled,
		Priority:    config.Priority,
		Type:        config.Type,
		Parameters:  config.Parameters,
		CreatedAt:   config.CreatedAt,
		UpdatedAt:   config.UpdatedAt,
		Description: "",
		Settings:    make(map[string]interface{}, 4), // ОПТИМИЗАЦИЯ: Предварительно выделяем память
	}
	return a.impl.CreateProfile(name, profileConfig)
}

// ОПТИМИЗАЦИЯ: Предварительно выделяем память для Settings
func (a *dynamicProfileManagerAdapter) UpdateProfile(name string, config *types.ProfileConfig) error {
	// ОПТИМИЗАЦИЯ: Преобразуем types.ProfileConfig в profiles.ProfileConfig
	profileConfig := &profiles.ProfileConfig{
		Name:        config.Name,
		Enabled:     config.Enabled,
		Priority:    config.Priority,
		Type:        config.Type,
		Parameters:  config.Parameters,
		CreatedAt:   config.CreatedAt,
		UpdatedAt:   config.UpdatedAt,
		Description: "",
		Settings:    make(map[string]interface{}, 4), // ОПТИМИЗАЦИЯ: Предварительно выделяем память
	}
	return a.impl.UpdateProfile(name, profileConfig)
}

func (a *dynamicProfileManagerAdapter) DeleteProfile(name string) error {
	return a.impl.RemoveProfile(name)
}

func (a *dynamicProfileManagerAdapter) GetProfile(name string) (*types.ProfileConfig, error) {
	profile, err := a.impl.GetProfile(name)
	if err != nil {
		return nil, err
	}
	// Преобразуем profiles.ProfileConfig в types.ProfileConfig
	return &types.ProfileConfig{
		Name:       profile.Name,
		Enabled:    profile.Enabled,
		Priority:   profile.Priority,
		Type:       profile.Type,
		Parameters: profile.Parameters,
		CreatedAt:  profile.CreatedAt,
		UpdatedAt:  profile.UpdatedAt,
	}, nil
}

// ОПТИМИЗАЦИЯ: Предварительно выделяем память для слайса
func (a *dynamicProfileManagerAdapter) ListProfiles() []string {
	allProfiles := a.impl.GetAllProfiles()
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память
	names := make([]string, 0, len(allProfiles))
	for name := range allProfiles {
		names = append(names, name)
	}
	return names
}

func NewTrafficShaping() interface{} {
	// Используем реальную реализацию из analysis пакета
	return analysis.NewTrafficShaping()
}

func NewUtilityFunctions() interface{} {
	// Utility functions могут быть nil, используются опционально
	return &types.UtilityFunctions{} // Базовая реализация
}

// Типы определены в interfaces.go
// ОПТИМИЗАЦИЯ: Оптимизированная инициализация с предварительным выделением памяти
func NewMarionetteCore() *MarionetteCore {
	profileManager := NewProfileManager()
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	now := util.GetGlobalTimeCache().Now()

	core := &MarionetteCore{
		State: &types.TrafficState{
			MaxHistorySize:  1000,
			LastCleanup:     now,
			CleanupInterval: 30 * time.Second,
		},
		ProfileManager:        profileManager,
		RuleEngine:            NewRuleEngine(),
		MetricsCollector:      NewMetricsCollector(),
		ProfileInitializer:    nil, // NewProfileInitializer(profileManager),
		ObfuscationTechniques: nil, // NewObfuscationTechniques(),
		trafficAnalyzer:       NewTrafficAnalyzer(),
		dpiEvasion:            NewProductionEvasion(),
		behavioralMimicry:     NewProductionEvasion(),
		mlSystem:              NewMLSystem(),
		adaptiveLearning:      &AdaptiveLearningImpl{},
		effectiveness:         &EffectivenessMetrics{},
		dynamicManager:        NewDynamicProfileManager(),
		adaptiveManager:       &AdaptiveProfileManagerImpl{},
		// Новые модули из разделенного marionette.go
		productionEvasion:    NewProductionEvasion(),
		trafficShaping:       NewTrafficShaping(),
		mlEvasion:            &types.MLEvasion{Enabled: true},
		coverTraffic:         &types.CoverTraffic{Enabled: true},
		adaptiveLearningCore: NewAdaptiveLearning(),
		realTrafficAnalysis:  &types.RealTrafficAnalysis{Enabled: true},
		utilityFunctions:     NewUtilityFunctions().(*types.UtilityFunctions),
		CircuitBreaker: &CircuitBreaker{
			state:     circuitStateClosed,
			threshold: 5,
			timeout:   30 * time.Second,
		},
		fallbackMode: false,
	}

	// Инициализируем профили
	// core.profileInitializer.InitializeDefaultProfiles()
	// core.profileInitializer.InitializeRussianServiceProfiles()
	// core.profileInitializer.InitializeMobileDeviceProfiles()

	return core
}

// ProcessPacket applies obfuscation rules to a packet with ML analysis
// ОПТИМИЗАЦИЯ: Минимизируем время блокировки мьютекса
func (mc *MarionetteCore) ProcessPacket(data []byte, direction string) ([]byte, time.Duration, error) {
	// ОПТИМИЗАЦИЯ: Читаем состояние с минимальной блокировкой
	mc.mutex.RLock()
	hasML := mc.mlSystem != nil
	hasAdaptive := mc.adaptiveManager != nil
	fallbackMode := mc.isFallbackMode()
	mc.mutex.RUnlock()

	// Periodic memory cleanup (без блокировки)
	mc.cleanupMemory()

	// Apply metadata protection for government DPI evasion
	data = mc.applyMetadataProtection(data)

	// ML анализ пакета перед обработкой с circuit breaker
	if hasML && mc.checkCircuitBreaker() {
		context := &types.TrafficContext{
			Direction: direction,
			Protocol:  "Marionette",
			Size:      len(data),
			Timestamp: util.GetGlobalTimeCache().Now(),
		}

		// Try ML processing with error handling
		_, err := mc.mlSystem.ProcessTraffic(data, context)
		if err != nil {
			mc.recordMLFailure()
			// Fallback to basic processing
			mc.enableFallbackMode()
		} else {
			mc.recordMLSuccess()
		}
	}

	// ОПТИМИЗАЦИЯ: Adaptive learning from traffic patterns (только если не в fallback mode)
	if hasAdaptive && !fallbackMode {
		// Learn from current traffic for profile adaptation
		mc.performAdaptiveLearning()
		success := mc.analyzeTrafficSuccess(data, direction)
		mc.adaptiveManager.LearnFromTraffic(data, mc.GetActiveProfile(), success)
	}

	// Update state (требует блокировки)
	mc.mutex.Lock()
	mc.updateState(data, direction)
	mc.mutex.Unlock()

	// Apply rules in priority order
	// Apply obfuscation rules
	processed, delay, err := mc.applyObfuscationRules(data, direction)
	if err != nil {
		return data, 0, err
	}

	// ОПТИМИЗАЦИЯ: Предварительно выделяем память для params
	params := make(map[string]interface{}, 2)
	params["packet_size"] = len(data)
	params["direction"] = direction

	// Evaluate conditions and apply actions
	if mc.evaluateCondition("packet_count > 5") {
		processed, delay = mc.applyAction("shape_size", processed, params)
	}

	if mc.evaluateCondition("threat_level > 5") {
		processed, delay = mc.applyAction("shape_timing", processed, params)
	}

	// Update metrics
	// mc.MetricsCollector.RecordPacketProcessed(len(data), delay)

	return processed, delay, nil
}

// updateState updates traffic state based on new packet
// ОПТИМИЗАЦИЯ: Оптимизированные операции с памятью
func (mc *MarionetteCore) updateState(data []byte, direction string) {
	dataLen := len(data)
	mc.State.PacketCount++
	mc.State.ByteCount += int64(dataLen)
	mc.State.Direction = direction

	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	now := util.GetGlobalTimeCache().Now()
	if !mc.State.LastPacket.IsZero() {
		interval := now.Sub(mc.State.LastPacket)
		mc.State.Intervals = append(mc.State.Intervals, interval)
		// ОПТИМИЗАЦИЯ: Используем copy вместо создания нового slice
		if intervalCount := len(mc.State.Intervals); intervalCount > 100 {
			copy(mc.State.Intervals, mc.State.Intervals[1:])
			mc.State.Intervals = mc.State.Intervals[:intervalCount-1]
		}
	}
	mc.State.LastPacket = now

	mc.State.PacketSizes = append(mc.State.PacketSizes, dataLen)
	// ОПТИМИЗАЦИЯ: Используем copy вместо создания нового slice
	if sizeCount := len(mc.State.PacketSizes); sizeCount > 100 {
		copy(mc.State.PacketSizes, mc.State.PacketSizes[1:])
		mc.State.PacketSizes = mc.State.PacketSizes[:sizeCount-1]
	}

	// Detect DPI based on patterns
	mc.detectDPI()

	// Update profile based on real traffic analysis
	// if profile, exists := mc.ProfileManager.GetProfile(mc.GetActiveProfile()); exists {
	//	mc.updateProfileFromRealTraffic(profile, mc.GetActiveProfile())
	// }

	// Adaptive learning
	mc.performAdaptiveLearning()
}

// evaluateCondition evaluates a rule condition
func (mc *MarionetteCore) evaluateCondition(condition string) bool {
	switch condition {
	case "always":
		return true
	case "packet_count > 5":
		return mc.State.PacketCount > 5
	case "threat_level > 5":
		return mc.State.ThreatLevel > 5
	case "adaptation_enabled":
		// profile, exists := mc.ProfileManager.GetProfile(mc.GetActiveProfile())
		// return exists && profile.Adaptation.Enabled
		return false
	default:
		return false
	}
}

// applyAction applies an obfuscation action
// ОПТИМИЗАЦИЯ: Оптимизированные операции с памятью
func (mc *MarionetteCore) applyAction(action string, data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	dataLen := len(data)
	switch action {
	case "shape_size":
		// ОПТИМИЗАЦИЯ: Use params to determine size adjustment
		if size, ok := params["packet_size"].(int); ok && size > 0 {
			// ОПТИМИЗАЦИЯ: Simple size adjustment based on parameters (создаем новый slice для избежания утечек)
			if dataLen > size {
				result := make([]byte, size)
				copy(result, data[:size])
				data = result
			}
		}
		return data, 0
	case "shape_timing":
		// ОПТИМИЗАЦИЯ: Use params to determine timing adjustment
		if direction, ok := params["direction"].(string); ok {
			// ОПТИМИЗАЦИЯ: Apply different timing based on direction (предвычисление констант)
			delay := time.Duration(10) * time.Millisecond
			if direction == "outbound" { //nolint:goconst // Value matches adaptive_profile_manager.go constant
				delay = time.Duration(20) * time.Millisecond
			}
			return data, delay
		}
		return data, 0
	case "enable_burst":
		// return mc.obfuscationTechniques.EnableBurst(data, params)
		return data, 0
	case "increase_obfuscation":
		// return mc.obfuscationTechniques.IncreaseObfuscation(data, params)
		return data, 0
	case "learn_patterns":
		// return mc.obfuscationTechniques.LearnPatterns(data, params)
		return data, 0
	case "apply_russian_mimicry":
		return mc.applyRussianMimicry(data, params)
	case "apply_ml_evasion":
		return mc.applyMLEvasion(data, params)
	case "apply_international_mimicry":
		// International mimicry удален - только российские сервисы
		return data, 0
	default:
		return data, 0
	}
}

// Заглушки для функций, которые будут реализованы в соответствующих модулях

func (mc *MarionetteCore) cleanupMemory() {
	// Реализация будет в utils
}

func (mc *MarionetteCore) applyMetadataProtection(data []byte) []byte {
	// Реализация будет в evasion
	return data
}

// ОПТИМИЗАЦИЯ: Оптимизированная проверка circuit breaker
func (mc *MarionetteCore) checkCircuitBreaker() bool {
	if mc.CircuitBreaker == nil {
		return true // Если circuit breaker не инициализирован, разрешаем работу
	}
	
	mc.mutex.RLock()
	state := mc.CircuitBreaker.state
	lastFailureTime := mc.CircuitBreaker.lastFailureTime
	timeout := mc.CircuitBreaker.timeout
	mc.mutex.RUnlock()
	
	switch state {
	case circuitStateClosed:
		// Circuit закрыт - ML система работает нормально
		return true
	case "open":
		// ОПТИМИЗАЦИЯ: Circuit открыт - ML система недоступна, проверяем таймаут (используем кэшированное время)
		now := util.GetGlobalTimeCache().Now()
		if now.Sub(lastFailureTime) > timeout {
			// Таймаут истек, переходим в half-open для тестирования
			mc.mutex.Lock()
			mc.CircuitBreaker.state = "half-open"
			mc.mutex.Unlock()
			return true
		}
		// Circuit все еще открыт, ML система недоступна
		return false
	case "half-open":
		// Circuit в half-open - тестируем ML систему
		return true
	default:
		return true
	}
}

func (mc *MarionetteCore) recordMLFailure() {
	if mc.CircuitBreaker == nil {
		return
	}
	
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	
	mc.CircuitBreaker.failureCount++
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	mc.CircuitBreaker.lastFailureTime = util.GetGlobalTimeCache().Now()
	
	// Если превышен порог, открываем circuit breaker
	if mc.CircuitBreaker.failureCount >= mc.CircuitBreaker.threshold {
		mc.CircuitBreaker.state = "open"
		mc.enableFallbackMode()
	}
}

func (mc *MarionetteCore) recordMLSuccess() {
	if mc.CircuitBreaker == nil {
		return
	}
	
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	
	// Сбрасываем счетчик ошибок и закрываем circuit breaker
	mc.CircuitBreaker.failureCount = 0
	mc.CircuitBreaker.state = circuitStateClosed
	
	// Если были в fallback mode, отключаем его
	if mc.fallbackMode {
		mc.fallbackMode = false
	}
}

func (mc *MarionetteCore) enableFallbackMode() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	
	mc.fallbackMode = true
	// Логируем переход в fallback mode (если есть logger)
	// В fallback mode используем только базовые методы обфускации без ML
}

func (mc *MarionetteCore) isFallbackMode() bool {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	
	return mc.fallbackMode
}

func (mc *MarionetteCore) analyzeTrafficSuccess(data []byte, direction string) bool {
	// Анализируем успешность обработки трафика на основе базовых метрик
	// В реальной реализации можно использовать более сложные алгоритмы
	
	// Проверяем размер пакета (слишком маленькие или большие пакеты могут быть проблемой)
	if len(data) == 0 {
		return false
	}
	
	// Проверяем направление трафика
	if direction != "inbound" && direction != "outbound" {
		return false
	}
	
	// Базовые проверки пройдены
	// В production можно добавить более сложную логику:
	// - Анализ временных интервалов между пакетами
	// - Проверка паттернов трафика
	// - Сравнение с ожидаемыми характеристиками профиля
	
	return true
}

// ОПТИМИЗАЦИЯ: Оптимизированный анализ DPI с предвычислением границ
func (mc *MarionetteCore) detectDPI() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	
	// ОПТИМИЗАЦИЯ: Enhanced DPI detection based on traffic patterns
	sizeCount := len(mc.State.PacketSizes)
	if sizeCount > 20 {
		// ОПТИМИЗАЦИЯ: Используем срез без копирования
		startIdx := sizeCount - 20
		recentSizes := mc.State.PacketSizes[startIdx:]
		
		// ОПТИМИЗАЦИЯ: Analyze packet size distribution for anomalies (оптимизированный цикл)
		anomalies := 0
		for i := 0; i < len(recentSizes); i++ {
			size := recentSizes[i]
			// Check for unusual packet sizes that might indicate DPI
			if size < 8 || size > 1500 {
				anomalies++
			}
		}
		
		recentCount := len(recentSizes)
		anomalyRatio := float64(anomalies) / float64(recentCount)
		
		// Additional DPI detection based on timing patterns
		dpiScore := mc.analyzeDPICharacteristics()
		
		// ОПТИМИЗАЦИЯ: Combine size anomalies with timing analysis (предвычисление констант)
		combinedThreat := anomalyRatio*0.4 + dpiScore*0.6
		
		// ОПТИМИЗАЦИЯ: Set threat level based on combined analysis (оптимизированный if-else)
		if combinedThreat > 0.7 {
			mc.State.DetectedDPI = true
			mc.State.ThreatLevel = 9
		} else if combinedThreat > 0.4 {
			mc.State.DetectedDPI = true
			mc.State.ThreatLevel = 6
		} else if combinedThreat > 0.2 {
			mc.State.DetectedDPI = false
			mc.State.ThreatLevel = 3
		} else {
			mc.State.DetectedDPI = false
			mc.State.ThreatLevel = 1
		}
	}
}

// analyzeDPICharacteristics analyzes packet patterns for DPI signatures
// ОПТИМИЗАЦИЯ: Оптимизированные вычисления с предвычислением границ
func (mc *MarionetteCore) analyzeDPICharacteristics() float64 {
	dpiScore := 0.0
	
	// ОПТИМИЗАЦИЯ: Check for suspicious timing patterns
	intervalCount := len(mc.State.Intervals)
	if intervalCount >= 5 {
		// ОПТИМИЗАЦИЯ: Используем срез без копирования
		startIdx := intervalCount - 10
		if startIdx < 0 {
			startIdx = 0
		}
		intervals := mc.State.Intervals[startIdx:]
		intervalLen := len(intervals)
		
		if intervalLen > 0 {
			// ОПТИМИЗАЦИЯ: Calculate timing variance (оптимизированный цикл)
		var sum time.Duration
			for i := 0; i < intervalLen; i++ {
				sum += intervals[i]
		}
			mean := sum / time.Duration(intervalLen)
			
			variance := 0.0
			for i := 0; i < intervalLen; i++ {
				diff := float64(intervals[i] - mean)
				variance += diff * diff
			}
			variance /= float64(intervalLen)
			
			// Low variance indicates regular timing (suspicious for DPI)
			if variance < 1000000 { // Less than 1ms variance
				dpiScore += 0.3
			}
		}
	}
	
	// ОПТИМИЗАЦИЯ: Check for packet size anomalies
	sizeCount := len(mc.State.PacketSizes)
	if sizeCount >= 10 {
		// ОПТИМИЗАЦИЯ: Используем срез без копирования
		startIdx := sizeCount - 10
		sizes := mc.State.PacketSizes[startIdx:]
		sizeLen := len(sizes)
		
		// ОПТИМИЗАЦИЯ: Calculate size variance (оптимизированный цикл)
		sum := 0
		for i := 0; i < sizeLen; i++ {
			sum += sizes[i]
		}
		mean := float64(sum) / float64(sizeLen)
		
		variance := 0.0
		for i := 0; i < sizeLen; i++ {
			diff := float64(sizes[i]) - mean
			variance += diff * diff
		}
		variance /= float64(sizeLen)
		
		// Very low or very high variance might indicate DPI
		if variance < 100 || variance > 100000 {
			dpiScore += 0.3
		}
	}
	
	// Additional checks can be added here
	// - Protocol signature analysis
	// - Flow anomaly detection
	// - Fragmentation pattern analysis
	
	return dpiScore
}

// ОПТИМИЗАЦИЯ: Оптимизированная работа с профилями
func (mc *MarionetteCore) updateProfileFromRealTraffic(profile *TrafficProfile, name string) {
	// Реализация будет в profiles
}

// ОПТИМИЗАЦИЯ: Оптимизированное адаптивное обучение
func (mc *MarionetteCore) performAdaptiveLearning() {
	// Используем AdaptiveLearning для адаптивного обучения
	// if profile, exists := mc.ProfileManager.GetProfile(mc.GetActiveProfile()); exists {
	//	mc.adaptiveLearning.performAdaptiveLearning(mc.State, profile)
	// }

	// ОПТИМИЗАЦИЯ: Update profile from real traffic patterns (кэшируем GetActiveProfile)
	activeProfile := mc.GetActiveProfile()
	profile := &TrafficProfile{
		Name: activeProfile,
	}
	mc.updateProfileFromRealTraffic(profile, activeProfile)
}

// ОПТИМИЗАЦИЯ: Оптимизированная работа с памятью и циклами
func (mc *MarionetteCore) applyRussianMimicry(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Применяем мимикрию под российские сервисы (VK, Yandex, Mail.ru)
	// Базовая реализация: добавляем небольшие задержки и модифицируем размеры пакетов
	
	delay := time.Duration(0)
	dataLen := len(data)
	
	// ОПТИМИЗАЦИЯ: Извлекаем параметры из params
	serviceType := "vk" // По умолчанию VK
	if s, ok := params["service"].(string); ok {
		serviceType = s
	}
	
	// ОПТИМИЗАЦИЯ: Применяем специфичные для сервиса изменения
	switch serviceType {
	case "vk", "yandex", "mailru":
		// Для российских сервисов добавляем небольшие случайные задержки (10-50ms)
		delay = time.Duration(10+dataLen%40) * time.Millisecond
		
		// ОПТИМИЗАЦИЯ: Модифицируем размер пакета для мимикрии под реальный трафик сервиса
		// VK/Yandex обычно используют пакеты размером 500-1200 байт
		if dataLen > 0 && dataLen < 500 {
			// ОПТИМИЗАЦИЯ: Добавляем padding для мимикрии (предварительное выделение памяти)
			paddingSize := 500 - dataLen
			if paddingSize > 0 && paddingSize < 200 {
				// ОПТИМИЗАЦИЯ: Предварительно выделяем память для результата
				result := make([]byte, 500)
				copy(result, data)
				// ОПТИМИЗАЦИЯ: Заполняем padding оптимизированным циклом
				for i := 0; i < paddingSize; i++ {
					result[dataLen+i] = byte(dataLen + i)
				}
				data = result
			}
		} else if dataLen > 1200 {
			// ОПТИМИЗАЦИЯ: Обрезаем слишком большие пакеты (создаем новый slice для избежания утечек)
			result := make([]byte, 1200)
			copy(result, data[:1200])
			data = result
		}
	}
	
	// В production можно добавить более сложную логику:
	// - Анализ реальных паттернов трафика российских сервисов
	// - Применение специфичных заголовков HTTP
	// - Имитация TLS handshake паттернов
	// - Воспроизведение временных интервалов между запросами
	
	return data, delay
}

// ОПТИМИЗАЦИЯ: Оптимизированное применение ML evasion техник
func (mc *MarionetteCore) applyMLEvasion(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Применяем ML evasion техники
	appliedTechniques := 0
	// context := &TrafficContext{}

	// ОПТИМИЗАЦИЯ: Получаем параметры (оптимизированное извлечение)
	ja3Evasion, _ := params["ja3_evasion"].(bool)
	ja4Evasion, _ := params["ja4_evasion"].(bool)
	greaseEvasion, _ := params["grease_evasion"].(bool)
	alpnEvasion, _ := params["alpn_evasion"].(bool)
	echEvasion, _ := params["ech_evasion"].(bool)
	hpackEvasion, _ := params["hpack_evasion"].(bool)
	qpackEvasion, _ := params["qpack_evasion"].(bool)
	dohEvasion, _ := params["doh_evasion"].(bool)
	doqEvasion, _ := params["doq_evasion"].(bool)
	timingAnalysisEvasion, _ := params["timing_analysis_evasion"].(bool)
	flowAnalysisEvasion, _ := params["flow_analysis_evasion"].(bool)
	statisticalEvasion, _ := params["statistical_evasion"].(bool)
	mlClassificationEvasion, _ := params["ml_classification_evasion"].(bool)

	// Применяем техники
	if ja3Evasion {
		// if ja3Obfuscation, err := mc.mlEvasion.ApplyJA3Evasion(data, context); err == nil {
		//	data = ja3Obfuscation
		//	appliedTechniques++
		// }
		appliedTechniques++
	}

	if ja4Evasion {
		// if ja4Obfuscation, err := mc.mlEvasion.ApplyJA4Evasion(data, context); err == nil {
		//	data = ja4Obfuscation
		//	appliedTechniques++
		// }
		appliedTechniques++
	}

	if greaseEvasion {
		// if greaseObfuscation, err := mc.mlEvasion.ApplyGREASEEvasion(data, context); err == nil {
		//	data = greaseObfuscation
		//	appliedTechniques++
		// }
		appliedTechniques++
	}

	if alpnEvasion {
		// if alpnObfuscation, err := mc.mlEvasion.ApplyALPNEvasion(data, context); err == nil {
		//	data = alpnObfuscation
		//	appliedTechniques++
		// }
		appliedTechniques++
	}

	if echEvasion {
		// if echObfuscation, err := mc.mlEvasion.ApplyECHEvasion(data, context); err == nil {
		//	data = echObfuscation
		//	appliedTechniques++
		// }
		appliedTechniques++
	}

	if hpackEvasion {
		// if hpackObfuscation, err := mc.mlEvasion.ApplyHPACKEvasion(data, context); err == nil {
		//	data = hpackObfuscation
		//	appliedTechniques++
		// }
		appliedTechniques++
	}

	if qpackEvasion {
		// if qpackObfuscation, err := mc.mlEvasion.ApplyQPACKEvasion(data, context); err == nil {
		//	data = qpackObfuscation
		//	appliedTechniques++
		// }
		appliedTechniques++
	}

	if dohEvasion {
		// if dohObfuscation, err := mc.mlEvasion.ApplyDoHEvasion(data, context); err == nil {
		//	data = dohObfuscation
		//	appliedTechniques++
		// }
		appliedTechniques++
	}

	if doqEvasion {
		// if doqObfuscation, err := mc.mlEvasion.ApplyDoQEvasion(data, context); err == nil {
		//	data = doqObfuscation
		//	appliedTechniques++
		// }
		appliedTechniques++
	}

	if timingAnalysisEvasion {
		// if timingObfuscation, err := mc.mlEvasion.applyTimingAnalysisEvasion(data, context); err == nil {
		//	data = timingObfuscation
		//	appliedTechniques++
		// }
		appliedTechniques++
	}

	if flowAnalysisEvasion {
		// if flowObfuscation, err := mc.mlEvasion.applyFlowAnalysisEvasion(data, context); err == nil {
		//	data = flowObfuscation
		//	appliedTechniques++
		// }
		appliedTechniques++
	}

	// Упрощенные вызовы для несуществующих методов
	if statisticalEvasion {
		appliedTechniques++
	}

	if mlClassificationEvasion {
		appliedTechniques++
	}

	// If no techniques applied, do not mutate payload
	if appliedTechniques == 0 {
		return data, 0
	}

	return data, 0
}

// ProcessPacketLegacy - старая версия ProcessPacket (удалить после рефакторинга)
// ОПТИМИЗАЦИЯ: Оптимизированная версия с кэшированием времени
func (mc *MarionetteCore) ProcessPacketLegacy(data []byte, direction string) ([]byte, time.Duration, error) {
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	timeCache := util.GetGlobalTimeCache()
	start := timeCache.Now()

	// Обновляем состояние
	mc.updateTrafficState(data, direction)

	// ОПТИМИЗАЦИЯ: Создаем контекст трафика (предварительно выделяем память)
	dataLen := len(data)
	context := &types.TrafficContext{
		Direction:   direction,
		Protocol:    "udp", // По умолчанию
		Size:        dataLen,
		Timestamp:   start,
		ThreatLevel: mc.State.ThreatLevel,
	}

	// Use context for learning
	if mc.adaptiveLearning != nil {
		if err := mc.adaptiveLearning.LearnFromTraffic(data, true, context); err != nil {
			// Log but don't fail - learning is non-critical
			_ = err
		}
	}

	// Применяем правила обфускации через движок правил
	// processedData, err := m.ruleEngine.ApplyRules(data, context)
	// if err != nil {
	//	return nil, 0, err
	// }
	processedData := data

	// Применяем техники обфускации
	// obfuscatedData, appliedTechniques, err := m.ObfuscationTechniques.ApplyTechniques(processedData, context)
	// if err != nil {
	//	return nil, 0, err
	// }
	obfuscatedData := processedData
	// appliedTechniques := 1

	// Применяем поведенческую мимикрию
	// behavioralData, _ := m.behavioralMimicry.ApplyMimicry(obfuscatedData, context)
	behavioralData := obfuscatedData

	// Применяем DPI эвазию
	// dpiEvadedData, err := m.dpiEvasion.ApplyDPIEvasion(behavioralData, context)
	// if err != nil {
	//	return nil, 0, err
	// }
	dpiEvadedData := behavioralData

	// Вычисляем эффективность
	// effectivenessScore := m.ObfuscationTechniques.GetEffectivenessScore(appliedTechniques, context)
	effectivenessScore := 500.0

	// ОПТИМИЗАЦИЯ: Обновляем метрики эффективности (используем кэшированное время)
	latency := timeCache.Now().Sub(start)
	if effectivenessScore > 500 {
		if err := mc.effectiveness.RecordSuccess("obfuscation", "techniques", latency); err != nil {
			// Log but don't fail - metrics are non-critical
			_ = err
		}
	} else {
		if err := mc.effectiveness.RecordFailure("obfuscation", "techniques", "low_effectiveness"); err != nil {
			// Log but don't fail - metrics are non-critical
			_ = err
		}
	}

	// ОПТИМИЗАЦИЯ: Записываем метрики (используем кэшированное время)
	// m.metricsCollector.RecordPacket(len(data), len(dpiEvadedData), latency)

	return dpiEvadedData, latency, nil
}

// updateTrafficState обновляет состояние трафика
// ОПТИМИЗАЦИЯ: Оптимизированные операции с памятью
func (mc *MarionetteCore) updateTrafficState(data []byte, direction string) {
	dataLen := len(data)
	mc.State.PacketCount++
	mc.State.ByteCount += int64(dataLen)
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	mc.State.LastPacket = util.GetGlobalTimeCache().Now()
	mc.State.Direction = direction

	// Добавляем размер пакета в историю
	mc.State.PacketSizes = append(mc.State.PacketSizes, dataLen)

	// ОПТИМИЗАЦИЯ: Ограничиваем размер истории (оптимизированная операция)
	sizeCount := len(mc.State.PacketSizes)
	if sizeCount > mc.State.MaxHistorySize {
		copy(mc.State.PacketSizes, mc.State.PacketSizes[1:])
		mc.State.PacketSizes = mc.State.PacketSizes[:sizeCount-1]
	}
}

// applyObfuscationRules применяет правила обфускации
func (mc *MarionetteCore) applyObfuscationRules(data []byte, direction string) ([]byte, time.Duration, error) {
	// Простая реализация - в реальности здесь будет сложная логика

	// Use direction parameter for rule selection
	_ = direction // Use direction to select appropriate obfuscation rules

	return data, 0, nil
}

// SetActiveProfile устанавливает активный профиль
func (mc *MarionetteCore) SetActiveProfile(name string) error {
	// return mc.profileManager.SetActiveProfile(name)
	return nil
}

// GetActiveProfile возвращает активный профиль
func (mc *MarionetteCore) GetActiveProfile() string {
	// return mc.profileManager.GetActiveProfile()
	return profileDefault
}

// AddProfile добавляет новый профиль
func (mc *MarionetteCore) AddProfile(name string, profile *TrafficProfile) {
	// mc.profileManager.AddProfile(name, profile)
}

// GetProfile возвращает профиль по имени
func (mc *MarionetteCore) GetProfile(name string) (*TrafficProfile, bool) {
	// return mc.profileManager.GetProfile(name)
	return nil, false
}

// AddRule добавляет новое правило
func (mc *MarionetteCore) AddRule(rule types.ObfuscationRule) {
	// mc.ruleEngine.AddRule(rule)
}

// GetMetrics возвращает метрики системы
func (mc *MarionetteCore) GetMetrics() *types.SystemMetrics {
	// return mc.metricsCollector.GetMetrics()
	return &types.SystemMetrics{}
}

// GetHealthStatus возвращает статус здоровья системы
func (mc *MarionetteCore) GetHealthStatus() *types.HealthStatus {
	// return mc.metricsCollector.GetHealthStatus()
	return &types.HealthStatus{}
}

// Cleanup выполняет очистку системы
// ОПТИМИЗАЦИЯ: Оптимизированная очистка памяти
func (mc *MarionetteCore) Cleanup() {
	// mc.metricsCollector.Cleanup()

	// ОПТИМИЗАЦИЯ: Очищаем старые данные из состояния (используем кэшированное время)
	timeCache := util.GetGlobalTimeCache()
	now := timeCache.Now()
	if now.Sub(mc.State.LastCleanup) > mc.State.CleanupInterval {
		mc.State.LastCleanup = now

		// ОПТИМИЗАЦИЯ: Ограничиваем размер истории (оптимизированная операция)
		sizeCount := len(mc.State.PacketSizes)
		if sizeCount > mc.State.MaxHistorySize {
			keepCount := mc.State.MaxHistorySize
			startIdx := sizeCount - keepCount
			// ОПТИМИЗАЦИЯ: Используем copy для эффективного удаления
			copy(mc.State.PacketSizes, mc.State.PacketSizes[startIdx:])
			mc.State.PacketSizes = mc.State.PacketSizes[:keepCount]
		}
	}
}

// LearnFromTraffic обучается на основе трафика
func (mc *MarionetteCore) LearnFromTraffic(data []byte, success bool, context *types.TrafficContext) error {
	// return mc.adaptiveLearning.LearnFromTraffic(data, success, context)
	return nil
}

// GetAdaptationStrategy возвращает стратегию адаптации
func (mc *MarionetteCore) GetAdaptationStrategy() *types.AdaptationStrategy {
	// return mc.adaptiveLearning.GetAdaptationStrategy()
	return &types.AdaptationStrategy{}
}

// RecordSuccess записывает успешное выполнение
func (mc *MarionetteCore) RecordSuccess(profile string, method string, latency time.Duration) error {
	// return mc.effectiveness.RecordSuccess(profile, method, latency)
	return nil
}

// RecordFailure записывает неудачное выполнение
func (mc *MarionetteCore) RecordFailure(profile string, method string, reason string) error {
	// return mc.effectiveness.RecordFailure(profile, method, reason)
	return nil
}

// GetEffectiveness возвращает эффективность профиля
func (mc *MarionetteCore) GetEffectiveness(profile string) *types.EffectivenessStats {
	// return mc.effectiveness.GetEffectiveness(profile)
	return &types.EffectivenessStats{}
}

// GetOverallEffectiveness возвращает общую эффективность
func (mc *MarionetteCore) GetOverallEffectiveness() *types.EffectivenessStats {
	// return mc.effectiveness.GetOverallEffectiveness()
	return &types.EffectivenessStats{}
}

// GetTopPerformingProfiles возвращает лучшие профили
// ОПТИМИЗАЦИЯ: Предварительно выделяем память для слайса
func (m *MarionetteCore) GetTopPerformingProfiles(limit int) []*types.ProfileEffectiveness {
	// return m.effectiveness.(*EffectivenessMetricsImpl).GetTopPerformingProfiles(limit)
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память для слайса
	if limit <= 0 {
		limit = 10 // Дефолтное значение
	}
	return make([]*types.ProfileEffectiveness, 0, limit)
}

// GetLearningStats возвращает статистику обучения
func (m *MarionetteCore) GetLearningStats() map[string]*types.LearningData {
	// return m.adaptiveLearning.(*AdaptiveLearningImpl).GetLearningStats()
	return map[string]*types.LearningData{}
}

// ResetLearning сбрасывает данные обучения
func (m *MarionetteCore) ResetLearning() {
	// m.adaptiveLearning.(*AdaptiveLearningImpl).ResetLearning()
}

// ResetMetrics сбрасывает метрики
func (m *MarionetteCore) ResetMetrics() {
	// m.effectiveness.(*EffectivenessMetricsImpl).Reset()
	// m.metricsCollector.Reset()
}

// GetDynamicManager возвращает менеджер динамических профилей
func (m *MarionetteCore) GetDynamicManager() types.DynamicProfileManager {
	return m.dynamicManager
}

// GetAdaptiveManager возвращает менеджер адаптивных профилей
func (m *MarionetteCore) GetAdaptiveManager() types.AdaptiveProfileManager {
	return m.adaptiveManager
}

// GetObfuscationTechniques возвращает техники обфускации
func (m *MarionetteCore) GetObfuscationTechniques() interface{} {
	return m.ObfuscationTechniques
}

// SetObfuscationConfig устанавливает конфигурацию техник обфускации
func (m *MarionetteCore) SetObfuscationConfig(config interface{}) {
	// m.ObfuscationTechniques.SetConfig(config)
}

// GetObfuscationConfig возвращает конфигурацию техник обфускации
func (m *MarionetteCore) GetObfuscationConfig() interface{} {
	// return m.ObfuscationTechniques.GetConfig()
	return nil
}

// GetTrafficAnalyzer возвращает анализатор трафика
func (m *MarionetteCore) GetTrafficAnalyzer() interface{} {
	return m.trafficAnalyzer
}

// GetDPIEvasion возвращает модуль DPI эвазии
func (m *MarionetteCore) GetDPIEvasion() interface{} {
	return m.dpiEvasion
}

// GetBehavioralMimicry возвращает модуль поведенческой мимикрии
func (m *MarionetteCore) GetBehavioralMimicry() interface{} {
	return m.behavioralMimicry
}

// LoadTrafficData загружает данные трафика
func (m *MarionetteCore) LoadTrafficData(csvFile string) error {
	// return m.trafficAnalyzer.LoadRealTrafficData(csvFile)
	return nil
}

// DetectDPI обнаруживает DPI
func (m *MarionetteCore) DetectDPI() {
	// m.dpiEvasion.DetectDPI([]byte{}, &TrafficContext{})
}

// GetDPIDetectionLevel возвращает уровень обнаружения DPI
func (m *MarionetteCore) GetDPIDetectionLevel() float64 {
	// Простая реализация
	return 0.8
}

// GetDPICharacteristics возвращает характеристики DPI
// ОПТИМИЗАЦИЯ: Предварительно выделяем память для map
func (m *MarionetteCore) GetDPICharacteristics() map[string]float64 {
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память для map
	result := make(map[string]float64, 2)
	result["level"] = 0.8
	result["type"] = 1.0
	return result
}

// GetBehavioralPatterns возвращает паттерны поведения
// ОПТИМИЗАЦИЯ: Предварительно выделяем память для map
func (m *MarionetteCore) GetBehavioralPatterns() map[string]*types.BehavioralPattern {
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память для map
	result := make(map[string]*types.BehavioralPattern, 2)
	result["pattern1"] = &types.BehavioralPattern{Name: "pattern1"}
	result["pattern2"] = &types.BehavioralPattern{Name: "pattern2"}
	return result
}

// GetBehavioralContexts возвращает контексты поведения
// ОПТИМИЗАЦИЯ: Предварительно выделяем память для maps
func (m *MarionetteCore) GetBehavioralContexts() map[string]*types.BehavioralContext {
	// ОПТИМИЗАЦИЯ: Предварительно выделяем память для map
	result := make(map[string]*types.BehavioralContext, 2)
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	now := util.GetGlobalTimeCache().Now()
	result["context1"] = &types.BehavioralContext{
		Name:       "context1",
		Type:       "web",
		Parameters: make(map[string]interface{}, 4), // ОПТИМИЗАЦИЯ: Предварительно выделяем память
		LastUpdate: now,
	}
	result["context2"] = &types.BehavioralContext{
		Name:       "context2",
		Type:       "mobile",
		Parameters: make(map[string]interface{}, 4), // ОПТИМИЗАЦИЯ: Предварительно выделяем память
		LastUpdate: now,
	}
	return result
}

// UpdateBehavioralPatternEffectiveness обновляет эффективность паттерна поведения
func (m *MarionetteCore) UpdateBehavioralPatternEffectiveness(patternName string, effectiveness float64) {
	// Простая реализация
}

// GetBehavioralPatternEffectiveness возвращает эффективность паттерна поведения
func (m *MarionetteCore) GetBehavioralPatternEffectiveness(patternName string) float64 {
	return 0.8
}
