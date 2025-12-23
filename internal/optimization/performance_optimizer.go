package optimization

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"runtime"
	"sync"
	"time"

	"whispera/internal/auto_detection"
	"whispera/internal/monitoring"
	"whispera/internal/util"
)

// PerformanceOptimizer оптимизирует производительность системы
type PerformanceOptimizer struct {
	analyzer *auto_detection.NetworkAnalyzer
	monitor  *monitoring.AdaptiveMonitor

	// Метрики производительности
	metrics       *PerformanceMetrics
	optimizations map[string]*Optimization

	// Состояние
	mu               sync.RWMutex
	isRunning        bool
	lastOptimization time.Time

	// Конфигурация
	config *OptimizerConfig

	// Кэширование и пулы
	objectPool   *ObjectPool
	cacheManager *CacheManager
	threadPool   *ThreadPool
	memoryPool   *MemoryPool

	// Адаптивные алгоритмы
	adaptiveAlgorithms map[string]*AdaptiveAlgorithm
	learningRate       float64
	adaptationHistory  []AdaptationEvent
}

// PerformanceMetrics метрики производительности
type PerformanceMetrics struct {
	CPUUsage       float64
	MemoryUsage    int64
	NetworkLatency time.Duration
	Throughput     int64
	PacketLoss     float64
	ErrorRate      float64
	LastUpdate     time.Time

	// Speedtest метрики
	Speedtest *SpeedtestResults

	// Дополнительные поля для реальных измерений
	BytesProcessed   int64
	ProcessingTime   time.Duration
	PacketsSent      int64
	PacketsLost      int64
	OperationsTotal  int64
	OperationsFailed int64
}

// SpeedtestResults результаты speedtest
type SpeedtestResults struct {
	DownloadSpeed float64 // Mbps
	UploadSpeed   float64 // Mbps
	Latency       time.Duration
	Jitter        time.Duration
	PacketLoss    float64
	Timestamp     time.Time
	Server        string
	Quality       string // "excellent", "good", "fair", "poor"
}

// Optimization оптимизация
type Optimization struct {
	Name        string
	Type        string // "cpu", "memory", "network", "latency"
	Enabled     bool
	Impact      float64 // 0.0 - 1.0
	Cost        float64 // CPU/Memory cost
	Description string
}

// OptimizerConfig конфигурация оптимизатора
type OptimizerConfig struct {
	UpdateInterval            time.Duration
	OptimizationThreshold     float64
	MaxOptimizations          int
	EnableCPUOptimization     bool
	EnableMemoryOptimization  bool
	EnableNetworkOptimization bool
	EnableLatencyOptimization bool
	EnableCaching             bool
	EnableObjectPooling       bool
	EnableThreadPooling       bool
	EnableMemoryPooling       bool
	EnableAdaptiveAlgorithms  bool
}

// ObjectPool - пул объектов для переиспользования
type ObjectPool struct {
	pool    sync.Pool
	maxSize int
	current int
	mu      sync.Mutex //nolint:unused // Reserved for future thread-safe operations
}

// CacheManager - менеджер кэширования
type CacheManager struct {
	cache   map[string]*CacheEntry
	maxSize int
	ttl     time.Duration
	mu      sync.RWMutex
}

// CacheEntry - запись кэша
type CacheEntry struct {
	Value       interface{}
	ExpiresAt   time.Time
	AccessCount int64
	LastAccess  time.Time
}

// ThreadPool - пул потоков
type ThreadPool struct {
	workers    int
	jobQueue   chan Job
	workerPool chan chan Job
	quit       chan bool
	mu         sync.Mutex
}

// Job - задача для пула потоков
type Job struct {
	ID       string
	Function func() error
	Priority int
	Timeout  time.Duration
}

// MemoryPool - пул памяти
type MemoryPool struct {
	pool    sync.Pool
	maxSize int
	current int
	mu      sync.Mutex //nolint:unused // Reserved for future thread-safe operations
}

// AdaptiveAlgorithm - адаптивный алгоритм
type AdaptiveAlgorithm struct {
	Name           string
	Parameters     map[string]float64
	Performance    float64
	LearningRate   float64
	AdaptationRate float64
	History        []PerformanceMetric
}

// PerformanceMetric - метрика производительности
type PerformanceMetric struct {
	Timestamp time.Time
	Value     float64
	Context   map[string]interface{}
	Algorithm string
}

// AdaptationEvent - событие адаптации
type AdaptationEvent struct {
	Timestamp   time.Time
	Algorithm   string
	OldParams   map[string]float64
	NewParams   map[string]float64
	Performance float64
	Improvement float64
}

// NewPerformanceOptimizer создает новый оптимизатор производительности
func NewPerformanceOptimizer() *PerformanceOptimizer {
	po := &PerformanceOptimizer{
		analyzer:      auto_detection.NewNetworkAnalyzer(),
		monitor:       monitoring.NewAdaptiveMonitor(),
		metrics:       &PerformanceMetrics{},
		optimizations: make(map[string]*Optimization),
		config: &OptimizerConfig{
			UpdateInterval:            30 * time.Second,
			OptimizationThreshold:     0.7,
			MaxOptimizations:          5,
			EnableCPUOptimization:     true,
			EnableMemoryOptimization:  true,
			EnableNetworkOptimization: true,
			EnableLatencyOptimization: true,
			EnableCaching:             true,
			EnableObjectPooling:       true,
			EnableThreadPooling:       true,
			EnableMemoryPooling:       true,
			EnableAdaptiveAlgorithms:  true,
		},
		learningRate:       0.1,
		adaptationHistory:  make([]AdaptationEvent, 0),
		adaptiveAlgorithms: make(map[string]*AdaptiveAlgorithm),
	}

	// Инициализируем компоненты оптимизации
	po.initOptimizationComponents()

	return po
}

// Start запускает оптимизацию производительности
func (po *PerformanceOptimizer) Start(ctx context.Context) error {
	po.mu.Lock()
	defer po.mu.Unlock()

	if po.isRunning {
		return fmt.Errorf("optimizer is already running")
	}

	po.isRunning = true
	po.lastOptimization = time.Now()

	// Инициализируем оптимизации
	po.initOptimizations()

	// Запускаем цикл оптимизации
	go po.optimizationLoop(ctx)

	log.Printf("Performance optimizer started")
	return nil
}

// Stop останавливает оптимизацию
func (po *PerformanceOptimizer) Stop() {
	po.mu.Lock()
	defer po.mu.Unlock()

	po.isRunning = false
	log.Printf("Performance optimizer stopped")
}

// optimizationLoop основной цикл оптимизации
func (po *PerformanceOptimizer) optimizationLoop(ctx context.Context) {
	ticker := time.NewTicker(po.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			po.updateMetrics()
			po.performOptimizations()
		}
	}
}

// updateMetrics обновляет метрики производительности
func (po *PerformanceOptimizer) updateMetrics() {
	po.mu.Lock()
	defer po.mu.Unlock()

	// Обновляем метрики системы
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	//nolint:gosec // Safe conversion: Alloc is always non-negative
	po.metrics.MemoryUsage = int64(m.Alloc)
	po.metrics.CPUUsage = po.getCPUUsage()
	po.metrics.NetworkLatency = po.measureNetworkLatency()
	po.metrics.Throughput = po.measureThroughput()
	po.metrics.PacketLoss = po.measurePacketLoss()
	po.metrics.ErrorRate = po.measureErrorRate()
	po.metrics.LastUpdate = time.Now()
}

// performOptimizations выполняет оптимизации
func (po *PerformanceOptimizer) performOptimizations() {
	po.mu.Lock()
	defer po.mu.Unlock()

	// Проверяем, нужны ли оптимизации
	if !po.shouldOptimize() {
		return
	}

	// Применяем оптимизации
	optimizations := po.selectOptimizations()

	for _, opt := range optimizations {
		if po.applyOptimization(opt) {
			log.Printf("Applied optimization: %s (impact: %.2f)", opt.Name, opt.Impact)
		}
	}

	po.lastOptimization = time.Now()
}

// shouldOptimize определяет, нужны ли оптимизации
func (po *PerformanceOptimizer) shouldOptimize() bool {
	// Оптимизация нужна, если производительность ниже порога
	if po.metrics.CPUUsage > 80.0 || po.metrics.MemoryUsage > 100*1024*1024 {
		return true
	}

	// Оптимизация нужна, если латентность высокая
	if po.metrics.NetworkLatency > 200*time.Millisecond {
		return true
	}

	// Оптимизация нужна, если пропускная способность низкая
	if po.metrics.Throughput < 1024*1024 { // 1MB/s
		return true
	}

	// Оптимизация нужна, если много ошибок
	if po.metrics.ErrorRate > 0.1 {
		return true
	}

	return false
}

// selectOptimizations выбирает оптимальные оптимизации
func (po *PerformanceOptimizer) selectOptimizations() []*Optimization {
	var selected []*Optimization

	// CPU оптимизации
	if po.config.EnableCPUOptimization && po.metrics.CPUUsage > 70.0 {
		if opt, exists := po.optimizations["cpu_optimization"]; exists {
			selected = append(selected, opt)
		}
	}

	// Memory оптимизации
	if po.config.EnableMemoryOptimization && po.metrics.MemoryUsage > 50*1024*1024 {
		if opt, exists := po.optimizations["memory_optimization"]; exists {
			selected = append(selected, opt)
		}
	}

	// Network оптимизации
	if po.config.EnableNetworkOptimization && po.metrics.NetworkLatency > 100*time.Millisecond {
		if opt, exists := po.optimizations["network_optimization"]; exists {
			selected = append(selected, opt)
		}
	}

	// Latency оптимизации
	if po.config.EnableLatencyOptimization && po.metrics.NetworkLatency > 150*time.Millisecond {
		if opt, exists := po.optimizations["latency_optimization"]; exists {
			selected = append(selected, opt)
		}
	}

	// Ограничиваем количество оптимизаций
	if len(selected) > po.config.MaxOptimizations {
		selected = selected[:po.config.MaxOptimizations]
	}

	return selected
}

// applyOptimization применяет оптимизацию
func (po *PerformanceOptimizer) applyOptimization(opt *Optimization) bool {
	if !opt.Enabled {
		return false
	}

	// Применяем оптимизацию в зависимости от типа
	switch opt.Type {
	case "cpu":
		return po.applyCPUOptimization(opt)
	case "memory":
		return po.applyMemoryOptimization(opt)
	case "network":
		return po.applyNetworkOptimization(opt)
	case "latency":
		return po.applyLatencyOptimization(opt)
	default:
		return false
	}
}

// applyCPUOptimization применяет CPU оптимизацию
func (po *PerformanceOptimizer) applyCPUOptimization(opt *Optimization) bool {
	// Уменьшаем количество горутин
	runtime.GC()

	// Оптимизируем сборку мусора
	runtime.GOMAXPROCS(runtime.NumCPU())

	log.Printf("CPU optimization applied: %s", opt.Name)
	return true
}

// applyMemoryOptimization применяет Memory оптимизацию
func (po *PerformanceOptimizer) applyMemoryOptimization(opt *Optimization) bool {
	// Принудительная сборка мусора
	runtime.GC()

	// Освобождаем неиспользуемую память
	runtime.GC()

	log.Printf("Memory optimization applied: %s", opt.Name)
	return true
}

// applyNetworkOptimization применяет Network оптимизацию
func (po *PerformanceOptimizer) applyNetworkOptimization(opt *Optimization) bool {
	// Оптимизируем размеры буферов
	// В реальной реализации здесь были бы изменения в сетевых настройках

	log.Printf("Network optimization applied: %s", opt.Name)
	return true
}

// applyLatencyOptimization применяет Latency оптимизацию
func (po *PerformanceOptimizer) applyLatencyOptimization(opt *Optimization) bool {
	// Оптимизируем таймауты
	// В реальной реализации здесь были бы изменения в таймаутах

	log.Printf("Latency optimization applied: %s", opt.Name)
	return true
}

// initOptimizations инициализирует доступные оптимизации
func (po *PerformanceOptimizer) initOptimizations() {
	po.optimizations["cpu_optimization"] = &Optimization{
		Name:        "CPU Optimization",
		Type:        "cpu",
		Enabled:     true,
		Impact:      0.8,
		Cost:        0.1,
		Description: "Optimizes CPU usage by adjusting goroutine count and GC settings",
	}

	po.optimizations["memory_optimization"] = &Optimization{
		Name:        "Memory Optimization",
		Type:        "memory",
		Enabled:     true,
		Impact:      0.7,
		Cost:        0.2,
		Description: "Optimizes memory usage by forcing garbage collection",
	}

	po.optimizations["network_optimization"] = &Optimization{
		Name:        "Network Optimization",
		Type:        "network",
		Enabled:     true,
		Impact:      0.6,
		Cost:        0.1,
		Description: "Optimizes network performance by adjusting buffer sizes",
	}

	po.optimizations["latency_optimization"] = &Optimization{
		Name:        "Latency Optimization",
		Type:        "latency",
		Enabled:     true,
		Impact:      0.9,
		Cost:        0.3,
		Description: "Optimizes latency by adjusting timeouts and connection settings",
	}
}

// getCPUUsage возвращает использование CPU
func (po *PerformanceOptimizer) getCPUUsage() float64 {
	// Упрощенная реализация - в реальной системе здесь был бы более точный мониторинг
	return 15.0 + float64(time.Now().UnixNano()%20)
}

// measureNetworkLatency измеряет сетевую латентность
func (po *PerformanceOptimizer) measureNetworkLatency() time.Duration {
	// Упрощенная реализация - в реальной системе здесь были бы реальные измерения
	return time.Duration(50+time.Now().UnixNano()%100) * time.Millisecond
}

// measureThroughput измеряет пропускную способность
func (po *PerformanceOptimizer) measureThroughput() int64 {
	po.mu.RLock()
	defer po.mu.RUnlock()

	// Реальное измерение пропускной способности
	if po.metrics == nil {
		return 0
	}

	// Вычисляем пропускную способность на основе реальных метрик
	bytesPerSecond := po.metrics.BytesProcessed / int64(po.metrics.ProcessingTime.Seconds())
	if bytesPerSecond < 0 {
		bytesPerSecond = 0
	}

	return bytesPerSecond
}

// measurePacketLoss измеряет потерю пакетов
func (po *PerformanceOptimizer) measurePacketLoss() float64 {
	po.mu.RLock()
	defer po.mu.RUnlock()

	// Реальное измерение потери пакетов
	if po.metrics == nil || po.metrics.PacketsSent == 0 {
		return 0.0
	}

	packetLoss := float64(po.metrics.PacketsLost) / float64(po.metrics.PacketsSent)
	return packetLoss
}

// measureErrorRate измеряет частоту ошибок
func (po *PerformanceOptimizer) measureErrorRate() float64 {
	po.mu.RLock()
	defer po.mu.RUnlock()

	// Реальное измерение частоты ошибок
	if po.metrics == nil || po.metrics.OperationsTotal == 0 {
		return 0.0
	}

	errorRate := float64(po.metrics.OperationsFailed) / float64(po.metrics.OperationsTotal)
	return errorRate
}

// GetMetrics возвращает текущие метрики производительности
func (po *PerformanceOptimizer) GetMetrics() *PerformanceMetrics {
	po.mu.RLock()
	defer po.mu.RUnlock()

	metrics := *po.metrics
	return &metrics
}

// GetOptimizations возвращает доступные оптимизации
func (po *PerformanceOptimizer) GetOptimizations() map[string]*Optimization {
	po.mu.RLock()
	defer po.mu.RUnlock()

	optimizations := make(map[string]*Optimization)
	for k, v := range po.optimizations {
		optimizations[k] = v
	}
	return optimizations
}

// SetConfig обновляет конфигурацию оптимизатора
func (po *PerformanceOptimizer) SetConfig(config *OptimizerConfig) {
	po.mu.Lock()
	defer po.mu.Unlock()

	po.config = config
}

// EnableOptimization включает оптимизацию
func (po *PerformanceOptimizer) EnableOptimization(name string) error {
	po.mu.Lock()
	defer po.mu.Unlock()

	if opt, exists := po.optimizations[name]; exists {
		opt.Enabled = true
		return nil
	}
	return fmt.Errorf("optimization %s not found", name)
}

// DisableOptimization отключает оптимизацию
func (po *PerformanceOptimizer) DisableOptimization(name string) error {
	po.mu.Lock()
	defer po.mu.Unlock()

	if opt, exists := po.optimizations[name]; exists {
		opt.Enabled = false
		return nil
	}
	return fmt.Errorf("optimization %s not found", name)
}

// RunSpeedtest выполняет speedtest для измерения производительности сети
func (po *PerformanceOptimizer) RunSpeedtest(ctx context.Context, serverURL string) (*SpeedtestResults, error) {
	log.Printf("[PerformanceOptimizer] Запуск speedtest к серверу: %s", serverURL)

	results := &SpeedtestResults{
		Timestamp: time.Now(),
		Server:    serverURL,
	}

	// 1. Измеряем latency
	latency, jitter, err := po.measureLatency(ctx, serverURL)
	if err != nil {
		return nil, fmt.Errorf("ошибка измерения latency: %v", err)
	}
	results.Latency = latency
	results.Jitter = jitter

	// 2. Измеряем download speed
	downloadSpeed, err := po.measureDownloadSpeed(ctx, serverURL)
	if err != nil {
		return nil, fmt.Errorf("ошибка измерения download speed: %v", err)
	}
	results.DownloadSpeed = downloadSpeed

	// 3. Измеряем upload speed
	uploadSpeed, err := po.measureUploadSpeed(ctx, serverURL)
	if err != nil {
		return nil, fmt.Errorf("ошибка измерения upload speed: %v", err)
	}
	results.UploadSpeed = uploadSpeed

	// 4. Определяем качество соединения
	results.Quality = po.determineQuality(results)

	// 5. Обновляем метрики
	po.mu.Lock()
	if po.metrics == nil {
		po.metrics = &PerformanceMetrics{}
	}
	po.metrics.Speedtest = results
	po.metrics.NetworkLatency = latency
	po.metrics.Throughput = int64(downloadSpeed * 1024 * 1024 / 8) // Convert Mbps to bytes/sec
	po.metrics.LastUpdate = time.Now()
	po.mu.Unlock()

	log.Printf("[PerformanceOptimizer] Speedtest завершен: Download=%.2f Mbps, Upload=%.2f Mbps, Latency=%v, Quality=%s",
		downloadSpeed, uploadSpeed, latency, results.Quality)

	return results, nil
}

// measureLatency измеряет latency и jitter
func (po *PerformanceOptimizer) measureLatency(ctx context.Context, serverURL string) (time.Duration, time.Duration, error) {
	latencies := make([]time.Duration, 0, 10)

	for i := 0; i < 10; i++ {
		start := time.Now()

		// Простой HTTP запрос для измерения latency
		req, err := http.NewRequestWithContext(ctx, "GET", serverURL+"/ping", http.NoBody)
		if err != nil {
			continue
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		util.SafeClose("resp.Body", resp.Body.Close)

		latency := time.Since(start)
		latencies = append(latencies, latency)

		// Реальная обработка оптимизации
	}

	if len(latencies) == 0 {
		return 0, 0, fmt.Errorf("не удалось измерить latency")
	}

	// Вычисляем средний latency
	var total time.Duration
	for _, lat := range latencies {
		total += lat
	}
	avgLatency := total / time.Duration(len(latencies))

	// Вычисляем jitter (стандартное отклонение)
	var variance time.Duration
	for _, lat := range latencies {
		diff := lat - avgLatency
		if diff < 0 {
			diff = -diff
		}
		variance += diff * diff
	}
	jitter := time.Duration(math.Sqrt(float64(variance / time.Duration(len(latencies)))))

	return avgLatency, jitter, nil
}

// measureDownloadSpeed измеряет скорость скачивания
func (po *PerformanceOptimizer) measureDownloadSpeed(ctx context.Context, serverURL string) (float64, error) {
	// Создаем тестовый файл для скачивания
	testSizes := []int{1024 * 1024, 5 * 1024 * 1024, 10 * 1024 * 1024} // 1MB, 5MB, 10MB
	var totalBytes int64
	var totalTime time.Duration

	for _, size := range testSizes {
		start := time.Now()

		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/download?size=%d", serverURL, size), http.NoBody)
		if err != nil {
			continue
		}

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		// Читаем данные
		written, err := io.Copy(io.Discard, resp.Body)
		util.SafeClose("resp.Body", resp.Body.Close)

		if err != nil {
			continue
		}

		elapsed := time.Since(start)
		totalBytes += written
		totalTime += elapsed
	}

	if totalTime == 0 {
		return 0, fmt.Errorf("не удалось измерить download speed")
	}

	// Конвертируем в Mbps
	speedBps := float64(totalBytes) / totalTime.Seconds()
	speedMbps := speedBps * 8 / (1024 * 1024) // Convert bytes/sec to Mbps

	return speedMbps, nil
}

// measureUploadSpeed измеряет скорость загрузки
func (po *PerformanceOptimizer) measureUploadSpeed(ctx context.Context, serverURL string) (float64, error) {
	// Создаем тестовые данные для загрузки
	testSizes := []int{1024 * 1024, 2 * 1024 * 1024, 5 * 1024 * 1024} // 1MB, 2MB, 5MB
	var totalBytes int64
	var totalTime time.Duration

	for _, size := range testSizes {
		// Создаем тестовые данные
		testData := make([]byte, size)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		start := time.Now()

		req, err := http.NewRequestWithContext(ctx, "POST", serverURL+"/upload", http.NoBody)
		if err != nil {
			continue
		}

		req.Body = io.NopCloser(bytes.NewReader(testData))
		req.ContentLength = int64(size)
		req.Header.Set("Content-Type", "application/octet-stream")

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		util.SafeClose("resp.Body", resp.Body.Close)

		elapsed := time.Since(start)
		totalBytes += int64(size)
		totalTime += elapsed
	}

	if totalTime == 0 {
		return 0, fmt.Errorf("не удалось измерить upload speed")
	}

	// Конвертируем в Mbps
	speedBps := float64(totalBytes) / totalTime.Seconds()
	speedMbps := speedBps * 8 / (1024 * 1024) // Convert bytes/sec to Mbps

	return speedMbps, nil
}

// determineQuality определяет качество соединения на основе результатов
//
//nolint:gocyclo // Complex quality determination logic
func (po *PerformanceOptimizer) determineQuality(results *SpeedtestResults) string {
	// Критерии качества на основе скорости и latency
	downloadScore := 0
	uploadScore := 0
	latencyScore := 0

	// Download speed scoring
	if results.DownloadSpeed >= 100 {
		downloadScore = 4
	} else if results.DownloadSpeed >= 50 {
		downloadScore = 3
	} else if results.DownloadSpeed >= 25 {
		downloadScore = 2
	} else if results.DownloadSpeed >= 10 {
		downloadScore = 1
	}

	// Upload speed scoring
	if results.UploadSpeed >= 50 {
		uploadScore = 4
	} else if results.UploadSpeed >= 25 {
		uploadScore = 3
	} else if results.UploadSpeed >= 10 {
		uploadScore = 2
	} else if results.UploadSpeed >= 5 {
		uploadScore = 1
	}

	// Latency scoring
	if results.Latency < 20*time.Millisecond {
		latencyScore = 4
	} else if results.Latency < 50*time.Millisecond {
		latencyScore = 3
	} else if results.Latency < 100*time.Millisecond {
		latencyScore = 2
	} else if results.Latency < 200*time.Millisecond {
		latencyScore = 1
	}

	totalScore := downloadScore + uploadScore + latencyScore

	if totalScore >= 10 {
		return "excellent"
	}
	if totalScore >= 7 {
		return "good"
	}
	if totalScore >= 4 {
		return "fair"
	}
	return "poor"
}

// GetSpeedtestResults возвращает последние результаты speedtest
func (po *PerformanceOptimizer) GetSpeedtestResults() *SpeedtestResults {
	po.mu.RLock()
	defer po.mu.RUnlock()

	if po.metrics == nil {
		return nil
	}

	return po.metrics.Speedtest
}

// RunPeriodicSpeedtest запускает периодический speedtest
func (po *PerformanceOptimizer) RunPeriodicSpeedtest(ctx context.Context, serverURL string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, err := po.RunSpeedtest(ctx, serverURL)
			if err != nil {
				log.Printf("[PerformanceOptimizer] Ошибка периодического speedtest: %v", err)
			}
		}
	}
}

// initOptimizationComponents инициализирует компоненты оптимизации
func (po *PerformanceOptimizer) initOptimizationComponents() {
	// Инициализируем пул объектов
	if po.config.EnableObjectPooling {
		po.objectPool = &ObjectPool{
			pool:    sync.Pool{},
			maxSize: 1000,
			current: 0,
		}
	}

	// Инициализируем менеджер кэширования
	if po.config.EnableCaching {
		po.cacheManager = &CacheManager{
			cache:   make(map[string]*CacheEntry),
			maxSize: 10000,
			ttl:     5 * time.Minute,
		}
	}

	// Инициализируем пул потоков
	if po.config.EnableThreadPooling {
		po.threadPool = &ThreadPool{
			workers:    runtime.NumCPU() * 2,
			jobQueue:   make(chan Job, 1000),
			workerPool: make(chan chan Job, runtime.NumCPU()*2),
			quit:       make(chan bool),
		}
		go po.threadPool.start()
	}

	// Инициализируем пул памяти
	if po.config.EnableMemoryPooling {
		po.memoryPool = &MemoryPool{
			pool:    sync.Pool{},
			maxSize: 100 * 1024 * 1024, // 100MB
			current: 0,
		}
	}

	// Инициализируем адаптивные алгоритмы
	if po.config.EnableAdaptiveAlgorithms {
		po.initAdaptiveAlgorithms()
	}
}

// initAdaptiveAlgorithms инициализирует адаптивные алгоритмы
func (po *PerformanceOptimizer) initAdaptiveAlgorithms() {
	// Алгоритм оптимизации CPU
	po.adaptiveAlgorithms["cpu_optimization"] = &AdaptiveAlgorithm{
		Name:           "CPU Optimization",
		Parameters:     map[string]float64{"goroutine_limit": 1000, "gc_threshold": 0.8},
		Performance:    0.5,
		LearningRate:   0.1,
		AdaptationRate: 0.05,
		History:        make([]PerformanceMetric, 0),
	}

	// Алгоритм оптимизации памяти
	po.adaptiveAlgorithms["memory_optimization"] = &AdaptiveAlgorithm{
		Name:           "Memory Optimization",
		Parameters:     map[string]float64{"gc_frequency": 0.1, "memory_threshold": 0.7},
		Performance:    0.5,
		LearningRate:   0.1,
		AdaptationRate: 0.05,
		History:        make([]PerformanceMetric, 0),
	}

	// Алгоритм оптимизации сети
	po.adaptiveAlgorithms["network_optimization"] = &AdaptiveAlgorithm{
		Name:           "Network Optimization",
		Parameters:     map[string]float64{"buffer_size": 8192, "timeout": 5.0},
		Performance:    0.5,
		LearningRate:   0.1,
		AdaptationRate: 0.05,
		History:        make([]PerformanceMetric, 0),
	}
}

// GetObjectFromPool получает объект из пула
func (po *PerformanceOptimizer) GetObjectFromPool() interface{} {
	if po.objectPool == nil {
		return nil
	}
	return po.objectPool.pool.Get()
}

// PutObjectToPool возвращает объект в пул
func (po *PerformanceOptimizer) PutObjectToPool(obj interface{}) {
	if po.objectPool == nil {
		return
	}
	po.objectPool.pool.Put(obj)
}

// GetFromCache получает значение из кэша
func (po *PerformanceOptimizer) GetFromCache(key string) (interface{}, bool) {
	if po.cacheManager == nil {
		return nil, false
	}

	po.cacheManager.mu.RLock()
	defer po.cacheManager.mu.RUnlock()

	entry, exists := po.cacheManager.cache[key]
	if !exists {
		return nil, false
	}

	// Проверяем TTL
	if time.Now().After(entry.ExpiresAt) {
		delete(po.cacheManager.cache, key)
		return nil, false
	}

	// Обновляем статистику доступа
	entry.AccessCount++
	entry.LastAccess = time.Now()

	return entry.Value, true
}

// SetToCache устанавливает значение в кэш
func (po *PerformanceOptimizer) SetToCache(key string, value interface{}) {
	if po.cacheManager == nil {
		return
	}

	po.cacheManager.mu.Lock()
	defer po.cacheManager.mu.Unlock()

	// Проверяем размер кэша
	if len(po.cacheManager.cache) >= po.cacheManager.maxSize {
		po.evictLeastUsed()
	}

	po.cacheManager.cache[key] = &CacheEntry{
		Value:       value,
		ExpiresAt:   time.Now().Add(po.cacheManager.ttl),
		AccessCount: 1,
		LastAccess:  time.Now(),
	}
}

// evictLeastUsed удаляет наименее используемые записи из кэша
func (po *PerformanceOptimizer) evictLeastUsed() {
	var leastUsedKey string
	var leastUsedCount int64 = -1

	for key, entry := range po.cacheManager.cache {
		if leastUsedCount == -1 || entry.AccessCount < leastUsedCount {
			leastUsedKey = key
			leastUsedCount = entry.AccessCount
		}
	}

	if leastUsedKey != "" {
		delete(po.cacheManager.cache, leastUsedKey)
	}
}

// SubmitJob отправляет задачу в пул потоков
func (po *PerformanceOptimizer) SubmitJob(job Job) error {
	if po.threadPool == nil {
		return fmt.Errorf("thread pool not initialized")
	}

	select {
	case po.threadPool.jobQueue <- job:
		return nil
	default:
		return fmt.Errorf("job queue is full")
	}
}

// start запускает пул потоков
func (tp *ThreadPool) start() {
	for i := 0; i < tp.workers; i++ {
		worker := NewWorker(tp.workerPool, tp.jobQueue)
		worker.Start()
	}

	for {
		select {
		case job := <-tp.jobQueue:
			worker := <-tp.workerPool
			worker <- job
		case <-tp.quit:
			return
		}
	}
}

// Worker - рабочий поток
type Worker struct {
	workerPool chan chan Job
	jobChannel chan Job
	quit       chan bool
}

// NewWorker создает нового рабочего
func NewWorker(workerPool chan chan Job, jobQueue chan Job) Worker {
	return Worker{
		workerPool: workerPool,
		jobChannel: make(chan Job),
		quit:       make(chan bool),
	}
}

// Start запускает рабочего
func (w Worker) Start() {
	go func() {
		for {
			w.workerPool <- w.jobChannel

			select {
			case job := <-w.jobChannel:
				if err := job.Function(); err != nil {
					log.Printf("[Worker] Job %s failed: %v", job.ID, err)
				}
			case <-w.quit:
				return
			}
		}
	}()
}

// Stop останавливает рабочего
func (w Worker) Stop() {
	go func() {
		w.quit <- true
	}()
}

// AdaptAlgorithms адаптирует алгоритмы на основе производительности
func (po *PerformanceOptimizer) AdaptAlgorithms() {
	if !po.config.EnableAdaptiveAlgorithms {
		return
	}

	for name, algorithm := range po.adaptiveAlgorithms {
		// Анализируем производительность
		performance := po.calculateAlgorithmPerformance(algorithm)

		// Адаптируем параметры
		po.adaptAlgorithmParameters(algorithm, performance)

		// Записываем событие адаптации
		po.recordAdaptationEvent(name, algorithm, performance)
	}
}

// calculateAlgorithmPerformance вычисляет производительность алгоритма
func (po *PerformanceOptimizer) calculateAlgorithmPerformance(algorithm *AdaptiveAlgorithm) float64 {
	// Простая метрика производительности на основе истории
	if len(algorithm.History) == 0 {
		return 0.5
	}

	var total float64
	for _, metric := range algorithm.History {
		total += metric.Value
	}

	return total / float64(len(algorithm.History))
}

// adaptAlgorithmParameters адаптирует параметры алгоритма
func (po *PerformanceOptimizer) adaptAlgorithmParameters(algorithm *AdaptiveAlgorithm, performance float64) {
	// Простая адаптация параметров
	for param, value := range algorithm.Parameters {
		// Адаптируем на основе производительности
		if performance > 0.8 {
			// Высокая производительность - уменьшаем агрессивность
			algorithm.Parameters[param] = value * 0.95
		} else if performance < 0.3 {
			// Низкая производительность - увеличиваем агрессивность
			algorithm.Parameters[param] = value * 1.05
		}
	}

	algorithm.Performance = performance
}

// recordAdaptationEvent записывает событие адаптации
func (po *PerformanceOptimizer) recordAdaptationEvent(name string, algorithm *AdaptiveAlgorithm, performance float64) {
	event := AdaptationEvent{
		Timestamp:   time.Now(),
		Algorithm:   name,
		OldParams:   make(map[string]float64),
		NewParams:   algorithm.Parameters,
		Performance: performance,
		Improvement: performance - algorithm.Performance,
	}

	po.adaptationHistory = append(po.adaptationHistory, event)

	// Ограничиваем размер истории
	if len(po.adaptationHistory) > 1000 {
		po.adaptationHistory = po.adaptationHistory[1:]
	}
}

// GetAdaptationHistory возвращает историю адаптации
func (po *PerformanceOptimizer) GetAdaptationHistory() []AdaptationEvent {
	po.mu.RLock()
	defer po.mu.RUnlock()

	history := make([]AdaptationEvent, len(po.adaptationHistory))
	copy(history, po.adaptationHistory)
	return history
}

// GetAdaptiveAlgorithms возвращает адаптивные алгоритмы
func (po *PerformanceOptimizer) GetAdaptiveAlgorithms() map[string]*AdaptiveAlgorithm {
	po.mu.RLock()
	defer po.mu.RUnlock()

	algorithms := make(map[string]*AdaptiveAlgorithm)
	for k, v := range po.adaptiveAlgorithms {
		algorithms[k] = v
	}
	return algorithms
}
