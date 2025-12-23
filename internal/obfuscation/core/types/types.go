package types

import (
	"sync"
	"time"
)

// MLSystem - интерфейс для ML системы
type MLSystem interface {
	PredictTraffic(data []byte, protocol string, direction string) (*MLPredictionResponse, error)
	DetectDPI(data []byte, protocol string, direction string) (*MLPredictionResponse, error)
	DetectAnomaly(data []byte, protocol string, direction string) (*MLPredictionResponse, error)
	ProcessTraffic(data []byte, context *TrafficContext) ([]byte, error)
	HealthCheck() error
}

// AdaptiveLearning - интерфейс для адаптивного обучения
type AdaptiveLearning interface {
	LearnFromTraffic(data []byte, success bool, context *TrafficContext) error
	GetAdaptationStrategy() *AdaptationStrategy
	UpdateEffectiveness(profile string, success bool) error
	GetLearningData() *LearningData
	SetLearningData(data *LearningData)
	GetLearningStats() *LearningStats
	ResetLearning() error
}

// EffectivenessMetrics - интерфейс для метрик эффективности
type EffectivenessMetrics interface {
	RecordSuccess(profile string, method string, latency time.Duration) error
	RecordFailure(profile string, method string, reason string) error
	GetEffectiveness(profile string) *EffectivenessStats
	GetOverallEffectiveness() *EffectivenessStats
}

// DynamicProfileManager - интерфейс для управления динамическими профилями
type DynamicProfileManager interface {
	CreateProfile(name string, config *ProfileConfig) error
	UpdateProfile(name string, config *ProfileConfig) error
	DeleteProfile(name string) error
	GetProfile(name string) (*ProfileConfig, error)
	ListProfiles() []string
}

// AdaptiveProfileManager - интерфейс для адаптивного управления профилями
type AdaptiveProfileManager interface {
	SelectOptimalProfile(context *TrafficContext) (string, error)
	AdaptProfile(profileName string, feedback *AdaptationFeedback) error
	GetProfileRecommendations(context *TrafficContext) []*ProfileRecommendation
	LearnFromTraffic(data []byte, profileName string, success bool)
}

// ProfileManager - интерфейс для управления профилями (реализован в profiles/profile_manager.go)

// ProfileInitializer - интерфейс для инициализации профилей
type ProfileInitializer interface {
	InitializeDefaultProfiles() error
	InitializeProfile(name string, config map[string]interface{}) error
	ValidateProfile(profile *TrafficProfile) error
}

// RuleEngine - интерфейс для движка правил (реализован в utils/rule_engine.go)

// MetricsCollector - интерфейс для сбора метрик
type MetricsCollector interface {
	RecordPacketProcessed(size int, latency time.Duration) error
	RecordMLPrediction(success bool, latency time.Duration) error
	RecordMLFailure(reason string) error
	GetMetrics() *SystemMetrics
	GetHealthStatus() *HealthStatus
	Cleanup()
	Reset()
	RecordPacket(size int, latency time.Duration) error
}

// ProfileInitializer - интерфейс для инициализации профилей (реализован в profiles/profile_initializer.go)

// ObfuscationTechniques - интерфейс для техник обфускации (реализован в evasion/obfuscation_techniques.go)

// TrafficAnalyzer - интерфейс для анализа трафика (реализован в analysis/traffic_analyzer.go)

// DPIEvasion - интерфейс для DPI эвазии (реализован в evasion/dpi_evasion.go)

// BehavioralMimicry - интерфейс для поведенческой мимикрии (реализован в evasion/behavioral_mimicry.go)

// ProductionEvasion - интерфейс для production эвазии (реализован в evasion/production_evasion.go)

// MLEvasion - интерфейс для ML эвазии (реализован в evasion/ml_evasion.go)

// ServiceProfile - профиль сервиса (определен в production_evasion.go)

// ProfileSwitch - переключение профиля
type ProfileSwitch struct {
	FromProfile   string
	ToProfile     string
	Reason        string
	Timestamp     time.Time
	Success       bool
	Effectiveness float64
}

// ContextAnalyzer - анализатор контекста
type ContextAnalyzerCore struct {
	UserBehavior string
	ThreatLevel  int
	NetworkInfo  *NetworkInfo
}

// NetworkAnalyzer - анализатор сети
type NetworkAnalyzerCore struct {
	RTT        time.Duration
	Bandwidth  int64
	PacketLoss float64
	Jitter     time.Duration
	Congestion int
}

// MLPredictionRequest - запрос к ML системе
type MLPredictionRequest struct {
	Packets   []MLPacketData `json:"packets"`
	ModelType string         `json:"model_type"`
	Task      string         `json:"task"`
}

// MLPacketData - данные пакета для ML
type MLPacketData struct {
	Features  []float64 `json:"features"`
	Protocol  string    `json:"protocol"`
	Direction string    `json:"direction"`
	Size      int       `json:"size"`
}

// PredictionResult - результат предсказания
type PredictionResult struct {
	ClassID      int     `json:"class_id"`
	Confidence   float64 `json:"confidence"`
	Protocol     string  `json:"protocol"`
	Direction    string  `json:"direction"`
	DPIType      int     `json:"dpi_type"`
	DPIName      string  `json:"dpi_name"`
	IsAnomaly    bool    `json:"is_anomaly"`
	AnomalyScore float64 `json:"anomaly_score"`
}

// MLPredictionResponse - ответ ML системы
type MLPredictionResponse struct {
	Prediction        string             `json:"prediction"`
	Confidence        float64            `json:"confidence"`
	Method            string             `json:"method"`
	Metadata          map[string]string  `json:"metadata"`
	RecommendedAction string             `json:"recommended_action"`
	ModelUsed         string             `json:"model_used"`
	Timestamp         time.Time          `json:"timestamp"`
	Predictions       []PredictionResult `json:"predictions"`
}

// MLPrediction - предсказание ML
type MLPrediction struct {
	Type       string                 `json:"type"`
	Confidence float64                `json:"confidence"`
	Method     string                 `json:"method"`
	Parameters map[string]interface{} `json:"parameters"`
}

// NetworkInfo - информация о сети
type NetworkInfo struct {
	RTT        time.Duration `json:"rtt"`
	Bandwidth  int64         `json:"bandwidth"`
	PacketLoss float64       `json:"packet_loss"`
	Jitter     time.Duration `json:"jitter"`
	Congestion int           `json:"congestion"`
}

// UserBehavior - поведение пользователя
type UserBehavior struct {
	SessionDuration time.Duration `json:"session_duration"`
	DataVolume      int64         `json:"data_volume"`
	RequestPattern  string        `json:"request_pattern"`
	TimeOfDay       int           `json:"time_of_day"`
	DayOfWeek       int           `json:"day_of_week"`
}

// AdaptationStrategy - стратегия адаптации
type AdaptationStrategy struct {
	ProfileChanges    []*ProfileChange    `json:"profile_changes"`
	TimingAdjustments []*TimingAdjustment `json:"timing_adjustments"`
	Priority          int                 `json:"priority"`
	Confidence        float64             `json:"confidence"`
}

// ProfileChange - изменение профиля
type ProfileChange struct {
	ProfileName string                 `json:"profile_name"`
	Parameters  map[string]interface{} `json:"parameters"`
	Reason      string                 `json:"reason"`
}

// TimingAdjustment - корректировка таймингов
type TimingAdjustment struct {
	Parameter string        `json:"parameter"`
	Value     time.Duration `json:"value"`
	Reason    string        `json:"reason"`
}

// HealthStatus represents system health status
type HealthStatus struct {
	Status     string
	LastCheck  time.Time
	Components map[string]bool
}

// ProfileEffectiveness represents profile effectiveness metrics
type ProfileEffectiveness struct {
	ProfileName string
	SuccessRate float64
	Latency     time.Duration
	LastUpdate  time.Time
}

// AdaptiveProfile represents an adaptive profile
type AdaptiveProfile struct {
	Name            string
	Type            string
	Parameters      map[string]interface{}
	Effectiveness   float64
	LastUpdate      time.Time
	UsageCount      int64
	LastUsed        time.Time
	SuccessRate     float64
	AverageLatency  time.Duration
	AdaptationCount int64
	LastAdaptation  time.Time
}

// TrafficContext - контекст трафика
type TrafficContext struct {
	Direction    string        `json:"direction"`
	Protocol     string        `json:"protocol"`
	Size         int           `json:"size"`
	Timestamp    time.Time     `json:"timestamp"`
	NetworkInfo  *NetworkInfo  `json:"network_info"`
	UserBehavior *UserBehavior `json:"user_behavior"`
	ThreatLevel  int           `json:"threat_level"`
}

// SizeDistribution - распределение размеров
type SizeDistribution struct {
	Bins    []int
	Weights []float64
	Mean    float64
	StdDev  float64
	Min     int
	Max     int
}

// IntervalDistribution - распределение интервалов
type IntervalDistribution struct {
	Bins    []time.Duration
	Weights []float64
	Mean    time.Duration
	StdDev  time.Duration
	Min     time.Duration
	Max     time.Duration
	Pattern string
}

// BurstPatterns - паттерны burst'ов
type BurstPatterns struct {
	Probability float64
	MinSize     int
	MaxSize     int
	MinGap      time.Duration
	MaxGap      time.Duration
}

// UnifiedMLSystemInterface defines the interface for unified ML operations
// Moved here to break circular dependency between obfuscation and fte packages
type UnifiedMLSystemInterface interface {
	ProcessTraffic(data []byte, context *UnifiedTrafficContext) ([]byte, error)
	GetStats() *MLStats
	HealthCheck() error
	LoadModels() error
}

// MLStats represents ML system statistics
type MLStats struct {
	ProcessedPackets int64     `json:"processed_packets"`
	Accuracy         float64   `json:"accuracy"`
	DPIEvasionRate   float64   `json:"dpi_evasion_rate"`
	ModelStatus      string    `json:"model_status"`
	LastUpdate       time.Time `json:"last_update"`
}

// UnifiedTrafficContext - унифицированный контекст трафика
type UnifiedTrafficContext struct {
	Context   *TrafficContext
	Profile   *TrafficProfile
	State     *TrafficState
	Protocol  string
	Direction string
	Size      int
	Timestamp time.Time
	IsTLS     bool   // Используется ли TLS/DTLS
	TLSMode   string // "tls", "dtls", "noise_ik", ""
}

// ObfuscationTechniques - техники обфускации
type ObfuscationTechniques struct {
	Config *TechniquesConfig
}

// TechniquesConfig - конфигурация техник
type TechniquesConfig struct {
	Enabled bool
}

// DPIEvasion - DPI эвазия
type DPIEvasion struct {
	Enabled bool
}

// BehavioralMimicry - поведенческая мимикрия
type BehavioralMimicry struct {
	Enabled bool
}

// BehavioralPattern - поведенческий паттерн
type BehavioralPattern struct {
	Name string
}

// MetricsCollectorImpl - реализация сборщика метрик
type MetricsCollectorImpl struct {
	Enabled bool
}

// ServiceStats represents service statistics
type ServiceStats struct {
	Count       int
	TotalSize   int
	AverageSize float64
	MinSize     int
	MaxSize     int
}

// BehavioralContext represents behavioral context
type BehavioralContext struct {
	Name       string
	Type       string
	Parameters map[string]interface{}
	LastUpdate time.Time
}

// MLModel represents an ML model
type MLModel struct {
	Name       string
	Type       string
	Parameters map[string]interface{}
	Accuracy   float64
	LastUpdate time.Time
}

// TrafficRecord - запись трафика
type TrafficRecord struct {
	Timestamp   time.Time
	Size        int
	Direction   string
	Protocol    string
	Service     string
	Features    []float64
	Duration    time.Duration
	SourceIP    string
	DestIP      string
	SourcePort  int
	DestPort    int
	DeviceType  string
	NetworkType string
	Location    string
}

// TrafficAnalysis - анализ трафика
type TrafficAnalysis struct {
	TotalPackets     int
	TotalBytes       int64
	AverageSize      float64
	SizeStdDev       float64
	MinSize          int
	MaxSize          int
	AverageInterval  time.Duration
	IntervalStdDev   time.Duration
	BurstFrequency   float64
	SessionDuration  time.Duration
	Protocols        map[string]int
	Services         map[string]int
	SizeDistribution map[string]int
	TimingPatterns   map[string]time.Duration
	TotalSize        int64
	ServiceStats     map[string]int
	TimePatterns     map[string]time.Duration
	DeviceStats      map[string]int
	NetworkStats     map[string]time.Duration
	LocationStats    map[string]int
	PacketSizes      []int
	Intervals        []time.Duration
	Features         [][]float64
	TotalRecords     int
	StdDev           float64
}

// LearningPattern - паттерн обучения
type LearningPattern struct {
	Name        string
	Frequency   float64
	SuccessRate float64
	UsageCount  int64
	LastUsed    time.Time
	Parameters  map[string]interface{}
}

// UtilityFunctions - утилиты
type UtilityFunctions struct {
	// Поля будут добавлены по мере необходимости
}

// NewUtilityFunctions создает новый экземпляр утилит
func NewUtilityFunctions() *UtilityFunctions {
	return &UtilityFunctions{}
}

// TrafficProfile - профиль трафика
type TrafficProfile struct {
	Name                 string
	Type                 string
	PacketSizes          SizeDistribution
	Intervals            IntervalDistribution
	BurstPatterns        BurstProfile
	Coverage             CoverageProfile
	Adaptation           AdaptationProfile
	CreatedAt            time.Time
	LastUsed             time.Time
	UsageCount           int
	SizeWeights          []float64
	SizeDistribution     *SizeDistribution
	IntervalDistribution *IntervalDistribution
	BurstProfile         *BurstProfile
	CoverageProfile      *CoverageProfile
	AdaptationProfile    *AdaptationProfile
	ServiceType          string
	Timings              []time.Duration
	TimingWeights        []float64
	BehavioralData       map[string]interface{}
	MLFeatures           []float64
	DeviceID             string
	Effectiveness        float64
}

// BurstProfile - профиль всплесков
type BurstProfile struct {
	Probability float64
	MinBurst    int
	MaxBurst    int
	BurstGap    time.Duration
	MinSize     int
	MaxSize     int
	MinInterval time.Duration
	MaxInterval time.Duration
	Frequency   float64
	Enabled     bool
}

// CoverageProfile - профиль покрытия
type CoverageProfile struct {
	Enabled        bool
	Probability    float64
	MinSize        int
	MaxSize        int
	Interval       time.Duration
	MinCoverage    float64
	MaxCoverage    float64
	TargetCoverage float64
	Coverage       float64
}

// AdaptationProfile - профиль адаптации
type AdaptationProfile struct {
	Enabled             bool
	Sensitivity         float64
	LearningRate        float64
	AdaptationThreshold float64
}

// TrafficState - состояние трафика
type TrafficState struct {
	PacketCount         int
	ByteCount           int64
	Direction           string
	Protocol            string
	LastPacket          time.Time
	Intervals           []time.Duration
	PacketSizes         []int
	RecentPacketSizes   []int
	RecentDPIDetections []bool
	DetectedDPI         bool
	ThreatLevel         int
	MaxHistorySize      int
	LastCleanup         time.Time
	CleanupInterval     time.Duration

	// Additional fields for enhanced traffic tracking
	PacketHistory       []PacketInfo
	TotalPackets        int64
	TotalBytes          int64
	OutboundPackets     int64
	OutboundBytes       int64
	InboundPackets      int64
	InboundBytes        int64
	SessionStart        time.Time
	SessionDuration     time.Duration
	AveragePacketSize   float64
	AverageInterval     time.Duration
	BurstCount          int
	IdleCount           int
	LastBurstTime       time.Time
	LastIdleTime        time.Time
	CurrentProfile      string
	ProfileSwitches     []ProfileSwitch
	MLPredictions       int64
	MLFailures          int64
	EvasionSuccesses    int64
	EvasionFailures     int64
	LastMLPrediction    time.Time
	LastEvasionAttempt  time.Time
	CircuitBreakerState string
	FallbackMode        bool
	AdaptiveLearning    bool
	PerformanceMetrics  *PerformanceMetrics
}

// PacketInfo - информация о пакете
type PacketInfo struct {
	Size      int
	Direction string
	Timestamp time.Time
	Protocol  string
	Processed bool
	Evasion   bool
	MLUsed    bool
}

// PerformanceMetrics - метрики производительности
type PerformanceMetrics struct {
	DPIEvasionSuccess float64
	FalsePositiveRate float64
	Latency           time.Duration
	Throughput        float64
	MemoryUsage       int64
	CPUUsage          float64
	LastUpdate        time.Time
}

// ObfuscationRule - правило обфускации
type ObfuscationRule struct {
	Name       string
	Condition  Condition
	Action     Action
	Parameters map[string]interface{}
	Priority   int
	Enabled    bool
}

// Condition - условие для правила обфускации
type Condition struct {
	Type      string
	Field     string
	Operator  string
	Value     interface{}
	LogicalOp string // "AND", "OR", "NOT"
	Children  []Condition
}

// Action - действие для правила обфускации
type Action struct {
	Type       string
	Method     string
	Parameters map[string]interface{}
	Priority   int
	Enabled    bool
}

// EffectivenessStats - статистика эффективности
type EffectivenessStats struct {
	SuccessRate    float64       `json:"success_rate"`
	AverageLatency time.Duration `json:"average_latency"`
	TotalAttempts  int64         `json:"total_attempts"`
	LastUpdated    time.Time     `json:"last_updated"`
	// Additional fields for detailed metrics
	TotalBytes     int64 `json:"total_bytes"`
	TotalPackets   int64 `json:"total_packets"`
	SuccessCount   int64 `json:"success_count"`
	FailureCount   int64 `json:"failure_count"`
}

// ProfileConfig - конфигурация профиля
type ProfileConfig struct {
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
	Enabled    bool                   `json:"enabled"`
	Priority   int                    `json:"priority"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// AdaptationFeedback - обратная связь для адаптации
type AdaptationFeedback struct {
	Success     bool            `json:"success"`
	Latency     time.Duration   `json:"latency"`
	ErrorReason string          `json:"error_reason"`
	Context     *TrafficContext `json:"context"`
	Timestamp   time.Time       `json:"timestamp"`
}

// ProfileRecommendation - рекомендация профиля
type ProfileRecommendation struct {
	ProfileName string  `json:"profile_name"`
	Confidence  float64 `json:"confidence"`
	Reason      string  `json:"reason"`
	Priority    int     `json:"priority"`
}

// Note: TrafficShaping, CoverTraffic, and RealTrafficAnalysis types are defined above

// FTE - Format Transforming Encryption
type FTE struct {
	Enabled bool
	Mode    string
}

// TrafficProfiler - профилировщик трафика
type TrafficProfiler struct {
	profiles map[string]*TrafficProfile //nolint:unused // Reserved for future use
	active   string                     //nolint:unused // Reserved for future use
	mu       sync.RWMutex               //nolint:unused // Reserved for future use
}

// ProtocolStateMachine - машина состояний протокола
type ProtocolStateMachine struct {
	states   map[string]*ProtocolState //nolint:unused // Reserved for future use
	current  string                    //nolint:unused // Reserved for future use
	protocol string                    //nolint:unused // Reserved for future use
	mu       sync.RWMutex              //nolint:unused // Reserved for future use
}

// ProtocolState - состояние протокола
type ProtocolState struct {
	Name        string
	Transitions map[string]string
	Actions     []string
}

// NewProfileManager - конструктор для ProfileManager
func NewProfileManager() interface{} {
	return nil
}

// NewRuleEngine - конструктор для RuleEngine
func NewRuleEngine() interface{} {
	return nil
}

// NewMetricsCollector - конструктор для MetricsCollector
func NewMetricsCollector() interface{} {
	return nil
}

// NewTrafficAnalyzer - конструктор для TrafficAnalyzer
func NewTrafficAnalyzer() interface{} {
	return nil
}

// NewProductionEvasion - конструктор для ProductionEvasion
func NewProductionEvasion() interface{} {
	return nil
}

// NewMLSystem - конструктор для MLSystem
func NewMLSystem() interface{} {
	return nil
}

// NewEffectivenessMetrics - конструктор для EffectivenessMetrics
func NewEffectivenessMetrics() interface{} {
	return nil
}

// NewDynamicProfileManager - конструктор для DynamicProfileManager
func NewDynamicProfileManager() interface{} {
	return nil
}

// NewTrafficShaping - конструктор для TrafficShaping
func NewTrafficShaping() interface{} {
	return nil
}

// NewMLEvasion - конструктор для MLEvasion
func NewMLEvasion() interface{} {
	return nil
}

// NewUnifiedMLSystem - конструктор для UnifiedMLSystem
func NewUnifiedMLSystem() interface{} {
	return nil
}

// NewCoverTraffic - конструктор для CoverTraffic
func NewCoverTraffic() interface{} {
	return nil
}

// NewRealTrafficAnalysis - конструктор для RealTrafficAnalysis
func NewRealTrafficAnalysis() interface{} {
	return nil
}

// MLEvasion - ML эвазия
type MLEvasion struct {
	Enabled bool
}

// SystemMetrics - системные метрики
type SystemMetrics struct {
	PacketsProcessed    int64
	MLPredictions       int64
	MLFailures          int64
	AverageLatency      time.Duration
	MemoryUsage         int64
	LastCleanup         time.Time
	CircuitBreakerTrips int64
}

// TrafficAnalyzer - анализатор трафика
type TrafficAnalyzer struct {
	Enabled bool
}

// RuleEngine - движок правил
type RuleEngine struct {
	Enabled bool
}

// LearningStats - статистика обучения
type LearningStats struct {
	TotalSamples    int64
	SuccessCount    int64
	FailureCount    int64
	AverageAccuracy float64
	LastUpdate      time.Time
	LearningRate    float64
	AdaptationCount int64
}

// LearningData - данные обучения
type LearningData struct {
	Patterns      map[string]*LearningPattern
	Effectiveness map[string]float64
	LastUpdate    time.Time
}

// CoverTraffic - прикрывающий трафик
type CoverTraffic struct {
	Enabled bool
}

// RealTrafficAnalysis - анализ реального трафика
type RealTrafficAnalysis struct {
	Enabled bool
}

// UnifiedMLSystem - заглушка удалена, используйте obfuscation.NewUnifiedMLSystem()
// Реальная реализация находится в internal/obfuscation/marionette.go

// TrafficRecordFTE - запись трафика для FTE
type TrafficRecordFTE struct {
	Data         []byte
	Protocol     string
	Direction    string
	Size         int
	Timestamp    time.Time
	TrafficClass string
	DPIType      string
	IsAnomaly    bool
	Features     []float64
}
