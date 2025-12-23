package monitoring

import (
	"fmt"
	"runtime"
	"sync"
	"time"
	"whispera/internal/obfuscation/core/types"
)

// EffectivenessMetricsImpl - реализация метрик эффективности
type EffectivenessMetricsImpl struct {
	metrics    map[string]*types.EffectivenessStats
	overall    *types.EffectivenessStats
	mutex      sync.RWMutex
	windowSize time.Duration

	// Enhanced analytics components
	detailedAnalytics  *DetailedAnalytics
	performanceTracker *PerformanceTracker
	threatAnalyzer     *ThreatAnalyzer
	trendAnalyzer      *TrendAnalyzer
	anomalyDetector    *AnomalyDetector
	reportGenerator    *ReportGenerator
}

// DetailedAnalytics - детальная аналитика эффективности
type DetailedAnalytics struct {
	RealTimeMetrics     *RealTimeMetrics
	HistoricalData      *HistoricalData
	ComparativeAnalysis *ComparativeAnalysis
	PredictiveAnalysis  *PredictiveAnalysis
	RiskAssessment      *RiskAssessment
	Recommendations     *Recommendations
}

// RealTimeMetrics - метрики в реальном времени
type RealTimeMetrics struct {
	CurrentThroughput  float64
	CurrentLatency     time.Duration
	CurrentSuccessRate float64
	CurrentErrorRate   float64
	ActiveConnections  int
	QueueSize          int
	CPUUsage           float64
	MemoryUsage        float64
	NetworkUtilization float64
	LastUpdate         time.Time
}

// HistoricalData - исторические данные
type HistoricalData struct {
	DataPoints      []DataPoint
	TimeRange       time.Duration
	Granularity     time.Duration
	AggregatedStats *AggregatedStats
	Trends          []Trend
	Patterns        []Pattern
}

// DataPoint - точка данных
type DataPoint struct {
	Timestamp    time.Time
	Value        float64
	Metric       string
	Profile      string
	Context      map[string]interface{}
	AnomalyScore float64
	Quality      string
}

// AggregatedStats - агрегированная статистика
type AggregatedStats struct {
	Mean        float64
	Median      float64
	Mode        float64
	StdDev      float64
	Variance    float64
	Min         float64
	Max         float64
	Percentiles map[int]float64
	Skewness    float64
	Kurtosis    float64
}

// Trend - тренд
type Trend struct {
	Type        string
	Direction   string
	Strength    float64
	Confidence  float64
	StartTime   time.Time
	EndTime     time.Time
	Description string
}

// Pattern - паттерн
type Pattern struct {
	Name        string
	Type        string
	Frequency   float64
	Confidence  float64
	Occurrences []time.Time
	Description string
}

// ComparativeAnalysis - сравнительный анализ
type ComparativeAnalysis struct {
	BaselineComparison    *BaselineComparison
	ProfileComparison     *ProfileComparison
	TimeComparison        *TimeComparison
	PerformanceComparison *PerformanceComparison
}

// BaselineComparison - сравнение с базовой линией
type BaselineComparison struct {
	BaselineValue    float64
	CurrentValue     float64
	Deviation        float64
	DeviationPercent float64
	Significance     string
	Impact           string
}

// ProfileComparison - сравнение профилей
type ProfileComparison struct {
	Profiles         []string
	ComparisonMatrix map[string]map[string]float64
	BestProfile      string
	WorstProfile     string
	Recommendations  []string
}

// TimeComparison - временное сравнение
type TimeComparison struct {
	TimeRanges       []TimeRange
	ComparisonMatrix map[string]map[string]float64
	BestTime         time.Time
	WorstTime        time.Time
	Seasonality      *Seasonality
}

// TimeRange - временной диапазон
type TimeRange struct {
	Start   time.Time
	End     time.Time
	Label   string
	Metrics map[string]float64
}

// Seasonality - сезонность
type Seasonality struct {
	DailyPattern   map[int]float64
	WeeklyPattern  map[int]float64
	MonthlyPattern map[int]float64
	YearlyPattern  map[int]float64
	HolidayEffects map[string]float64
}

// PerformanceComparison - сравнение производительности
type PerformanceComparison struct {
	Metrics        []string
	ComparisonData map[string]map[string]float64
	Rankings       map[string]int
	Improvements   map[string]float64
	Degradations   map[string]float64
}

// PredictiveAnalysis - предиктивный анализ
type PredictiveAnalysis struct {
	Forecasts        []Forecast
	Predictions      []Prediction
	ConfidenceLevels map[string]float64
	RiskFactors      []RiskFactor
	Opportunities    []Opportunity
}

// Forecast - прогноз
type Forecast struct {
	Metric      string
	TimeHorizon time.Duration
	Values      []float64
	Confidence  float64
	Method      string
	Accuracy    float64
}

// Prediction - предсказание
type Prediction struct {
	Event       string
	Probability float64
	TimeFrame   time.Duration
	Impact      string
	Confidence  float64
	Factors     []string
}

// RiskFactor - фактор риска
type RiskFactor struct {
	Name        string
	Level       string
	Probability float64
	Impact      string
	Mitigation  string
}

// Opportunity - возможность
type Opportunity struct {
	Name        string
	Type        string
	Potential   float64
	Effort      string
	Timeframe   time.Duration
	Description string
}

// RiskAssessment - оценка рисков
type RiskAssessment struct {
	OverallRisk    string
	RiskFactors    []RiskFactor
	MitigationPlan *MitigationPlan
	RiskTrends     []RiskTrend
	Alerts         []Alert
}

// MitigationPlan - план снижения рисков
type MitigationPlan struct {
	Actions        []Action
	Timeline       time.Duration
	Resources      []string
	SuccessMetrics []string
	Owner          string
}

// Action - действие
type Action struct {
	Name        string
	Description string
	Priority    string
	Effort      string
	Timeline    time.Duration
	Status      string
}

// RiskTrend - тренд риска
type RiskTrend struct {
	RiskType   string
	Direction  string
	Rate       float64
	Confidence float64
	Timeframe  time.Duration
}

// Alert - предупреждение
type Alert struct {
	Type      string
	Severity  string
	Message   string
	Timestamp time.Time
	Resolved  bool
	Actions   []string
}

// Recommendations - рекомендации
type Recommendations struct {
	Immediate    []Recommendation
	ShortTerm    []Recommendation
	LongTerm     []Recommendation
	Critical     []Recommendation
	Optimization []Recommendation
}

// Recommendation - рекомендация
type Recommendation struct {
	Title       string
	Description string
	Priority    string
	Impact      string
	Effort      string
	Timeline    time.Duration
	Status      string
}

// PerformanceTracker - трекер производительности
type PerformanceTracker struct {
	Metrics     map[string]*PerformanceMetric
	Alerts      []Alert
	Thresholds  map[string]float64
	Trends      []Trend
	Predictions []Prediction
}

// PerformanceMetric - метрика производительности
type PerformanceMetric struct {
	Name       string
	Value      float64
	Unit       string
	Trend      string
	Threshold  float64
	Status     string
	LastUpdate time.Time
	History    []DataPoint
}

// ThreatAnalyzer - анализатор угроз
type ThreatAnalyzer struct {
	Threats      []Threat
	ThreatLevels map[string]string
	Mitigations  map[string][]string
	Trends       []ThreatTrend
	Alerts       []Alert
}

// Threat - угроза
type Threat struct {
	Type        string
	Level       string
	Probability float64
	Impact      string
	Source      string
	Target      string
	Description string
	Mitigation  []string
}

// ThreatTrend - тренд угроз
type ThreatTrend struct {
	ThreatType string
	Direction  string
	Rate       float64
	Confidence float64
	Timeframe  time.Duration
}

// TrendAnalyzer - анализатор трендов
type TrendAnalyzer struct {
	Trends      []Trend
	Patterns    []Pattern
	Seasonality *Seasonality
	Forecasts   []Forecast
	Anomalies   []Anomaly
}

// Anomaly - аномалия
type Anomaly struct {
	Type        string
	Severity    string
	Value       float64
	Expected    float64
	Deviation   float64
	Timestamp   time.Time
	Context     map[string]interface{}
	Description string
}

// AnomalyDetector - детектор аномалий
type AnomalyDetector struct {
	Anomalies      []Anomaly
	Thresholds     map[string]float64
	Methods        []string
	Sensitivity    float64
	FalsePositives int
	FalseNegatives int
}

// ReportGenerator - генератор отчетов
type ReportGenerator struct {
	Templates  map[string]string
	Formats    []string
	Schedule   time.Duration
	Recipients []string
	LastReport time.Time
}

// NewEffectivenessMetrics создает новую систему метрик эффективности
func NewEffectivenessMetrics() types.EffectivenessMetrics {
	em := &EffectivenessMetricsImpl{
		metrics:    make(map[string]*types.EffectivenessStats),
		overall:    &types.EffectivenessStats{},
		windowSize: 5 * time.Minute,
	}

	// Initialize enhanced analytics components
	em.initializeDetailedAnalytics()
	em.initializePerformanceTracker()
	em.initializeThreatAnalyzer()
	em.initializeTrendAnalyzer()
	em.initializeAnomalyDetector()
	em.initializeReportGenerator()

	return em
}

// RecordSuccess записывает успешное выполнение
func (em *EffectivenessMetricsImpl) RecordSuccess(profile, method string, latency time.Duration) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	// Обновляем метрики профиля
	if em.metrics[profile] == nil {
		em.metrics[profile] = &types.EffectivenessStats{
			LastUpdated: time.Now(),
		}
	}

	profileStats := em.metrics[profile]
	profileStats.TotalAttempts++
	profileStats.SuccessRate = float64(profileStats.TotalAttempts) / float64(profileStats.TotalAttempts)

	// Обновляем среднюю задержку
	if profileStats.AverageLatency == 0 {
		profileStats.AverageLatency = latency
	} else {
		// Экспоненциальное сглаживание
		alpha := 0.1
		profileStats.AverageLatency = time.Duration(
			float64(profileStats.AverageLatency)*(1-alpha) + float64(latency)*alpha,
		)
	}

	profileStats.LastUpdated = time.Now()

	// Обновляем общие метрики
	em.updateOverallMetrics()

	return nil
}

// RecordFailure записывает неудачное выполнение
func (em *EffectivenessMetricsImpl) RecordFailure(profile, method, reason string) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	// Обновляем метрики профиля
	if em.metrics[profile] == nil {
		em.metrics[profile] = &types.EffectivenessStats{
			LastUpdated: time.Now(),
		}
	}

	profileStats := em.metrics[profile]
	profileStats.TotalAttempts++

	// Пересчитываем успешность
	successCount := int64(float64(profileStats.TotalAttempts) * profileStats.SuccessRate)
	profileStats.SuccessRate = float64(successCount) / float64(profileStats.TotalAttempts)

	profileStats.LastUpdated = time.Now()

	// Обновляем общие метрики
	em.updateOverallMetrics()

	return nil
}

// GetEffectiveness возвращает эффективность профиля
func (em *EffectivenessMetricsImpl) GetEffectiveness(profile string) *types.EffectivenessStats {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	if stats, exists := em.metrics[profile]; exists {
		// Возвращаем копию для безопасности
		return &types.EffectivenessStats{
			SuccessRate:    stats.SuccessRate,
			AverageLatency: stats.AverageLatency,
			TotalAttempts:  stats.TotalAttempts,
			LastUpdated:    stats.LastUpdated,
		}
	}

	return &types.EffectivenessStats{}
}

// GetOverallEffectiveness возвращает общую эффективность
func (em *EffectivenessMetricsImpl) GetOverallEffectiveness() *types.EffectivenessStats {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	// Возвращаем копию для безопасности
	return &types.EffectivenessStats{
		SuccessRate:    em.overall.SuccessRate,
		AverageLatency: em.overall.AverageLatency,
		TotalAttempts:  em.overall.TotalAttempts,
		LastUpdated:    em.overall.LastUpdated,
	}
}

// updateOverallMetrics обновляет общие метрики
func (em *EffectivenessMetricsImpl) updateOverallMetrics() {
	totalAttempts := int64(0)
	totalSuccesses := int64(0)
	totalLatency := time.Duration(0)
	profileCount := 0

	for _, stats := range em.metrics {
		totalAttempts += stats.TotalAttempts
		totalSuccesses += int64(float64(stats.TotalAttempts) * stats.SuccessRate)
		totalLatency += stats.AverageLatency
		profileCount++
	}

	if totalAttempts > 0 {
		em.overall.SuccessRate = float64(totalSuccesses) / float64(totalAttempts)
	}

	if profileCount > 0 {
		em.overall.AverageLatency = totalLatency / time.Duration(profileCount)
	}

	em.overall.TotalAttempts = totalAttempts
	em.overall.LastUpdated = time.Now()
}

// initializeDetailedAnalytics инициализирует детальную аналитику
func (em *EffectivenessMetricsImpl) initializeDetailedAnalytics() {
	em.detailedAnalytics = &DetailedAnalytics{
		RealTimeMetrics: &RealTimeMetrics{
			CurrentThroughput:  0.0,
			CurrentLatency:     0,
			CurrentSuccessRate: 0.0,
			CurrentErrorRate:   0.0,
			ActiveConnections:  0,
			QueueSize:          0,
			CPUUsage:           0.0,
			MemoryUsage:        0.0,
			NetworkUtilization: 0.0,
			LastUpdate:         time.Now(),
		},
		HistoricalData: &HistoricalData{
			DataPoints:      make([]DataPoint, 0),
			TimeRange:       24 * time.Hour,
			Granularity:     5 * time.Minute,
			AggregatedStats: &AggregatedStats{},
			Trends:          make([]Trend, 0),
			Patterns:        make([]Pattern, 0),
		},
		ComparativeAnalysis: &ComparativeAnalysis{},
		PredictiveAnalysis:  &PredictiveAnalysis{},
		RiskAssessment:      &RiskAssessment{},
		Recommendations:     &Recommendations{},
	}
}

// initializePerformanceTracker инициализирует трекер производительности
func (em *EffectivenessMetricsImpl) initializePerformanceTracker() {
	em.performanceTracker = &PerformanceTracker{
		Metrics:     make(map[string]*PerformanceMetric),
		Alerts:      make([]Alert, 0),
		Thresholds:  make(map[string]float64),
		Trends:      make([]Trend, 0),
		Predictions: make([]Prediction, 0),
	}
}

// initializeThreatAnalyzer инициализирует анализатор угроз
func (em *EffectivenessMetricsImpl) initializeThreatAnalyzer() {
	em.threatAnalyzer = &ThreatAnalyzer{
		Threats:      make([]Threat, 0),
		ThreatLevels: make(map[string]string),
		Mitigations:  make(map[string][]string),
		Trends:       make([]ThreatTrend, 0),
		Alerts:       make([]Alert, 0),
	}
}

// initializeTrendAnalyzer инициализирует анализатор трендов
func (em *EffectivenessMetricsImpl) initializeTrendAnalyzer() {
	em.trendAnalyzer = &TrendAnalyzer{
		Trends:      make([]Trend, 0),
		Patterns:    make([]Pattern, 0),
		Seasonality: &Seasonality{},
		Forecasts:   make([]Forecast, 0),
		Anomalies:   make([]Anomaly, 0),
	}
}

// initializeAnomalyDetector инициализирует детектор аномалий
func (em *EffectivenessMetricsImpl) initializeAnomalyDetector() {
	em.anomalyDetector = &AnomalyDetector{
		Anomalies:      make([]Anomaly, 0),
		Thresholds:     make(map[string]float64),
		Methods:        []string{"statistical", "ml", "rule_based"},
		Sensitivity:    0.8,
		FalsePositives: 0,
		FalseNegatives: 0,
	}
}

// initializeReportGenerator инициализирует генератор отчетов
func (em *EffectivenessMetricsImpl) initializeReportGenerator() {
	em.reportGenerator = &ReportGenerator{
		Templates:  make(map[string]string),
		Formats:    []string{"json", "csv", "html", "pdf"},
		Schedule:   24 * time.Hour,
		Recipients: make([]string, 0),
		LastReport: time.Now(),
	}
}

// GetDetailedAnalytics возвращает детальную аналитику
func (em *EffectivenessMetricsImpl) GetDetailedAnalytics() *DetailedAnalytics {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.detailedAnalytics
}

// GetRealTimeMetrics возвращает метрики в реальном времени
func (em *EffectivenessMetricsImpl) GetRealTimeMetrics() *RealTimeMetrics {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.detailedAnalytics.RealTimeMetrics
}

// GetHistoricalData возвращает исторические данные
func (em *EffectivenessMetricsImpl) GetHistoricalData() *HistoricalData {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.detailedAnalytics.HistoricalData
}

// GetComparativeAnalysis возвращает сравнительный анализ
func (em *EffectivenessMetricsImpl) GetComparativeAnalysis() *ComparativeAnalysis {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.detailedAnalytics.ComparativeAnalysis
}

// GetPredictiveAnalysis возвращает предиктивный анализ
func (em *EffectivenessMetricsImpl) GetPredictiveAnalysis() *PredictiveAnalysis {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.detailedAnalytics.PredictiveAnalysis
}

// GetRiskAssessment возвращает оценку рисков
func (em *EffectivenessMetricsImpl) GetRiskAssessment() *RiskAssessment {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.detailedAnalytics.RiskAssessment
}

// GetRecommendations возвращает рекомендации
func (em *EffectivenessMetricsImpl) GetRecommendations() *Recommendations {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.detailedAnalytics.Recommendations
}

// GetPerformanceTracker возвращает трекер производительности
func (em *EffectivenessMetricsImpl) GetPerformanceTracker() *PerformanceTracker {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.performanceTracker
}

// GetThreatAnalyzer возвращает анализатор угроз
func (em *EffectivenessMetricsImpl) GetThreatAnalyzer() *ThreatAnalyzer {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.threatAnalyzer
}

// GetTrendAnalyzer возвращает анализатор трендов
func (em *EffectivenessMetricsImpl) GetTrendAnalyzer() *TrendAnalyzer {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.trendAnalyzer
}

// GetAnomalyDetector возвращает детектор аномалий
func (em *EffectivenessMetricsImpl) GetAnomalyDetector() *AnomalyDetector {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.anomalyDetector
}

// GetReportGenerator возвращает генератор отчетов
func (em *EffectivenessMetricsImpl) GetReportGenerator() *ReportGenerator {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.reportGenerator
}

// GenerateDetailedReport генерирует детальный отчет
func (em *EffectivenessMetricsImpl) GenerateDetailedReport() (string, error) {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	// Generate comprehensive report
	report := "=== WHISPERA EFFECTIVENESS REPORT ===\n\n"

	// Real-time metrics
	report += "REAL-TIME METRICS:\n"
	report += fmt.Sprintf("  Throughput: %.2f ops/sec\n", em.detailedAnalytics.RealTimeMetrics.CurrentThroughput)
	report += fmt.Sprintf("  Latency: %v\n", em.detailedAnalytics.RealTimeMetrics.CurrentLatency)
	report += fmt.Sprintf("  Success Rate: %.2f%%\n", em.detailedAnalytics.RealTimeMetrics.CurrentSuccessRate*100)
	report += fmt.Sprintf("  Error Rate: %.2f%%\n", em.detailedAnalytics.RealTimeMetrics.CurrentErrorRate*100)
	report += fmt.Sprintf("  Active Connections: %d\n", em.detailedAnalytics.RealTimeMetrics.ActiveConnections)
	report += fmt.Sprintf("  CPU Usage: %.2f%%\n", em.detailedAnalytics.RealTimeMetrics.CPUUsage*100)
	report += fmt.Sprintf("  Memory Usage: %.2f%%\n", em.detailedAnalytics.RealTimeMetrics.MemoryUsage*100)
	report += fmt.Sprintf("  Network Utilization: %.2f%%\n", em.detailedAnalytics.RealTimeMetrics.NetworkUtilization*100)
	report += "\n"

	// Historical trends
	report += "HISTORICAL TRENDS:\n"
	for _, trend := range em.detailedAnalytics.HistoricalData.Trends {
		report += fmt.Sprintf("  %s: %s (%.2f confidence)\n", trend.Type, trend.Direction, trend.Confidence)
	}
	report += "\n"

	// Risk assessment
	report += "RISK ASSESSMENT:\n"
	report += fmt.Sprintf("  Overall Risk: %s\n", em.detailedAnalytics.RiskAssessment.OverallRisk)
	for _, risk := range em.detailedAnalytics.RiskAssessment.RiskFactors {
		report += fmt.Sprintf("  %s: %s (%.2f probability)\n", risk.Name, risk.Level, risk.Probability)
	}
	report += "\n"

	// Recommendations
	report += "RECOMMENDATIONS:\n"
	for _, rec := range em.detailedAnalytics.Recommendations.Immediate {
		report += fmt.Sprintf("  IMMEDIATE: %s - %s\n", rec.Title, rec.Description)
	}
	for _, rec := range em.detailedAnalytics.Recommendations.ShortTerm {
		report += fmt.Sprintf("  SHORT-TERM: %s - %s\n", rec.Title, rec.Description)
	}
	for _, rec := range em.detailedAnalytics.Recommendations.LongTerm {
		report += fmt.Sprintf("  LONG-TERM: %s - %s\n", rec.Title, rec.Description)
	}

	return report, nil
}

// UpdateRealTimeMetrics обновляет метрики в реальном времени
func (em *EffectivenessMetricsImpl) UpdateRealTimeMetrics() {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	// Update real-time metrics based on current system state
	em.detailedAnalytics.RealTimeMetrics.CurrentThroughput = em.calculateCurrentThroughput()
	em.detailedAnalytics.RealTimeMetrics.CurrentLatency = em.calculateCurrentLatency()
	em.detailedAnalytics.RealTimeMetrics.CurrentSuccessRate = em.calculateCurrentSuccessRate()
	em.detailedAnalytics.RealTimeMetrics.CurrentErrorRate = em.calculateCurrentErrorRate()
	em.detailedAnalytics.RealTimeMetrics.ActiveConnections = em.calculateActiveConnections()
	em.detailedAnalytics.RealTimeMetrics.QueueSize = em.calculateQueueSize()
	em.detailedAnalytics.RealTimeMetrics.CPUUsage = em.calculateCPUUsage()
	em.detailedAnalytics.RealTimeMetrics.MemoryUsage = em.calculateMemoryUsage()
	em.detailedAnalytics.RealTimeMetrics.NetworkUtilization = em.calculateNetworkUtilization()
	em.detailedAnalytics.RealTimeMetrics.LastUpdate = time.Now()
}

// Helper methods for metrics calculation
func (em *EffectivenessMetricsImpl) calculateCurrentThroughput() float64 {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	
	if em.overall == nil {
		return 0.0
	}
	
	// Calculate from recent packet history
	if len(em.detailedAnalytics.HistoricalData.DataPoints) > 0 {
		var totalBytes float64
		var timeWindow time.Duration
		now := time.Now()
		
		// Sum bytes from last minute
		for _, point := range em.detailedAnalytics.HistoricalData.DataPoints {
			if now.Sub(point.Timestamp) < time.Minute {
				if point.Metric == "throughput" {
					totalBytes += point.Value
				}
				timeWindow = now.Sub(point.Timestamp)
			}
		}
		
		if timeWindow > 0 {
			return totalBytes / timeWindow.Seconds()
		}
	}
	
	// Fallback to overall stats
	if em.overall.TotalBytes > 0 && em.overall.TotalPackets > 0 {
		avgPacketSize := float64(em.overall.TotalBytes) / float64(em.overall.TotalPackets)
		return avgPacketSize * 8.0 // Convert to bits per second estimate
	}
	
	return 0.0
}

func (em *EffectivenessMetricsImpl) calculateCurrentLatency() time.Duration {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	
	if em.overall == nil {
		return 0
	}
	
	// Use overall average latency
	if em.overall.AverageLatency > 0 {
		return em.overall.AverageLatency
	}
	
	// Calculate from recent data points
	if len(em.detailedAnalytics.HistoricalData.DataPoints) > 0 {
		var totalLatency time.Duration
		count := 0
		now := time.Now()
		
		for _, point := range em.detailedAnalytics.HistoricalData.DataPoints {
			if now.Sub(point.Timestamp) < time.Minute && point.Metric == "latency" {
				totalLatency += time.Duration(point.Value) * time.Millisecond
				count++
			}
		}
		
		if count > 0 {
			return totalLatency / time.Duration(count)
		}
	}
	
	return 50 * time.Millisecond // Default fallback
}

func (em *EffectivenessMetricsImpl) calculateCurrentSuccessRate() float64 {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	
	if em.overall == nil {
		return 0.0
	}
	
	total := em.overall.SuccessCount + em.overall.FailureCount
	if total == 0 {
		return 0.95 // Default optimistic
	}
	
	return float64(em.overall.SuccessCount) / float64(total)
}

func (em *EffectivenessMetricsImpl) calculateCurrentErrorRate() float64 {
	return 1.0 - em.calculateCurrentSuccessRate()
}

func (em *EffectivenessMetricsImpl) calculateActiveConnections() int {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	
	// Use real-time metrics if available
	if em.detailedAnalytics.RealTimeMetrics != nil {
		return em.detailedAnalytics.RealTimeMetrics.ActiveConnections
	}
	
	return 0
}

func (em *EffectivenessMetricsImpl) calculateQueueSize() int {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	
	// Use real-time metrics if available
	if em.detailedAnalytics.RealTimeMetrics != nil {
		return em.detailedAnalytics.RealTimeMetrics.QueueSize
	}
	
	return 0
}

func (em *EffectivenessMetricsImpl) calculateCPUUsage() float64 {
	// Use real-time metrics if available
	em.mutex.RLock()
	if em.detailedAnalytics.RealTimeMetrics != nil {
		cpu := em.detailedAnalytics.RealTimeMetrics.CPUUsage
		em.mutex.RUnlock()
		return cpu
	}
	em.mutex.RUnlock()
	
	// Fallback: use runtime stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	// Rough CPU estimate based on GC activity
	if m.NumGC > 0 {
		return float64(m.NumGC) * 0.01 // Rough estimate
	}
	
	return 0.0
}

func (em *EffectivenessMetricsImpl) calculateMemoryUsage() float64 {
	// Use real-time metrics if available
	em.mutex.RLock()
	if em.detailedAnalytics.RealTimeMetrics != nil {
		mem := em.detailedAnalytics.RealTimeMetrics.MemoryUsage
		em.mutex.RUnlock()
		return mem
	}
	em.mutex.RUnlock()
	
	// Use runtime stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	// Calculate memory usage percentage (rough estimate)
	if m.Sys > 0 {
		return float64(m.Alloc) / float64(m.Sys)
	}
	
	return 0.0
}

func (em *EffectivenessMetricsImpl) calculateNetworkUtilization() float64 {
	// Use real-time metrics if available
	em.mutex.RLock()
	if em.detailedAnalytics.RealTimeMetrics != nil {
		net := em.detailedAnalytics.RealTimeMetrics.NetworkUtilization
		em.mutex.RUnlock()
		return net
	}
	em.mutex.RUnlock()
	
	// Calculate from throughput
	throughput := em.calculateCurrentThroughput()
	if throughput > 0 {
		// Assume 100 Mbps link, calculate utilization
		maxThroughput := 100.0 * 1024 * 1024 / 8.0 // 100 Mbps in bytes/sec
		utilization := throughput / maxThroughput
		if utilization > 1.0 {
			utilization = 1.0
		}
		return utilization
	}
	
	return 0.0
}

// GetTopPerformingProfiles возвращает лучшие профили
func (em *EffectivenessMetricsImpl) GetTopPerformingProfiles(limit int) []*ProfileEffectiveness {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	var profiles []*ProfileEffectiveness

	for name, stats := range em.metrics {
		if stats.TotalAttempts > 0 {
			profiles = append(profiles, &ProfileEffectiveness{
				ProfileName:    name,
				SuccessRate:    stats.SuccessRate,
				AverageLatency: stats.AverageLatency,
				TotalAttempts:  stats.TotalAttempts,
			})
		}
	}

	// Сортируем по успешности
	for i := 0; i < len(profiles)-1; i++ {
		for j := i + 1; j < len(profiles); j++ {
			if profiles[i].SuccessRate < profiles[j].SuccessRate {
				profiles[i], profiles[j] = profiles[j], profiles[i]
			}
		}
	}

	// Ограничиваем количество
	if limit > 0 && len(profiles) > limit {
		profiles = profiles[:limit]
	}

	return profiles
}

// CleanupOldMetrics очищает старые метрики
func (em *EffectivenessMetricsImpl) CleanupOldMetrics() {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	cutoff := time.Now().Add(-em.windowSize)

	for name, stats := range em.metrics {
		if stats.LastUpdated.Before(cutoff) {
			delete(em.metrics, name)
		}
	}
}

// Reset сбрасывает все метрики
func (em *EffectivenessMetricsImpl) Reset() {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	em.metrics = make(map[string]*types.EffectivenessStats)
	em.overall = &types.EffectivenessStats{}
}

// ProfileEffectiveness - эффективность профиля
type ProfileEffectiveness struct {
	ProfileName    string        `json:"profile_name"`
	SuccessRate    float64       `json:"success_rate"`
	AverageLatency time.Duration `json:"average_latency"`
	TotalAttempts  int64         `json:"total_attempts"`
}
