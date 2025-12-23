package evasion

import (
	"math"
	"time"
	"whispera/internal/obfuscation/core/types"
)

// LearningPattern - паттерн обучения (используем из types)
type LearningPattern = types.LearningPattern

// LearningData - данные обучения (используем из types)
type LearningData = types.LearningData

// LearningStats - статистика обучения (используем из types)
type LearningStats = types.LearningStats

// TrafficContext, NetworkInfo, UserBehavior определены в types/types.go
// Используем типы из пакета types

// TrafficState - состояние трафика (используем из types)
type TrafficState = types.TrafficState

// TrafficProfile - профиль трафика (используем из types)
type TrafficProfile = types.TrafficProfile

// AdaptationStrategy - стратегия адаптации (используем из types)
type AdaptationStrategy = types.AdaptationStrategy

// ProfileChange - изменение профиля (используем из types)
type ProfileChange = types.ProfileChange

// TimingAdjustment - корректировка таймингов (используем из types)
type TimingAdjustment = types.TimingAdjustment

// AdaptiveLearningImpl - реализация адаптивного обучения
type AdaptiveLearningImpl struct {
	learningRate    float64
	adaptationSpeed float64
	patterns        map[string]*LearningPattern
	recentSizes     []int
	recentIntervals []time.Duration
	threatLevel     float64
	sessionStart    time.Time
}

// LearningPatternStats - статистика паттерна обучения
type LearningPatternStats struct {
	UsageCount    int64
	LastUsed      time.Time
	Effectiveness float64
}

// NewAdaptiveLearning создает новый модуль адаптивного обучения
func NewAdaptiveLearning() *AdaptiveLearningImpl {
	return &AdaptiveLearningImpl{
		learningRate:    0.1,
		adaptationSpeed: 0.5,
		patterns:        make(map[string]*LearningPattern),
		recentSizes:     make([]int, 0),
		recentIntervals: make([]time.Duration, 0),
		threatLevel:     0.5,
		sessionStart:    time.Now(),
	}
}

// performAdaptiveLearning выполняет адаптивное обучение
func (al *AdaptiveLearningImpl) performAdaptiveLearning() {
	// Выполняем адаптивное обучение
	al.learnPacketSizePatterns()
	al.learnTimingPatterns()
	al.learnBehavioralPatterns()
	al.adaptToThreatLevel()
}

// learnPacketSizePatterns изучает паттерны размеров пакетов
func (al *AdaptiveLearningImpl) learnPacketSizePatterns() {
	if len(al.recentSizes) == 0 {
		return
	}

	// Анализируем недавние размеры
	mean := al.calculateMean(al.recentSizes)
	stdDev := al.calculateStdDev(al.recentSizes, mean)
	min := al.calculateMin(al.recentSizes)
	max := al.calculateMax(al.recentSizes)

	// Обновляем паттерны на основе анализа
	pattern := al.getOrCreatePattern("packet_size")
	pattern.Parameters["mean"] = mean
	pattern.Parameters["std_dev"] = stdDev
	pattern.Parameters["min"] = min
	pattern.Parameters["max"] = max
	pattern.Parameters["count"] = len(al.recentSizes)

	// Обновляем эффективность
	pattern.SuccessRate = al.calculatePatternEffectiveness("packet_size")
}

// learnTimingPatterns изучает паттерны таймингов
func (al *AdaptiveLearningImpl) learnTimingPatterns() {
	if len(al.recentIntervals) == 0 {
		return
	}

	// Анализируем недавние интервалы
	meanInterval := al.calculateMeanInterval(al.recentIntervals)
	stdDevInterval := al.calculateStdDevInterval(al.recentIntervals, meanInterval)
	minInterval := al.calculateMinInterval(al.recentIntervals)
	maxInterval := al.calculateMaxInterval(al.recentIntervals)

	// Обновляем паттерны на основе анализа
	pattern := al.getOrCreatePattern("timing")
	pattern.Parameters["mean_interval"] = meanInterval
	pattern.Parameters["std_dev_interval"] = stdDevInterval
	pattern.Parameters["min_interval"] = minInterval
	pattern.Parameters["max_interval"] = maxInterval
	pattern.Parameters["count"] = len(al.recentIntervals)

	// Обновляем эффективность
	pattern.SuccessRate = al.calculatePatternEffectiveness("timing")
}

// learnBehavioralPatterns изучает поведенческие паттерны
func (al *AdaptiveLearningImpl) learnBehavioralPatterns() {
	// Анализируем поведенческие паттерны
	sessionDuration := time.Since(al.sessionStart)
	hour := time.Now().Hour()
	dayOfWeek := int(time.Now().Weekday())

	// Создаем поведенческий паттерн
	pattern := al.getOrCreatePattern("behavioral")
	pattern.Parameters["session_duration"] = sessionDuration
	pattern.Parameters["hour"] = hour
	pattern.Parameters["day_of_week"] = dayOfWeek
	pattern.Parameters["threat_level"] = al.threatLevel

	// Обновляем эффективность
	pattern.SuccessRate = al.calculatePatternEffectiveness("behavioral")
}

// adaptToThreatLevel адаптируется к уровню угрозы
func (al *AdaptiveLearningImpl) adaptToThreatLevel() {
	// Адаптируем параметры на основе уровня угрозы
	if al.threatLevel > 0.7 {
		// Высокий уровень угрозы - увеличиваем адаптацию
		al.learningRate = math.Min(al.learningRate*1.2, 0.5)
		al.adaptationSpeed = math.Min(al.adaptationSpeed*1.1, 1.0)
	} else if al.threatLevel < 0.3 {
		// Низкий уровень угрозы - уменьшаем адаптацию
		al.learningRate = math.Max(al.learningRate*0.9, 0.01)
		al.adaptationSpeed = math.Max(al.adaptationSpeed*0.95, 0.1)
	}
}

// calculateAdvancedStats вычисляет продвинутую статистику
func (al *AdaptiveLearningImpl) calculateAdvancedStats(data []int) (float64, float64, float64, float64) {
	if len(data) == 0 {
		return 0, 0, 0, 0
	}

	// Вычисляем среднее
	mean := al.calculateMean(data)

	// Вычисляем стандартное отклонение
	stdDev := al.calculateStdDev(data, mean)

	// Вычисляем минимум
	min := al.calculateMin(data)

	// Вычисляем максимум
	max := al.calculateMax(data)

	return float64(mean), float64(stdDev), float64(min), float64(max)
}

// updateSizeDistributionWeights обновляет веса распределения размеров
func (al *AdaptiveLearningImpl) updateSizeDistributionWeights(profile *TrafficProfile, recentSizes []int) {
	if len(recentSizes) == 0 {
		return
	}

	// Обновляем веса на основе недавних размеров
	mean := al.calculateMean(recentSizes)
	stdDev := al.calculateStdDev(recentSizes, mean)

	// Адаптируем веса
	if profile.SizeDistribution != nil {
		for i, size := range profile.SizeDistribution.Bins {
			if i < len(profile.SizeWeights) {
				// Вычисляем расстояние от среднего
				distance := math.Abs(float64(size) - float64(mean))

				// Обновляем вес на основе расстояния
				if distance < float64(stdDev) {
					profile.SizeWeights[i] = math.Min(profile.SizeWeights[i]*1.1, 1.0)
				} else {
					profile.SizeWeights[i] = math.Max(profile.SizeWeights[i]*0.9, 0.0)
				}
			}
		}
	}
}

// analyzeBurstPatterns анализирует паттерны burst'ов
func (al *AdaptiveLearningImpl) analyzeBurstPatterns() float64 {
	// Анализируем паттерны burst'ов
	score := 0.0

	// Анализируем частоту burst'ов
	if len(al.recentSizes) > 10 {
		burstCount := 0
		for i := 1; i < len(al.recentSizes); i++ {
			if al.recentSizes[i] > al.recentSizes[i-1]*2 {
				burstCount++
			}
		}
		burstFrequency := float64(burstCount) / float64(len(al.recentSizes))
		score += burstFrequency * 0.4
	}

	// Анализируем размеры burst'ов
	if len(al.recentSizes) > 0 {
		mean := al.calculateMean(al.recentSizes)
		largePackets := 0
		for _, size := range al.recentSizes {
			if size > mean*2 {
				largePackets++
			}
		}
		largePacketRatio := float64(largePackets) / float64(len(al.recentSizes))
		score += largePacketRatio * 0.3
	}

	// Анализируем интервалы между burst'ами
	if len(al.recentIntervals) > 5 {
		shortIntervals := 0
		meanInterval := al.calculateMeanInterval(al.recentIntervals)
		for _, interval := range al.recentIntervals {
			if interval < meanInterval/2 {
				shortIntervals++
			}
		}
		shortIntervalRatio := float64(shortIntervals) / float64(len(al.recentIntervals))
		score += shortIntervalRatio * 0.3
	}

	return math.Min(score, 1.0)
}

// analyzeSessionPatterns анализирует паттерны сессии
func (al *AdaptiveLearningImpl) analyzeSessionPatterns() time.Duration {
	// Анализируем паттерны сессии
	_ = time.Since(al.sessionStart) // используем для расчета

	// Адаптируем на основе времени суток
	hour := time.Now().Hour()
	if hour >= 6 && hour <= 12 {
		// Утро - короткие сессии
		return 5 * time.Minute
	} else if hour >= 13 && hour <= 18 {
		// День - средние сессии
		return 15 * time.Minute
	} else if hour >= 19 && hour <= 23 {
		// Вечер - длинные сессии
		return 30 * time.Minute
	}
	// Ночь - очень короткие сессии
	return 2 * time.Minute
}

// calculateAdaptiveSensitivity рассчитывает адаптивную чувствительность
func (al *AdaptiveLearningImpl) calculateAdaptiveSensitivity(sessionLength time.Duration) float64 {
	// Рассчитываем адаптивную чувствительность
	baseSensitivity := 0.5

	// Адаптируем на основе длины сессии
	if sessionLength > 20*time.Minute {
		// Длинные сессии - высокая чувствительность
		return math.Min(baseSensitivity*1.5, 1.0)
	} else if sessionLength < 5*time.Minute {
		// Короткие сессии - низкая чувствительность
		return math.Max(baseSensitivity*0.5, 0.1)
	}

	// Адаптируем на основе уровня угрозы
	if al.threatLevel > 0.7 {
		return math.Min(baseSensitivity*1.3, 1.0)
	} else if al.threatLevel < 0.3 {
		return math.Max(baseSensitivity*0.7, 0.1)
	}

	return baseSensitivity
}

// calculateMean вычисляет среднее значение
func (al *AdaptiveLearningImpl) calculateMean(values []int) int {
	if len(values) == 0 {
		return 0
	}

	sum := 0
	for _, value := range values {
		sum += value
	}

	return sum / len(values)
}

// calculateStdDev вычисляет стандартное отклонение
func (al *AdaptiveLearningImpl) calculateStdDev(values []int, mean int) int {
	if len(values) == 0 {
		return 0
	}

	sum := 0
	for _, value := range values {
		diff := value - mean
		sum += diff * diff
	}

	return int(math.Sqrt(float64(sum) / float64(len(values))))
}

// calculateMin вычисляет минимальное значение
func (al *AdaptiveLearningImpl) calculateMin(values []int) int {
	if len(values) == 0 {
		return 0
	}

	min := values[0]
	for _, value := range values {
		if value < min {
			min = value
		}
	}

	return min
}

// calculateMax вычисляет максимальное значение
func (al *AdaptiveLearningImpl) calculateMax(values []int) int {
	if len(values) == 0 {
		return 0
	}

	max := values[0]
	for _, value := range values {
		if value > max {
			max = value
		}
	}

	return max
}

// calculateMeanInterval вычисляет средний интервал
func (al *AdaptiveLearningImpl) calculateMeanInterval(intervals []time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	var sum time.Duration
	for _, interval := range intervals {
		sum += interval
	}

	return sum / time.Duration(len(intervals))
}

// calculateStdDevInterval вычисляет стандартное отклонение интервалов
func (al *AdaptiveLearningImpl) calculateStdDevInterval(intervals []time.Duration, mean time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	var sum float64
	for _, interval := range intervals {
		diff := float64(interval - mean)
		sum += diff * diff
	}

	return time.Duration(math.Sqrt(sum / float64(len(intervals))))
}

// calculateMinInterval вычисляет минимальный интервал
func (al *AdaptiveLearningImpl) calculateMinInterval(intervals []time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	min := intervals[0]
	for _, interval := range intervals {
		if interval < min {
			min = interval
		}
	}

	return min
}

// calculateMaxInterval вычисляет максимальный интервал
func (al *AdaptiveLearningImpl) calculateMaxInterval(intervals []time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	max := intervals[0]
	for _, interval := range intervals {
		if interval > max {
			max = interval
		}
	}

	return max
}

// getOrCreatePattern получает или создает паттерн
func (al *AdaptiveLearningImpl) getOrCreatePattern(name string) *LearningPattern {
	pattern, exists := al.patterns[name]
	if !exists {
		pattern = &LearningPattern{
			Name:        name,
			Frequency:   0.5,
			SuccessRate: 0.5,
			UsageCount:  0,
			LastUsed:    time.Now(),
			Parameters:  make(map[string]interface{}),
		}
		al.patterns[name] = pattern
	}

	// Обновляем статистику
	pattern.UsageCount++
	pattern.LastUsed = time.Now()

	return pattern
}

// calculatePatternEffectiveness вычисляет эффективность паттерна
func (al *AdaptiveLearningImpl) calculatePatternEffectiveness(patternName string) float64 {
	pattern, exists := al.patterns[patternName]
	if !exists {
		return 0.0
	}

	// Базовая эффективность
	effectiveness := 0.5

	// Учитываем количество использований
	if pattern.UsageCount > 10 {
		effectiveness += 0.2
	}

	// Учитываем недавность использования
	timeSinceLastUse := time.Since(pattern.LastUsed)
	if timeSinceLastUse < 5*time.Minute {
		effectiveness += 0.1
	}

	// Учитываем уровень угрозы
	if al.threatLevel > 0.7 {
		effectiveness += 0.2
	}

	return math.Min(effectiveness, 1.0)
}

// AddRecentSize добавляет недавний размер
func (al *AdaptiveLearningImpl) AddRecentSize(size int) {
	al.recentSizes = append(al.recentSizes, size)

	// Ограничиваем количество недавних размеров
	maxRecent := 100
	if len(al.recentSizes) > maxRecent {
		al.recentSizes = al.recentSizes[len(al.recentSizes)-maxRecent:]
	}
}

// AddRecentInterval добавляет недавний интервал
func (al *AdaptiveLearningImpl) AddRecentInterval(interval time.Duration) {
	al.recentIntervals = append(al.recentIntervals, interval)

	// Ограничиваем количество недавних интервалов
	maxRecent := 100
	if len(al.recentIntervals) > maxRecent {
		al.recentIntervals = al.recentIntervals[len(al.recentIntervals)-maxRecent:]
	}
}

// SetThreatLevel устанавливает уровень угрозы
func (al *AdaptiveLearningImpl) SetThreatLevel(level float64) {
	al.threatLevel = math.Max(0.0, math.Min(level, 1.0))
}

// GetThreatLevel возвращает уровень угрозы
func (al *AdaptiveLearningImpl) GetThreatLevel() float64 {
	return al.threatLevel
}

// GetLearningRate возвращает скорость обучения
func (al *AdaptiveLearningImpl) GetLearningRate() float64 {
	return al.learningRate
}

// SetLearningRate устанавливает скорость обучения
func (al *AdaptiveLearningImpl) SetLearningRate(rate float64) {
	al.learningRate = math.Max(0.01, math.Min(rate, 1.0))
}

// GetAdaptationSpeed возвращает скорость адаптации
func (al *AdaptiveLearningImpl) GetAdaptationSpeed() float64 {
	return al.adaptationSpeed
}

// SetAdaptationSpeed устанавливает скорость адаптации
func (al *AdaptiveLearningImpl) SetAdaptationSpeed(speed float64) {
	al.adaptationSpeed = math.Max(0.1, math.Min(speed, 1.0))
}

// GetPatterns возвращает все паттерны
func (al *AdaptiveLearningImpl) GetPatterns() map[string]*LearningPattern {
	return al.patterns
}

// GetPattern возвращает паттерн по имени
func (al *AdaptiveLearningImpl) GetPattern(name string) *LearningPattern {
	return al.patterns[name]
}

// ResetPatterns сбрасывает все паттерны
func (al *AdaptiveLearningImpl) ResetPatterns() {
	al.patterns = make(map[string]*LearningPattern)
	al.recentSizes = make([]int, 0)
	al.recentIntervals = make([]time.Duration, 0)
	al.sessionStart = time.Now()
}

// GetSessionDuration возвращает длительность сессии
func (al *AdaptiveLearningImpl) GetSessionDuration() time.Duration {
	return time.Since(al.sessionStart)
}

// ResetSession сбрасывает сессию
func (al *AdaptiveLearningImpl) ResetSession() {
	al.sessionStart = time.Now()
	al.recentSizes = make([]int, 0)
	al.recentIntervals = make([]time.Duration, 0)
}

// LearnFromTraffic обучается на основе трафика
func (al *AdaptiveLearningImpl) LearnFromTraffic(data []byte, success bool, context *types.TrafficContext) error {
	// Добавляем размер пакета в недавние размеры
	al.AddRecentSize(len(data))

	// Обновляем паттерны на основе успешности
	if success {
		al.threatLevel = math.Max(0.0, al.threatLevel-0.1)
	} else {
		al.threatLevel = math.Min(1.0, al.threatLevel+0.1)
	}

	// Выполняем адаптивное обучение
	al.performAdaptiveLearning()

	// Calculate advanced statistics
	mean, stdDev, min, max := al.calculateAdvancedStats(al.recentSizes)
	_ = mean
	_ = stdDev
	_ = min
	_ = max

	// Analyze burst patterns
	burstScore := al.analyzeBurstPatterns()
	_ = burstScore

	// Analyze session patterns
	sessionDuration := al.analyzeSessionPatterns()
	_ = sessionDuration

	// Calculate adaptive sensitivity
	sensitivity := al.calculateAdaptiveSensitivity(sessionDuration)
	_ = sensitivity

	return nil
}

// GetAdaptationStrategy возвращает стратегию адаптации
func (al *AdaptiveLearningImpl) GetAdaptationStrategy() *AdaptationStrategy {
	return &AdaptationStrategy{
		ProfileChanges:    []*ProfileChange{},
		TimingAdjustments: []*TimingAdjustment{},
		Priority:          1,
		Confidence:        al.calculatePatternEffectiveness("behavioral"),
	}
}

// UpdateEffectiveness обновляет эффективность профиля
func (al *AdaptiveLearningImpl) UpdateEffectiveness(profile string, success bool) error {
	pattern := al.getOrCreatePattern(profile)
	if success {
		pattern.SuccessRate = math.Min(1.0, pattern.SuccessRate+0.1)
	} else {
		pattern.SuccessRate = math.Max(0.0, pattern.SuccessRate-0.05)
	}

	// Update size distribution weights based on recent sizes
	trafficProfile := &TrafficProfile{
		Name: profile,
	}
	al.updateSizeDistributionWeights(trafficProfile, al.recentSizes)

	return nil
}

// GetLearningData возвращает данные обучения
func (al *AdaptiveLearningImpl) GetLearningData() *types.LearningData {
	patterns := make(map[string]*LearningPattern)
	for name, pattern := range al.patterns {
		patterns[name] = pattern
	}

	effectiveness := make(map[string]float64)
	for name, pattern := range al.patterns {
		effectiveness[name] = pattern.SuccessRate
	}

	return &types.LearningData{
		Patterns:      patterns,
		Effectiveness: effectiveness,
		LastUpdate:    time.Now(),
	}
}

// SetLearningData устанавливает данные обучения
func (al *AdaptiveLearningImpl) SetLearningData(data *types.LearningData) {
	if data == nil {
		return
	}

	// Обновляем паттерны
	for name, pattern := range data.Patterns {
		al.patterns[name] = pattern
	}

	// Обновляем эффективность
	for name, eff := range data.Effectiveness {
		if pattern, exists := al.patterns[name]; exists {
			pattern.SuccessRate = eff
		}
	}
}

// GetLearningStats возвращает статистику обучения
func (al *AdaptiveLearningImpl) GetLearningStats() *types.LearningStats {
	totalSamples := int64(len(al.recentSizes) + len(al.recentIntervals))
	successCount := int64(0)
	failureCount := int64(0)

	// Подсчитываем успешные и неудачные попытки
	for _, pattern := range al.patterns {
		if pattern.SuccessRate > 0.5 {
			successCount += pattern.UsageCount
		} else {
			failureCount += pattern.UsageCount
		}
	}

	averageAccuracy := 0.0
	if totalSamples > 0 {
		averageAccuracy = float64(successCount) / float64(totalSamples)
	}

	return &types.LearningStats{
		TotalSamples:    totalSamples,
		SuccessCount:    successCount,
		FailureCount:    failureCount,
		AverageAccuracy: averageAccuracy,
		LastUpdate:      time.Now(),
		LearningRate:    al.learningRate,
		AdaptationCount: int64(len(al.patterns)),
	}
}

// ResetLearning сбрасывает обучение
func (al *AdaptiveLearningImpl) ResetLearning() error {
	al.ResetPatterns()
	al.learningRate = 0.1
	al.adaptationSpeed = 0.5
	al.threatLevel = 0.5
	return nil
}
