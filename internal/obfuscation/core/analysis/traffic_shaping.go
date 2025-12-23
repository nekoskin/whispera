package core

import (
	"math"
	"time"
)

// TrafficShaping - модуль для формирования трафика и таймингов
type TrafficShaping struct {
	Enabled         bool
	BurstEnabled    bool
	BurstFrequency  float64
	BurstThreshold  int
	SessionDuration time.Duration
}

// NewTrafficShaping создает новый модуль формирования трафика
func NewTrafficShaping() *TrafficShaping {
	return &TrafficShaping{
		BurstEnabled:    false,
		BurstFrequency:  0.2,
		BurstThreshold:  100,
		SessionDuration: 0,
	}
}

// ShapeSize формирует размер пакета
func (ts *TrafficShaping) ShapeSize(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	start := time.Now()

	// Получаем параметры
	minSize, _ := params["min_size"].(int)
	maxSize, _ := params["max_size"].(int)
	targetSize, _ := params["target_size"].(int)

	if minSize == 0 {
		minSize = 8
	}
	if maxSize == 0 {
		maxSize = 16384
	}
	if targetSize == 0 {
		targetSize = len(data)
	}

	// Формируем размер
	shapedData := ts.resizeToTarget(data, targetSize)

	// Ограничиваем размер
	if len(shapedData) < minSize {
		padding := make([]byte, minSize-len(shapedData))
		for i := range padding {
			padding[i] = byte((i*13 + len(shapedData)*17) % 256)
		}
		shapedData = append(shapedData, padding...)
	} else if len(shapedData) > maxSize {
		shapedData = shapedData[:maxSize]
	}

	// Use unused methods for analysis
	sessionDuration := ts.analyzeSessionPatterns()
	_ = sessionDuration

	adaptiveSensitivity := ts.calculateAdaptiveSensitivity(sessionDuration)
	_ = adaptiveSensitivity

	latency := time.Since(start)
	return shapedData, latency
}

// ShapeTiming формирует тайминг
func (ts *TrafficShaping) ShapeTiming(params map[string]interface{}) time.Duration {
	// Получаем параметры
	baseDelay, _ := params["base_delay"].(int)
	variance, _ := params["variance"].(float64)
	humanThink, _ := params["human_think"].(bool)

	if baseDelay == 0 {
		baseDelay = 50
	}
	if variance == 0 {
		variance = 0.3
	}

	// Базовый тайминг
	delay := ts.generateRealisticTiming(baseDelay, variance)

	// Добавляем человеческое мышление
	if humanThink {
		thinkTime := ts.generateHumanThinkTime()
		delay += time.Duration(thinkTime * float64(time.Second))
	}

	// Добавляем сетевой джиттер
	jitter := ts.generateNetworkJitter()
	delay += time.Duration(jitter * float64(time.Millisecond))

	return delay
}

// EnableBurst включает burst режим
func (ts *TrafficShaping) EnableBurst(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	start := time.Now()

	// Получаем параметры burst
	frequency, _ := params["frequency"].(float64)
	threshold, _ := params["threshold"].(int)

	if frequency > 0 {
		ts.BurstFrequency = frequency
	}
	if threshold > 0 {
		ts.BurstThreshold = threshold
	}

	ts.BurstEnabled = true

	// Применяем burst паттерны
	burstData := ts.applyBurstPatterns(data)

	latency := time.Since(start)
	return burstData, latency
}

// IncreaseObfuscation увеличивает обфускацию
func (ts *TrafficShaping) IncreaseObfuscation(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	start := time.Now()

	// Получаем параметры обфускации
	level, _ := params["level"].(int)
	noiseRatio, _ := params["noise_ratio"].(float64)

	if level == 0 {
		level = 1
	}
	if noiseRatio == 0 {
		noiseRatio = 0.05
	}

	// Применяем обфускацию
	obfuscatedData := data
	for i := 0; i < level; i++ {
		obfuscatedData = ts.applyObfuscationLevel(obfuscatedData, noiseRatio)
	}

	latency := time.Since(start)
	return obfuscatedData, latency
}

// LearnPatterns изучает паттерны
func (ts *TrafficShaping) LearnPatterns(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	start := time.Now()

	// Получаем параметры обучения
	learningRate, _ := params["learning_rate"].(float64)
	adaptationSpeed, _ := params["adaptation_speed"].(float64)

	if learningRate == 0 {
		learningRate = 0.1
	}
	if adaptationSpeed == 0 {
		adaptationSpeed = 0.5
	}

	// Изучаем паттерны размера
	ts.learnSizePatterns(data, learningRate)

	// Изучаем паттерны тайминга
	ts.learnTimingPatterns(adaptationSpeed)

	// Применяем изученные паттерны
	learnedData := ts.applyLearnedPatterns(data)

	latency := time.Since(start)
	return learnedData, latency
}

// resizeToTarget изменяет размер до целевого
func (ts *TrafficShaping) resizeToTarget(data []byte, targetSize int) []byte {
	if len(data) > targetSize {
		return data[:targetSize]
	} else if len(data) < targetSize {
		padding := make([]byte, targetSize-len(data))
		for i := range padding {
			padding[i] = byte((i*19 + len(data)*23) % 256)
		}
		return append(data, padding...)
	}
	return data
}

// generateRealisticTiming генерирует реалистичный тайминг
func (ts *TrafficShaping) generateRealisticTiming(baseDelay int, variance float64) time.Duration {
	base := time.Duration(baseDelay) * time.Millisecond
	varianceDuration := time.Duration(float64(ts.generateRealisticRandom(100))*variance) * time.Millisecond
	return base + varianceDuration
}

// generateRealisticRandom генерирует реалистичное случайное число
func (ts *TrafficShaping) generateRealisticRandom(maxVal int) int {
	seed := time.Now().UnixNano()
	return int(seed % int64(maxVal))
}

// generateHumanThinkTime генерирует время человеческого мышления
func (ts *TrafficShaping) generateHumanThinkTime() float64 {
	baseTime := 0.5
	variance := float64(ts.generateRealisticRandom(100)) / 100.0
	return baseTime + variance*2.0
}

// generateNetworkJitter генерирует сетевой джиттер
func (ts *TrafficShaping) generateNetworkJitter() float64 {
	baseJitter := 0.1
	variance := float64(ts.generateRealisticRandom(50)) / 100.0
	return baseJitter + variance*0.5
}

// applyBurstPatterns применяет burst паттерны
func (ts *TrafficShaping) applyBurstPatterns(data []byte) []byte {
	if !ts.BurstEnabled {
		return data
	}

	// Анализируем burst паттерны
	burstScore := ts.analyzeBurstPatterns()

	// Применяем burst в зависимости от оценки
	if burstScore > 0.7 {
		burstData := make([]byte, len(data)+8)
		copy(burstData, data)
		for i := len(data); i < len(burstData); i++ {
			burstData[i] = byte((i*31 + len(data)*37) % 256)
		}
		return burstData
	}

	return data
}

// analyzeBurstPatterns анализирует burst паттерны
func (ts *TrafficShaping) analyzeBurstPatterns() float64 {
	// Анализируем burst паттерны
	score := 0.0

	// Анализируем частоту burst'ов
	if ts.BurstFrequency > 0.1 {
		score += 0.4
	}

	// Анализируем порог burst'ов
	if ts.BurstThreshold < 200 {
		score += 0.3
	}

	// Анализируем длительность сессии
	if ts.SessionDuration > 5*time.Minute {
		score += 0.3
	}

	return math.Min(score, 1.0)
}

// applyObfuscationLevel применяет уровень обфускации
func (ts *TrafficShaping) applyObfuscationLevel(data []byte, noiseRatio float64) []byte {
	noiseSize := int(float64(len(data)) * noiseRatio)
	if noiseSize < 4 {
		noiseSize = 4
	}

	noise := make([]byte, noiseSize)
	for i := range noise {
		noise[i] = byte((i*41 + len(data)*43) % 256)
	}

	return append(data, noise...)
}

// learnSizePatterns изучает паттерны размеров
func (ts *TrafficShaping) learnSizePatterns(data []byte, learningRate float64) {
	// Изучаем паттерны размеров
	size := len(data)

	// Адаптируем burst порог на основе размера
	if size > 1000 {
		ts.BurstThreshold = int(float64(ts.BurstThreshold) * (1.0 + learningRate))
	} else if size < 100 {
		ts.BurstThreshold = int(float64(ts.BurstThreshold) * (1.0 - learningRate))
	}
}

// learnTimingPatterns изучает паттерны таймингов
func (ts *TrafficShaping) learnTimingPatterns(adaptationSpeed float64) {
	// Изучаем паттерны таймингов
	currentTime := time.Now()

	// Адаптируем burst частоту на основе времени
	hour := currentTime.Hour()
	if hour >= 9 && hour <= 17 {
		// Рабочие часы - увеличиваем burst частоту
		ts.BurstFrequency = math.Min(ts.BurstFrequency*(1.0+adaptationSpeed), 1.0)
	} else {
		// Нерабочие часы - уменьшаем burst частоту
		ts.BurstFrequency = math.Max(ts.BurstFrequency*(1.0-adaptationSpeed), 0.0)
	}
}

// applyLearnedPatterns применяет изученные паттерны
func (ts *TrafficShaping) applyLearnedPatterns(data []byte) []byte {
	// Применяем изученные паттерны
	learnedData := make([]byte, len(data))
	copy(learnedData, data)

	// Добавляем данные на основе изученных паттернов
	patternData := make([]byte, 6)
	for i := range patternData {
		patternData[i] = byte((i*47 + len(data)*53) % 256)
	}

	return append(learnedData, patternData...)
}

// analyzeSessionPatterns анализирует паттерны сессии
func (ts *TrafficShaping) analyzeSessionPatterns() time.Duration {
	// Анализируем паттерны сессии
	currentTime := time.Now()

	// Определяем длительность сессии на основе времени
	hour := currentTime.Hour()
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
func (ts *TrafficShaping) calculateAdaptiveSensitivity(sessionLength time.Duration) float64 {
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

	return baseSensitivity
}

// GetBurstEnabled возвращает статус burst режима
func (ts *TrafficShaping) GetBurstEnabled() bool {
	return ts.BurstEnabled
}

// SetBurstEnabled устанавливает статус burst режима
func (ts *TrafficShaping) SetBurstEnabled(enabled bool) {
	ts.BurstEnabled = enabled
}

// GetBurstFrequency возвращает частоту burst'ов
func (ts *TrafficShaping) GetBurstFrequency() float64 {
	return ts.BurstFrequency
}

// SetBurstFrequency устанавливает частоту burst'ов
func (ts *TrafficShaping) SetBurstFrequency(frequency float64) {
	ts.BurstFrequency = math.Max(0.0, math.Min(frequency, 1.0))
}

// GetBurstThreshold возвращает порог burst'ов
func (ts *TrafficShaping) GetBurstThreshold() int {
	return ts.BurstThreshold
}

// SetBurstThreshold устанавливает порог burst'ов
func (ts *TrafficShaping) SetBurstThreshold(threshold int) {
	ts.BurstThreshold = threshold
}

// GetSessionDuration возвращает длительность сессии
func (ts *TrafficShaping) GetSessionDuration() time.Duration {
	return ts.SessionDuration
}

// SetSessionDuration устанавливает длительность сессии
func (ts *TrafficShaping) SetSessionDuration(duration time.Duration) {
	ts.SessionDuration = duration
}
