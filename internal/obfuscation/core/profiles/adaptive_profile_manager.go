package profiles

import (
	"fmt"
	"math"
	"sync"
	"time"
	"whispera/internal/obfuscation/core/types"
)

const profileTypeProtocol = "protocol"

// AdaptiveProfileManagerImpl - реализация адаптивного управления профилями
type AdaptiveProfileManagerImpl struct {
	profiles            map[string]*AdaptiveProfile
	recommendations     map[string]*types.ProfileRecommendation
	feedback            map[string]*types.AdaptationFeedback
	mutex               sync.RWMutex
	learningRate        float64
	adaptationThreshold float64
}

// AdaptiveProfile - адаптивный профиль
type AdaptiveProfile struct {
	Name            string
	Type            string
	Parameters      map[string]interface{}
	Effectiveness   float64
	UsageCount      int64
	LastUsed        time.Time
	AdaptationCount int64
	SuccessRate     float64
	AverageLatency  time.Duration
	LastAdaptation  time.Time
}

// NewAdaptiveProfileManager создает новый менеджер адаптивных профилей
func NewAdaptiveProfileManager() types.AdaptiveProfileManager {
	return &AdaptiveProfileManagerImpl{
		profiles:            make(map[string]*AdaptiveProfile),
		recommendations:     make(map[string]*types.ProfileRecommendation),
		feedback:            make(map[string]*types.AdaptationFeedback),
		learningRate:        0.1,
		adaptationThreshold: 0.8,
	}
}

// SelectOptimalProfile выбирает оптимальный профиль для контекста
func (apm *AdaptiveProfileManagerImpl) SelectOptimalProfile(context *types.TrafficContext) (string, error) {
	apm.mutex.RLock()
	defer apm.mutex.RUnlock()

	if len(apm.profiles) == 0 {
		return "", fmt.Errorf("no profiles available")
	}

	var bestProfile string
	bestScore := -1.0

	for name, profile := range apm.profiles {
		score := apm.calculateProfileScore(profile, context)
		if score > bestScore {
			bestScore = score
			bestProfile = name
		}
	}

	if bestProfile == "" {
		return "", fmt.Errorf("no suitable profile found")
	}

	return bestProfile, nil
}

// AdaptProfile адаптирует профиль на основе обратной связи
func (apm *AdaptiveProfileManagerImpl) AdaptProfile(profileName string, feedback *types.AdaptationFeedback) error {
	apm.mutex.Lock()
	defer apm.mutex.Unlock()

	profile, exists := apm.profiles[profileName]
	if !exists {
		return fmt.Errorf("profile %s not found", profileName)
	}

	// Обновляем статистику профиля
	profile.UsageCount++
	profile.LastUsed = time.Now()

	// Обновляем успешность
	if feedback.Success {
		profile.SuccessRate = (profile.SuccessRate*float64(profile.UsageCount-1) + 1.0) / float64(profile.UsageCount)
	} else {
		profile.SuccessRate = (profile.SuccessRate*float64(profile.UsageCount-1) + 0.0) / float64(profile.UsageCount)
	}

	// Обновляем среднюю задержку
	if profile.AverageLatency == 0 {
		profile.AverageLatency = feedback.Latency
	} else {
		// Экспоненциальное сглаживание
		alpha := apm.learningRate
		profile.AverageLatency = time.Duration(
			float64(profile.AverageLatency)*(1-alpha) + float64(feedback.Latency)*alpha,
		)
	}

	// Адаптируем параметры профиля
	apm.adaptProfileParameters(profile, feedback)

	// Сохраняем обратную связь
	apm.feedback[profileName] = feedback

	// Увеличиваем счетчик адаптаций
	profile.AdaptationCount++
	profile.LastAdaptation = time.Now()

	return nil
}

// GetProfileRecommendations возвращает рекомендации профилей
func (apm *AdaptiveProfileManagerImpl) GetProfileRecommendations(
	context *types.TrafficContext,
) []*types.ProfileRecommendation {
	apm.mutex.RLock()
	defer apm.mutex.RUnlock()

	recommendations := make([]*types.ProfileRecommendation, 0, len(apm.profiles))

	for name, profile := range apm.profiles {
		score := apm.calculateProfileScore(profile, context)
		confidence := apm.calculateConfidence(profile, context)

		recommendation := &types.ProfileRecommendation{
			ProfileName: name,
			Confidence:  confidence,
			Reason:      apm.getRecommendationReason(profile, context),
			Priority:    int(score * 100),
		}

		recommendations = append(recommendations, recommendation)
	}

	// Сортируем по приоритету (высший приоритет первым)
	for i := 0; i < len(recommendations)-1; i++ {
		for j := i + 1; j < len(recommendations); j++ {
			if recommendations[i].Priority < recommendations[j].Priority {
				recommendations[i], recommendations[j] = recommendations[j], recommendations[i]
			}
		}
	}

	return recommendations
}

// calculateProfileScore вычисляет оценку профиля для контекста
func (apm *AdaptiveProfileManagerImpl) calculateProfileScore(
	profile *AdaptiveProfile, context *types.TrafficContext,
) float64 {
	score := 0.0

	// Базовый счет на основе эффективности
	score += profile.Effectiveness * 0.4

	// Счет на основе успешности
	score += profile.SuccessRate * 0.3

	// Счет на основе задержки (меньше задержка = выше счет)
	if profile.AverageLatency > 0 {
		latencyScore := 1.0 - math.Min(float64(profile.AverageLatency)/float64(100*time.Millisecond), 1.0)
		score += latencyScore * 0.2
	}

	// Счет на основе типа профиля и контекста
	score += apm.calculateTypeScore(profile, context) * 0.1

	return math.Min(score, 1.0)
}

// calculateTypeScore вычисляет счет на основе типа профиля
func (apm *AdaptiveProfileManagerImpl) calculateTypeScore(
	profile *AdaptiveProfile, context *types.TrafficContext,
) float64 {
	switch profile.Type {
	case profileTypeProtocol:
		if context.Protocol == "udp" || context.Protocol == "tcp" {
			return 0.9
		}
		return 0.5
	case "social":
		if context.Direction == "outbound" && context.Size > 100 {
			return 0.8
		}
		return 0.4
	case "mobile":
		if context.ThreatLevel > 5 {
			return 0.7
		}
		return 0.6
	case "search":
		if context.Direction == "outbound" && context.Size < 1000 {
			return 0.8
		}
		return 0.5
	default:
		return 0.5
	}
}

// calculateConfidence вычисляет уверенность в рекомендации
func (apm *AdaptiveProfileManagerImpl) calculateConfidence(
	profile *AdaptiveProfile, context *types.TrafficContext,
) float64 {
	// Use context parameter for confidence calculation
	_ = context.Direction
	_ = context.Protocol

	confidence := 0.5

	// Увеличиваем уверенность на основе количества использований
	if profile.UsageCount > 0 {
		confidence += math.Min(float64(profile.UsageCount)/100.0, 0.3)
	}

	// Увеличиваем уверенность на основе успешности
	confidence += profile.SuccessRate * 0.2

	// Уменьшаем уверенность для новых профилей
	if profile.UsageCount < 5 {
		confidence *= 0.7
	}

	return math.Min(confidence, 1.0)
}

// getRecommendationReason возвращает причину рекомендации
func (apm *AdaptiveProfileManagerImpl) getRecommendationReason(
	profile *AdaptiveProfile, context *types.TrafficContext,
) string {
	if profile.SuccessRate > 0.9 {
		return "high_success_rate"
	}
	if profile.AverageLatency < 50*time.Millisecond {
		return "low_latency"
	}
	if profile.UsageCount > 100 {
		return "proven_reliability"
	}
	if profile.Type == "protocol" && context.Protocol != "" {
		return "protocol_match"
	}
	return "general_recommendation"
}

// adaptProfileParameters адаптирует параметры профиля
func (apm *AdaptiveProfileManagerImpl) adaptProfileParameters(
	profile *AdaptiveProfile, feedback *types.AdaptationFeedback,
) {
	if profile.Parameters == nil {
		profile.Parameters = make(map[string]interface{})
	}

	// Адаптируем параметры на основе обратной связи
	apm.adaptAggressiveness(profile, feedback.Success)

	// Адаптируем параметры задержки
	apm.adaptDelayFactor(profile, feedback.Latency)
}

// adaptAggressiveness адаптирует агрессивность профиля
func (apm *AdaptiveProfileManagerImpl) adaptAggressiveness(profile *AdaptiveProfile, success bool) {
	val, exists := profile.Parameters["aggressiveness"]
	if !exists {
		if success {
			profile.Parameters["aggressiveness"] = 0.5
		} else {
			profile.Parameters["aggressiveness"] = 0.3
		}
		return
	}

	aggressiveness, ok := val.(float64)
	if !ok {
		return
	}

	if success {
		profile.Parameters["aggressiveness"] = math.Min(aggressiveness+apm.learningRate, 1.0)
	} else {
		profile.Parameters["aggressiveness"] = math.Max(aggressiveness-apm.learningRate, 0.0)
	}
}

// adaptDelayFactor адаптирует фактор задержки профиля
func (apm *AdaptiveProfileManagerImpl) adaptDelayFactor(profile *AdaptiveProfile, latency time.Duration) {
	if latency <= 0 {
		return
	}

	val, exists := profile.Parameters["delay_factor"]
	if !exists {
		profile.Parameters["delay_factor"] = 1.0
		return
	}

	delayFactor, ok := val.(float64)
	if !ok {
		return
	}

	// Адаптируем фактор задержки на основе фактической задержки
	targetLatency := 50 * time.Millisecond
	ratio := float64(latency) / float64(targetLatency)
	newDelayFactor := delayFactor * ratio
	profile.Parameters["delay_factor"] = math.Max(0.1, math.Min(newDelayFactor, 2.0))
}

// AddProfile добавляет новый адаптивный профиль
func (apm *AdaptiveProfileManagerImpl) AddProfile(name string, profile *AdaptiveProfile) {
	apm.mutex.Lock()
	defer apm.mutex.Unlock()

	profile.Name = name
	profile.LastUsed = time.Now()
	profile.LastAdaptation = time.Now()

	apm.profiles[name] = profile
}

// GetProfile возвращает адаптивный профиль
func (apm *AdaptiveProfileManagerImpl) GetProfile(name string) (*AdaptiveProfile, bool) {
	apm.mutex.RLock()
	defer apm.mutex.RUnlock()

	profile, exists := apm.profiles[name]
	if !exists {
		return nil, false
	}

	// Возвращаем копию для безопасности
	profileCopy := *profile
	return &profileCopy, true
}

// GetProfileStats возвращает статистику профилей
func (apm *AdaptiveProfileManagerImpl) GetProfileStats() map[string]*AdaptiveProfileStats {
	apm.mutex.RLock()
	defer apm.mutex.RUnlock()

	stats := make(map[string]*AdaptiveProfileStats)
	for name, profile := range apm.profiles {
		stats[name] = &AdaptiveProfileStats{
			Name:            name,
			Type:            profile.Type,
			Effectiveness:   profile.Effectiveness,
			UsageCount:      profile.UsageCount,
			SuccessRate:     profile.SuccessRate,
			AverageLatency:  profile.AverageLatency,
			AdaptationCount: profile.AdaptationCount,
			LastUsed:        profile.LastUsed,
			LastAdaptation:  profile.LastAdaptation,
		}
	}

	return stats
}

// SetLearningRate устанавливает скорость обучения
func (apm *AdaptiveProfileManagerImpl) SetLearningRate(rate float64) {
	apm.mutex.Lock()
	defer apm.mutex.Unlock()

	apm.learningRate = rate
}

// SetAdaptationThreshold устанавливает порог адаптации
func (apm *AdaptiveProfileManagerImpl) SetAdaptationThreshold(threshold float64) {
	apm.mutex.Lock()
	defer apm.mutex.Unlock()

	apm.adaptationThreshold = threshold
}

// AdaptiveProfileStats - статистика адаптивного профиля
type AdaptiveProfileStats struct {
	Name            string        `json:"name"`
	Type            string        `json:"type"`
	Effectiveness   float64       `json:"effectiveness"`
	UsageCount      int64         `json:"usage_count"`
	SuccessRate     float64       `json:"success_rate"`
	AverageLatency  time.Duration `json:"average_latency"`
	AdaptationCount int64         `json:"adaptation_count"`
	LastUsed        time.Time     `json:"last_used"`
	LastAdaptation  time.Time     `json:"last_adaptation"`
}

// LearnFromTraffic обучается на основе трафика
func (apm *AdaptiveProfileManagerImpl) LearnFromTraffic(data []byte, profileName string, success bool) {
	apm.mutex.Lock()
	defer apm.mutex.Unlock()

	profile, exists := apm.profiles[profileName]
	if !exists {
		return
	}

	// Обновляем статистику профиля
	profile.UsageCount++
	profile.LastUsed = time.Now()

	// Обновляем успешность
	if success {
		profile.SuccessRate = (profile.SuccessRate*float64(profile.UsageCount-1) + 1.0) / float64(profile.UsageCount)
	} else {
		profile.SuccessRate = (profile.SuccessRate*float64(profile.UsageCount-1) + 0.0) / float64(profile.UsageCount)
	}
}
