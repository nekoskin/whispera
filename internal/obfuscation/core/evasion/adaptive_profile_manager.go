package evasion

import (
	"fmt"
	"math"
	"sync"
	"time"
	"whispera/internal/obfuscation/core/types"
)

const (
	directionOutbound   = "outbound"
	networkTypeMobile   = "mobile"
	profileTypeProtocol = "protocol"
)

// AdaptiveProfile - адаптивный профиль
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

// ProfileRecommendation - рекомендация профиля (используем из types)
type ProfileRecommendation = types.ProfileRecommendation

// AdaptationFeedback - обратная связь для адаптации (используем из types)
type AdaptationFeedback = types.AdaptationFeedback

// TrafficContext, NetworkInfo, UserBehavior определены в types/types.go
// Используем типы из пакета types

// AdaptiveProfileManager - интерфейс адаптивного управления профилями (используем из types)
type AdaptiveProfileManager = types.AdaptiveProfileManager

// AdaptiveProfileManagerImpl - реализация адаптивного управления профилями
type AdaptiveProfileManagerImpl struct {
	profiles            map[string]*AdaptiveProfile
	recommendations     map[string]*ProfileRecommendation
	feedback            map[string]*AdaptationFeedback
	mutex               sync.RWMutex
	learningRate        float64
	adaptationThreshold float64
	effectiveness       map[string]float64
}

// AdaptiveProfileStats - статистика адаптивного профиля
type AdaptiveProfileStats struct {
	Name            string
	Type            string
	Effectiveness   float64
	UsageCount      int64
	LastUsed        time.Time
	AdaptationCount int64
	SuccessRate     float64
	AverageLatency  time.Duration
	LastAdaptation  time.Time
}

// NewAdaptiveProfileManager создает новый менеджер адаптивных профилей
func NewAdaptiveProfileManager() AdaptiveProfileManager {
	return &AdaptiveProfileManagerImpl{
		profiles:            make(map[string]*AdaptiveProfile),
		recommendations:     make(map[string]*ProfileRecommendation),
		feedback:            make(map[string]*AdaptationFeedback),
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
func (apm *AdaptiveProfileManagerImpl) GetProfileRecommendations(context *types.TrafficContext) []*types.ProfileRecommendation {
	apm.mutex.RLock()
	defer apm.mutex.RUnlock()

	var recommendations []*types.ProfileRecommendation

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

// LearnFromTraffic обучается на основе трафика
func (apm *AdaptiveProfileManagerImpl) LearnFromTraffic(data []byte, profileName string, success bool) {
	// Простая реализация обучения
	if success {
		apm.effectiveness[profileName] += 0.1
	} else {
		apm.effectiveness[profileName] -= 0.05
	}

	// Ограничиваем значения
	if apm.effectiveness[profileName] > 1.0 {
		apm.effectiveness[profileName] = 1.0
	}
	if apm.effectiveness[profileName] < 0.0 {
		apm.effectiveness[profileName] = 0.0
	}
}

// calculateProfileScore вычисляет оценку профиля для контекста
func (apm *AdaptiveProfileManagerImpl) calculateProfileScore(profile *AdaptiveProfile, context *types.TrafficContext) float64 {
	// Use context parameter for score calculation
	_ = context.Direction
	_ = context.Protocol

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
func (apm *AdaptiveProfileManagerImpl) calculateTypeScore(profile *AdaptiveProfile, context *types.TrafficContext) float64 {
	switch profile.Type {
	case profileTypeProtocol:
		if context.Protocol == "udp" || context.Protocol == "tcp" {
			return 0.9
		}
		return 0.5
	case "social":
		if context.Direction == directionOutbound && context.Size > 100 {
			return 0.8
		}
		return 0.4
	case networkTypeMobile:
		if context.ThreatLevel > 5 {
			return 0.7
		}
		return 0.6
	case "search":
		if context.Direction == directionOutbound && context.Size < 1000 {
			return 0.8
		}
		return 0.5
	default:
		return 0.5
	}
}

// calculateConfidence вычисляет уверенность в рекомендации
func (apm *AdaptiveProfileManagerImpl) calculateConfidence(profile *AdaptiveProfile, context *types.TrafficContext) float64 {
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
func (apm *AdaptiveProfileManagerImpl) getRecommendationReason(profile *AdaptiveProfile, context *types.TrafficContext) string {
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
func (apm *AdaptiveProfileManagerImpl) adaptProfileParameters(profile *AdaptiveProfile, feedback *types.AdaptationFeedback) {
	if profile.Parameters == nil {
		profile.Parameters = make(map[string]interface{})
	}

	// Адаптируем параметры на основе обратной связи
	if feedback.Success {
		// Успешное выполнение - увеличиваем агрессивность
		if val, exists := profile.Parameters["aggressiveness"]; exists {
			if aggressiveness, ok := val.(float64); ok {
				profile.Parameters["aggressiveness"] = math.Min(aggressiveness+apm.learningRate, 1.0)
			}
		} else {
			profile.Parameters["aggressiveness"] = 0.5
		}
	} else {
		// Неудачное выполнение - уменьшаем агрессивность
		if val, exists := profile.Parameters["aggressiveness"]; exists {
			if aggressiveness, ok := val.(float64); ok {
				profile.Parameters["aggressiveness"] = math.Max(aggressiveness-apm.learningRate, 0.0)
			}
		} else {
			profile.Parameters["aggressiveness"] = 0.3
		}
	}

	// Адаптируем параметры задержки
	if feedback.Latency > 0 {
		if val, exists := profile.Parameters["delay_factor"]; exists {
			if delayFactor, ok := val.(float64); ok {
				// Адаптируем фактор задержки на основе фактической задержки
				targetLatency := 50 * time.Millisecond
				ratio := float64(feedback.Latency) / float64(targetLatency)
				newDelayFactor := delayFactor * ratio
				profile.Parameters["delay_factor"] = math.Max(0.1, math.Min(newDelayFactor, 2.0))
			}
		} else {
			profile.Parameters["delay_factor"] = 1.0
		}
	}
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
