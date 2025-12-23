package obfuscation

import (
	"log"
	"sync"
	"time"

	"whispera/internal/obfuscation/core/types"
)

// ProtocolRecommendation рекомендация протокола от ML системы
type ProtocolRecommendation struct {
	Protocol       string  // "tls", "dtls", "noise_ik", "websocket", "http2"
	Confidence     float64 // Уверенность в рекомендации (0.0-1.0)
	Reason         string  // Причина рекомендации
	ExpectedEffectiveness float64 // Ожидаемая эффективность обхода DPI (0.0-1.0)
	ThreatLevel    int     // Уровень угрозы DPI (0-10)
}

// ProtocolSelector выбирает оптимальный протокол на основе ML анализа
type ProtocolSelector struct {
	mlSystem      *UnifiedMLSystem
	recommendations map[string]*ProtocolRecommendation // Кэш рекомендаций по протоколу
	lastAnalysis  time.Time
	mu            sync.RWMutex
	history       []ProtocolRecommendation // История рекомендаций
	maxHistory    int
}

// NewProtocolSelector создает новый селектор протоколов
func NewProtocolSelector(mlSystem *UnifiedMLSystem) *ProtocolSelector {
	return &ProtocolSelector{
		mlSystem:      mlSystem,
		recommendations: make(map[string]*ProtocolRecommendation),
		maxHistory:     100,
	}
}

// SelectProtocol выбирает оптимальный протокол на основе ML анализа
func (ps *ProtocolSelector) SelectProtocol(networkConditions *NetworkConditions) (*ProtocolRecommendation, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Если ML система недоступна, используем базовую логику
	if ps.mlSystem == nil {
		return ps.getDefaultRecommendation(networkConditions), nil
	}

	// Создаем тестовый пакет для анализа
	testPacket := ps.createTestPacket(networkConditions)

	// Получаем предсказание от ML системы напрямую
	var response *types.MLPredictionResponse
	var err error
	
	if ps.mlSystem != nil && ps.mlSystem.mlClient != nil {
		response, err = ps.mlSystem.mlClient.PredictTraffic(testPacket, "protocol_selection", "outbound")
		if err != nil {
			log.Printf("[ProtocolSelector] ML prediction failed: %v, using default", err)
			return ps.getDefaultRecommendation(networkConditions), nil
		}
	} else {
		// ML система недоступна - используем базовую логику
		return ps.getDefaultRecommendation(networkConditions), nil
	}

	// Анализируем предсказание и выбираем протокол
	recommendation := ps.analyzeMLPrediction(response, networkConditions)

	// Кэшируем рекомендацию
	ps.recommendations[networkConditions.NetworkType] = recommendation
	ps.lastAnalysis = time.Now()

	// Добавляем в историю
	ps.history = append(ps.history, *recommendation)
	if len(ps.history) > ps.maxHistory {
		ps.history = ps.history[1:]
	}

	return recommendation, nil
}

// createTestPacket создает тестовый пакет для ML анализа
func (ps *ProtocolSelector) createTestPacket(conditions *NetworkConditions) []byte {
	// Создаем тестовый пакет, который отражает текущие условия сети
	testPacket := make([]byte, 128)
	
	// Заполняем пакет данными, отражающими условия сети
	testPacket[0] = byte(conditions.ThreatLevel)
	testPacket[1] = byte(conditions.NetworkType[0]) // Первый символ типа сети
	
	// Добавляем информацию о латентности
	latencyBytes := make([]byte, 8)
	latencyBytes[0] = byte(conditions.Latency.Milliseconds() / 10)
	copy(testPacket[2:10], latencyBytes)
	
	return testPacket
}

// analyzeMLPrediction анализирует предсказание ML и выбирает протокол
func (ps *ProtocolSelector) analyzeMLPrediction(response *types.MLPredictionResponse, conditions *NetworkConditions) *ProtocolRecommendation {
	if response == nil || len(response.Predictions) == 0 {
		return ps.getDefaultRecommendation(conditions)
	}

	pred := response.Predictions[0]
	recommendation := &ProtocolRecommendation{
        Confidence:            pred.Confidence,
        ExpectedEffectiveness: 1.0 - float64(pred.DPIType)*0.1, // Обратная зависимость от типа DPI
        ThreatLevel:           conditions.ThreatLevel,
	}

	// Выбираем протокол на основе типа DPI и условий сети
	switch {
	case pred.DPIType >= 4: // ML-based Detection - используем TLS для максимальной маскировки
		recommendation.Protocol = "tls"
		recommendation.Reason = "ML-based DPI detected, using TLS for maximum evasion"
		recommendation.ExpectedEffectiveness = 0.85

	case pred.DPIType >= 3: // Statistical Analysis - используем DTLS
		recommendation.Protocol = "dtls"
		recommendation.Reason = "Statistical DPI detected, using DTLS for UDP traffic"
		recommendation.ExpectedEffectiveness = 0.75

	case pred.DPIType >= 2: // Flow Analysis - используем TLS с обфускацией
		recommendation.Protocol = "tls"
		recommendation.Reason = "Flow analysis detected, using TLS with obfuscation"
		recommendation.ExpectedEffectiveness = 0.70

	case pred.DPIType >= 1: // Deep Packet Inspection - используем TLS или Noise IK в зависимости от условий
		if conditions.ThreatLevel >= 7 {
			recommendation.Protocol = "tls"
			recommendation.Reason = "High threat level with DPI, using TLS"
			recommendation.ExpectedEffectiveness = 0.80
		} else {
			recommendation.Protocol = "noise_ik"
			recommendation.Reason = "Low-moderate threat with DPI, using Noise IK"
			recommendation.ExpectedEffectiveness = 0.65
		}

	default: // No DPI detected - используем Noise IK для производительности
		recommendation.Protocol = "noise_ik"
		recommendation.Reason = "No DPI detected, using Noise IK for performance"
		recommendation.ExpectedEffectiveness = 0.90
	}

	// Адаптация под тип сети
	if conditions.NetworkType == "corporate" || conditions.NetworkType == "government" {
		// Для корпоративных/государственных сетей предпочитаем TLS
		if recommendation.Protocol == "noise_ik" {
			recommendation.Protocol = "tls"
			recommendation.Reason += " (switched to TLS for corporate network)"
			recommendation.ExpectedEffectiveness += 0.1
		}
	}

	// Учитываем латентность
	if conditions.Latency > 200*time.Millisecond {
		// Высокая латентность - предпочитаем UDP (DTLS)
		if recommendation.Protocol == "tls" {
			recommendation.Protocol = "dtls"
			recommendation.Reason += " (switched to DTLS for high latency)"
		}
	}

	return recommendation
}

// getDefaultRecommendation возвращает рекомендацию по умолчанию
func (ps *ProtocolSelector) getDefaultRecommendation(conditions *NetworkConditions) *ProtocolRecommendation {
	recommendation := &ProtocolRecommendation{
		ThreatLevel:    conditions.ThreatLevel,
		Confidence:     0.5,
		Reason:         "Default recommendation (ML unavailable)",
		ExpectedEffectiveness: 0.6,
	}

	// Базовая логика выбора
	switch {
	case conditions.ThreatLevel >= 8:
		recommendation.Protocol = "tls"
		recommendation.ExpectedEffectiveness = 0.85
	case conditions.ThreatLevel >= 6:
		recommendation.Protocol = "dtls"
		recommendation.ExpectedEffectiveness = 0.75
	case conditions.ThreatLevel >= 4:
		recommendation.Protocol = "noise_ik"
		recommendation.ExpectedEffectiveness = 0.65
	default:
		recommendation.Protocol = "noise_ik"
		recommendation.ExpectedEffectiveness = 0.90
	}

	return recommendation
}

// NetworkConditions условия сети для анализа
type NetworkConditions struct {
	ThreatLevel  int           // Уровень угрозы DPI (0-10)
	NetworkType  string        // Тип сети: "corporate", "mobile", "public_wifi", "government"
	Latency      time.Duration // Латентность сети
	Bandwidth    int           // Пропускная способность (Mbps)
	PacketLoss   float64       // Потеря пакетов (0.0-1.0)
	Jitter       time.Duration // Джиттер
}

// ShouldUseTLS определяет, нужно ли использовать TLS на основе ML анализа
func (ps *ProtocolSelector) ShouldUseTLS(conditions *NetworkConditions) (bool, float64, error) {
	recommendation, err := ps.SelectProtocol(conditions)
	if err != nil {
		return false, 0.0, err
	}

	// Используем TLS если рекомендован TLS или DTLS
	useTLS := recommendation.Protocol == "tls" || recommendation.Protocol == "dtls"
	return useTLS, recommendation.Confidence, nil
}

// GetRecommendationHistory возвращает историю рекомендаций
func (ps *ProtocolSelector) GetRecommendationHistory() []ProtocolRecommendation {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	history := make([]ProtocolRecommendation, len(ps.history))
	copy(history, ps.history)
	return history
}

// GetLastRecommendation возвращает последнюю рекомендацию для типа сети
func (ps *ProtocolSelector) GetLastRecommendation(networkType string) *ProtocolRecommendation {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	return ps.recommendations[networkType]
}

