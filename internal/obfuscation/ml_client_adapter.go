package obfuscation

import (
	"whispera/internal/obfuscation/core/evasion"
	"whispera/internal/obfuscation/core/types"
)

// init инициализирует адаптер для реального ML клиента в evasion пакете
//
//nolint:gochecknoinits // Required for ML client adapter initialization
func init() {
	// Переопределяем переменную NewPythonMLClientLocal в evasion пакете
	// для использования реального Python ML клиента вместо заглушки
	evasion.NewPythonMLClientLocal = func() evasion.PythonMLClient {
		realClient := NewPythonMLClientLocal()
		return &PythonMLClientEvasionAdapter{client: realClient}
	}
}

// PythonMLClientEvasionAdapter адаптирует реальный PythonMLClient к интерфейсу evasion.PythonMLClient
type PythonMLClientEvasionAdapter struct {
	client *PythonMLClient
}

func (a *PythonMLClientEvasionAdapter) ProcessTraffic(data []byte, context *types.UnifiedTrafficContext) ([]byte, error) {
	// Конвертируем UnifiedTrafficContext в параметры для PredictTraffic
	protocol := "tcp"
	direction := "outbound"
	if context != nil {
		if context.Protocol != "" {
			protocol = context.Protocol
		}
		if context.Direction != "" {
			direction = context.Direction
		}
	}

	// Используем реальный ML клиент для предсказания
	response, err := a.client.PredictTraffic(data, protocol, direction)
	if err != nil {
		// В случае ошибки возвращаем исходные данные (graceful degradation)
		return data, nil
	}

	// Применяем обфускацию на основе ML предсказания
	if len(response.Predictions) > 0 {
		pred := response.Predictions[0]
		// Если обнаружен DPI, применяем дополнительную обфускацию
		if pred.DPIType > 0 && pred.Confidence > 0.7 {
			// Можно применить дополнительную обфускацию здесь
			_ = pred // Suppress unused warning for future implementation
		}
	}

	return data, nil
}

func (a *PythonMLClientEvasionAdapter) HealthCheck() error {
	return a.client.HealthCheck()
}

func (a *PythonMLClientEvasionAdapter) LoadModels() error {
	return a.client.LoadModels()
}
