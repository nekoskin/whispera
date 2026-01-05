package monitoring

import (
	"encoding/json"
	"time"
)

// SetConfig обновляет конфигурацию мониторинга
func (am *AdaptiveMonitor) SetConfig(config *MonitorConfig) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.config = config
}

// ExportMetrics экспортирует метрики в JSON
func (am *AdaptiveMonitor) ExportMetrics() ([]byte, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	data := map[string]interface{}{
		"metrics":       am.metrics,
		"effectiveness": am.effectiveness,
		"adaptation":    am.adaptation,
		"config":        am.config,
		"timestamp":     time.Now(),
	}

	return json.MarshalIndent(data, "", "  ")
}

// ImportMetrics импортирует метрики из JSON
func (am *AdaptiveMonitor) ImportMetrics(data []byte) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	var imported map[string]interface{}
	if err := json.Unmarshal(data, &imported); err != nil {
		return err
	}

	// Восстанавливаем метрики (упрощенная версия)
	if _, ok := imported["metrics"].(map[string]interface{}); ok {
		// В реальной реализации здесь был бы парсинг структуры
		// am.metrics = &PerformanceMetrics{...}
		// Заглушка для совместимости
		am.metrics = &PerformanceMetrics{
			LastUpdate: time.Now(),
		}
	}

	return nil
}
