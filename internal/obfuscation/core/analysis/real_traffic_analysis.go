package core

import (
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"whispera/internal/util"
)

// TrafficProfile is defined in traffic_analyzer.go

// SizeDistribution is defined in traffic_analyzer.go

// IntervalDistribution is defined in traffic_analyzer.go

// BurstProfile is defined in traffic_analyzer.go

// CoverageProfile is defined in traffic_analyzer.go

// AdaptationProfile is defined in traffic_analyzer.go

// RealTrafficAnalysis - модуль для анализа реального трафика
type RealTrafficAnalysis struct {
	TrafficData    []TrafficRecord
	Analysis       *TrafficAnalysis
	Profiles       map[string]*TrafficProfile
	LastUpdate     time.Time
	UpdateInterval time.Duration
}

// TrafficRecord is defined in traffic_analyzer.go

// TrafficAnalysis is defined in traffic_analyzer.go

// ServiceStats is defined in traffic_analyzer.go

// NewRealTrafficAnalysis создает новый модуль анализа реального трафика
func NewRealTrafficAnalysis() *RealTrafficAnalysis {
	return &RealTrafficAnalysis{
		TrafficData:    make([]TrafficRecord, 0),
		Analysis:       nil,
		Profiles:       make(map[string]*TrafficProfile),
		LastUpdate:     time.Now(),
		UpdateInterval: 5 * time.Minute,
	}
}

// LoadRealTrafficData загружает данные реального трафика
func (rta *RealTrafficAnalysis) LoadRealTrafficData(csvFile string) error {
	// Загружаем данные реального трафика
	records, err := rta.parseTrafficCSV(csvFile)
	if err != nil {
		return err
	}

	rta.TrafficData = records
	rta.Analysis = rta.analyzeRealTraffic(records)
	rta.updateProfilesFromRealData(rta.Analysis)
	rta.LastUpdate = time.Now()

	return nil
}

// parseTrafficCSV парсит CSV файл с данными трафика
func (rta *RealTrafficAnalysis) parseTrafficCSV(filename string) ([]TrafficRecord, error) {
	file, err := os.Open(filename) //nolint:gosec // Filename is validated by caller
	if err != nil {
		return nil, err
	}
	defer util.SafeClose("file", file.Close)

	reader := csv.NewReader(file)
	records := make([]TrafficRecord, 0)

	// Пропускаем заголовок
	_, err = reader.Read()
	if err != nil {
		return nil, err
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Парсим запись
		trafficRecord, err := rta.parseTrafficRecord(record)
		if err != nil {
			continue // Пропускаем некорректные записи
		}

		records = append(records, trafficRecord)
	}

	return records, nil
}

// parseTrafficRecord парсит запись трафика
func (rta *RealTrafficAnalysis) parseTrafficRecord(record []string) (TrafficRecord, error) {
	if len(record) < 8 {
		return TrafficRecord{}, fmt.Errorf("недостаточно полей в записи")
	}

	// Парсим timestamp
	timestamp, err := time.Parse("2006-01-02 15:04:05", record[0])
	if err != nil {
		return TrafficRecord{}, err
	}

	// Парсим размер
	size, err := strconv.Atoi(record[1])
	if err != nil {
		return TrafficRecord{}, err
	}

	// Парсим направление
	direction := record[2]

	// Парсим сервис
	service := record[3]

	// Парсим признаки
	features, err := rta.parseFeatures(record[4])
	if err != nil {
		return TrafficRecord{}, err
	}

	// Парсим тип устройства
	deviceType := record[5]

	// Парсим тип сети
	networkType := record[6]

	// Парсим местоположение
	location := record[7]

	return TrafficRecord{
		Timestamp:   timestamp,
		Size:        size,
		Direction:   direction,
		Service:     service,
		Features:    features,
		DeviceType:  deviceType,
		NetworkType: networkType,
		Location:    location,
	}, nil
}

// parseFeatures парсит признаки
func (rta *RealTrafficAnalysis) parseFeatures(featuresStr string) ([]float64, error) {
	// Парсим признаки из строки
	features := make([]float64, 0)

	// Разделяем по запятым
	parts := strings.Split(featuresStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		value, err := strconv.ParseFloat(part, 64)
		if err != nil {
			continue // Пропускаем некорректные значения
		}

		features = append(features, value)
	}

	return features, nil
}

// analyzeRealTraffic анализирует реальный трафик
func (rta *RealTrafficAnalysis) analyzeRealTraffic(records []TrafficRecord) *TrafficAnalysis {
	analysis := &TrafficAnalysis{
		TotalPackets:     len(records),
		TotalBytes:       0,
		AverageSize:      0,
		SizeDistribution: make(map[string]int),
		Protocols:        make(map[string]int),
		Services:         make(map[string]int),
		TimingPatterns:   make(map[string]time.Duration),
		DeviceStats:      make(map[string]int),
		NetworkStats:     make(map[string]time.Duration),
		LocationStats:    make(map[string]int),
	}

	// Анализируем записи
	for _, record := range records {
		// Общий размер
		analysis.TotalBytes += int64(record.Size)

		// Распределение размеров
		sizeCategory := rta.categorizeSize(record.Size)
		analysis.SizeDistribution[sizeCategory]++

		// Статистика сервисов
		rta.updateServiceStats(analysis, record)

		// Временные паттерны
		hour := record.Timestamp.Hour()
		timeCategory := rta.categorizeTime(hour)
		analysis.TimePatterns[timeCategory]++

		// Статистика устройств
		analysis.DeviceStats[record.DeviceType]++

		// Статистика сетей
		analysis.NetworkStats[record.NetworkType]++

		// Статистика местоположений
		analysis.LocationStats[record.Location]++
	}

	// Вычисляем средний размер
	if analysis.TotalPackets > 0 {
		analysis.AverageSize = float64(analysis.TotalSize) / float64(analysis.TotalPackets)
	}

	return analysis
}

// updateServiceStats обновляет статистику сервисов
func (rta *RealTrafficAnalysis) updateServiceStats(analysis *TrafficAnalysis, record TrafficRecord) {
	service := record.Service

	stats, exists := analysis.ServiceStats[service]
	if !exists {
		stats = &ServiceStats{
			Count:       0,
			TotalSize:   0,
			AverageSize: 0,
			MinSize:     record.Size,
			MaxSize:     record.Size,
			StdDev:      0,
		}
		analysis.ServiceStats[service] = stats
	}

	stats.Count++
	stats.TotalSize += record.Size
	stats.AverageSize = float64(stats.TotalSize) / float64(stats.Count)

	if record.Size < stats.MinSize {
		stats.MinSize = record.Size
	}
	if record.Size > stats.MaxSize {
		stats.MaxSize = record.Size
	}
}

// categorizeSize категоризирует размер
func (rta *RealTrafficAnalysis) categorizeSize(size int) string {
	if size < 100 {
		return "small"
	} else if size < 1000 {
		return "medium"
	} else if size < 10000 {
		return "large"
	}
	return "very_large"
}

// categorizeTime категоризирует время
func (rta *RealTrafficAnalysis) categorizeTime(hour int) string {
	if hour >= 6 && hour < 12 {
		return "morning"
	} else if hour >= 12 && hour < 18 {
		return "afternoon"
	} else if hour >= 18 && hour < 22 {
		return "evening"
	}
	return "night"
}

// updateProfilesFromRealData обновляет профили на основе реальных данных
func (rta *RealTrafficAnalysis) updateProfilesFromRealData(analysis *TrafficAnalysis) {
	// Обновляем профили на основе реальных данных
	for service := range analysis.ServiceStats {
		profile := rta.createDynamicProfile(service, service)
		rta.analyzeServiceTraffic(profile, service)
		rta.Profiles[service] = profile
	}
}

// createDynamicProfile создает динамический профиль
func (rta *RealTrafficAnalysis) createDynamicProfile(name, serviceType string) *TrafficProfile {
	// Use serviceType parameter
	_ = serviceType

	profile := &TrafficProfile{
		Name: name,
		// ServiceType:    serviceType,
		// PacketSizes:    make([]int, 0),
		// SizeWeights:    make([]float64, 0),
		// Timings:        make([]time.Duration, 0),
		// TimingWeights:  make([]float64, 0),
		// BehavioralData: make([]byte, 0),
		// MLFeatures:     make([]float64, 0),
		// DeviceID:       "",
		// Effectiveness:  0.5,
		// UsageCount:     0,
		// LastUsed:       time.Now(),
	}

	// Инициализируем базовые значения
	profile.PacketSizes = SizeDistribution{
		Bins:    []int{64, 128, 256, 512, 1024, 2048, 4096, 8192},
		Weights: []float64{0.1, 0.2, 0.3, 0.2, 0.1, 0.05, 0.03, 0.02},
	}

	profile.Intervals = IntervalDistribution{
		Bins: []time.Duration{
			10 * time.Millisecond,
			25 * time.Millisecond,
			50 * time.Millisecond,
			100 * time.Millisecond,
			200 * time.Millisecond,
			500 * time.Millisecond,
			1000 * time.Millisecond,
			2000 * time.Millisecond,
		},
		Weights: []float64{0.05, 0.1, 0.2, 0.3, 0.2, 0.1, 0.03, 0.02},
	}

	return profile
}

// analyzeServiceTraffic анализирует трафик сервиса
func (rta *RealTrafficAnalysis) analyzeServiceTraffic(profile *TrafficProfile, serviceType string) {
	// Анализируем трафик сервиса
	switch serviceType {
	case "vk":
		rta.analyzeVKTraffic(profile)
	case "yandex":
		rta.analyzeYandexTraffic(profile)
	case "mailru":
		rta.analyzeMailruTraffic(profile)
	case "ozon":
		rta.analyzeOzonTraffic(profile)
	default:
		rta.analyzeGenericTraffic(profile)
	}
}

// analyzeVKTraffic анализирует трафик ВКонтакте
func (rta *RealTrafficAnalysis) analyzeVKTraffic(profile *TrafficProfile) {
	// Анализируем трафик ВКонтакте
	profile.PacketSizes = SizeDistribution{
		Bins:    []int{128, 256, 512, 1024, 2048, 4096},
		Weights: []float64{0.2, 0.3, 0.25, 0.15, 0.08, 0.02},
	}

	profile.Intervals = IntervalDistribution{
		Bins: []time.Duration{
			20 * time.Millisecond,
			50 * time.Millisecond,
			100 * time.Millisecond,
			200 * time.Millisecond,
			500 * time.Millisecond,
		},
		Weights: []float64{0.1, 0.3, 0.4, 0.15, 0.05},
	}
}

// analyzeYandexTraffic анализирует трафик Яндекс
func (rta *RealTrafficAnalysis) analyzeYandexTraffic(profile *TrafficProfile) {
	// Анализируем трафик Яндекс
	profile.PacketSizes = SizeDistribution{
		Bins:    []int{256, 512, 1024, 2048, 4096, 8192},
		Weights: []float64{0.15, 0.25, 0.3, 0.2, 0.08, 0.02},
	}

	profile.Intervals = IntervalDistribution{
		Bins: []time.Duration{
			30 * time.Millisecond,
			75 * time.Millisecond,
			150 * time.Millisecond,
			300 * time.Millisecond,
			600 * time.Millisecond,
		},
		Weights: []float64{0.05, 0.2, 0.4, 0.25, 0.1},
	}
}

// analyzeMailruTraffic анализирует трафик Mail.ru
func (rta *RealTrafficAnalysis) analyzeMailruTraffic(profile *TrafficProfile) {
	// Анализируем трафик Mail.ru
	profile.PacketSizes = SizeDistribution{
		Bins:    []int{128, 256, 512, 1024, 2048, 4096},
		Weights: []float64{0.25, 0.3, 0.25, 0.15, 0.04, 0.01},
	}

	profile.Intervals = IntervalDistribution{
		Bins: []time.Duration{
			25 * time.Millisecond,
			60 * time.Millisecond,
			120 * time.Millisecond,
			250 * time.Millisecond,
			500 * time.Millisecond,
		},
		Weights: []float64{0.1, 0.25, 0.35, 0.2, 0.1},
	}
}

// analyzeOzonTraffic анализирует трафик Ozon
func (rta *RealTrafficAnalysis) analyzeOzonTraffic(profile *TrafficProfile) {
	// Анализируем трафик Ozon
	profile.PacketSizes = SizeDistribution{
		Bins:    []int{256, 512, 1024, 2048, 4096, 8192},
		Weights: []float64{0.1, 0.2, 0.3, 0.25, 0.12, 0.03},
	}

	profile.Intervals = IntervalDistribution{
		Bins: []time.Duration{
			40 * time.Millisecond,
			100 * time.Millisecond,
			200 * time.Millisecond,
			400 * time.Millisecond,
			800 * time.Millisecond,
		},
		Weights: []float64{0.05, 0.15, 0.35, 0.3, 0.15},
	}
}

// analyzeGenericTraffic анализирует общий трафик
func (rta *RealTrafficAnalysis) analyzeGenericTraffic(profile *TrafficProfile) {
	// Анализируем общий трафик
	profile.PacketSizes = SizeDistribution{
		Bins:    []int{64, 128, 256, 512, 1024, 2048, 4096},
		Weights: []float64{0.1, 0.2, 0.3, 0.25, 0.1, 0.04, 0.01},
	}

	profile.Intervals = IntervalDistribution{
		Bins: []time.Duration{
			15 * time.Millisecond,
			40 * time.Millisecond,
			80 * time.Millisecond,
			160 * time.Millisecond,
			320 * time.Millisecond,
		},
		Weights: []float64{0.1, 0.3, 0.4, 0.15, 0.05},
	}
}

// updateProfileFromRealTraffic обновляет профиль на основе реального трафика
func (rta *RealTrafficAnalysis) updateProfileFromRealTraffic(profile *TrafficProfile, serviceType string) {
	// Обновляем профиль на основе реального трафика
	if analysis, exists := rta.Analysis.ServiceStats[serviceType]; exists {
		// Use serviceType to determine specific updates
		profile.ServiceType = serviceType
		// Обновляем размеры пакетов
		profile.PacketSizes = SizeDistribution{
			Bins: []int{
				analysis.MinSize,
				analysis.MinSize + (analysis.MaxSize-analysis.MinSize)/4,
				analysis.MinSize + (analysis.MaxSize-analysis.MinSize)/2,
				analysis.MinSize + 3*(analysis.MaxSize-analysis.MinSize)/4,
				analysis.MaxSize,
			},
		}

		// Обновляем веса на основе стандартного отклонения
		stdDev := analysis.StdDev
		if stdDev > 0 {
			profile.PacketSizes.Weights = []float64{0.2, 0.3, 0.3, 0.15, 0.05}
		} else {
			profile.PacketSizes.Weights = []float64{0.1, 0.2, 0.4, 0.2, 0.1}
		}

		// Обновляем эффективность
		profile.Effectiveness = math.Min(0.9, 0.5+stdDev/1000.0)
	}
}

// GetTrafficData возвращает данные трафика
func (rta *RealTrafficAnalysis) GetTrafficData() []TrafficRecord {
	return rta.TrafficData
}

// GetAnalysis возвращает анализ трафика
func (rta *RealTrafficAnalysis) GetAnalysis() *TrafficAnalysis {
	return rta.Analysis
}

// GetProfiles возвращает профили
func (rta *RealTrafficAnalysis) GetProfiles() map[string]*TrafficProfile {
	return rta.Profiles
}

// GetProfile возвращает профиль по имени
func (rta *RealTrafficAnalysis) GetProfile(name string) *TrafficProfile {
	return rta.Profiles[name]
}

// IsUpdateNeeded проверяет, нужно ли обновление
func (rta *RealTrafficAnalysis) IsUpdateNeeded() bool {
	return time.Since(rta.LastUpdate) > rta.UpdateInterval
}

// UpdateIfNeeded обновляет данные если нужно
func (rta *RealTrafficAnalysis) UpdateIfNeeded() {
	if rta.IsUpdateNeeded() {
		rta.Analysis = rta.analyzeRealTraffic(rta.TrafficData)
		rta.updateProfilesFromRealData(rta.Analysis)

		// Update profiles from real traffic
		for serviceType, profile := range rta.Profiles {
			rta.updateProfileFromRealTraffic(profile, serviceType)
		}

		rta.LastUpdate = time.Now()
	}
}

// SetUpdateInterval устанавливает интервал обновления
func (rta *RealTrafficAnalysis) SetUpdateInterval(interval time.Duration) {
	rta.UpdateInterval = interval
}

// GetUpdateInterval возвращает интервал обновления
func (rta *RealTrafficAnalysis) GetUpdateInterval() time.Duration {
	return rta.UpdateInterval
}

// ClearData очищает данные
func (rta *RealTrafficAnalysis) ClearData() {
	rta.TrafficData = make([]TrafficRecord, 0)
	rta.Analysis = nil
	rta.Profiles = make(map[string]*TrafficProfile)
	rta.LastUpdate = time.Now()
}

// GetDataSize возвращает размер данных
func (rta *RealTrafficAnalysis) GetDataSize() int {
	return len(rta.TrafficData)
}

// GetLastUpdate возвращает время последнего обновления
func (rta *RealTrafficAnalysis) GetLastUpdate() time.Time {
	return rta.LastUpdate
}
