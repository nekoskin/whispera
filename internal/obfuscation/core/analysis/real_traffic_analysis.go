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







type RealTrafficAnalysis struct {
	TrafficData    []TrafficRecord
	Analysis       *TrafficAnalysis
	Profiles       map[string]*TrafficProfile
	LastUpdate     time.Time
	UpdateInterval time.Duration
}




func NewRealTrafficAnalysis() *RealTrafficAnalysis {
	return &RealTrafficAnalysis{
		TrafficData:    make([]TrafficRecord, 0),
		Analysis:       nil,
		Profiles:       make(map[string]*TrafficProfile),
		LastUpdate:     time.Now(),
		UpdateInterval: 5 * time.Minute,
	}
}

func (rta *RealTrafficAnalysis) LoadRealTrafficData(csvFile string) error {
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

func (rta *RealTrafficAnalysis) parseTrafficCSV(filename string) ([]TrafficRecord, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer util.SafeClose("file", file.Close)

	reader := csv.NewReader(file)
	records := make([]TrafficRecord, 0)

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

		trafficRecord, err := rta.parseTrafficRecord(record)
		if err != nil {
			continue
		}

		records = append(records, trafficRecord)
	}

	return records, nil
}

func (rta *RealTrafficAnalysis) parseTrafficRecord(record []string) (TrafficRecord, error) {
	if len(record) < 8 {
		return TrafficRecord{}, fmt.Errorf("недостаточно полей в записи")
	}

	timestamp, err := time.Parse("2006-01-02 15:04:05", record[0])
	if err != nil {
		return TrafficRecord{}, err
	}

	size, err := strconv.Atoi(record[1])
	if err != nil {
		return TrafficRecord{}, err
	}

	direction := record[2]

	service := record[3]

	features, err := rta.parseFeatures(record[4])
	if err != nil {
		return TrafficRecord{}, err
	}

	deviceType := record[5]

	networkType := record[6]

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

func (rta *RealTrafficAnalysis) parseFeatures(featuresStr string) ([]float64, error) {
	features := make([]float64, 0)

	parts := strings.Split(featuresStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		value, err := strconv.ParseFloat(part, 64)
		if err != nil {
			continue
		}

		features = append(features, value)
	}

	return features, nil
}

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

	for _, record := range records {
		analysis.TotalBytes += int64(record.Size)

		sizeCategory := rta.categorizeSize(record.Size)
		analysis.SizeDistribution[sizeCategory]++

		rta.updateServiceStats(analysis, record)

		hour := record.Timestamp.Hour()
		timeCategory := rta.categorizeTime(hour)
		analysis.TimePatterns[timeCategory]++

		analysis.DeviceStats[record.DeviceType]++

		analysis.NetworkStats[record.NetworkType]++

		analysis.LocationStats[record.Location]++
	}

	if analysis.TotalPackets > 0 {
		analysis.AverageSize = float64(analysis.TotalSize) / float64(analysis.TotalPackets)
	}

	return analysis
}

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

func (rta *RealTrafficAnalysis) updateProfilesFromRealData(analysis *TrafficAnalysis) {
	for service := range analysis.ServiceStats {
		profile := rta.createDynamicProfile(service, service)
		rta.analyzeServiceTraffic(profile, service)
		rta.Profiles[service] = profile
	}
}

func (rta *RealTrafficAnalysis) createDynamicProfile(name, serviceType string) *TrafficProfile {
	_ = serviceType

	profile := &TrafficProfile{
		Name: name,
	}

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

func (rta *RealTrafficAnalysis) analyzeServiceTraffic(profile *TrafficProfile, serviceType string) {
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

func (rta *RealTrafficAnalysis) analyzeVKTraffic(profile *TrafficProfile) {
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

func (rta *RealTrafficAnalysis) analyzeYandexTraffic(profile *TrafficProfile) {
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

func (rta *RealTrafficAnalysis) analyzeMailruTraffic(profile *TrafficProfile) {
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

func (rta *RealTrafficAnalysis) analyzeOzonTraffic(profile *TrafficProfile) {
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

func (rta *RealTrafficAnalysis) analyzeGenericTraffic(profile *TrafficProfile) {
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

func (rta *RealTrafficAnalysis) updateProfileFromRealTraffic(profile *TrafficProfile, serviceType string) {
	if analysis, exists := rta.Analysis.ServiceStats[serviceType]; exists {
		profile.ServiceType = serviceType
		profile.PacketSizes = SizeDistribution{
			Bins: []int{
				analysis.MinSize,
				analysis.MinSize + (analysis.MaxSize-analysis.MinSize)/4,
				analysis.MinSize + (analysis.MaxSize-analysis.MinSize)/2,
				analysis.MinSize + 3*(analysis.MaxSize-analysis.MinSize)/4,
				analysis.MaxSize,
			},
		}

		stdDev := analysis.StdDev
		if stdDev > 0 {
			profile.PacketSizes.Weights = []float64{0.2, 0.3, 0.3, 0.15, 0.05}
		} else {
			profile.PacketSizes.Weights = []float64{0.1, 0.2, 0.4, 0.2, 0.1}
		}

		profile.Effectiveness = math.Min(0.9, 0.5+stdDev/1000.0)
	}
}

func (rta *RealTrafficAnalysis) GetTrafficData() []TrafficRecord {
	return rta.TrafficData
}

func (rta *RealTrafficAnalysis) GetAnalysis() *TrafficAnalysis {
	return rta.Analysis
}

func (rta *RealTrafficAnalysis) GetProfiles() map[string]*TrafficProfile {
	return rta.Profiles
}

func (rta *RealTrafficAnalysis) GetProfile(name string) *TrafficProfile {
	return rta.Profiles[name]
}

func (rta *RealTrafficAnalysis) IsUpdateNeeded() bool {
	return time.Since(rta.LastUpdate) > rta.UpdateInterval
}

func (rta *RealTrafficAnalysis) UpdateIfNeeded() {
	if rta.IsUpdateNeeded() {
		rta.Analysis = rta.analyzeRealTraffic(rta.TrafficData)
		rta.updateProfilesFromRealData(rta.Analysis)

		for serviceType, profile := range rta.Profiles {
			rta.updateProfileFromRealTraffic(profile, serviceType)
		}

		rta.LastUpdate = time.Now()
	}
}

func (rta *RealTrafficAnalysis) SetUpdateInterval(interval time.Duration) {
	rta.UpdateInterval = interval
}

func (rta *RealTrafficAnalysis) GetUpdateInterval() time.Duration {
	return rta.UpdateInterval
}

func (rta *RealTrafficAnalysis) ClearData() {
	rta.TrafficData = make([]TrafficRecord, 0)
	rta.Analysis = nil
	rta.Profiles = make(map[string]*TrafficProfile)
	rta.LastUpdate = time.Now()
}

func (rta *RealTrafficAnalysis) GetDataSize() int {
	return len(rta.TrafficData)
}

func (rta *RealTrafficAnalysis) GetLastUpdate() time.Time {
	return rta.LastUpdate
}
