package core

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"whispera/internal/util"
)

type TrafficRecord struct {
	Timestamp   time.Time
	Size        int
	Direction   string
	Protocol    string
	Service     string
	Features    []float64
	Duration    time.Duration
	SourceIP    string
	DestIP      string
	SourcePort  int
	DestPort    int
	DeviceType  string
	NetworkType string
	Location    string
}

type TrafficAnalysis struct {
	TotalPackets     int
	TotalBytes       int64
	AverageSize      float64
	SizeStdDev       float64
	MinSize          int
	MaxSize          int
	AverageInterval  time.Duration
	IntervalStdDev   time.Duration
	BurstFrequency   float64
	SessionDuration  time.Duration
	Protocols        map[string]int
	Services         map[string]int
	SizeDistribution map[string]int
	TimingPatterns   map[string]time.Duration
	TotalSize        int64
	ServiceStats     map[string]*ServiceStats
	TimePatterns     map[string]time.Duration
	DeviceStats      map[string]int
	NetworkStats     map[string]time.Duration
	LocationStats    map[string]int
	PacketSizes      []int
	Intervals        []time.Duration
	Features         [][]float64
	TotalRecords     int
	StdDev           float64
}

type SizeDistribution struct {
	Min     int
	Max     int
	Mean    float64
	StdDev  float64
	Bins    []int
	Weights []float64
}

type IntervalDistribution struct {
	Min     time.Duration
	Max     time.Duration
	Mean    time.Duration
	StdDev  time.Duration
	Pattern string
	Bins    []time.Duration
	Weights []float64
}

type BurstProfile struct {
	Probability float64
	MinBurst    int
	MaxBurst    int
	BurstGap    time.Duration
	MinSize     int
	MaxSize     int
	MinInterval time.Duration
	MaxInterval time.Duration
	Frequency   float64
	Enabled     bool
}

type CoverageProfile struct {
	Enabled        bool
	Probability    float64
	MinSize        int
	MaxSize        int
	Interval       time.Duration
	MinCoverage    float64
	MaxCoverage    float64
	TargetCoverage float64
	Coverage       float64
}

type AdaptationProfile struct {
	Enabled             bool
	Sensitivity         float64
	LearningRate        float64
	AdaptationThreshold float64
}

type ServiceStats struct {
	Count       int
	TotalSize   int
	AverageSize float64
	MinSize     int
	MaxSize     int
	StdDev      float64
}

type TrafficProfile struct {
	Name                 string
	Type                 string
	PacketSizes          SizeDistribution
	Intervals            IntervalDistribution
	BurstPatterns        BurstProfile
	Coverage             CoverageProfile
	Adaptation           AdaptationProfile
	CreatedAt            time.Time
	LastUsed             time.Time
	UsageCount           int
	SizeWeights          []float64
	SizeDistribution     *SizeDistribution
	IntervalDistribution *IntervalDistribution
	BurstProfile         *BurstProfile
	CoverageProfile      *CoverageProfile
	AdaptationProfile    *AdaptationProfile
	ServiceType          string
	Timings              []time.Duration
	TimingWeights        []float64
	BehavioralData       map[string]interface{}
	MLFeatures           []float64
	DeviceID             string
	Effectiveness        float64
}

type TrafficRecordCSV struct {
	TrafficClass int       `json:"traffic_class"`
	DPIType      int       `json:"dpi_type"`
	IsAnomaly    int       `json:"is_anomaly"`
	Timestamp    float64   `json:"timestamp"`
	Features     []float64 `json:"features"`
}

type TrafficAnalyzerImpl struct {
	records  []TrafficRecord
	analysis *TrafficAnalysis
}


func NewTrafficAnalyzerCSV() *TrafficAnalyzerImpl {
	return &TrafficAnalyzerImpl{
		records: make([]TrafficRecord, 0),
		analysis: &TrafficAnalysis{
			Protocols:        make(map[string]int),
			Services:         make(map[string]int),
			SizeDistribution: make(map[string]int),
			TimingPatterns:   make(map[string]time.Duration),
		},
	}
}

func (ta *TrafficAnalyzerImpl) LoadRealTrafficDataCSV(csvFile string) error {
	records, err := ta.parseTrafficCSV(csvFile)
	if err != nil {
		return fmt.Errorf("failed to parse traffic CSV: %w", err)
	}

	ta.records = records
	ta.analysis = ta.analyzeRealTrafficFromRecords(records)

	return nil
}

func (ta *TrafficAnalyzerImpl) parseTrafficCSV(filename string) ([]TrafficRecord, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer util.SafeClose("file", file.Close)

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	trafficRecords := make([]TrafficRecord, 0, len(records))

	for i, record := range records {
		if i == 0 {
			continue
		}

		if len(record) < 8 {
			continue
		}

		trafficRecord := TrafficRecord{}

		if timestamp, err := time.Parse("2006-01-02 15:04:05", record[0]); err == nil {
			trafficRecord.Timestamp = timestamp
		}

		if size, err := strconv.Atoi(record[1]); err == nil {
			trafficRecord.Size = size
		}

		trafficRecord.Direction = record[2]

		trafficRecord.Protocol = record[3]

		trafficRecord.Service = record[4]

		if features, err := ta.parseFeatures(record[5]); err == nil {
			trafficRecord.Features = features
		}

		if duration, err := time.ParseDuration(record[6]); err == nil {
			trafficRecord.Duration = duration
		}

		if len(record) > 7 {
			trafficRecord.SourceIP = record[7]
		}
		if len(record) > 8 {
			trafficRecord.DestIP = record[8]
		}
		if len(record) > 9 {
			if port, err := strconv.Atoi(record[9]); err == nil {
				trafficRecord.SourcePort = port
			}
		}
		if len(record) > 10 {
			if port, err := strconv.Atoi(record[10]); err == nil {
				trafficRecord.DestPort = port
			}
		}

		trafficRecords = append(trafficRecords, trafficRecord)
	}

	return trafficRecords, nil
}

func (ta *TrafficAnalyzerImpl) parseFeatures(featuresStr string) ([]float64, error) {
	parts := strings.Split(featuresStr, ",")
	features := make([]float64, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if value, err := strconv.ParseFloat(part, 64); err == nil {
			features = append(features, value)
		}
	}

	return features, nil
}

func (ta *TrafficAnalyzerImpl) analyzeRealTrafficFromRecords(records []TrafficRecord) *TrafficAnalysis {
	analysis := &TrafficAnalysis{
		TotalPackets:     len(records),
		Protocols:        make(map[string]int),
		Services:         make(map[string]int),
		SizeDistribution: make(map[string]int),
		TimingPatterns:   make(map[string]time.Duration),
	}

	if len(records) == 0 {
		return analysis
	}

	sizes := make([]int, 0, len(records))
	for _, record := range records {
		sizes = append(sizes, record.Size)
		analysis.TotalBytes += int64(record.Size)
	}

	analysis.AverageSize = ta.calculateMean(sizes)
	analysis.SizeStdDev = ta.calculateStdDev(sizes, int(analysis.AverageSize))
	analysis.MinSize = ta.calculateMin(sizes)
	analysis.MaxSize = ta.calculateMax(sizes)

	intervals := make([]time.Duration, 0, len(records)-1)
	for i := 1; i < len(records); i++ {
		interval := records[i].Timestamp.Sub(records[i-1].Timestamp)
		intervals = append(intervals, interval)
	}

	if len(intervals) > 0 {
		analysis.AverageInterval = ta.calculateMeanDuration(intervals)
		analysis.IntervalStdDev = ta.calculateStdDevDuration(intervals)
	}

	for _, record := range records {
		analysis.Protocols[record.Protocol]++
		analysis.Services[record.Service]++

		sizeRange := ta.getSizeRange(record.Size)
		analysis.SizeDistribution[sizeRange]++
	}

	analysis.TimingPatterns = make(map[string]time.Duration)

	analysis.BurstFrequency = 0.1

	csvRecords := make([]TrafficRecordCSV, 0, len(records))
	for _, record := range records {
		csvRecords = append(csvRecords, TrafficRecordCSV{
			Timestamp:    float64(record.Timestamp.Unix()),
			TrafficClass: 0,
			DPIType:      0,
			IsAnomaly:    0,
			Features:     []float64{float64(record.Size)},
		})
	}

	timingPatterns := ta.analyzeTimingPatternsCSV(csvRecords)
	for key, value := range timingPatterns {
		analysis.TimingPatterns[key] = value
	}

	burstFreq := ta.analyzeBurstFrequency(csvRecords)
	analysis.BurstFrequency = burstFreq

	if len(records) > 1 {
		analysis.SessionDuration = records[len(records)-1].Timestamp.Sub(records[0].Timestamp)
	}

	return analysis
}

func (ta *TrafficAnalyzerImpl) calculateMean(values []int) float64 {
	if len(values) == 0 {
		return 0
	}

	sum := 0
	for _, value := range values {
		sum += value
	}

	return float64(sum) / float64(len(values))
}

func (ta *TrafficAnalyzerImpl) calculateStdDev(values []int, mean int) float64 {
	if len(values) == 0 {
		return 0
	}

	sumSquaredDiffs := 0.0
	for _, value := range values {
		diff := float64(value - mean)
		sumSquaredDiffs += diff * diff
	}

	variance := sumSquaredDiffs / float64(len(values))
	return math.Sqrt(variance)
}

func (ta *TrafficAnalyzerImpl) calculateMin(values []int) int {
	if len(values) == 0 {
		return 0
	}

	minVal := values[0]
	for _, value := range values {
		if value < minVal {
			minVal = value
		}
	}

	return minVal
}

func (ta *TrafficAnalyzerImpl) calculateMax(values []int) int {
	if len(values) == 0 {
		return 0
	}

	maxVal := values[0]
	for _, value := range values {
		if value > maxVal {
			maxVal = value
		}
	}

	return maxVal
}

func (ta *TrafficAnalyzerImpl) calculateMeanDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}

	sum := time.Duration(0)
	for _, value := range values {
		sum += value
	}

	return sum / time.Duration(len(values))
}

func (ta *TrafficAnalyzerImpl) calculateStdDevDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}

	mean := ta.calculateMeanDuration(values)
	sumSquaredDiffs := 0.0

	for _, value := range values {
		diff := float64(value - mean)
		sumSquaredDiffs += diff * diff
	}

	variance := sumSquaredDiffs / float64(len(values))
	return time.Duration(math.Sqrt(variance))
}

func (ta *TrafficAnalyzerImpl) getSizeRange(size int) string {
	switch {
	case size < 100:
		return "small"
	case size < 1000:
		return "medium"
	case size < 10000:
		return "large"
	default:
		return "xlarge"
	}
}

func (ta *TrafficAnalyzerImpl) analyzeTimingPatternsCSV(records []TrafficRecordCSV) map[string]time.Duration {
	patterns := make(map[string]time.Duration)

	if len(records) < 2 {
		return patterns
	}

	intervals := make([]time.Duration, 0, len(records)-1)
	for i := 1; i < len(records); i++ {
		t1 := time.Unix(int64(records[i-1].Timestamp), 0)
		t2 := time.Unix(int64(records[i].Timestamp), 0)
		interval := t2.Sub(t1)
		intervals = append(intervals, interval)
	}

	if len(intervals) > 0 {
		patterns["average_interval"] = ta.calculateMeanDuration(intervals)
		patterns["min_interval"] = ta.calculateMinDuration(intervals)
		patterns["max_interval"] = ta.calculateMaxDuration(intervals)
	}

	return patterns
}

func (ta *TrafficAnalyzerImpl) calculateMinDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}

	minVal := values[0]
	for _, value := range values {
		if value < minVal {
			minVal = value
		}
	}

	return minVal
}

func (ta *TrafficAnalyzerImpl) calculateMaxDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}

	maxVal := values[0]
	for _, value := range values {
		if value > maxVal {
			maxVal = value
		}
	}

	return maxVal
}

func (ta *TrafficAnalyzerImpl) analyzeBurstFrequency(records []TrafficRecordCSV) float64 {
	if len(records) < 2 {
		return 0
	}

	burstCount := 0
	burstThreshold := 100 * time.Millisecond

	for i := 1; i < len(records); i++ {
		t1 := time.Unix(int64(records[i-1].Timestamp), 0)
		t2 := time.Unix(int64(records[i].Timestamp), 0)
		interval := t2.Sub(t1)
		if interval < burstThreshold {
			burstCount++
		}
	}

	return float64(burstCount) / float64(len(records)-1)
}

func (ta *TrafficAnalyzerImpl) GetAnalysis() *TrafficAnalysis {
	return ta.analysis
}

func (ta *TrafficAnalyzerImpl) GetRecords() []TrafficRecord {
	return ta.records
}

func (ta *TrafficAnalyzerImpl) UpdateProfilesFromRealData(profiles map[string]*TrafficProfile) {
	if ta.analysis == nil {
		return
	}

	for name, profile := range profiles {
		ta.updateProfileFromRealTraffic(profile, name)
	}
}

func (ta *TrafficAnalyzerImpl) updateProfileFromRealTraffic(profile *TrafficProfile, serviceType string) {
	if ta.analysis == nil {
		return
	}

	profile.ServiceType = serviceType

	profile.SizeDistribution = &SizeDistribution{
		Min:    ta.analysis.MinSize,
		Max:    ta.analysis.MaxSize,
		Mean:   ta.analysis.AverageSize,
		StdDev: ta.analysis.SizeStdDev,
	}

	profile.IntervalDistribution = &IntervalDistribution{
		Min:    ta.analysis.AverageInterval,
		Max:    ta.analysis.AverageInterval + ta.analysis.IntervalStdDev,
		Mean:   ta.analysis.AverageInterval,
		StdDev: ta.analysis.IntervalStdDev,
	}

	profile.BurstProfile = &BurstProfile{
		Frequency: ta.analysis.BurstFrequency,
		MinSize:   100,
		MaxSize:   1000,
		Enabled:   true,
	}

	profile.CoverageProfile = &CoverageProfile{
		Coverage: 1.0,
		Enabled:  true,
	}

	profile.AdaptationProfile = &AdaptationProfile{
		Sensitivity: 0.5,
		Enabled:     true,
	}
}
