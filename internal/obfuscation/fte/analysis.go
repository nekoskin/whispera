package fte

import (
	"encoding/csv"
	"math"
	"os"
	"strconv"
	"time"

	"whispera/internal/obfuscation/core/types"
	"whispera/internal/util"
)


func (fte *FTE) loadRealTrafficData(csvFile string) {
	records, err := fte.parseTrafficCSV(csvFile)
	if err != nil {
		return
	}
	analysis := fte.analyzeRealTraffic(records)
	fte.updateProfilesFromRealData(analysis)
}

func (fte *FTE) parseTrafficCSV(filename string) ([]types.TrafficRecordFTE, error) {
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

	var trafficRecords []types.TrafficRecordFTE
	for i, row := range records {
		if i == 0 {
			continue
		}
		if len(row) < 5 {
			continue
		}
		size, _ := strconv.Atoi(row[2])
		timestamp, _ := strconv.ParseInt(row[0], 10, 64)
		trafficRecords = append(trafficRecords, types.TrafficRecordFTE{
			Timestamp: time.Unix(timestamp, 0),
			Size:      size,
			Protocol:  row[3],
			Direction: row[4],
		})
	}
	return trafficRecords, nil
}

type TrafficAnalysis struct {
	AverageSize  int
	MaxSize      int
	ProtocolDist map[string]int
}

func (fte *FTE) analyzeRealTraffic(records []types.TrafficRecordFTE) *TrafficAnalysis {
	if len(records) == 0 {
		return nil
	}
	totalSize := 0
	maxSize := 0
	protoDist := make(map[string]int)
	for _, r := range records {
		totalSize += r.Size
		if r.Size > maxSize {
			maxSize = r.Size
		}
		protoDist[r.Protocol]++
	}
	return &TrafficAnalysis{
		AverageSize:  totalSize / len(records),
		MaxSize:      maxSize,
		ProtocolDist: protoDist,
	}
}

func (fte *FTE) updateProfilesFromRealData(analysis *TrafficAnalysis) {
	if analysis == nil {
		return
	}
}


func (fte *FTE) calculateTargetEntropy(service string) float64 {
	switch service {
	case "vk":
		return 7.2
	case "yandex":
		return 6.8
	case "mailru":
		return 7.0
	case "rutube":
		return 7.5
	default:
		return 7.0
	}
}

func (fte *FTE) calculateEntropy(data []byte) float64 {
	return fte.calculateDataEntropy(data)
}

func (fte *FTE) calculateDataEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(len(data))
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func (fte *FTE) adjustPaddingEntropy(padding []byte, targetEntropy float64) []byte {
	if len(padding) == 0 || fte.calculateDataEntropy(padding) >= targetEntropy {
		return padding
	}
	adjusted := getPaddingBuffer(len(padding))
	if cap(adjusted) < len(padding) {
		adjusted = make([]byte, len(padding))
	} else {
		adjusted = adjusted[:len(padding)]
	}
	copy(adjusted, padding)
	for i := range adjusted {
		if i%2 == 0 {
			adjusted[i] = byte(secureRandInt(256))
		}
	}
	return adjusted
}


func (fte *FTE) calculateTargetSize(profile *ProtocolProfile) int {
	if len(profile.CommonSizes) == 0 {
		return profile.MinSize
	}

	weights := make([]float64, len(profile.CommonSizes))
	totalWeight := 0.0
	mlWeights := fte.getMLBasedSizeWeights(profile)

	for i, size := range profile.CommonSizes {
		var baseWeight float64
		switch fte.active {
		case "vk":
			if size >= 200 && size <= 400 {
				baseWeight = 0.35
			} else if size >= 800 && size <= 1200 {
				baseWeight = 0.25
			} else if size >= 50 && size <= 150 {
				baseWeight = 0.20
			} else {
				baseWeight = 0.05
			}
		case "yandex":
			if size >= 100 && size <= 200 {
				baseWeight = 0.40
			} else if size >= 400 && size <= 600 {
				baseWeight = 0.30
			} else {
				baseWeight = 0.0
			}
		case "http2":
			if size >= 9 && size <= 17 {
				baseWeight = 0.25
			} else if size >= 25 && size <= 50 {
				baseWeight = 0.20
			} else {
				baseWeight = math.Exp(-float64(size)/400.0) * 0.3
			}
		default:
			baseWeight = math.Exp(-float64(size)/500.0) * 0.25
		}

		mlAdjustment := 1.0
		if mlWeights != nil && i < len(mlWeights) {
			mlAdjustment = mlWeights[i]
		}
		weights[i] = baseWeight * mlAdjustment
		timeVariance := fte.getTimeBasedVariance()
		weights[i] *= timeVariance
		totalWeight += weights[i]
	}

	if totalWeight > 0 {
		for i := range weights {
			weights[i] /= totalWeight
		}
	}
	return fte.selectWeightedSize(profile.CommonSizes, weights)
}

func (fte *FTE) getMLBasedSizeWeights(profile *ProtocolProfile) []float64 {
	if fte.mlSystem == nil {
		return nil
	}
	context := &types.UnifiedTrafficContext{
		Direction: "outbound",
		Protocol:  fte.active,
		Size:      len(profile.CommonSizes),
		Timestamp: util.GetGlobalTimeCache().Now(),
	}

	weights := make([]float64, len(profile.CommonSizes))
	for i := range weights {
		weights[i] = 1.0
	}

	if context.Direction == "inbound" {
		for i := range weights {
			if profile.CommonSizes[i] > 512 {
				weights[i] *= 1.2
			}
		}
	}

	switch context.Protocol {
	case "vk":
		for i := range weights {
			if profile.CommonSizes[i] >= 256 && profile.CommonSizes[i] <= 1024 {
				weights[i] *= 1.3
			}
		}
	case "yandex":
		for i := range weights {
			if profile.CommonSizes[i] < 256 || profile.CommonSizes[i] > 2048 {
				weights[i] *= 1.2
			}
		}
	}

	if context.Size > 5 {
		for i := range weights {
			weights[i] *= 1.0 + 0.05*float64(context.Size-5)
		}
	}

	hour := context.Timestamp.Hour()
	if hour >= 9 && hour <= 18 {
		for i := range weights {
			weights[i] *= 1.0 + 0.1*float64(i%3)
		}
	}

	return weights
}
