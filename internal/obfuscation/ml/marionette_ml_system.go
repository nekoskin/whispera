package ml

import (
	"fmt"
	"time"
	"whispera/internal/obfuscation/core/types"
	"whispera/internal/util"
)

type UnifiedMLSystem struct {
	mlClient         *PythonMLClient
	stats            *types.MLStats
	packetCount      int64
	protocolSelector *ProtocolSelector

	// Data collection for online learning
	dataCollector *DataCollector
}

func (mls *UnifiedMLSystem) ProcessTraffic(data []byte, context *types.UnifiedTrafficContext) ([]byte, error) {
	if len(data) == 0 || context == nil || mls.mlClient == nil {
		return data, fmt.Errorf("invalid input")
	}

	startTime := time.Now()

	processed, err := mls.mlClient.ProcessTraffic(data, context)
	if err != nil {
		return data, err
	}

	latency := time.Since(startTime)
	mls.packetCount++

	// Update statistics
	if mls.stats != nil {
		mls.stats.ProcessedPackets = mls.packetCount
	}

	// Collect sample for online learning
	if mls.dataCollector != nil {
		// Get prediction for sample collection
		pred, _ := mls.mlClient.PredictTraffic(data, context.Protocol, context.Direction)

		sample := TrafficSample{
			Timestamp: time.Now(),
			Protocol:  context.Protocol,
			Direction: context.Direction,
			Size:      len(data),
			Entropy:   mls.mlClient.calculateEntropy(data),
		}

		if pred != nil && len(pred.Predictions) > 0 {
			p := pred.Predictions[0]
			sample.TrafficClass = p.ClassID
			sample.DPIDetected = p.DPIType > 0
			sample.DPIType = p.DPIType
			sample.IsAnomaly = p.IsAnomaly
			sample.AnomalyScore = p.AnomalyScore
			sample.PredictedClass = p.ClassID
			sample.Confidence = p.Confidence
		}

		mls.dataCollector.CollectSample(sample)
		mls.dataCollector.RecordPrediction(sample.PredictedClass, sample.TrafficClass, sample.Confidence, latency.Nanoseconds())
	}

	return processed, nil
}

func (mls *UnifiedMLSystem) GetStats() *types.MLStats { return mls.stats }

func (mls *UnifiedMLSystem) HealthCheck() error { return mls.mlClient.HealthCheck() }

func (mls *UnifiedMLSystem) LoadModels() error { return mls.mlClient.LoadModels() }

// GetDataCollector returns the data collector for training data access
func (mls *UnifiedMLSystem) GetDataCollector() *DataCollector {
	return mls.dataCollector
}

// GetRuntimeMetrics returns current ML runtime metrics
func (mls *UnifiedMLSystem) GetRuntimeMetrics() RuntimeMetrics {
	if mls.dataCollector != nil {
		return mls.dataCollector.GetMetrics()
	}
	return RuntimeMetrics{}
}

func NewUnifiedMLSystem() *UnifiedMLSystem {
	return &UnifiedMLSystem{
		mlClient: NewPythonMLClientLocal(),
		stats: &types.MLStats{
			ProcessedPackets: 0,
			Accuracy:         0.85,
			DPIEvasionRate:   0.75,
			ModelStatus:      "active",
			LastUpdate:       util.GetGlobalTimeCache().Now(),
		},
		dataCollector: NewDataCollector(10000, "./ml_data"), // 10K samples, save to ./ml_data
	}
}
