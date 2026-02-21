package ml

import (
	"whispera/internal/obfuscation/core/evasion"
	"whispera/internal/obfuscation/core/types"
)

func init() {
	evasion.NewPythonMLClientLocal = func() evasion.PythonMLClient {
		realClient := NewPythonMLClientLocal()
		return &PythonMLClientEvasionAdapter{client: realClient}
	}
}

type PythonMLClientEvasionAdapter struct {
	client *PythonMLClient
}

func (a *PythonMLClientEvasionAdapter) ProcessTraffic(data []byte, context *types.UnifiedTrafficContext) ([]byte, error) {
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

	response, err := a.client.PredictTraffic(data, protocol, direction)
	if err != nil {
		return data, nil
	}

	if len(response.Predictions) > 0 {
		pred := response.Predictions[0]
		if pred.DPIType > 0 && pred.Confidence > 0.7 {
			if pred.Confidence > 0.8 {
			}
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
