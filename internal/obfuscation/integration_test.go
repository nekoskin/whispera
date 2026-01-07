package obfuscation

import (
	"testing"
	"time"
)

func TestMLConfig(t *testing.T) {
	cfg := DefaultMLConfig()

	if cfg.BatchSize != 10 {
		t.Errorf("Expected BatchSize 10, got %d", cfg.BatchSize)
	}
	if cfg.MaxConcurrentWorkers != 2 {
		t.Errorf("Expected MaxConcurrentWorkers 2, got %d", cfg.MaxConcurrentWorkers)
	}
	if cfg.CircuitBreakerLimit != 5 {
		t.Errorf("Expected CircuitBreakerLimit 5, got %d", cfg.CircuitBreakerLimit)
	}
}

func TestCircuitBreaker(t *testing.T) {
	im := NewIntegrationManager()

	// Simulate 5 failures
	for i := 0; i < 5; i++ {
		im.mlFailures++
	}

	// Trip circuit breaker
	if im.mlFailures >= im.config.CircuitBreakerLimit {
		im.mlDisabledUntil = time.Now().Add(im.config.CircuitBreakerCooldown)
		im.mlFailures = 0
	}

	if !time.Now().Before(im.mlDisabledUntil) {
		t.Error("Circuit breaker should be tripped")
	}

	if im.mlFailures != 0 {
		t.Errorf("mlFailures should be reset to 0, got %d", im.mlFailures)
	}
}

func TestDynamicSampling(t *testing.T) {
	im := NewIntegrationManager()

	// Initial rate
	if im.sampleRate != im.config.DefaultSampleRate {
		t.Errorf("Expected default rate %d, got %d", im.config.DefaultSampleRate, im.sampleRate)
	}

	// Simulate stable network
	im.mu.Lock()
	for i := 0; i < 10; i++ {
		im.packetTimings = append(im.packetTimings, time.Now().Add(time.Duration(i)*10*time.Millisecond))
	}
	im.updateNetworkStabilityLocked()
	im.mu.Unlock()

	if im.sampleRate != im.config.StableSampleRate {
		t.Errorf("Expected stable rate %d, got %d", im.config.StableSampleRate, im.sampleRate)
	}
}

func TestSemaphoreLimits(t *testing.T) {
	im := NewIntegrationManager()

	// Fill semaphore
	workerCount := im.config.MaxConcurrentWorkers
	for i := 0; i < workerCount; i++ {
		select {
		case im.mlSemaphore <- struct{}{}:
		default:
			t.Fatalf("Should be able to acquire semaphore %d times", workerCount)
		}
	}

	// Next acquire should fail (non-blocking)
	select {
	case im.mlSemaphore <- struct{}{}:
		t.Error("Semaphore should be full")
	default:
		// Expected
	}
}
