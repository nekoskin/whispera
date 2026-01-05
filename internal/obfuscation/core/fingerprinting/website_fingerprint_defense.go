package fingerprinting

import (
	crand "crypto/rand"
	"encoding/binary"
	"math"
	"math/big"
	"sync"
	"time"
)

// ОПТИМИЗАЦИЯ: Пул буферов для переиспользования памяти при генерации случайных чисел
var (
	randBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 8)
		},
	}
)

// secureRandFloat64 generates a random float64 between 0.0 and 1.0
// ОПТИМИЗАЦИЯ: Используем пул буферов для уменьшения аллокаций
func secureRandFloat64() float64 {
	b := randBufferPool.Get().([]byte)
	defer randBufferPool.Put(b)

	if _, err := crand.Read(b); err != nil {
		return 0.0
	}
	val := binary.BigEndian.Uint64(b)
	return float64(val) / float64(^uint64(0))
}

// secureRandInt generates a random integer from 0 to max (exclusive)
func secureRandInt(maxVal int) int {
	if maxVal <= 0 {
		return 0
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(maxVal)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

// WebsiteFingerprintDefense handles website fingerprinting defense
type WebsiteFingerprintDefense struct {
	// Defense strategies
	paddingStrategies map[string]PaddingStrategy
	timingStrategies  map[string]TimingStrategy
	sizeStrategies    map[string]SizeStrategy
}

// PaddingStrategy defines padding strategies
type PaddingStrategy interface {
	ApplyPadding(data []byte, targetSize int) []byte
	CalculateTargetSize(originalSize int) int
}

// TimingStrategy defines timing obfuscation strategies
type TimingStrategy interface {
	ApplyTimingObfuscation(data []byte) []byte
	GenerateTimingMarkers(dataLen int) []byte
}

// SizeStrategy defines size obfuscation strategies
type SizeStrategy interface {
	ApplySizeObfuscation(data []byte) []byte
	CalculateObfuscatedSize(originalSize int) int
}

// AdaptivePadding implements adaptive padding strategy
type AdaptivePadding struct {
	MinSize      int
	MaxSize      int
	AdaptiveRate float64
}

// DeterministicPadding implements deterministic padding strategy
type DeterministicPadding struct {
	MinSize int
	MaxSize int
	Seed    int64
}

// RandomPadding implements random padding strategy
type RandomPadding struct {
	MinSize    int
	MaxSize    int
	RandomSeed int64
}

// NewWebsiteFingerprintDefense creates new website fingerprint defense module
func NewWebsiteFingerprintDefense() *WebsiteFingerprintDefense {
	return &WebsiteFingerprintDefense{
		paddingStrategies: make(map[string]PaddingStrategy),
		timingStrategies:  make(map[string]TimingStrategy),
		sizeStrategies:    make(map[string]SizeStrategy),
	}
}

// ApplyWebsiteFingerprintDefense applies comprehensive fingerprint defense
func (w *WebsiteFingerprintDefense) ApplyWebsiteFingerprintDefense(
	data []byte,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	result := data

	// Apply padding strategy
	if profile.PaddingStrategy != "" {
		if strategy, exists := w.paddingStrategies[profile.PaddingStrategy]; exists {
			targetSize := strategy.CalculateTargetSize(len(result))
			result = strategy.ApplyPadding(result, targetSize)
		}
	}

	// Apply timing obfuscation
	if profile.TimingObfuscation {
		if strategy, exists := w.timingStrategies["adaptive"]; exists {
			result = strategy.ApplyTimingObfuscation(result)
		}
	}

	// Apply size obfuscation
	if profile.SizeObfuscation {
		if strategy, exists := w.sizeStrategies["adaptive"]; exists {
			result = strategy.ApplySizeObfuscation(result)
		}
	}

	// Apply direction obfuscation
	if profile.DirectionObfuscation {
		result = w.applyDirectionObfuscation(result)
	}

	// Apply cover traffic
	if profile.CoverTraffic {
		result = w.applyCoverTraffic(result, profile)
	}

	return result
}

// WebsiteFingerprintDefenseProfile defines defense profile
type WebsiteFingerprintDefenseProfile struct {
	Enabled              bool          `json:"enabled"`
	PaddingStrategy      string        `json:"padding_strategy"`      // "random", "deterministic", "adaptive"
	TimingObfuscation    bool          `json:"timing_obfuscation"`    // Obfuscate timing patterns
	SizeObfuscation      bool          `json:"size_obfuscation"`      // Obfuscate packet size patterns
	DirectionObfuscation bool          `json:"direction_obfuscation"` // Obfuscate traffic direction
	CoverTraffic         bool          `json:"cover_traffic"`         // Generate cover traffic
	CoverProbability     float64       `json:"cover_probability"`     // Probability of cover traffic
	CoverSize            int           `json:"cover_size"`            // Size of cover traffic packets
	CoverInterval        time.Duration `json:"cover_interval"`        // Interval between cover traffic
	ObfuscationLevel     int           `json:"obfuscation_level"`     // 0-10 obfuscation intensity
}

// ApplyAdaptivePadding applies adaptive padding
func (w *WebsiteFingerprintDefense) ApplyAdaptivePadding(
	data []byte,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	targetSize := w.calculateAdaptiveTargetSize(len(data), profile)
	return w.generateAdaptivePadding(targetSize, profile)
}

func (w *WebsiteFingerprintDefense) calculateAdaptiveTargetSize(
	originalSize int,
	profile *WebsiteFingerprintDefenseProfile,
) int {
	// Adaptive target size calculation based on obfuscation level
	baseSize := originalSize
	obfuscationLevel := profile.ObfuscationLevel

	// Calculate size multiplier based on obfuscation level
	multiplier := 1.0 + float64(obfuscationLevel)/10.0

	// Add random variance
	// rand.Seed removed: default global source is sufficient
	variance := 0.1 + secureRandFloat64()*0.3 // 10-40% variance

	targetSize := int(float64(baseSize) * multiplier * (1.0 + variance))

	// Ensure within reasonable bounds
	if targetSize < 64 {
		targetSize = 64
	}
	if targetSize > 8192 {
		targetSize = 8192
	}

	return targetSize
}

func (w *WebsiteFingerprintDefense) generateAdaptivePadding(
	size int,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	// Generate adaptive padding based on profile
	padding := make([]byte, size)

	// Use different padding patterns based on obfuscation level
	obfuscationLevel := profile.ObfuscationLevel

	// rand.Seed removed

	switch {
	case obfuscationLevel < 3:
		// Low obfuscation - simple random padding
		if _, err := crand.Read(padding); err != nil {
			// Fallback: заполняем детерминированными значениями
			for i := range padding {
				padding[i] = byte(i * 17)
			}
		}
	case obfuscationLevel < 7:
		// Medium obfuscation - structured random padding
		for i := 0; i < len(padding); i++ {
			if i%4 == 0 {
				padding[i] = byte(secureRandInt(256))
			} else {
				padding[i] = padding[i-1] + byte(secureRandInt(3)-1)
			}
		}
	default:
		// High obfuscation - complex pattern padding
		pattern := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
		for i := 0; i < len(padding); i++ {
			padding[i] = pattern[i%len(pattern)] + byte(secureRandInt(16))
		}
	}

	return padding
}

// ApplyDeterministicPadding applies deterministic padding
func (w *WebsiteFingerprintDefense) ApplyDeterministicPadding(
	data []byte,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	targetSize := w.calculateDeterministicTargetSize(len(data), profile)
	return w.generateDeterministicPadding(targetSize, profile)
}

func (w *WebsiteFingerprintDefense) calculateDeterministicTargetSize(
	originalSize int,
	profile *WebsiteFingerprintDefenseProfile,
) int {
	// Deterministic target size calculation
	baseSize := originalSize
	obfuscationLevel := profile.ObfuscationLevel

	// Use deterministic algorithm based on size and obfuscation level
	seed := int64(baseSize) * int64(obfuscationLevel) * 12345
	if seed > 0 {
		// Seed used for deterministic pattern generation
	}
	// rand.Seed removed (determinism not required here)

	// Calculate size based on deterministic pattern
	sizeMultiplier := 1.0 + float64(obfuscationLevel)/20.0
	targetSize := int(float64(baseSize) * sizeMultiplier)

	// Round to nearest power of 2 for deterministic behavior
	targetSize = int(math.Pow(2, math.Ceil(math.Log2(float64(targetSize)))))

	// Ensure within bounds
	if targetSize < 64 {
		targetSize = 64
	}
	if targetSize > 8192 {
		targetSize = 8192
	}

	return targetSize
}

func (w *WebsiteFingerprintDefense) generateDeterministicPadding(
	size int,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	// Generate deterministic padding
	padding := make([]byte, size)

	// Use deterministic seed
	seed := int64(size) * int64(profile.ObfuscationLevel) * 54321
	// rand.Seed removed (determinism not required here)

	// Generate deterministic pattern
	for i := 0; i < len(padding); i++ {
		padding[i] = byte((i*7 + int(seed)) % 256)
	}

	return padding
}

// ApplyRandomPadding applies random padding
func (w *WebsiteFingerprintDefense) ApplyRandomPadding(data []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	targetSize := w.calculateRandomTargetSize(len(data), profile)
	return w.generateRandomPadding(targetSize, profile)
}

func (w *WebsiteFingerprintDefense) calculateRandomTargetSize(
	originalSize int,
	profile *WebsiteFingerprintDefenseProfile,
) int {
	// Random target size calculation
	baseSize := originalSize
	obfuscationLevel := profile.ObfuscationLevel

	// rand.Seed removed

	// Random size within range based on obfuscation level
	minSize := baseSize
	maxSize := baseSize * (1 + obfuscationLevel)

	targetSize := minSize + secureRandInt(maxSize-minSize+1)

	// Ensure within bounds
	if targetSize < 64 {
		targetSize = 64
	}
	if targetSize > 8192 {
		targetSize = 8192
	}

	return targetSize
}

func (w *WebsiteFingerprintDefense) generateRandomPadding(size int, _ *WebsiteFingerprintDefenseProfile) []byte {
	// Generate random padding
	padding := make([]byte, size)

	// rand.Seed removed
	if _, err := crand.Read(padding); err != nil {
		// Fallback: заполняем детерминированными значениями
		for i := range padding {
			padding[i] = byte(i * 17)
		}
	}

	return padding
}

// ApplySizeObfuscation applies size obfuscation
func (w *WebsiteFingerprintDefense) ApplySizeObfuscation(
	data []byte,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	obfuscatedSize := w.calculateObfuscatedSize(len(data), profile)
	return w.padToObfuscatedSize(data, obfuscatedSize, profile)
}

func (w *WebsiteFingerprintDefense) calculateObfuscatedSize(
	originalSize int,
	profile *WebsiteFingerprintDefenseProfile,
) int {
	// Calculate obfuscated size based on profile
	baseSize := originalSize
	obfuscationLevel := profile.ObfuscationLevel

	// Use size obfuscation algorithm
	sizeMultiplier := 1.0 + float64(obfuscationLevel)/15.0

	// Add random variance
	// rand.Seed removed
	variance := 0.05 + secureRandFloat64()*0.2 // 5-25% variance

	targetSize := int(float64(baseSize) * sizeMultiplier * (1.0 + variance))

	// Round to common packet sizes
	commonSizes := []int{64, 128, 256, 512, 1024, 1500, 2048, 4096, 8192}

	for _, size := range commonSizes {
		if targetSize <= size {
			return size
		}
	}

	return commonSizes[len(commonSizes)-1]
}

func (w *WebsiteFingerprintDefense) padToObfuscatedSize(
	data []byte,
	targetSize int,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	if len(data) >= targetSize {
		return data[:targetSize]
	}

	// Generate padding
	paddingSize := targetSize - len(data)
	padding := w.generateAdaptivePadding(paddingSize, profile)

	// Combine data and padding
	result := make([]byte, targetSize)
	copy(result, data)
	copy(result[len(data):], padding)

	return result
}

// ApplyTimingObfuscation applies timing obfuscation
func (w *WebsiteFingerprintDefense) ApplyTimingObfuscation(
	data []byte,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	// Generate timing markers
	markers := w.generateTimingMarkers(len(data), profile)

	// Insert timing markers
	return w.insertTimingMarkers(data, markers, profile)
}

func (w *WebsiteFingerprintDefense) generateTimingMarkers(
	dataLen int, //nolint:unparam // Reserved for future use
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	// Generate timing markers based on profile
	obfuscationLevel := profile.ObfuscationLevel

	// Calculate number of markers based on obfuscation level
	numMarkers := obfuscationLevel + 1
	if numMarkers > 10 {
		numMarkers = 10
	}

	markers := make([]byte, numMarkers*8) // 8 bytes per marker

	// rand.Seed removed

	for i := 0; i < numMarkers; i++ {
		offset := i * 8

		// Marker type
		markers[offset] = byte(0x80 + i)

		// Timing value
		timing := time.Duration(secureRandInt(1000)) * time.Millisecond
		nanos := timing.Nanoseconds()
		if nanos < 0 {
			nanos = 0
		}
		//nolint:gosec // nanos is checked to prevent overflow
		binary.LittleEndian.PutUint64(markers[offset+1:offset+9], uint64(nanos))
	}

	return markers
}

func (w *WebsiteFingerprintDefense) insertTimingMarkers(
	data, markers []byte,
	_ *WebsiteFingerprintDefenseProfile,
) []byte {
	// Insert timing markers into data
	result := make([]byte, len(data)+len(markers))

	// Insert markers at regular intervals
	interval := len(data) / (len(markers)/8 + 1)
	if interval < 10 {
		interval = 10
	}

	dataOffset := 0
	markerOffset := 0

	for i := 0; i < len(data); i++ {
		if i%interval == 0 && markerOffset < len(markers) {
			// Insert marker
			copy(result[dataOffset:dataOffset+8], markers[markerOffset:markerOffset+8])
			dataOffset += 8
			markerOffset += 8
		}

		// Insert data byte
		result[dataOffset] = data[i]
		dataOffset++
	}

	// Add remaining markers
	if markerOffset < len(markers) {
		copy(result[dataOffset:], markers[markerOffset:])
	}

	return result
}

// ApplyDirectionObfuscation applies direction obfuscation
func (w *WebsiteFingerprintDefense) ApplyDirectionObfuscation(
	data []byte,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	// Generate direction markers
	markers := w.generateDirectionMarkers(len(data), profile)

	// Insert direction markers
	return w.insertDirectionMarkers(data, markers, profile)
}

func (w *WebsiteFingerprintDefense) generateDirectionMarkers(
	dataLen int, //nolint:unparam // Reserved for future use
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	// Generate direction markers based on profile
	obfuscationLevel := profile.ObfuscationLevel

	// Calculate number of markers
	numMarkers := obfuscationLevel/2 + 1
	if numMarkers > 5 {
		numMarkers = 5
	}

	markers := make([]byte, numMarkers*4) // 4 bytes per marker

	// rand.Seed removed

	for i := 0; i < numMarkers; i++ {
		offset := i * 4

		// Direction marker
		markers[offset] = byte(0x90 + i)

		// Direction value (0 = inbound, 1 = outbound)
		markers[offset+1] = byte(secureRandInt(2))

		// Random padding
		markers[offset+2] = byte(secureRandInt(256))
		markers[offset+3] = byte(secureRandInt(256))
	}

	return markers
}

func (w *WebsiteFingerprintDefense) insertDirectionMarkers(
	data, markers []byte,
	_ *WebsiteFingerprintDefenseProfile,
) []byte {
	// Insert direction markers into data
	result := make([]byte, len(data)+len(markers))

	// Insert markers at regular intervals
	interval := len(data) / (len(markers)/4 + 1)
	if interval < 20 {
		interval = 20
	}

	dataOffset := 0
	markerOffset := 0

	for i := 0; i < len(data); i++ {
		if i%interval == 0 && markerOffset < len(markers) {
			// Insert marker
			copy(result[dataOffset:dataOffset+4], markers[markerOffset:markerOffset+4])
			dataOffset += 4
			markerOffset += 4
		}

		// Insert data byte
		result[dataOffset] = data[i]
		dataOffset++
	}

	// Add remaining markers
	if markerOffset < len(markers) {
		copy(result[dataOffset:], markers[markerOffset:])
	}

	return result
}

// ApplyCoverTraffic applies cover traffic
func (w *WebsiteFingerprintDefense) ApplyCoverTraffic(data []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	// Check if cover traffic should be applied
	// rand.Seed removed
	if secureRandFloat64() > profile.CoverProbability {
		return data
	}

	// Generate cover traffic
	coverData := w.generateCoverTraffic(profile)

	// Combine with original data
	result := make([]byte, len(data)+len(coverData))
	copy(result, data)
	copy(result[len(data):], coverData)

	return result
}

func (w *WebsiteFingerprintDefense) generateCoverTraffic(profile *WebsiteFingerprintDefenseProfile) []byte {
	// Generate cover traffic based on profile
	coverSize := profile.CoverSize
	if coverSize <= 0 {
		coverSize = 512 // Default cover size
	}

	coverData := make([]byte, coverSize)

	if _, err := crand.Read(coverData); err != nil {
		// Fallback: заполняем детерминированными значениями
		for i := range coverData {
			coverData[i] = byte(i * 17)
		}
	}

	// Add realistic patterns to cover traffic
	for i := 0; i < len(coverData); i += 10 {
		if i+10 < len(coverData) {
			// Add HTTP-like patterns
			coverData[i] = 'H'
			coverData[i+1] = 'T'
			coverData[i+2] = 'T'
			coverData[i+3] = 'P'
		}
	}

	return coverData
}

// Helper methods
func (w *WebsiteFingerprintDefense) applyDirectionObfuscation(data []byte) []byte {
	// Apply direction obfuscation
	profile := &WebsiteFingerprintDefenseProfile{
		DirectionObfuscation: true,
		ObfuscationLevel:     5,
	}

	return w.ApplyDirectionObfuscation(data, profile)
}

func (w *WebsiteFingerprintDefense) applyCoverTraffic(data []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	// Apply cover traffic
	return w.ApplyCoverTraffic(data, profile)
}
