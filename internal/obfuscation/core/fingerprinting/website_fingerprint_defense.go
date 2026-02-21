package fingerprinting

import (
	crand "crypto/rand"
	"encoding/binary"
	"math"
	"math/big"
	"sync"
	"time"
)

var (
	randBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 8)
		},
	}
)

func secureRandFloat64() float64 {
	b := randBufferPool.Get().([]byte)
	defer randBufferPool.Put(b)

	if _, err := crand.Read(b); err != nil {
		return 0.0
	}
	val := binary.BigEndian.Uint64(b)
	return float64(val) / float64(^uint64(0))
}

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

type WebsiteFingerprintDefense struct {
	paddingStrategies map[string]PaddingStrategy
	timingStrategies  map[string]TimingStrategy
	sizeStrategies    map[string]SizeStrategy
}

type PaddingStrategy interface {
	ApplyPadding(data []byte, targetSize int) []byte
	CalculateTargetSize(originalSize int) int
}

type TimingStrategy interface {
	ApplyTimingObfuscation(data []byte) []byte
	GenerateTimingMarkers(dataLen int) []byte
}

type SizeStrategy interface {
	ApplySizeObfuscation(data []byte) []byte
	CalculateObfuscatedSize(originalSize int) int
}

type AdaptivePadding struct {
	MinSize      int
	MaxSize      int
	AdaptiveRate float64
}

type DeterministicPadding struct {
	MinSize int
	MaxSize int
	Seed    int64
}

type RandomPadding struct {
	MinSize    int
	MaxSize    int
	RandomSeed int64
}

func NewWebsiteFingerprintDefense() *WebsiteFingerprintDefense {
	return &WebsiteFingerprintDefense{
		paddingStrategies: make(map[string]PaddingStrategy),
		timingStrategies:  make(map[string]TimingStrategy),
		sizeStrategies:    make(map[string]SizeStrategy),
	}
}

func (w *WebsiteFingerprintDefense) ApplyWebsiteFingerprintDefense(
	data []byte,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	result := data

	if profile.PaddingStrategy != "" {
		if strategy, exists := w.paddingStrategies[profile.PaddingStrategy]; exists {
			targetSize := strategy.CalculateTargetSize(len(result))
			result = strategy.ApplyPadding(result, targetSize)
		}
	}

	if profile.TimingObfuscation {
		if strategy, exists := w.timingStrategies["adaptive"]; exists {
			result = strategy.ApplyTimingObfuscation(result)
		}
	}

	if profile.SizeObfuscation {
		if strategy, exists := w.sizeStrategies["adaptive"]; exists {
			result = strategy.ApplySizeObfuscation(result)
		}
	}

	if profile.DirectionObfuscation {
		result = w.applyDirectionObfuscation(result)
	}

	if profile.CoverTraffic {
		result = w.applyCoverTraffic(result, profile)
	}

	return result
}

type WebsiteFingerprintDefenseProfile struct {
	Enabled              bool          `json:"enabled"`
	PaddingStrategy      string        `json:"padding_strategy"`
	TimingObfuscation    bool          `json:"timing_obfuscation"`
	SizeObfuscation      bool          `json:"size_obfuscation"`
	DirectionObfuscation bool          `json:"direction_obfuscation"`
	CoverTraffic         bool          `json:"cover_traffic"`
	CoverProbability     float64       `json:"cover_probability"`
	CoverSize            int           `json:"cover_size"`
	CoverInterval        time.Duration `json:"cover_interval"`
	ObfuscationLevel     int           `json:"obfuscation_level"`
}

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
	baseSize := originalSize
	obfuscationLevel := profile.ObfuscationLevel

	multiplier := 1.0 + float64(obfuscationLevel)/10.0

	variance := 0.1 + secureRandFloat64()*0.3

	targetSize := int(float64(baseSize) * multiplier * (1.0 + variance))

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
	padding := make([]byte, size)

	obfuscationLevel := profile.ObfuscationLevel


	switch {
	case obfuscationLevel < 3:
		if _, err := crand.Read(padding); err != nil {
			for i := range padding {
				padding[i] = byte(i * 17)
			}
		}
	case obfuscationLevel < 7:
		for i := 0; i < len(padding); i++ {
			if i%4 == 0 {
				padding[i] = byte(secureRandInt(256))
			} else {
				padding[i] = padding[i-1] + byte(secureRandInt(3)-1)
			}
		}
	default:
		pattern := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
		for i := 0; i < len(padding); i++ {
			padding[i] = pattern[i%len(pattern)] + byte(secureRandInt(16))
		}
	}

	return padding
}

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
	baseSize := originalSize
	obfuscationLevel := profile.ObfuscationLevel

	seed := int64(baseSize) * int64(obfuscationLevel) * 12345
	if seed > 0 {
	}

	sizeMultiplier := 1.0 + float64(obfuscationLevel)/20.0
	targetSize := int(float64(baseSize) * sizeMultiplier)

	targetSize = int(math.Pow(2, math.Ceil(math.Log2(float64(targetSize)))))

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
	padding := make([]byte, size)

	seed := int64(size) * int64(profile.ObfuscationLevel) * 54321

	for i := 0; i < len(padding); i++ {
		padding[i] = byte((i*7 + int(seed)) % 256)
	}

	return padding
}

func (w *WebsiteFingerprintDefense) ApplyRandomPadding(data []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	targetSize := w.calculateRandomTargetSize(len(data), profile)
	return w.generateRandomPadding(targetSize, profile)
}

func (w *WebsiteFingerprintDefense) calculateRandomTargetSize(
	originalSize int,
	profile *WebsiteFingerprintDefenseProfile,
) int {
	baseSize := originalSize
	obfuscationLevel := profile.ObfuscationLevel


	minSize := baseSize
	maxSize := baseSize * (1 + obfuscationLevel)

	targetSize := minSize + secureRandInt(maxSize-minSize+1)

	if targetSize < 64 {
		targetSize = 64
	}
	if targetSize > 8192 {
		targetSize = 8192
	}

	return targetSize
}

func (w *WebsiteFingerprintDefense) generateRandomPadding(size int, _ *WebsiteFingerprintDefenseProfile) []byte {
	padding := make([]byte, size)

	if _, err := crand.Read(padding); err != nil {
		for i := range padding {
			padding[i] = byte(i * 17)
		}
	}

	return padding
}

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
	baseSize := originalSize
	obfuscationLevel := profile.ObfuscationLevel

	sizeMultiplier := 1.0 + float64(obfuscationLevel)/15.0

	variance := 0.05 + secureRandFloat64()*0.2

	targetSize := int(float64(baseSize) * sizeMultiplier * (1.0 + variance))

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

	paddingSize := targetSize - len(data)
	padding := w.generateAdaptivePadding(paddingSize, profile)

	result := make([]byte, targetSize)
	copy(result, data)
	copy(result[len(data):], padding)

	return result
}

func (w *WebsiteFingerprintDefense) ApplyTimingObfuscation(
	data []byte,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	markers := w.generateTimingMarkers(len(data), profile)

	return w.insertTimingMarkers(data, markers, profile)
}

func (w *WebsiteFingerprintDefense) generateTimingMarkers(
	dataLen int,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	obfuscationLevel := profile.ObfuscationLevel

	numMarkers := obfuscationLevel + 1
	if numMarkers > 10 {
		numMarkers = 10
	}

	markers := make([]byte, numMarkers*8)


	for i := 0; i < numMarkers; i++ {
		offset := i * 8

		markers[offset] = byte(0x80 + i)

		timing := time.Duration(secureRandInt(1000)) * time.Millisecond
		nanos := timing.Nanoseconds()
		if nanos < 0 {
			nanos = 0
		}
		binary.LittleEndian.PutUint64(markers[offset+1:offset+9], uint64(nanos))
	}

	return markers
}

func (w *WebsiteFingerprintDefense) insertTimingMarkers(
	data, markers []byte,
	_ *WebsiteFingerprintDefenseProfile,
) []byte {
	result := make([]byte, len(data)+len(markers))

	interval := len(data) / (len(markers)/8 + 1)
	if interval < 10 {
		interval = 10
	}

	dataOffset := 0
	markerOffset := 0

	for i := 0; i < len(data); i++ {
		if i%interval == 0 && markerOffset < len(markers) {
			copy(result[dataOffset:dataOffset+8], markers[markerOffset:markerOffset+8])
			dataOffset += 8
			markerOffset += 8
		}

		result[dataOffset] = data[i]
		dataOffset++
	}

	if markerOffset < len(markers) {
		copy(result[dataOffset:], markers[markerOffset:])
	}

	return result
}

func (w *WebsiteFingerprintDefense) ApplyDirectionObfuscation(
	data []byte,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	markers := w.generateDirectionMarkers(len(data), profile)

	return w.insertDirectionMarkers(data, markers, profile)
}

func (w *WebsiteFingerprintDefense) generateDirectionMarkers(
	dataLen int,
	profile *WebsiteFingerprintDefenseProfile,
) []byte {
	obfuscationLevel := profile.ObfuscationLevel

	numMarkers := obfuscationLevel/2 + 1
	if numMarkers > 5 {
		numMarkers = 5
	}

	markers := make([]byte, numMarkers*4)


	for i := 0; i < numMarkers; i++ {
		offset := i * 4

		markers[offset] = byte(0x90 + i)

		markers[offset+1] = byte(secureRandInt(2))

		markers[offset+2] = byte(secureRandInt(256))
		markers[offset+3] = byte(secureRandInt(256))
	}

	return markers
}

func (w *WebsiteFingerprintDefense) insertDirectionMarkers(
	data, markers []byte,
	_ *WebsiteFingerprintDefenseProfile,
) []byte {
	result := make([]byte, len(data)+len(markers))

	interval := len(data) / (len(markers)/4 + 1)
	if interval < 20 {
		interval = 20
	}

	dataOffset := 0
	markerOffset := 0

	for i := 0; i < len(data); i++ {
		if i%interval == 0 && markerOffset < len(markers) {
			copy(result[dataOffset:dataOffset+4], markers[markerOffset:markerOffset+4])
			dataOffset += 4
			markerOffset += 4
		}

		result[dataOffset] = data[i]
		dataOffset++
	}

	if markerOffset < len(markers) {
		copy(result[dataOffset:], markers[markerOffset:])
	}

	return result
}

func (w *WebsiteFingerprintDefense) ApplyCoverTraffic(data []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	if secureRandFloat64() > profile.CoverProbability {
		return data
	}

	coverData := w.generateCoverTraffic(profile)

	result := make([]byte, len(data)+len(coverData))
	copy(result, data)
	copy(result[len(data):], coverData)

	return result
}

func (w *WebsiteFingerprintDefense) generateCoverTraffic(profile *WebsiteFingerprintDefenseProfile) []byte {
	coverSize := profile.CoverSize
	if coverSize <= 0 {
		coverSize = 512
	}

	coverData := make([]byte, coverSize)

	if _, err := crand.Read(coverData); err != nil {
		for i := range coverData {
			coverData[i] = byte(i * 17)
		}
	}

	for i := 0; i < len(coverData); i += 10 {
		if i+10 < len(coverData) {
			coverData[i] = 'H'
			coverData[i+1] = 'T'
			coverData[i+2] = 'T'
			coverData[i+3] = 'P'
		}
	}

	return coverData
}

func (w *WebsiteFingerprintDefense) applyDirectionObfuscation(data []byte) []byte {
	profile := &WebsiteFingerprintDefenseProfile{
		DirectionObfuscation: true,
		ObfuscationLevel:     5,
	}

	return w.ApplyDirectionObfuscation(data, profile)
}

func (w *WebsiteFingerprintDefense) applyCoverTraffic(data []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	return w.ApplyCoverTraffic(data, profile)
}
