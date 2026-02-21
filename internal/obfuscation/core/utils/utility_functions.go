package utils

import (
	"crypto/md5"
	"math"
	"time"
	"whispera/internal/obfuscation/core/types"
)

type ServiceProfile struct {
	DeviceID string
	Name     string
	Type     string
}

type UtilityFunctions struct {
	randomSeed int64
}

func NewUtilityFunctions() *UtilityFunctions {
	return &UtilityFunctions{
		randomSeed: time.Now().UnixNano(),
	}
}

func (uf *UtilityFunctions) CalculateMean(values []int) int {
	if len(values) == 0 {
		return 0
	}

	sum := 0
	for _, value := range values {
		sum += value
	}

	return sum / len(values)
}

func (uf *UtilityFunctions) CalculateStdDev(values []int, mean int) int {
	if len(values) == 0 {
		return 0
	}

	sum := 0
	for _, value := range values {
		diff := value - mean
		sum += diff * diff
	}

	return int(math.Sqrt(float64(sum) / float64(len(values))))
}

func (uf *UtilityFunctions) CalculateMin(values []int) int {
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

func (uf *UtilityFunctions) CalculateMax(values []int) int {
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

func (uf *UtilityFunctions) SelectWeightedSize(sizes []int, weights []float64) int {
	if len(sizes) == 0 || len(weights) == 0 {
		return 0
	}

	totalWeight := 0.0
	for _, weight := range weights {
		totalWeight += weight
	}

	if totalWeight == 0 {
		return sizes[0]
	}

	random := uf.GenerateRealisticRandom(1000) / 1000.0
	currentWeight := 0.0

	for i, weight := range weights {
		currentWeight += weight / totalWeight
		if float64(random) <= currentWeight {
			return sizes[i]
		}
	}

	return sizes[len(sizes)-1]
}

func (uf *UtilityFunctions) GenerateRealisticRandom(maxVal int) int {
	uf.randomSeed = (uf.randomSeed*1103515245 + 12345) & 0x7fffffff
	return int(uf.randomSeed % int64(maxVal))
}

func (uf *UtilityFunctions) GenerateRealisticTiming(baseDelay int, variance float64) time.Duration {
	base := time.Duration(baseDelay) * time.Millisecond
	varianceDuration := time.Duration(float64(uf.GenerateRealisticRandom(100))*variance) * time.Millisecond
	return base + varianceDuration
}

func (uf *UtilityFunctions) GenerateHumanThinkTime() float64 {
	baseTime := 0.5
	variance := float64(uf.GenerateRealisticRandom(100)) / 100.0
	return baseTime + variance*2.0
}

func (uf *UtilityFunctions) GenerateNetworkJitter() float64 {
	baseJitter := 0.1
	variance := float64(uf.GenerateRealisticRandom(50)) / 100.0
	return baseJitter + variance*0.5
}

func (uf *UtilityFunctions) GenerateScientificDeviceID() string {
	deviceID := "sci_device_"
	for i := 0; i < 16; i++ {
		deviceID += string(rune('a' + (i*7)%26))
	}
	return deviceID
}

func (uf *UtilityFunctions) CalculateMD5Hash(input string) []byte {
	hash := md5.Sum([]byte(input))
	return hash[:]
}

func (uf *UtilityFunctions) GenerateTLSClientHello() []byte {
	tlsData := make([]byte, 32)
	for i := range tlsData {
		tlsData[i] = byte((i*17 + len(tlsData)*13) % 256)
	}

	return tlsData
}

func (uf *UtilityFunctions) GenerateTLSExtensions() []byte {
	extensions := make([]byte, 24)
	for i := range extensions {
		extensions[i] = byte((i*23 + len(extensions)*19) % 256)
	}

	return extensions
}

func (uf *UtilityFunctions) GenerateJA4Extensions() []byte {
	extensions := make([]byte, 24)
	for i := range extensions {
		extensions[i] = byte((i*23 + len(extensions)*19) % 256)
	}

	return extensions
}

func (uf *UtilityFunctions) CalculateJA3Hash(tlsData []byte) []byte {
	hash := md5.Sum(tlsData)
	return hash[:]
}

func (uf *UtilityFunctions) CalculateJA4Hash(extensions []byte) []byte {
	hash := md5.Sum(extensions)
	return hash[:]
}

func (uf *UtilityFunctions) BuildJA3String(profile *ServiceProfile) string {
	ja3String := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-" +
		"49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-" +
		"27-17513,29-23-24,0"

	if profile != nil {
		ja3String += "-" + profile.DeviceID
	}

	return ja3String
}

func (uf *UtilityFunctions) CreateDynamicProfile(name, serviceType string) *types.TrafficProfile {
	profile := &types.TrafficProfile{
		Name:        name,
		ServiceType: serviceType,
		SizeDistribution: &types.SizeDistribution{
			Bins: make([]int, 0),
		},
		SizeWeights:    make([]float64, 0),
		Timings:        make([]time.Duration, 0),
		TimingWeights:  make([]float64, 0),
		BehavioralData: make(map[string]interface{}),
		MLFeatures:     make([]float64, 0),
		DeviceID:       uf.GenerateScientificDeviceID(),
		Effectiveness:  0.5,
		UsageCount:     0,
		LastUsed:       time.Now(),
	}

	profile.SizeDistribution.Bins = []int{64, 128, 256, 512, 1024, 2048, 4096, 8192}
	profile.SizeWeights = []float64{0.1, 0.2, 0.3, 0.2, 0.1, 0.05, 0.03, 0.02}

	profile.Timings = []time.Duration{
		10 * time.Millisecond,
		25 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		200 * time.Millisecond,
		500 * time.Millisecond,
		1000 * time.Millisecond,
		2000 * time.Millisecond,
	}
	profile.TimingWeights = []float64{0.05, 0.1, 0.2, 0.3, 0.2, 0.1, 0.03, 0.02}

	return profile
}

func (uf *UtilityFunctions) AnalyzeServiceTraffic(profile *types.TrafficProfile, serviceType string) {
	switch serviceType {
	case "vk":
		uf.analyzeVKTraffic(profile)
	case "yandex":
		uf.analyzeYandexTraffic(profile)
	case "mailru":
		uf.analyzeMailruTraffic(profile)
	case "ozon":
		uf.analyzeOzonTraffic(profile)
	default:
		uf.analyzeGenericTraffic(profile)
	}
}

func (uf *UtilityFunctions) analyzeVKTraffic(profile *types.TrafficProfile) {
	profile.SizeDistribution.Bins = []int{128, 256, 512, 1024, 2048, 4096}
	profile.SizeWeights = []float64{0.2, 0.3, 0.25, 0.15, 0.08, 0.02}

	profile.Timings = []time.Duration{
		20 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		200 * time.Millisecond,
		500 * time.Millisecond,
	}
	profile.TimingWeights = []float64{0.1, 0.3, 0.4, 0.15, 0.05}
}

func (uf *UtilityFunctions) analyzeYandexTraffic(profile *types.TrafficProfile) {
	profile.SizeDistribution.Bins = []int{256, 512, 1024, 2048, 4096, 8192}
	profile.SizeWeights = []float64{0.15, 0.25, 0.3, 0.2, 0.08, 0.02}

	profile.Timings = []time.Duration{
		30 * time.Millisecond,
		75 * time.Millisecond,
		150 * time.Millisecond,
		300 * time.Millisecond,
		600 * time.Millisecond,
	}
	profile.TimingWeights = []float64{0.05, 0.2, 0.4, 0.25, 0.1}
}

func (uf *UtilityFunctions) analyzeMailruTraffic(profile *types.TrafficProfile) {
	profile.SizeDistribution.Bins = []int{128, 256, 512, 1024, 2048, 4096}
	profile.SizeWeights = []float64{0.25, 0.3, 0.25, 0.15, 0.04, 0.01}

	profile.Timings = []time.Duration{
		25 * time.Millisecond,
		60 * time.Millisecond,
		120 * time.Millisecond,
		250 * time.Millisecond,
		500 * time.Millisecond,
	}
	profile.TimingWeights = []float64{0.1, 0.25, 0.35, 0.2, 0.1}
}

func (uf *UtilityFunctions) analyzeOzonTraffic(profile *types.TrafficProfile) {
	profile.SizeDistribution.Bins = []int{256, 512, 1024, 2048, 4096, 8192}
	profile.SizeWeights = []float64{0.1, 0.2, 0.3, 0.25, 0.12, 0.03}

	profile.Timings = []time.Duration{
		40 * time.Millisecond,
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
	}
	profile.TimingWeights = []float64{0.05, 0.15, 0.35, 0.3, 0.15}
}

func (uf *UtilityFunctions) analyzeGenericTraffic(profile *types.TrafficProfile) {
	profile.SizeDistribution.Bins = []int{64, 128, 256, 512, 1024, 2048, 4096}
	profile.SizeWeights = []float64{0.1, 0.2, 0.3, 0.25, 0.1, 0.04, 0.01}

	profile.Timings = []time.Duration{
		15 * time.Millisecond,
		40 * time.Millisecond,
		80 * time.Millisecond,
		160 * time.Millisecond,
		320 * time.Millisecond,
	}
	profile.TimingWeights = []float64{0.1, 0.3, 0.4, 0.15, 0.05}
}

func (uf *UtilityFunctions) UpdateProfileFromRealTraffic(profile *types.TrafficProfile, serviceType string) {
	profile.Effectiveness = math.Min(0.9, profile.Effectiveness+0.1)
	profile.LastUsed = time.Now()
}

func (uf *UtilityFunctions) GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)

	for i := range result {
		result[i] = charset[uf.GenerateRealisticRandom(len(charset))]
	}

	return string(result)
}

func (uf *UtilityFunctions) GenerateRandomBytes(length int) []byte {
	result := make([]byte, length)

	for i := range result {
		result[i] = byte(uf.GenerateRealisticRandom(256))
	}

	return result
}

func (uf *UtilityFunctions) CalculateEntropy(data []byte) float64 {
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

func (uf *UtilityFunctions) CalculateMeanFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	sum := 0.0
	for _, value := range values {
		sum += value
	}

	return sum / float64(len(values))
}

func (uf *UtilityFunctions) CalculateStdDevFloat(values []float64, mean float64) float64 {
	if len(values) == 0 {
		return 0
	}

	sum := 0.0
	for _, value := range values {
		diff := value - mean
		sum += diff * diff
	}

	return math.Sqrt(sum / float64(len(values)))
}

func (uf *UtilityFunctions) NormalizeValues(values []float64) []float64 {
	if len(values) == 0 {
		return values
	}

	minVal := values[0]
	maxVal := values[0]
	for _, value := range values {
		if value < minVal {
			minVal = value
		}
		if value > maxVal {
			maxVal = value
		}
	}

	normalized := make([]float64, len(values))
	rangeValue := maxVal - minVal
	if rangeValue == 0 {
		for i := range normalized {
			normalized[i] = 0.5
		}
	} else {
		for i, value := range values {
			normalized[i] = (value - minVal) / rangeValue
		}
	}

	return normalized
}

func (uf *UtilityFunctions) ClampValue(value, minVal, maxVal float64) float64 {
	if value < minVal {
		return minVal
	}
	if value > maxVal {
		return maxVal
	}
	return value
}

func (uf *UtilityFunctions) Lerp(a, b, t float64) float64 {
	return a + t*(b-a)
}

func (uf *UtilityFunctions) SmoothStep(edge0, edge1, x float64) float64 {
	t := uf.ClampValue((x-edge0)/(edge1-edge0), 0.0, 1.0)
	return t * t * (3.0 - 2.0*t)
}

func (uf *UtilityFunctions) GetRandomSeed() int64 {
	return uf.randomSeed
}

func (uf *UtilityFunctions) SetRandomSeed(seed int64) {
	uf.randomSeed = seed
}

func (uf *UtilityFunctions) ResetRandomSeed() {
	uf.randomSeed = time.Now().UnixNano()
}
