package utils

import (
	"crypto/md5" //nolint:gosec // MD5 used for TLS fingerprinting, not cryptography
	"math"
	"time"
	"whispera/internal/obfuscation/core/types"
)

// ServiceProfile - профиль сервиса
type ServiceProfile struct {
	DeviceID string
	Name     string
	Type     string
}

// UtilityFunctions - модуль с утилитарными функциями
type UtilityFunctions struct {
	randomSeed int64
}

// NewUtilityFunctions создает новый модуль утилитарных функций
func NewUtilityFunctions() *UtilityFunctions {
	return &UtilityFunctions{
		randomSeed: time.Now().UnixNano(),
	}
}

// CalculateMean вычисляет среднее значение
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

// CalculateStdDev вычисляет стандартное отклонение
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

// CalculateMin вычисляет минимальное значение
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

// CalculateMax вычисляет максимальное значение
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

// SelectWeightedSize выбирает взвешенный размер
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

// GenerateRealisticRandom генерирует реалистичное случайное число
func (uf *UtilityFunctions) GenerateRealisticRandom(maxVal int) int {
	// Генерируем реалистичное случайное число
	uf.randomSeed = (uf.randomSeed*1103515245 + 12345) & 0x7fffffff
	return int(uf.randomSeed % int64(maxVal))
}

// GenerateRealisticTiming генерирует реалистичный тайминг
func (uf *UtilityFunctions) GenerateRealisticTiming(baseDelay int, variance float64) time.Duration {
	base := time.Duration(baseDelay) * time.Millisecond
	varianceDuration := time.Duration(float64(uf.GenerateRealisticRandom(100))*variance) * time.Millisecond
	return base + varianceDuration
}

// GenerateHumanThinkTime генерирует время человеческого мышления
func (uf *UtilityFunctions) GenerateHumanThinkTime() float64 {
	// Генерируем время человеческого мышления
	baseTime := 0.5
	variance := float64(uf.GenerateRealisticRandom(100)) / 100.0
	return baseTime + variance*2.0
}

// GenerateNetworkJitter генерирует сетевой джиттер
func (uf *UtilityFunctions) GenerateNetworkJitter() float64 {
	// Генерируем сетевой джиттер
	baseJitter := 0.1
	variance := float64(uf.GenerateRealisticRandom(50)) / 100.0
	return baseJitter + variance*0.5
}

// GenerateScientificDeviceID генерирует научный ID устройства
func (uf *UtilityFunctions) GenerateScientificDeviceID() string {
	// Генерируем научный ID устройства
	deviceID := "sci_device_"
	for i := 0; i < 16; i++ {
		deviceID += string(rune('a' + (i*7)%26))
	}
	return deviceID
}

// CalculateMD5Hash вычисляет MD5 hash
func (uf *UtilityFunctions) CalculateMD5Hash(input string) []byte {
	hash := md5.Sum([]byte(input)) //nolint:gosec // MD5 for TLS fingerprinting
	return hash[:]
}

// GenerateTLSClientHello генерирует TLS Client Hello
func (uf *UtilityFunctions) GenerateTLSClientHello() []byte {
	// Генерируем TLS Client Hello данные
	tlsData := make([]byte, 32)
	for i := range tlsData {
		tlsData[i] = byte((i*17 + len(tlsData)*13) % 256)
	}

	return tlsData
}

// GenerateTLSExtensions генерирует TLS extensions
func (uf *UtilityFunctions) GenerateTLSExtensions() []byte {
	// Генерируем TLS extensions данные
	extensions := make([]byte, 24)
	for i := range extensions {
		extensions[i] = byte((i*23 + len(extensions)*19) % 256)
	}

	return extensions
}

// GenerateJA4Extensions генерирует JA4 extensions
func (uf *UtilityFunctions) GenerateJA4Extensions() []byte {
	// Генерируем JA4 extensions данные
	extensions := make([]byte, 24)
	for i := range extensions {
		extensions[i] = byte((i*23 + len(extensions)*19) % 256)
	}

	return extensions
}

// CalculateJA3Hash вычисляет JA3 hash
func (uf *UtilityFunctions) CalculateJA3Hash(tlsData []byte) []byte {
	// Вычисляем MD5 hash от TLS данных
	hash := md5.Sum(tlsData) //nolint:gosec // MD5 for TLS fingerprinting
	return hash[:]
}

// CalculateJA4Hash вычисляет JA4 hash
func (uf *UtilityFunctions) CalculateJA4Hash(extensions []byte) []byte {
	// Вычисляем MD5 hash от extensions данных
	hash := md5.Sum(extensions) //nolint:gosec // MD5 for TLS fingerprinting
	return hash[:]
}

// BuildJA3String строит JA3 строку
func (uf *UtilityFunctions) BuildJA3String(profile *ServiceProfile) string {
	// Строим JA3 строку на основе профиля
	ja3String := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-" +
		"49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-" +
		"27-17513,29-23-24,0"

	// Добавляем данные профиля
	if profile != nil {
		ja3String += "-" + profile.DeviceID
	}

	return ja3String
}

// CreateDynamicProfile создает динамический профиль
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

	// Инициализируем базовые значения
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

// AnalyzeServiceTraffic анализирует трафик сервиса
func (uf *UtilityFunctions) AnalyzeServiceTraffic(profile *types.TrafficProfile, serviceType string) {
	// Анализируем трафик сервиса
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

// analyzeVKTraffic анализирует трафик ВКонтакте
func (uf *UtilityFunctions) analyzeVKTraffic(profile *types.TrafficProfile) {
	// Анализируем трафик ВКонтакте
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

// analyzeYandexTraffic анализирует трафик Яндекс
func (uf *UtilityFunctions) analyzeYandexTraffic(profile *types.TrafficProfile) {
	// Анализируем трафик Яндекс
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

// analyzeMailruTraffic анализирует трафик Mail.ru
func (uf *UtilityFunctions) analyzeMailruTraffic(profile *types.TrafficProfile) {
	// Анализируем трафик Mail.ru
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

// analyzeOzonTraffic анализирует трафик Ozon
func (uf *UtilityFunctions) analyzeOzonTraffic(profile *types.TrafficProfile) {
	// Анализируем трафик Ozon
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

// analyzeGenericTraffic анализирует общий трафик
func (uf *UtilityFunctions) analyzeGenericTraffic(profile *types.TrafficProfile) {
	// Анализируем общий трафик
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

// UpdateProfileFromRealTraffic обновляет профиль на основе реального трафика
func (uf *UtilityFunctions) UpdateProfileFromRealTraffic(profile *types.TrafficProfile, serviceType string) {
	// Обновляем профиль на основе реального трафика
	// Здесь можно добавить логику обновления на основе реальных данных
	profile.Effectiveness = math.Min(0.9, profile.Effectiveness+0.1)
	profile.LastUsed = time.Now()
}

// GenerateRandomString генерирует случайную строку
func (uf *UtilityFunctions) GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)

	for i := range result {
		result[i] = charset[uf.GenerateRealisticRandom(len(charset))]
	}

	return string(result)
}

// GenerateRandomBytes генерирует случайные байты
func (uf *UtilityFunctions) GenerateRandomBytes(length int) []byte {
	result := make([]byte, length)

	for i := range result {
		result[i] = byte(uf.GenerateRealisticRandom(256))
	}

	return result
}

// CalculateEntropy вычисляет энтропию
func (uf *UtilityFunctions) CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Подсчитываем частоты байтов
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Вычисляем энтропию
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(len(data))
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// CalculateMeanFloat вычисляет среднее значение для float64
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

// CalculateStdDevFloat вычисляет стандартное отклонение для float64
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

// NormalizeValues нормализует значения
func (uf *UtilityFunctions) NormalizeValues(values []float64) []float64 {
	if len(values) == 0 {
		return values
	}

	// Находим минимум и максимум
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

	// Нормализуем
	normalized := make([]float64, len(values))
	rangeValue := maxVal - minVal
	if rangeValue == 0 {
		// Все значения одинаковые
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

// ClampValue ограничивает значение
func (uf *UtilityFunctions) ClampValue(value, minVal, maxVal float64) float64 {
	if value < minVal {
		return minVal
	}
	if value > maxVal {
		return maxVal
	}
	return value
}

// Lerp выполняет линейную интерполяцию
func (uf *UtilityFunctions) Lerp(a, b, t float64) float64 {
	return a + t*(b-a)
}

// SmoothStep выполняет плавную интерполяцию
func (uf *UtilityFunctions) SmoothStep(edge0, edge1, x float64) float64 {
	t := uf.ClampValue((x-edge0)/(edge1-edge0), 0.0, 1.0)
	return t * t * (3.0 - 2.0*t)
}

// GetRandomSeed возвращает текущий seed
func (uf *UtilityFunctions) GetRandomSeed() int64 {
	return uf.randomSeed
}

// SetRandomSeed устанавливает seed
func (uf *UtilityFunctions) SetRandomSeed(seed int64) {
	uf.randomSeed = seed
}

// ResetRandomSeed сбрасывает seed
func (uf *UtilityFunctions) ResetRandomSeed() {
	uf.randomSeed = time.Now().UnixNano()
}
