package evasion

import (
	"crypto/rand"
	"math"
	"time"
)

type CoverTraffic struct {
	enabled            bool
	coverData          []byte
	metadataProtection bool
	noiseLevel         float64
	generationRate     time.Duration
}

func NewCoverTraffic() *CoverTraffic {
	return &CoverTraffic{
		enabled:            false,
		coverData:          make([]byte, 0),
		metadataProtection: true,
		noiseLevel:         0.1,
		generationRate:     5 * time.Second,
	}
}

func (ct *CoverTraffic) GenerateCoverTraffic() []byte {
	coverSize := ct.calculateCoverTrafficSize()
	coverData := make([]byte, coverSize)

	if _, err := rand.Read(coverData); err != nil {
		for i := range coverData {
			coverData[i] = byte(i * 17)
		}
	}
	ct.addRealisticPatterns(coverData)
	ct.coverData = append(ct.coverData, coverData...)

	return coverData
}
func (ct *CoverTraffic) ClearCoverTraffic() {
	ct.coverData = make([]byte, 0)
}
func (ct *CoverTraffic) GetCoverTrafficSize() int {
	return len(ct.coverData)
}
func (ct *CoverTraffic) ApplyMetadataProtection(data []byte) []byte {
	if !ct.metadataProtection {
		return data
	}
	protectedData := make([]byte, len(data))
	copy(protectedData, data)

	noiseSize := int(float64(len(data)) * ct.noiseLevel)
	if noiseSize < 4 {
		noiseSize = 4
	}

	noise := make([]byte, noiseSize)
	if _, err := rand.Read(noise); err != nil {
		for i := range noise {
			noise[i] = byte(i * 17)
		}
	}
	for i := range protectedData {
		if i < len(noise) {
			protectedData[i] ^= noise[i]
		}
	}
	paddingSize := 8
	padding := make([]byte, paddingSize)
	if _, err := rand.Read(padding); err != nil {
		for i := range padding {
			padding[i] = byte(i * 17)
		}
	}

	return append(protectedData, padding...)
}
func (ct *CoverTraffic) calculateCoverTrafficSize() int {
	baseSize := 1024
	noiseMultiplier := int(ct.noiseLevel * 10)

	randomFactor := ct.generateRealisticRandom(500)

	return baseSize + noiseMultiplier*100 + randomFactor
}
func (ct *CoverTraffic) addRealisticPatterns(data []byte) {
	patternSize := len(data) / 10
	if patternSize < 4 {
		patternSize = 4
	}

	for i := 0; i < patternSize; i++ {
		switch i % 4 {
		case 0:
			data[i] = 'H'
		case 1:
			data[i] = 'T'
		case 2:
			data[i] = 'T'
		default:
			data[i] = 'P'
		}
	}

	jsonStart := patternSize
	jsonEnd := patternSize + patternSize/2
	if jsonEnd > len(data) {
		jsonEnd = len(data)
	}

	for i := jsonStart; i < jsonEnd; i++ {
		switch i % 8 {
		case 0:
			data[i] = '{'
		case 1:
			data[i] = '"'
		case 2:
			data[i] = 'k'
		case 3:
			data[i] = 'e'
		case 4:
			data[i] = 'y'
		case 5:
			data[i] = '"'
		case 6:
			data[i] = ':'
		default:
			data[i] = '"'
		}
	}
}
func (ct *CoverTraffic) generateRealisticRandom(max int) int {
	seed := time.Now().UnixNano()
	return int(seed % int64(max))
}

func (ct *CoverTraffic) IsEnabled() bool {
	return ct.enabled
}

func (ct *CoverTraffic) SetEnabled(enabled bool) {
	ct.enabled = enabled
}

func (ct *CoverTraffic) IsMetadataProtectionEnabled() bool {
	return ct.metadataProtection
}

func (ct *CoverTraffic) SetMetadataProtectionEnabled(enabled bool) {
	ct.metadataProtection = enabled
}

func (ct *CoverTraffic) GetNoiseLevel() float64 {
	return ct.noiseLevel
}

func (ct *CoverTraffic) SetNoiseLevel(level float64) {
	ct.noiseLevel = math.Max(0.0, math.Min(level, 1.0))
}

func (ct *CoverTraffic) GetGenerationRate() time.Duration {
	return ct.generationRate
}

func (ct *CoverTraffic) SetGenerationRate(rate time.Duration) {
	ct.generationRate = rate
}

func (ct *CoverTraffic) GenerateRealisticCoverTraffic() []byte {
	coverSize := ct.calculateRealisticCoverSize()
	coverData := make([]byte, coverSize)
	ct.fillWithRealisticData(coverData)
	ct.addTimestamps(coverData)
	ct.addHeaders(coverData)

	return coverData
}

func (ct *CoverTraffic) calculateRealisticCoverSize() int {
	hour := time.Now().Hour()
	var baseSize int
	if hour >= 9 && hour <= 17 {
		baseSize = 2048
	} else if hour >= 19 && hour <= 23 {
		baseSize = 1024
	} else {
		baseSize = 256
	}

	noiseMultiplier := int(ct.noiseLevel * 20)
	randomFactor := ct.generateRealisticRandom(1000)

	return baseSize + noiseMultiplier*50 + randomFactor
}

func (ct *CoverTraffic) fillWithRealisticData(data []byte) {
	patterns := []string{
		"GET /api/",
		"POST /data/",
		"PUT /update/",
		"DELETE /remove/",
		"HEAD /check/",
		"OPTIONS /info/",
	}

	patternIndex := 0
	for i := 0; i < len(data); i++ {
		if i < len(patterns[patternIndex]) {
			data[i] = patterns[patternIndex][i]
		} else {
			data[i] = byte('a' + (i % 26))
		}

		if i > 0 && i%20 == 0 {
			patternIndex = (patternIndex + 1) % len(patterns)
		}
	}
}

func (ct *CoverTraffic) addTimestamps(data []byte) {
	timestamp := time.Now().Unix()
	if len(data) >= 8 {
		for i := 0; i < 8; i++ {
			data[i] = byte(timestamp >> (i * 8))
		}
	}
}

func (ct *CoverTraffic) addHeaders(data []byte) {
	headers := []string{
		"Content-Type: application/json",
		"User-Agent: Mozilla/5.0",
		"Accept: */*",
		"Cache-Control: no-cache",
		"Connection: keep-alive",
	}

	headerIndex := 0
	headerPos := 0

	for i := 0; i < len(data) && headerIndex < len(headers); i++ {
		if headerPos < len(headers[headerIndex]) {
			data[i] = headers[headerIndex][headerPos]
			headerPos++
		} else {
			headerIndex++
			headerPos = 0
			if headerIndex < len(headers) {
				data[i] = '\n'
			}
		}
	}
}

func (ct *CoverTraffic) GenerateNoiseTraffic() []byte {
	noiseSize := int(ct.noiseLevel * 1000)
	if noiseSize < 64 {
		noiseSize = 64
	}

	noiseData := make([]byte, noiseSize)
	if _, err := rand.Read(noiseData); err != nil {
		for i := range noiseData {
			noiseData[i] = byte(i * 17)
		}
	}
	ct.addNoiseStructure(noiseData)

	return noiseData
}

func (ct *CoverTraffic) addNoiseStructure(data []byte) {
	structureSize := len(data) / 20
	if structureSize < 4 {
		structureSize = 4
	}
	for i := 0; i < len(data); i += structureSize {
		if i+3 < len(data) {
			data[i] = 0x00
			data[i+1] = 0x01
			data[i+2] = 0x02
			data[i+3] = 0x03
		}
	}
}

func (ct *CoverTraffic) GenerateDecoyTraffic() []byte {
	decoySize := 2048
	decoyData := make([]byte, decoySize)
	ct.fillDecoyData(decoyData)

	return decoyData
}

func (ct *CoverTraffic) fillDecoyData(data []byte) {
	decoyPatterns := []string{
		"HTTP/1.1 200 OK",
		"Content-Length: ",
		"Server: nginx/1.18.0",
		"Date: ",
		"Connection: close",
		"Cache-Control: no-cache",
		"Pragma: no-cache",
		"Expires: 0",
	}

	patternIndex := 0
	patternPos := 0

	for i := 0; i < len(data); i++ {
		if patternIndex < len(decoyPatterns) && patternPos < len(decoyPatterns[patternIndex]) {
			data[i] = decoyPatterns[patternIndex][patternPos]
			patternPos++
		} else {
			patternIndex++
			patternPos = 0
			if patternIndex < len(decoyPatterns) {
				data[i] = '\n'
			} else {
				data[i] = byte('A' + (i % 26))
			}
		}
	}
}

func (ct *CoverTraffic) GetCoverTrafficStats() map[string]interface{} {
	stats := make(map[string]interface{})

	stats["enabled"] = ct.enabled
	stats["size"] = len(ct.coverData)
	stats["metadata_protection"] = ct.metadataProtection
	stats["noise_level"] = ct.noiseLevel
	stats["generation_rate"] = ct.generationRate.String()

	return stats
}

func (ct *CoverTraffic) ResetCoverTraffic() {
	ct.coverData = make([]byte, 0)
	ct.noiseLevel = 0.1
	ct.generationRate = 5 * time.Second
}

func (ct *CoverTraffic) UpdateCoverTraffic() {
	if ct.enabled {
		newCoverData := ct.GenerateCoverTraffic()
		ct.coverData = append(ct.coverData, newCoverData...)

		maxSize := 1024 * 1024
		if len(ct.coverData) > maxSize {
			ct.coverData = ct.coverData[len(ct.coverData)-maxSize:]
		}
	}
}
