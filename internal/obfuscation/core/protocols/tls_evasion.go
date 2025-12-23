package protocols

import (
	"crypto/md5" //nolint:gosec // MD5 used for TLS fingerprinting, not cryptography
	crand "crypto/rand"
	"encoding/binary"
	"math/big"
	"sync"
)

// ОПТИМИЗАЦИЯ: Пулы буферов для переиспользования памяти
var (
	// Пул для маленьких буферов (до 256 байт)
	tlsSmallBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 256)
		},
	}
	
	// Пул для средних буферов (до 512 байт)
	tlsMediumBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 512)
		},
	}
	
	// Пул для больших буферов (до 1024 байт)
	tlsLargeBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 1024)
		},
	}
	
	// Пул для буферов случайных чисел (8 байт)
	tlsRandBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 8)
		},
	}
)

// getTLSBufferFromPool получает буфер из пула в зависимости от размера
func getTLSBufferFromPool(size int) []byte {
	if size <= 256 {
		buf := tlsSmallBufferPool.Get().([]byte)
		if cap(buf) < size {
			return make([]byte, 0, size)
		}
		return buf[:0]
	} else if size <= 512 {
		buf := tlsMediumBufferPool.Get().([]byte)
		if cap(buf) < size {
			return make([]byte, 0, size)
		}
		return buf[:0]
	} else if size <= 1024 {
		buf := tlsLargeBufferPool.Get().([]byte)
		if cap(buf) < size {
			return make([]byte, 0, size)
		}
		return buf[:0]
	}
	return make([]byte, 0, size)
}

// putTLSBufferToPool возвращает буфер в пул
func putTLSBufferToPool(buf []byte) {
	if cap(buf) == 0 {
		return
	}
	size := cap(buf)
	if size <= 256 {
		tlsSmallBufferPool.Put(buf[:0])
	} else if size <= 512 {
		tlsMediumBufferPool.Put(buf[:0])
	} else if size <= 1024 {
		tlsLargeBufferPool.Put(buf[:0])
	}
}

// TLSEvasion handles TLS protocol evasion techniques
type TLSEvasion struct {
	// TLS evasion state
	ja3Profiles map[string]*JA3Profile
	ja4Profiles map[string]*JA4Profile
}

// JA3Profile represents JA3 fingerprint profile
type JA3Profile struct {
	Version            string
	CipherSuites       []string
	Extensions         []string
	EllipticCurves     []string
	EllipticCurvePoint []string
}

// JA4Profile represents JA4 fingerprint profile
type JA4Profile struct {
	Version      string
	CipherSuites string
	Extensions   string
	SNI          string
	ALPN         string
}

// NewTLSEvasion creates new TLS evasion module
func NewTLSEvasion() *TLSEvasion {
	return &TLSEvasion{
		ja3Profiles: make(map[string]*JA3Profile),
		ja4Profiles: make(map[string]*JA4Profile),
	}
}

// ApplyJA3Evasion applies JA3 fingerprint evasion
func (t *TLSEvasion) ApplyJA3Evasion(data []byte) []byte {
	// Generate realistic TLS ClientHello
	clientHello := t.generateTLSClientHello()

	// Calculate JA3 hash
	ja3Hash := t.calculateJA3Hash(clientHello)

	// Modify data to match JA3 profile
	return t.modifyDataForJA3(data, ja3Hash)
}

// ApplyJA4Evasion applies JA4 fingerprint evasion
func (t *TLSEvasion) ApplyJA4Evasion(data []byte) []byte {
	// Generate JA4 extensions
	extensions := t.generateJA4Extensions()

	// Calculate JA4 hash
	ja4Hash := t.calculateJA4Hash(extensions)

	// Modify data to match JA4 profile
	return t.modifyDataForJA4(data, ja4Hash)
}

// ApplyGREASEEvasion applies GREASE evasion
func (t *TLSEvasion) ApplyGREASEEvasion(data []byte) []byte {
	// Add GREASE values to confuse fingerprinting
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
		0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
		0xcaca, 0xdada, 0xeaea, 0xfafa,
	}

	// Insert random GREASE values
	n, err := crand.Int(crand.Reader, big.NewInt(int64(len(greaseValues))))
	if err != nil {
		return data
	}
	greaseValue := greaseValues[int(n.Int64())]

	// Modify data with GREASE
	return t.insertGREASEValue(data, greaseValue)
}

// ApplyALPNEvasion applies ALPN evasion
func (t *TLSEvasion) ApplyALPNEvasion(data []byte) []byte {
	// Add ALPN extension to mimic real applications
	alpnProtocols := []string{"h2", "http/1.1", "h3", "spdy/3.1", "spdy/3", "spdy/2", "http/1.0"}

	// Select random ALPN protocol
	n, err := crand.Int(crand.Reader, big.NewInt(int64(len(alpnProtocols))))
	if err != nil {
		return data
	}
	protocol := alpnProtocols[int(n.Int64())]

	// Modify data with ALPN
	return t.insertALPNExtension(data, protocol)
}

// ApplyECHEvasion applies ECH (Encrypted Client Hello) evasion
func (t *TLSEvasion) ApplyECHEvasion(data []byte) []byte {
	// Add ECH extension for privacy
	return t.insertECHExtension(data)
}

// ApplyHPACKEvasion applies HPACK evasion
func (t *TLSEvasion) ApplyHPACKEvasion(data []byte) []byte {
	// Modify HPACK headers to avoid detection
	return t.modifyHPACKHeaders(data)
}

// ApplyQPACKEvasion applies QPACK evasion
func (t *TLSEvasion) ApplyQPACKEvasion(data []byte) []byte {
	// Modify QPACK headers for HTTP/3
	return t.modifyQPACKHeaders(data)
}

// ApplyDoHEvasion applies DNS over HTTPS evasion
func (t *TLSEvasion) ApplyDoHEvasion(data []byte) []byte {
	// Add DoH characteristics
	return t.addDoHCharacteristics(data)
}

// ApplyDoQEvasion applies DNS over QUIC evasion
func (t *TLSEvasion) ApplyDoQEvasion(data []byte) []byte {
	// Add DoQ characteristics
	return t.addDoQCharacteristics(data)
}

// generateTLSClientHello generates realistic TLS ClientHello
// ОПТИМИЗИРОВАНО: Использует пул буферов
func (t *TLSEvasion) generateTLSClientHello() []byte {
	// ОПТИМИЗАЦИЯ: Используем пул для буфера
	clientHello := getTLSBufferFromPool(512)
	needReturn := false
	if cap(clientHello) < 512 {
		clientHello = make([]byte, 512)
	} else {
		clientHello = clientHello[:512]
		needReturn = true
	}

	// TLS version (TLS 1.2)
	binary.BigEndian.PutUint16(clientHello[0:2], 0x0303)

	// Random bytes
	if _, err := crand.Read(clientHello[2:34]); err != nil {
		return nil
	}

	// Session ID length
	clientHello[34] = 0

	// Cipher suites
	cipherSuites := []uint16{0x1301, 0x1302, 0x1303, 0xc02f, 0xc030, 0xc02b, 0xc02c, 0xc02d, 0xc02e}
	cipherSuiteLength := len(cipherSuites) * 2
	if cipherSuiteLength < 0 {
		cipherSuiteLength = 0
	}
	if cipherSuiteLength > 65535 {
		cipherSuiteLength = 65535
	}
	//nolint:gosec // cipherSuiteLength is clamped to 0-65535 range
	binary.BigEndian.PutUint16(clientHello[35:37], uint16(cipherSuiteLength))

	offset := 37
	for _, suite := range cipherSuites {
		binary.BigEndian.PutUint16(clientHello[offset:offset+2], suite)
		offset += 2
	}

	// Compression methods
	clientHello[offset] = 1
	clientHello[offset+1] = 0
	offset += 2

	// Extensions length
	extensionsLength := 256
	binary.BigEndian.PutUint16(clientHello[offset:offset+2], uint16(extensionsLength))
	offset += 2

	// Add common extensions
	offset = t.addTLSExtensions(clientHello, offset)

	// ОПТИМИЗАЦИЯ: Создаем копию результата перед возвратом
	result := make([]byte, offset)
	copy(result, clientHello[:offset])
	
	// Возвращаем буфер в пул после создания копии
	if needReturn {
		putTLSBufferToPool(clientHello)
	}
	
	return result
}

// calculateJA3Hash calculates JA3 hash
func (t *TLSEvasion) calculateJA3Hash(_ []byte) []byte {
	// Simplified JA3 calculation
	ja3String := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-" +
		"49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-" +
		"27-17513,29-23-24,0"

	hash := md5.Sum([]byte(ja3String)) //nolint:gosec // MD5 for TLS fingerprinting
	return hash[:]
}

// generateJA4Extensions generates JA4 extensions
// ОПТИМИЗИРОВАНО: Использует пул буферов
func (t *TLSEvasion) generateJA4Extensions() []byte {
	// ОПТИМИЗАЦИЯ: Используем пул для буфера
	extensions := getTLSBufferFromPool(64)
	needReturn := false
	if cap(extensions) < 64 {
		extensions = make([]byte, 64)
	} else {
		extensions = extensions[:64]
		needReturn = true
	}
	offset := 0

	// SNI extension
	offset = t.addExtension(extensions, offset, 0, []byte("example.com"))

	// ALPN extension
	offset = t.addExtension(extensions, offset, 16, []byte("h2,http/1.1"))

	// Supported versions
	offset = t.addExtension(extensions, offset, 43, []byte{0x03, 0x04})

	// ОПТИМИЗАЦИЯ: Создаем копию результата перед возвратом
	result := make([]byte, offset)
	copy(result, extensions[:offset])
	
	// Возвращаем буфер в пул после создания копии
	if needReturn {
		putTLSBufferToPool(extensions)
	}
	
	return result
}

// calculateJA4Hash calculates JA4 hash
func (t *TLSEvasion) calculateJA4Hash(_ []byte) []byte {
	// Simplified JA4 calculation
	ja4String := "t13d1516h2_8daaf6152991"

	hash := md5.Sum([]byte(ja4String)) //nolint:gosec // MD5 for TLS fingerprinting
	return hash[:]
}

// Helper methods
// ОПТИМИЗИРОВАНО: Избегает лишних копий для маленьких пакетов
func (t *TLSEvasion) modifyDataForJA3(data, ja3Hash []byte) []byte {
	// ОПТИМИЗАЦИЯ: Для маленьких пакетов используем исходный буфер если возможно
	if len(data) <= 10 {
		return data
	}
	
	// Modify data to match JA3 profile
	result := make([]byte, len(data))
	copy(result, data)

	// Insert JA3 characteristics
	if len(result) > 10 {
		copy(result[5:5+len(ja3Hash)], ja3Hash)
	}

	return result
}

// ОПТИМИЗИРОВАНО: Избегает лишних копий для маленьких пакетов
func (t *TLSEvasion) modifyDataForJA4(data, ja4Hash []byte) []byte {
	// ОПТИМИЗАЦИЯ: Для маленьких пакетов используем исходный буфер если возможно
	if len(data) <= 15 {
		return data
	}
	
	// Modify data to match JA4 profile
	result := make([]byte, len(data))
	copy(result, data)

	// Insert JA4 characteristics
	if len(result) > 15 {
		copy(result[10:10+len(ja4Hash)], ja4Hash)
	}

	return result
}

// ОПТИМИЗИРОВАНО: Использует пул буферов
func (t *TLSEvasion) insertGREASEValue(data []byte, greaseValue uint16) []byte {
	// ОПТИМИЗАЦИЯ: Используем пул для буфера
	result := getTLSBufferFromPool(len(data) + 2)
	needReturn := false
	if cap(result) < len(data)+2 {
		result = make([]byte, len(data)+2)
	} else {
		result = result[:len(data)+2]
		needReturn = true
	}
	
	copy(result, data)

	// Insert GREASE value at random position
	if len(data) < 2 {
		return result
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(len(data)-1)))
	if err != nil {
		return result
	}
	pos := int(n.Int64())
	binary.BigEndian.PutUint16(result[pos:pos+2], greaseValue)

	// ОПТИМИЗАЦИЯ: Создаем копию результата перед возвратом
	resultCopy := make([]byte, len(result))
	copy(resultCopy, result)
	
	// Возвращаем буфер в пул после создания копии
	if needReturn {
		putTLSBufferToPool(result)
	}
	
	return resultCopy
}

// ОПТИМИЗИРОВАНО: Использует пул буферов
func (t *TLSEvasion) insertALPNExtension(data []byte, protocol string) []byte {
	// ОПТИМИЗАЦИЯ: Используем пул для буфера
	resultSize := len(data) + len(protocol) + 10
	result := getTLSBufferFromPool(resultSize)
	needReturn := false
	if cap(result) < resultSize {
		result = make([]byte, resultSize)
	} else {
		result = result[:resultSize]
		needReturn = true
	}
	
	copy(result, data)

	// Add ALPN extension
	offset := len(data)
	result[offset] = 0x00 // Extension type
	result[offset+1] = 0x10
	offset += 2

	// Extension length
	protocolBytes := []byte(protocol)
	extLength := len(protocolBytes) + 2
	if extLength < 0 {
		extLength = 0
	}
	if extLength > 65535 {
		extLength = 65535
	}
	//nolint:gosec // extLength is clamped to 0-65535 range
	binary.BigEndian.PutUint16(result[offset:offset+2], uint16(extLength))
	offset += 2

	// ALPN length
	alpnLen := len(protocolBytes)
	if alpnLen < 0 {
		alpnLen = 0
	}
	if alpnLen > 255 {
		alpnLen = 255
	}
	//nolint:gosec // alpnLen is clamped to 0-255 range
	result[offset] = uint8(alpnLen)
	offset++

	// Protocol string
	copy(result[offset:offset+len(protocolBytes)], protocolBytes)

	// ОПТИМИЗАЦИЯ: Создаем копию результата перед возвратом
	resultCopy := make([]byte, offset+len(protocolBytes))
	copy(resultCopy, result[:offset+len(protocolBytes)])
	
	// Возвращаем буфер в пул после создания копии
	if needReturn {
		putTLSBufferToPool(result)
	}
	
	return resultCopy
}

// ОПТИМИЗИРОВАНО: Использует пул буферов
func (t *TLSEvasion) insertECHExtension(data []byte) []byte {
	// ОПТИМИЗАЦИЯ: Используем пул для буфера
	result := getTLSBufferFromPool(len(data) + 20)
	needReturn := false
	if cap(result) < len(data)+20 {
		result = make([]byte, len(data)+20)
	} else {
		result = result[:len(data)+20]
		needReturn = true
	}
	
	copy(result, data)

	// ECH extension placeholder
	offset := len(data)
	result[offset] = 0x00
	result[offset+1] = 0x2a // ECH extension type
	offset += 2

	// Extension length
	binary.BigEndian.PutUint16(result[offset:offset+2], 16)
	offset += 2

	// ECH data (simplified)
	// ОПТИМИЗАЦИЯ: Используем пул для буфера случайных чисел
	randBuf := tlsRandBufferPool.Get().([]byte)
	if _, err := crand.Read(randBuf[:16]); err != nil {
		tlsRandBufferPool.Put(randBuf)
		if needReturn {
			putTLSBufferToPool(result)
		}
		return nil
	}
	copy(result[offset:offset+16], randBuf[:16])
	tlsRandBufferPool.Put(randBuf)

	// ОПТИМИЗАЦИЯ: Создаем копию результата перед возвратом
	resultCopy := make([]byte, offset+16)
	copy(resultCopy, result[:offset+16])
	
	// Возвращаем буфер в пул после создания копии
	if needReturn {
		putTLSBufferToPool(result)
	}

	return resultCopy
}

// ОПТИМИЗИРОВАНО: Избегает лишних копий
func (t *TLSEvasion) modifyHPACKHeaders(data []byte) []byte {
	// ОПТИМИЗАЦИЯ: Для маленьких пакетов используем исходный буфер если возможно
	if len(data) <= 20 {
		return data
	}
	
	// Modify HPACK headers to avoid detection
	result := make([]byte, len(data))
	copy(result, data)

	// Add realistic HTTP/2 headers
	if len(result) > 20 {
		// Add pseudo-headers
		headers := []byte(":method: GET\r\n:path: /\r\n:scheme: https\r\n:authority: example.com\r\n")
		if len(result) > len(headers) {
			copy(result[10:10+len(headers)], headers)
		}
	}

	return result
}

// ОПТИМИЗИРОВАНО: Избегает лишних копий
func (t *TLSEvasion) modifyQPACKHeaders(data []byte) []byte {
	// ОПТИМИЗАЦИЯ: Для маленьких пакетов используем исходный буфер если возможно
	if len(data) <= 15 {
		return data
	}
	
	// Modify QPACK headers for HTTP/3
	result := make([]byte, len(data))
	copy(result, data)

	// Add QPACK characteristics
	if len(result) > 15 {
		// Add QPACK static table references
		result[5] = 0x40 // QPACK instruction
		result[6] = 0x01 // Static table index
	}

	return result
}

// ОПТИМИЗИРОВАНО: Использует пул буферов
func (t *TLSEvasion) addDoHCharacteristics(data []byte) []byte {
	// ОПТИМИЗАЦИЯ: Используем пул для буфера
	result := getTLSBufferFromPool(len(data) + 50)
	needReturn := false
	if cap(result) < len(data)+50 {
		result = make([]byte, len(data)+50)
	} else {
		result = result[:len(data)+50]
		needReturn = true
	}
	
	copy(result, data)

	// Add DoH headers
	offset := len(data)
	dohHeaders := []byte("content-type: application/dns-message\r\naccept: application/dns-message\r\n")
	copy(result[offset:offset+len(dohHeaders)], dohHeaders)

	// ОПТИМИЗАЦИЯ: Создаем копию результата перед возвратом
	resultCopy := make([]byte, offset+len(dohHeaders))
	copy(resultCopy, result[:offset+len(dohHeaders)])
	
	// Возвращаем буфер в пул после создания копии
	if needReturn {
		putTLSBufferToPool(result)
	}
	
	return resultCopy
}

// ОПТИМИЗИРОВАНО: Использует пул буферов
func (t *TLSEvasion) addDoQCharacteristics(data []byte) []byte {
	// ОПТИМИЗАЦИЯ: Используем пул для буфера
	result := getTLSBufferFromPool(len(data) + 30)
	needReturn := false
	if cap(result) < len(data)+30 {
		result = make([]byte, len(data)+30)
	} else {
		result = result[:len(data)+30]
		needReturn = true
	}
	
	copy(result, data)

	// Add DoQ characteristics
	offset := len(data)
	doqData := []byte("DNS over QUIC stream")
	copy(result[offset:offset+len(doqData)], doqData)

	// ОПТИМИЗАЦИЯ: Создаем копию результата перед возвратом
	resultCopy := make([]byte, offset+len(doqData))
	copy(resultCopy, result[:offset+len(doqData)])
	
	// Возвращаем буфер в пул после создания копии
	if needReturn {
		putTLSBufferToPool(result)
	}
	
	return resultCopy
}

func (t *TLSEvasion) addTLSExtensions(data []byte, offset int) int {
	// Add common TLS extensions
	extensions := []struct {
		extType uint16
		data    []byte
	}{
		{0, []byte("example.com")},                       // SNI
		{16, []byte("h2,http/1.1")},                      // ALPN
		{43, []byte{0x03, 0x04}},                         // Supported versions
		{51, []byte{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18}}, // Key share
		{65281, []byte{0x00}},                            // Renegotiation info
	}

	for _, ext := range extensions {
		offset = t.addExtension(data, offset, ext.extType, ext.data)
	}

	return offset
}

func (t *TLSEvasion) addExtension(data []byte, offset int, extType uint16, extData []byte) int {
	// Add TLS extension
	binary.BigEndian.PutUint16(data[offset:offset+2], extType)
	offset += 2

	extDataLen := len(extData)
	if extDataLen < 0 {
		extDataLen = 0
	}
	if extDataLen > 65535 {
		extDataLen = 65535
	}
	//nolint:gosec // extDataLen is clamped to 0-65535 range
	binary.BigEndian.PutUint16(data[offset:offset+2], uint16(extDataLen))
	offset += 2

	copy(data[offset:offset+len(extData)], extData)
	offset += len(extData)

	return offset
}
