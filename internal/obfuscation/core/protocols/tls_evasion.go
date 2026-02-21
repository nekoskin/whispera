package protocols

import (
	"crypto/md5"
	crand "crypto/rand"
	"encoding/binary"
	"math/big"
	"sync"
)

var (
	tlsSmallBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 256)
		},
	}

	tlsMediumBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 512)
		},
	}

	tlsLargeBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 1024)
		},
	}

	tlsRandBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 8)
		},
	}
)

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

type TLSEvasion struct {
	ja3Profiles map[string]*JA3Profile
	ja4Profiles map[string]*JA4Profile
}

type JA3Profile struct {
	Version            string
	CipherSuites       []string
	Extensions         []string
	EllipticCurves     []string
	EllipticCurvePoint []string
}

type JA4Profile struct {
	Version      string
	CipherSuites string
	Extensions   string
	SNI          string
	ALPN         string
}

func NewTLSEvasion() *TLSEvasion {
	return &TLSEvasion{
		ja3Profiles: make(map[string]*JA3Profile),
		ja4Profiles: make(map[string]*JA4Profile),
	}
}

func (t *TLSEvasion) ApplyJA3Evasion(data []byte) []byte {
	clientHello := t.generateTLSClientHello()

	ja3Hash := t.calculateJA3Hash(clientHello)

	return t.modifyDataForJA3(data, ja3Hash)
}

func (t *TLSEvasion) ApplyJA4Evasion(data []byte) []byte {
	extensions := t.generateJA4Extensions()

	ja4Hash := t.calculateJA4Hash(extensions)

	return t.modifyDataForJA4(data, ja4Hash)
}

func (t *TLSEvasion) ApplyGREASEEvasion(data []byte) []byte {
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
		0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
		0xcaca, 0xdada, 0xeaea, 0xfafa,
	}

	n, err := crand.Int(crand.Reader, big.NewInt(int64(len(greaseValues))))
	if err != nil {
		return data
	}
	greaseValue := greaseValues[int(n.Int64())]

	return t.insertGREASEValue(data, greaseValue)
}

func (t *TLSEvasion) ApplyALPNEvasion(data []byte) []byte {
	alpnProtocols := []string{"h2", "http/1.1", "h3", "spdy/3.1", "spdy/3", "spdy/2", "http/1.0"}

	n, err := crand.Int(crand.Reader, big.NewInt(int64(len(alpnProtocols))))
	if err != nil {
		return data
	}
	protocol := alpnProtocols[int(n.Int64())]

	return t.insertALPNExtension(data, protocol)
}

func (t *TLSEvasion) ApplyECHEvasion(data []byte) []byte {
	return t.insertECHExtension(data)
}

func (t *TLSEvasion) ApplyHPACKEvasion(data []byte) []byte {
	return t.modifyHPACKHeaders(data)
}

func (t *TLSEvasion) ApplyQPACKEvasion(data []byte) []byte {
	return t.modifyQPACKHeaders(data)
}

func (t *TLSEvasion) ApplyDoHEvasion(data []byte) []byte {
	return t.addDoHCharacteristics(data)
}

func (t *TLSEvasion) ApplyDoQEvasion(data []byte) []byte {
	return t.addDoQCharacteristics(data)
}

func (t *TLSEvasion) generateTLSClientHello() []byte {
	clientHello := getTLSBufferFromPool(512)
	needReturn := false
	if cap(clientHello) < 512 {
		clientHello = make([]byte, 512)
	} else {
		clientHello = clientHello[:512]
		needReturn = true
	}

	binary.BigEndian.PutUint16(clientHello[0:2], 0x0303)

	if _, err := crand.Read(clientHello[2:34]); err != nil {
		return nil
	}

	clientHello[34] = 0

	cipherSuites := []uint16{0x1301, 0x1302, 0x1303, 0xc02f, 0xc030, 0xc02b, 0xc02c, 0xc02d, 0xc02e}
	cipherSuiteLength := len(cipherSuites) * 2
	if cipherSuiteLength < 0 {
		cipherSuiteLength = 0
	}
	if cipherSuiteLength > 65535 {
		cipherSuiteLength = 65535
	}
	binary.BigEndian.PutUint16(clientHello[35:37], uint16(cipherSuiteLength))

	offset := 37
	for _, suite := range cipherSuites {
		binary.BigEndian.PutUint16(clientHello[offset:offset+2], suite)
		offset += 2
	}

	clientHello[offset] = 1
	clientHello[offset+1] = 0
	offset += 2

	extensionsLength := 256
	binary.BigEndian.PutUint16(clientHello[offset:offset+2], uint16(extensionsLength))
	offset += 2

	offset = t.addTLSExtensions(clientHello, offset)

	result := make([]byte, offset)
	copy(result, clientHello[:offset])

	if needReturn {
		putTLSBufferToPool(clientHello)
	}

	return result
}

func (t *TLSEvasion) calculateJA3Hash(_ []byte) []byte {
	ja3String := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-" +
		"49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-" +
		"27-17513,29-23-24,0"

	hash := md5.Sum([]byte(ja3String))
	return hash[:]
}

func (t *TLSEvasion) generateJA4Extensions() []byte {
	extensions := getTLSBufferFromPool(64)
	needReturn := false
	if cap(extensions) < 64 {
		extensions = make([]byte, 64)
	} else {
		extensions = extensions[:64]
		needReturn = true
	}
	offset := 0

	offset = t.addExtension(extensions, offset, 0, []byte("example.com"))

	offset = t.addExtension(extensions, offset, 16, []byte("h2,http/1.1"))

	offset = t.addExtension(extensions, offset, 43, []byte{0x03, 0x04})

	result := make([]byte, offset)
	copy(result, extensions[:offset])

	if needReturn {
		putTLSBufferToPool(extensions)
	}

	return result
}

func (t *TLSEvasion) calculateJA4Hash(_ []byte) []byte {
	ja4String := "t13d1516h2_8daaf6152991"

	hash := md5.Sum([]byte(ja4String))
	return hash[:]
}

func (t *TLSEvasion) modifyDataForJA3(data, ja3Hash []byte) []byte {
	if len(data) <= 10 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	if len(result) > 10 {
		copy(result[5:5+len(ja3Hash)], ja3Hash)
	}

	return result
}

func (t *TLSEvasion) modifyDataForJA4(data, ja4Hash []byte) []byte {
	if len(data) <= 15 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	if len(result) > 15 {
		copy(result[10:10+len(ja4Hash)], ja4Hash)
	}

	return result
}

func (t *TLSEvasion) insertGREASEValue(data []byte, greaseValue uint16) []byte {
	result := getTLSBufferFromPool(len(data) + 2)
	needReturn := false
	if cap(result) < len(data)+2 {
		result = make([]byte, len(data)+2)
	} else {
		result = result[:len(data)+2]
		needReturn = true
	}

	copy(result, data)

	if len(data) < 2 {
		return result
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(len(data)-1)))
	if err != nil {
		return result
	}
	pos := int(n.Int64())
	binary.BigEndian.PutUint16(result[pos:pos+2], greaseValue)

	resultCopy := make([]byte, len(result))
	copy(resultCopy, result)

	if needReturn {
		putTLSBufferToPool(result)
	}

	return resultCopy
}

func (t *TLSEvasion) insertALPNExtension(data []byte, protocol string) []byte {
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

	offset := len(data)
	result[offset] = 0x00
	result[offset+1] = 0x10
	offset += 2

	protocolBytes := []byte(protocol)
	extLength := len(protocolBytes) + 2
	if extLength < 0 {
		extLength = 0
	}
	if extLength > 65535 {
		extLength = 65535
	}
	binary.BigEndian.PutUint16(result[offset:offset+2], uint16(extLength))
	offset += 2

	alpnLen := len(protocolBytes)
	if alpnLen < 0 {
		alpnLen = 0
	}
	if alpnLen > 255 {
		alpnLen = 255
	}
	result[offset] = uint8(alpnLen)
	offset++

	copy(result[offset:offset+len(protocolBytes)], protocolBytes)

	resultCopy := make([]byte, offset+len(protocolBytes))
	copy(resultCopy, result[:offset+len(protocolBytes)])

	if needReturn {
		putTLSBufferToPool(result)
	}

	return resultCopy
}

func (t *TLSEvasion) insertECHExtension(data []byte) []byte {
	result := getTLSBufferFromPool(len(data) + 20)
	needReturn := false
	if cap(result) < len(data)+20 {
		result = make([]byte, len(data)+20)
	} else {
		result = result[:len(data)+20]
		needReturn = true
	}

	copy(result, data)

	offset := len(data)
	result[offset] = 0x00
	result[offset+1] = 0x2a
	offset += 2

	binary.BigEndian.PutUint16(result[offset:offset+2], 16)
	offset += 2

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

	resultCopy := make([]byte, offset+16)
	copy(resultCopy, result[:offset+16])

	if needReturn {
		putTLSBufferToPool(result)
	}

	return resultCopy
}

func (t *TLSEvasion) modifyHPACKHeaders(data []byte) []byte {
	if len(data) <= 20 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	if len(result) > 20 {
		headers := []byte(":method: GET\r\n:path: /\r\n:scheme: https\r\n:authority: example.com\r\n")
		if len(result) > len(headers) {
			copy(result[10:10+len(headers)], headers)
		}
	}

	return result
}

func (t *TLSEvasion) modifyQPACKHeaders(data []byte) []byte {
	if len(data) <= 15 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	if len(result) > 15 {
		result[5] = 0x40
		result[6] = 0x01
	}

	return result
}

func (t *TLSEvasion) addDoHCharacteristics(data []byte) []byte {
	result := getTLSBufferFromPool(len(data) + 50)
	needReturn := false
	if cap(result) < len(data)+50 {
		result = make([]byte, len(data)+50)
	} else {
		result = result[:len(data)+50]
		needReturn = true
	}

	copy(result, data)

	offset := len(data)
	dohHeaders := []byte("content-type: application/dns-message\r\naccept: application/dns-message\r\n")
	copy(result[offset:offset+len(dohHeaders)], dohHeaders)

	resultCopy := make([]byte, offset+len(dohHeaders))
	copy(resultCopy, result[:offset+len(dohHeaders)])

	if needReturn {
		putTLSBufferToPool(result)
	}

	return resultCopy
}

func (t *TLSEvasion) addDoQCharacteristics(data []byte) []byte {
	result := getTLSBufferFromPool(len(data) + 30)
	needReturn := false
	if cap(result) < len(data)+30 {
		result = make([]byte, len(data)+30)
	} else {
		result = result[:len(data)+30]
		needReturn = true
	}

	copy(result, data)

	offset := len(data)
	doqData := []byte("DNS over QUIC stream")
	copy(result[offset:offset+len(doqData)], doqData)

	resultCopy := make([]byte, offset+len(doqData))
	copy(resultCopy, result[:offset+len(doqData)])

	if needReturn {
		putTLSBufferToPool(result)
	}

	return resultCopy
}

func (t *TLSEvasion) addTLSExtensions(data []byte, offset int) int {
	extensions := []struct {
		extType uint16
		data    []byte
	}{
		{0, []byte("example.com")},
		{16, []byte("h2,http/1.1")},
		{43, []byte{0x03, 0x04}},
		{51, []byte{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18}},
		{65281, []byte{0x00}},
	}

	for _, ext := range extensions {
		offset = t.addExtension(data, offset, ext.extType, ext.data)
	}

	return offset
}

func (t *TLSEvasion) addExtension(data []byte, offset int, extType uint16, extData []byte) int {
	binary.BigEndian.PutUint16(data[offset:offset+2], extType)
	offset += 2

	extDataLen := len(extData)
	if extDataLen < 0 {
		extDataLen = 0
	}
	if extDataLen > 65535 {
		extDataLen = 65535
	}
	binary.BigEndian.PutUint16(data[offset:offset+2], uint16(extDataLen))
	offset += 2

	copy(data[offset:offset+len(extData)], extData)
	offset += len(extData)

	return offset
}
