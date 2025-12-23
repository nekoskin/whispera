package sniffing

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// ОПТИМИЗАЦИЯ: Пул буферов для переиспользования памяти
var (
	// Пул для маленьких буферов (5 байт для peek)
	peekBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 5)
		},
	}
	
	// Пул для средних буферов (до 16KB для TLS записей)
	recordBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 16384)
		},
	}
)

// ExtractSNI извлекает Server Name Indication из TLS ClientHello
// Возвращает домен и ошибку (если есть)
func ExtractSNI(conn net.Conn) (string, error) {
	// ОПТИМИЗАЦИЯ: Используем пул буферов для уменьшения аллокаций
	peekBuf := peekBufferPool.Get().([]byte)
	defer peekBufferPool.Put(peekBuf)
	
	// Читаем первые байты для определения типа записи
	_, err := io.ReadFull(conn, peekBuf)
	if err != nil {
		return "", fmt.Errorf("failed to read TLS header: %w", err)
	}

	// Проверяем, что это TLS handshake (0x16)
	if peekBuf[0] != 0x16 {
		return "", fmt.Errorf("not a TLS handshake record")
	}

	// Читаем длину записи (2 байта, big-endian)
	recordLen := int(binary.BigEndian.Uint16(peekBuf[3:5]))
	if recordLen > 16384 || recordLen < 0 {
		return "", fmt.Errorf("invalid TLS record length: %d", recordLen)
	}

	// ОПТИМИЗАЦИЯ: Используем пул для больших буферов
	var record []byte
	if recordLen+5 <= 16384 {
		record = recordBufferPool.Get().([]byte)
		record = record[:5+recordLen]
		defer recordBufferPool.Put(record[:0])
	} else {
		// Для очень больших записей создаем напрямую
		record = make([]byte, 5+recordLen)
	}
	copy(record, peekBuf)
	if recordLen > 0 {
		if _, err := io.ReadFull(conn, record[5:]); err != nil {
			return "", fmt.Errorf("failed to read TLS record: %w", err)
		}
	}

	// Проверяем, что это ClientHello (0x01)
	if len(record) < 6 || record[5] != 0x01 {
		return "", fmt.Errorf("not a ClientHello message")
	}

	// Парсим ClientHello
	// Структура TLS ClientHello:
	// - ProtocolVersion (2 bytes)
	// - Random (32 bytes)
	// - SessionID length (1 byte) + SessionID
	// - CipherSuites length (2 bytes) + CipherSuites
	// - CompressionMethods length (1 byte) + CompressionMethods
	// - Extensions length (2 bytes) + Extensions
	// - Extension: ServerName (0x0000)
	//   - ServerNameList length (2 bytes)
	//   - ServerName entry
	//     - NameType (1 byte, 0x00 = host_name)
	//     - Name length (2 bytes)
	//     - Name (string)

	offset := 5 + 1 // Skip record header and handshake type
	if len(record) < offset+3 {
		return "", fmt.Errorf("ClientHello too short")
	}

	// Skip ProtocolVersion (2 bytes)
	offset += 2
	if len(record) < offset+32 {
		return "", fmt.Errorf("ClientHello too short for Random")
	}
	// Skip Random (32 bytes)
	offset += 32

	// Skip SessionID
	if len(record) < offset+1 {
		return "", fmt.Errorf("ClientHello too short for SessionID length")
	}
	sessionIDLen := int(record[offset])
	offset += 1 + sessionIDLen
	if len(record) < offset {
		return "", fmt.Errorf("ClientHello too short for SessionID")
	}

	// Skip CipherSuites
	if len(record) < offset+2 {
		return "", fmt.Errorf("ClientHello too short for CipherSuites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(record[offset:offset+2]))
	offset += 2 + cipherSuitesLen
	if len(record) < offset {
		return "", fmt.Errorf("ClientHello too short for CipherSuites")
	}

	// Skip CompressionMethods
	if len(record) < offset+1 {
		return "", fmt.Errorf("ClientHello too short for CompressionMethods length")
	}
	compressionMethodsLen := int(record[offset])
	offset += 1 + compressionMethodsLen
	if len(record) < offset {
		return "", fmt.Errorf("ClientHello too short for CompressionMethods")
	}

	// Читаем Extensions
	if len(record) < offset+2 {
		return "", fmt.Errorf("ClientHello too short for Extensions length")
	}
	extensionsLen := int(binary.BigEndian.Uint16(record[offset:offset+2]))
	offset += 2
	extensionsEnd := offset + extensionsLen
	if len(record) < extensionsEnd {
		return "", fmt.Errorf("ClientHello too short for Extensions")
	}

	// Ищем extension ServerName (0x0000)
	for offset < extensionsEnd {
		if len(record) < offset+4 {
			break
		}
		extType := binary.BigEndian.Uint16(record[offset:offset+2])
		extLen := int(binary.BigEndian.Uint16(record[offset+2:offset+4]))
		offset += 4

		if extType == 0x0000 { // ServerName extension
			if len(record) < offset+extLen {
				break
			}
			extData := record[offset : offset+extLen]
			// Парсим ServerNameList
			if len(extData) < 2 {
				break
			}
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			if len(extData) < 2+listLen {
				break
			}
			listData := extData[2 : 2+listLen]
			// Ищем первый ServerName entry с типом host_name (0x00)
			listOffset := 0
			for listOffset < len(listData) {
				if len(listData) < listOffset+3 {
					break
				}
				nameType := listData[listOffset]
				nameLen := int(binary.BigEndian.Uint16(listData[listOffset+1:listOffset+3]))
				listOffset += 3
				if nameType == 0x00 && len(listData) >= listOffset+nameLen {
					// Нашли host_name
					hostname := string(listData[listOffset : listOffset+nameLen])
					return hostname, nil
				}
				listOffset += nameLen
			}
		}

		offset += extLen
	}

	return "", fmt.Errorf("SNI not found in ClientHello")
}

// PeekSNI пытается извлечь SNI без чтения данных из соединения
// Использует Peek для чтения без удаления из буфера
func PeekSNI(peekData []byte) (string, error) {
	if len(peekData) < 5 {
		return "", fmt.Errorf("data too short")
	}

	// Проверяем, что это TLS handshake (0x16)
	if peekData[0] != 0x16 {
		return "", fmt.Errorf("not a TLS handshake record")
	}

	// Читаем длину записи
	recordLen := int(binary.BigEndian.Uint16(peekData[3:5]))
	if recordLen > 16384 || recordLen < 0 {
		return "", fmt.Errorf("invalid TLS record length: %d", recordLen)
	}

	// Нужно прочитать полную запись
	if len(peekData) < 5+recordLen {
		return "", fmt.Errorf("incomplete TLS record in peek data")
	}

	record := peekData[0 : 5+recordLen]

	// Проверяем, что это ClientHello (0x01)
	if len(record) < 6 || record[5] != 0x01 {
		return "", fmt.Errorf("not a ClientHello message")
	}

	// Парсим ClientHello (аналогично ExtractSNI)
	offset := 5 + 1 // Skip record header and handshake type
	if len(record) < offset+3 {
		return "", fmt.Errorf("ClientHello too short")
	}

	// Skip ProtocolVersion (2 bytes)
	offset += 2
	if len(record) < offset+32 {
		return "", fmt.Errorf("ClientHello too short for Random")
	}
	// Skip Random (32 bytes)
	offset += 32

	// Skip SessionID
	if len(record) < offset+1 {
		return "", fmt.Errorf("ClientHello too short for SessionID length")
	}
	sessionIDLen := int(record[offset])
	offset += 1 + sessionIDLen
	if len(record) < offset {
		return "", fmt.Errorf("ClientHello too short for SessionID")
	}

	// Skip CipherSuites
	if len(record) < offset+2 {
		return "", fmt.Errorf("ClientHello too short for CipherSuites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(record[offset:offset+2]))
	offset += 2 + cipherSuitesLen
	if len(record) < offset {
		return "", fmt.Errorf("ClientHello too short for CipherSuites")
	}

	// Skip CompressionMethods
	if len(record) < offset+1 {
		return "", fmt.Errorf("ClientHello too short for CompressionMethods length")
	}
	compressionMethodsLen := int(record[offset])
	offset += 1 + compressionMethodsLen
	if len(record) < offset {
		return "", fmt.Errorf("ClientHello too short for CompressionMethods")
	}

	// Читаем Extensions
	if len(record) < offset+2 {
		return "", fmt.Errorf("ClientHello too short for Extensions length")
	}
	extensionsLen := int(binary.BigEndian.Uint16(record[offset:offset+2]))
	offset += 2
	extensionsEnd := offset + extensionsLen
	if len(record) < extensionsEnd {
		return "", fmt.Errorf("ClientHello too short for Extensions")
	}

	// Ищем extension ServerName (0x0000)
	for offset < extensionsEnd {
		if len(record) < offset+4 {
			break
		}
		extType := binary.BigEndian.Uint16(record[offset:offset+2])
		extLen := int(binary.BigEndian.Uint16(record[offset+2:offset+4]))
		offset += 4

		if extType == 0x0000 { // ServerName extension
			if len(record) < offset+extLen {
				break
			}
			extData := record[offset : offset+extLen]
			// Парсим ServerNameList
			if len(extData) < 2 {
				break
			}
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			if len(extData) < 2+listLen {
				break
			}
			listData := extData[2 : 2+listLen]
			// Ищем первый ServerName entry с типом host_name (0x00)
			listOffset := 0
			for listOffset < len(listData) {
				if len(listData) < listOffset+3 {
					break
				}
				nameType := listData[listOffset]
				nameLen := int(binary.BigEndian.Uint16(listData[listOffset+1:listOffset+3]))
				listOffset += 3
				if nameType == 0x00 && len(listData) >= listOffset+nameLen {
					// Нашли host_name
					hostname := string(listData[listOffset : listOffset+nameLen])
					return hostname, nil
				}
				listOffset += nameLen
			}
		}

		offset += extLen
	}

	return "", fmt.Errorf("SNI not found in ClientHello")
}

// IsTLSClientHello проверяет, является ли данные началом TLS ClientHello
func IsTLSClientHello(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	// TLS handshake record: 0x16
	// ClientHello: 0x01 (после длины записи)
	if data[0] == 0x16 && len(data) >= 6 && data[5] == 0x01 {
		return true
	}
	return false
}

// BufferedConnReader позволяет читать данные из соединения с возможностью "вернуть" их обратно
type BufferedConnReader struct {
	conn   net.Conn
	buffer *bytes.Buffer
}

// NewBufferedConnReader создает новый BufferedConnReader
func NewBufferedConnReader(conn net.Conn) *BufferedConnReader {
	return &BufferedConnReader{
		conn:   conn,
		buffer: bytes.NewBuffer(nil),
	}
}

// Read читает данные, сначала из буфера, затем из соединения
func (b *BufferedConnReader) Read(p []byte) (n int, err error) {
	if b.buffer.Len() > 0 {
		return b.buffer.Read(p)
	}
	return b.conn.Read(p)
}

// Peek читает данные из соединения и сохраняет их в буфере
func (b *BufferedConnReader) Peek(size int) ([]byte, error) {
	buf := make([]byte, size)
	n, err := io.ReadFull(b.conn, buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	b.buffer.Write(buf[:n])
	return buf[:n], nil
}

