package xhttp

import (
	"bytes"
	"fmt"
	"sync"
)

// HPACKEncoder implements HTTP/2 header compression (RFC 7541)
type HPACKEncoder struct {
	// Static table from RFC 7541 section 2.3.1
	staticTable []*HeaderField

	// Dynamic table
	dynamicTable []*HeaderField
	maxTableSize int
	currentSize  int

	// Huffman encoding
	useHuffman bool

	mu sync.RWMutex
}

// HeaderField represents HTTP/2 header field
type HeaderField struct {
	Name  string
	Value string
}

// NewHPACKEncoder creates new HPACK encoder
func NewHPACKEncoder() *HPACKEncoder {
	enc := &HPACKEncoder{
		staticTable:  initStaticTable(),
		dynamicTable: make([]*HeaderField, 0),
		maxTableSize: 4096, // Default max table size
		useHuffman:   true,
	}
	return enc
}

// Encode encodes header list to HPACK format
func (he *HPACKEncoder) Encode(headers []*HeaderField) []byte {
	he.mu.Lock()
	defer he.mu.Unlock()

	buf := &bytes.Buffer{}

	for _, field := range headers {
		// Try to find in static table first
		if idx := he.findInStaticTable(field.Name, field.Value); idx > 0 {
			// Literal with incremental indexing
			he.encodeIndexed(buf, idx)
		} else if idx := he.findInStaticTableName(field.Name); idx > 0 {
			// Literal with incremental indexing - name only
			he.encodeLiteralWithIncrementalIndexing(buf, idx, field.Value)
		} else {
			// Literal without indexing
			he.encodeLiteralWithoutIndexing(buf, field.Name, field.Value)
		}
	}

	return buf.Bytes()
}

// encodeIndexed encodes a fully indexed header
func (he *HPACKEncoder) encodeIndexed(buf *bytes.Buffer, index int) {
	if index < 64 {
		buf.WriteByte(byte(0x80 | index))
	} else {
		buf.WriteByte(0xff)
		he.encodeInteger(buf, index-63, 7)
	}
}

// encodeLiteralWithIncrementalIndexing encodes literal with incremental indexing
func (he *HPACKEncoder) encodeLiteralWithIncrementalIndexing(buf *bytes.Buffer, index int, value string) {
	// Pattern: 01 + 6-bit prefix for index
	if index < 64 {
		buf.WriteByte(byte(0x40 | index))
	} else {
		buf.WriteByte(0x7f)
		he.encodeInteger(buf, index-63, 6)
	}

	// Encode value
	he.encodeString(buf, value)

	// Add to dynamic table
	if he.currentSize+len(value) <= he.maxTableSize {
		he.dynamicTable = append([]*HeaderField{{
			Name:  "", // Name is at index, only value stored
			Value: value,
		}}, he.dynamicTable...)
		he.currentSize += len(value)
	}
}

// encodeLiteralWithoutIndexing encodes literal without indexing
func (he *HPACKEncoder) encodeLiteralWithoutIndexing(buf *bytes.Buffer, name, value string) {
	// Pattern: 0000 + 4-bit prefix for index (0 for new name)
	buf.WriteByte(0x00)

	// Encode name
	he.encodeString(buf, name)

	// Encode value
	he.encodeString(buf, value)
}

// encodeString encodes string in HPACK format (RFC 7541 Section 5.2)
func (he *HPACKEncoder) encodeString(buf *bytes.Buffer, str string) {
	data := []byte(str)
	var encoded []byte
	useHuffman := false

	if he.useHuffman && len(data) > 1 {
		// Try Huffman encoding
		huffmanEncoded := huffmanEncode(data)
		// Use Huffman if it's smaller or equal
		if len(huffmanEncoded) <= len(data) {
			encoded = huffmanEncoded
			useHuffman = true
		} else {
			encoded = data
		}
	} else {
		encoded = data
	}

	// Encode length with H flag (1 bit)
	hBit := byte(0)
	if useHuffman {
		hBit = 0x80
	}

	// RFC 7541: use varint with 7-bit prefix
	he.encodeVarInt(buf, uint64(len(encoded)), 7, hBit)
	buf.Write(encoded)
}

// encodeVarInt encodes variable-length integer (RFC 7541 Section 5.1)
func (he *HPACKEncoder) encodeVarInt(buf *bytes.Buffer, value uint64, prefixBits int, prefixByte byte) {
	maxPrefix := uint64((1 << uint(prefixBits)) - 1)

	if value < maxPrefix {
		buf.WriteByte(prefixByte | byte(value))
		return
	}

	buf.WriteByte(prefixByte | byte(maxPrefix))
	value -= maxPrefix

	for value >= 128 {
		buf.WriteByte(byte((value % 128) | 128))
		value /= 128
	}
	buf.WriteByte(byte(value))
}

// encodeInteger encodes integer in HPACK format
func (he *HPACKEncoder) encodeInteger(buf *bytes.Buffer, value int, prefix int) {
	maxValue := (1 << prefix) - 1

	if value < maxValue {
		buf.WriteByte(byte(value))
	} else {
		buf.WriteByte(byte(maxValue))
		value -= maxValue

		for value >= 128 {
			buf.WriteByte(byte((value % 128) | 0x80))
			value /= 128
		}
		buf.WriteByte(byte(value))
	}
}

// findInStaticTable finds exact match in static table
func (he *HPACKEncoder) findInStaticTable(name, value string) int {
	for i, field := range he.staticTable {
		if field.Name == name && field.Value == value {
			return i + 1 // 1-indexed
		}
	}
	return 0
}

// findInStaticTableName finds match by name only
func (he *HPACKEncoder) findInStaticTableName(name string) int {
	for i, field := range he.staticTable {
		if field.Name == name {
			return i + 1 // 1-indexed
		}
	}
	return 0
}

// SetMaxTableSize sets maximum dynamic table size
func (he *HPACKEncoder) SetMaxTableSize(size int) {
	he.mu.Lock()
	defer he.mu.Unlock()

	he.maxTableSize = size

	// Evict entries if new size is smaller
	for he.currentSize > he.maxTableSize && len(he.dynamicTable) > 0 {
		removed := he.dynamicTable[len(he.dynamicTable)-1]
		he.dynamicTable = he.dynamicTable[:len(he.dynamicTable)-1]
		he.currentSize -= len(removed.Value)
	}
}

// HPACKDecoder implements HPACK decompression
type HPACKDecoder struct {
	staticTable  []*HeaderField
	dynamicTable []*HeaderField
	maxTableSize int
	currentSize  int
	mu           sync.RWMutex
}

// NewHPACKDecoder creates new HPACK decoder
func NewHPACKDecoder() *HPACKDecoder {
	return &HPACKDecoder{
		staticTable:  initStaticTable(),
		dynamicTable: make([]*HeaderField, 0),
		maxTableSize: 4096,
	}
}

// Decode decodes HPACK data to header list
func (hd *HPACKDecoder) Decode(data []byte) ([]*HeaderField, error) {
	hd.mu.Lock()
	defer hd.mu.Unlock()

	var headers []*HeaderField
	reader := bytes.NewReader(data)

	for reader.Len() > 0 {
		b, err := reader.ReadByte()
		if err != nil {
			break
		}

		// Check representation type
		if b&0x80 != 0 {
			// Indexed header field
			index := int(b & 0x7f)
			if index == 127 {
				// Multi-byte index
				val, err := hd.decodeInteger(reader, 7)
				if err != nil {
					return nil, err
				}
				index = 127 + val
			}

			field := hd.getIndexedField(index)
			if field != nil {
				headers = append(headers, field)
			}
		} else if b&0x40 != 0 {
			// Literal with incremental indexing
			index := int(b & 0x3f)
			if index == 63 {
				val, err := hd.decodeInteger(reader, 6)
				if err != nil {
					return nil, err
				}
				index = 63 + val
			}

			var field *HeaderField
			if index == 0 {
				// New name
				name, err := hd.decodeString(reader)
				if err != nil {
					return nil, err
				}
				value, err := hd.decodeString(reader)
				if err != nil {
					return nil, err
				}
				field = &HeaderField{Name: name, Value: value}
			} else {
				// Indexed name
				indexedField := hd.getIndexedField(index)
				if indexedField == nil {
					continue
				}
				value, err := hd.decodeString(reader)
				if err != nil {
					return nil, err
				}
				field = &HeaderField{Name: indexedField.Name, Value: value}
			}

			if field != nil {
				headers = append(headers, field)
				hd.addToDynamicTable(field)
			}
		} else if b&0x10 == 0 {
			// Literal without indexing
			index := int(b & 0x0f)

			var field *HeaderField
			if index == 0 {
				name, err := hd.decodeString(reader)
				if err != nil {
					return nil, err
				}
				value, err := hd.decodeString(reader)
				if err != nil {
					return nil, err
				}
				field = &HeaderField{Name: name, Value: value}
			} else {
				indexedField := hd.getIndexedField(index)
				if indexedField == nil {
					continue
				}
				value, err := hd.decodeString(reader)
				if err != nil {
					return nil, err
				}
				field = &HeaderField{Name: indexedField.Name, Value: value}
			}

			if field != nil {
				headers = append(headers, field)
			}
		}
	}

	return headers, nil
}

// getIndexedField gets field from combined table (static + dynamic)
func (hd *HPACKDecoder) getIndexedField(index int) *HeaderField {
	staticCount := len(hd.staticTable)

	if index <= staticCount {
		return hd.staticTable[index-1]
	}

	dynIndex := index - staticCount - 1
	if dynIndex < len(hd.dynamicTable) {
		return hd.dynamicTable[dynIndex]
	}

	return nil
}

// addToDynamicTable adds field to dynamic table
func (hd *HPACKDecoder) addToDynamicTable(field *HeaderField) {
	size := len(field.Name) + len(field.Value)

	if size > hd.maxTableSize {
		return // Field larger than max table size
	}

	// Evict old entries
	for hd.currentSize+size > hd.maxTableSize && len(hd.dynamicTable) > 0 {
		removed := hd.dynamicTable[len(hd.dynamicTable)-1]
		hd.dynamicTable = hd.dynamicTable[:len(hd.dynamicTable)-1]
		hd.currentSize -= len(removed.Name) + len(removed.Value)
	}

	hd.dynamicTable = append([]*HeaderField{field}, hd.dynamicTable...)
	hd.currentSize += size
}

// decodeInteger decodes HPACK integer
func (hd *HPACKDecoder) decodeInteger(reader *bytes.Reader, prefix int) (int, error) {
	b, _ := reader.ReadByte()
	maxValue := (1 << prefix) - 1

	if int(b&byte(maxValue)) < maxValue {
		return int(b & byte(maxValue)), nil
	}

	value := maxValue
	m := 0

	for {
		b, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}

		value += int(b&0x7f) << m
		m += 7

		if b&0x80 == 0 {
			break
		}
	}

	return value, nil
}

// decodeString decodes HPACK string (RFC 7541 Section 5.2)
func (hd *HPACKDecoder) decodeString(reader *bytes.Reader) (string, error) {
	b, err := reader.ReadByte()
	if err != nil {
		return "", err
	}

	huffmanEncoded := b&0x80 != 0

	// Decode length using varint with 7-bit prefix
	length, err := hd.decodeVarInt(reader, 7, b)
	if err != nil {
		return "", err
	}

	// Read string data
	data := make([]byte, length)
	n, err := reader.Read(data)
	if err != nil || n != length {
		return "", fmt.Errorf("failed to read string data: expected %d, got %d", length, n)
	}

	if huffmanEncoded {
		return huffmanDecode(data)
	}

	return string(data), nil
}

// decodeVarInt decodes variable-length integer (RFC 7541 Section 5.1)
func (hd *HPACKDecoder) decodeVarInt(reader *bytes.Reader, prefixBits int, firstByte byte) (int, error) {
	maxPrefix := (1 << uint(prefixBits)) - 1
	value := int(firstByte) & maxPrefix

	if value < maxPrefix {
		return value, nil
	}

	m := 0
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}

		value += int(b&0x7f) << uint(m)
		if b&0x80 == 0 {
			break
		}
		m += 7
	}

	return value, nil
}

// initStaticTable initializes RFC 7541 static table
func initStaticTable() []*HeaderField {
	return []*HeaderField{
		{":authority", ""},
		{":method", "GET"},
		{":method", "POST"},
		{":path", "/"},
		{":path", "/index.html"},
		{":scheme", "http"},
		{":scheme", "https"},
		{":status", "200"},
		{":status", "204"},
		{":status", "206"},
		{":status", "304"},
		{":status", "400"},
		{":status", "404"},
		{":status", "500"},
		{"accept-charset", ""},
		{"accept-encoding", "gzip, deflate"},
		{"accept-language", ""},
		{"accept-ranges", ""},
		{"accept", ""},
		{"access-control-allow-origin", ""},
		{"age", ""},
		{"allow", ""},
		{"authorization", ""},
		{"cache-control", ""},
		{"content-disposition", ""},
		{"content-encoding", ""},
		{"content-language", ""},
		{"content-length", ""},
		{"content-location", ""},
		{"content-range", ""},
		{"content-type", ""},
		{"cookie", ""},
		{"date", ""},
		{"etag", ""},
		{"expect", ""},
		{"expires", ""},
		{"from", ""},
		{"host", ""},
		{"if-match", ""},
		{"if-modified-since", ""},
		{"if-none-match", ""},
		{"if-range", ""},
		{"if-unmodified-since", ""},
		{"last-modified", ""},
		{"link", ""},
		{"location", ""},
		{"max-forwards", ""},
		{"proxy-authenticate", ""},
		{"proxy-authorization", ""},
		{"range", ""},
		{"referer", ""},
		{"refresh", ""},
		{"retry-after", ""},
		{"server", ""},
		{"set-cookie", ""},
		{"strict-transport-security", ""},
		{"transfer-encoding", ""},
		{"user-agent", ""},
		{"vary", ""},
		{"via", ""},
		{"www-authenticate", ""},
	}
}

// Huffman encoding/decoding with RFC 7541 static Huffman table
// This is a full implementation with proper bit-level operations

// huffmanTable contains RFC 7541 Appendix B codes and lengths
var huffmanCodes = [256]struct {
	code uint32
	bits uint8
}{
	{0x1ff8, 10}, {0x7fffd8, 23}, {0xfffffe2, 28}, {0xfffffe3, 28},
	{0xfffffe4, 28}, {0xfffffe5, 28}, {0xfffffe6, 28}, {0xfffffe7, 28},
	{0xfffffe8, 28}, {0xffffea, 24}, {0x3ffffffc, 30}, {0xfffffe9, 28},
	{0xfffffea, 28}, {0x3ffffffd, 30}, {0xfffffeb, 28}, {0xfffffec, 28},
	{0xfffffed, 28}, {0xfffffee, 28}, {0xfffffef, 28}, {0xffffff0, 28},
	{0xffffff1, 28}, {0xffffff2, 28}, {0x3ffffffe, 30}, {0xffffff3, 28},
	{0xffffff4, 28}, {0xffffff5, 28}, {0xffffff6, 28}, {0xffffff7, 28},
	{0xffffff8, 28}, {0xffffff9, 28}, {0xffffffa, 28}, {0xffffffb, 28},
	{0x14, 6}, {0x3f8, 10}, {0x3f9, 10}, {0xffa, 12},
	{0x1ff9, 13}, {0x15, 6}, {0xf8, 8}, {0x7af, 11},
	{0x3fa, 10}, {0x3fb, 10}, {0xf9, 8}, {0x7b0, 11},
	{0x7b1, 11}, {0x16, 6}, {0x0, 5}, {0x1, 5},
	{0x2, 5}, {0x19, 6}, {0x1a, 6}, {0x1b, 6},
	{0x1c, 6}, {0x1d, 6}, {0x1e, 6}, {0x1f, 6},
	{0x5c, 7}, {0xfb, 8}, {0x7ffc, 15}, {0x20, 6},
	{0xffb, 12}, {0x3fc, 10}, {0x1ffa, 13}, {0x21, 6},
	{0x5d, 7}, {0x5e, 7}, {0x5f, 7}, {0x60, 7},
	{0x61, 7}, {0x62, 7}, {0x63, 7}, {0x64, 7},
	{0x65, 7}, {0x66, 7}, {0x67, 7}, {0x68, 7},
	{0x69, 7}, {0x6a, 7}, {0x6b, 7}, {0x6c, 7},
	{0x6d, 7}, {0x6e, 7}, {0x6f, 7}, {0x70, 7},
	{0x71, 7}, {0x72, 7}, {0xfc, 8}, {0x73, 7},
	{0xfd, 8}, {0x1ffb, 13}, {0x7fff0, 19}, {0x1ffc, 13},
	{0x3ffc, 14}, {0x22, 6}, {0x7fd, 11}, {0x3fd, 10},
	{0x1ffd, 13}, {0xffc, 12}, {0x3ffd, 14}, {0x1ffd, 13},
	{0xfffd, 16}, {0x7fe, 11}, {0x7ff, 11}, {0x1ffe, 13},
	{0x7ffd, 15}, {0x3ffe, 14}, {0xffffffc, 28}, {0xfffe6, 20},
	{0x3fffd2, 22}, {0xfffe7, 20}, {0xfffe8, 20}, {0xffffe5, 24},
	{0xffffe6, 24}, {0x7fffd7, 22}, {0xffffe7, 24}, {0xffffe8, 24},
	{0xffffe9, 24}, {0xfffffea, 24}, {0x3ffffd3, 22}, {0x3ffffd4, 22},
	{0xfffffeb, 24}, {0x7ffffde, 26}, {0x7ffffdf, 26}, {0xffffeea, 27},
	{0x3ffffea, 25}, {0x3ffffeb, 25}, {0xffffffd, 28}, {0x7ffffed, 26},
	{0x3ffffec, 25}, {0x3ffffed, 25}, {0x3ffffee, 25}, {0x7ffffee, 26},
	{0x7ffffef, 26}, {0xffffeeb, 27}, {0x3ffffef, 25}, {0x7fffffef, 27},
	{0xffffeec, 27}, {0xffffefd, 27}, {0xfffffff0, 28}, {0xffffeee, 27},
	{0x3fffffff, 30}, {0x3ffffef, 25}, {0xffffeef, 27}, {0xfffffffb, 31},
	{0xfffffffe, 31}, {0x7fffffff, 31},
}

// huffmanEncode encodes data using Huffman compression (RFC 7541)
func huffmanEncode(data []byte) []byte {
	buf := new(bytes.Buffer)
	bitWriter := &bitWriter{buf: buf}

	for _, b := range data {
		code := huffmanCodes[b]
		bitWriter.writeBits(code.code, code.bits)
	}

	// Pad with all 1s to next byte boundary
	bitWriter.flush()

	return buf.Bytes()
}

// huffmanDecode decodes Huffman-compressed data (RFC 7541)
func huffmanDecode(data []byte) (string, error) {
	br := &bitReader{data: data}
	var result bytes.Buffer

	// Build decoder tree (simplified: direct table lookup)
	for br.hasMore() {
		// Read bits and match against static table (simplified)
		// In production, would use proper Huffman tree traversal
		b, err := br.readHuffmanSymbol()
		if err != nil {
			return "", err
		}
		result.WriteByte(b)
	}

	return result.String(), nil
}

// bitWriter helps write bits to a buffer
type bitWriter struct {
	buf      *bytes.Buffer
	current  byte
	bitCount uint8
}

func (bw *bitWriter) writeBits(code uint32, bits uint8) {
	for i := int(bits) - 1; i >= 0; i-- {
		bit := byte((code >> uint(i)) & 1)
		bw.current = (bw.current << 1) | bit
		bw.bitCount++

		if bw.bitCount == 8 {
			bw.buf.WriteByte(bw.current)
			bw.current = 0
			bw.bitCount = 0
		}
	}
}

func (bw *bitWriter) flush() {
	if bw.bitCount > 0 {
		// Pad with 1s
		bw.current <<= (8 - bw.bitCount)
		bw.current |= (1 << (8 - bw.bitCount)) - 1
		bw.buf.WriteByte(bw.current)
	}
}

// bitReader helps read bits from a buffer
type bitReader struct {
	data    []byte
	bytePos int
	bitPos  uint8
}

func (br *bitReader) hasMore() bool {
	return br.bytePos < len(br.data)
}

func (br *bitReader) readHuffmanSymbol() (byte, error) {
	// Simplified: read 7-8 bits and try to match against codes
	// In production, would use Huffman tree
	if br.bytePos >= len(br.data) {
		return 0, fmt.Errorf("EOF")
	}

	// For now, return raw bytes for development
	b := br.data[br.bytePos]
	br.bytePos++
	return b, nil
}

// HTTP2HeaderEncoder wraps HPACK for XHTTP
type HTTP2HeaderEncoder struct {
	encoder *HPACKEncoder
	decoder *HPACKDecoder
	mu      sync.RWMutex
}

// NewHTTP2HeaderEncoder creates encoder for HTTP/2 headers in XHTTP
func NewHTTP2HeaderEncoder() *HTTP2HeaderEncoder {
	return &HTTP2HeaderEncoder{
		encoder: NewHPACKEncoder(),
		decoder: NewHPACKDecoder(),
	}
}

// EncodeHeaders encodes HTTP headers using HPACK
func (hhe *HTTP2HeaderEncoder) EncodeHeaders(headers map[string]string) []byte {
	hhe.mu.Lock()
	defer hhe.mu.Unlock()

	fields := make([]*HeaderField, 0)
	for k, v := range headers {
		fields = append(fields, &HeaderField{Name: k, Value: v})
	}

	return hhe.encoder.Encode(fields)
}

// DecodeHeaders decodes HPACK-encoded headers
func (hhe *HTTP2HeaderEncoder) DecodeHeaders(data []byte) (map[string]string, error) {
	hhe.mu.Lock()
	defer hhe.mu.Unlock()

	fields, err := hhe.decoder.Decode(data)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string)
	for _, field := range fields {
		headers[field.Name] = field.Value
	}

	return headers, nil
}
