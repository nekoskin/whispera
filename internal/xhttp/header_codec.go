package xhttp

import (
	"fmt"
	"sync"
)

// HeaderCodec is an abstraction for header compression used by XHTTP.
// Implementations may use HPACK (HTTP/2) or QPACK (HTTP/3).
type HeaderCodec interface {
	EncodeHeaders(headers map[string]string) []byte
	DecodeHeaders(data []byte) (map[string]string, error)
}

// QPACKAdapter is a skeleton adapter for QPACK support.
// For now it delegates to the existing HTTP2HeaderEncoder (HPACK)
// to provide a compatibility path. Replace with a proper QPACK
// implementation when ready.
type QPACKAdapter struct {
	// Underlying fallback codec (HPACK-based) for compatibility
	fallback *HTTP2HeaderEncoder
	// Dynamic table (simple FIFO for Phase 3)
	dynamicTable   []*HeaderField
	maxDynamicSize int
	currentDynSize int
	dynMu          sync.RWMutex
}

// Instruction opcodes (Phase 4 simplified)
const (
	qpackOpInsertWithName        byte = 0x01
	qpackOpInsertWithLiteralName byte = 0x02
)

// NewQPACKAdapter creates a new QPACKAdapter using HPACK fallback.
func NewQPACKAdapter() *QPACKAdapter {
	return &QPACKAdapter{
		fallback:       NewHTTP2HeaderEncoder(),
		dynamicTable:   make([]*HeaderField, 0),
		maxDynamicSize: 4096,
		currentDynSize: 0,
	}
}

// EncodeHeaders encodes headers using a minimal QPACK-like format.
// This is a limited, self-contained encoder used as an incremental
// step towards a full QPACK implementation. The format is:
//
//	[varint: header count]
//	repeated: [varint: name len][name bytes][varint: value len][value bytes]
//
// This is intentionally simple and only aims for round-trip correctness
// inside this codebase; it is NOT wire-compatible with real QPACK.
func (q *QPACKAdapter) EncodeHeaders(headers map[string]string) []byte {
	// Phase 1 QPACK-like encoding:
	// - If header exactly matches an entry in the RFC7541 static table: encode as [0x80][varint:index]
	// - Otherwise: encode as [0x00][varint:nameLen][name][varint:valLen][value]
	// First encode header count as varint to aid decoding.
	// instrBuf holds encoder instructions that must be processed by decoder
	instrBuf := make([]byte, 0)

	// header buffer holds the actual header block
	headerBuf := make([]byte, 0)
	headerBuf = appendVarInt(headerBuf, uint64(len(headers)))

	static := initStaticTable()

	q.dynMu.RLock()
	// build a shallow copy of dynamic table for read-only lookup
	dyn := q.dynamicTable
	q.dynMu.RUnlock()

	for name, value := range headers {
		// 1) exact static match
		if idx := findStaticIndex(static, name, value); idx > 0 {
			headerBuf = append(headerBuf, 0x80)
			headerBuf = appendVarInt(headerBuf, uint64(idx))
			continue
		}

		// 2) exact dynamic match
		if dIdx := findDynamicIndex(dyn, name, value); dIdx > 0 {
			// dynamic indexed tag 0xC0
			headerBuf = append(headerBuf, 0xC0)
			headerBuf = appendVarInt(headerBuf, uint64(dIdx))
			continue
		}

		// 3) name-indexed from static table
		if nameIdx := findStaticNameIndex(static, name); nameIdx > 0 {
			headerBuf = append(headerBuf, 0x40)
			headerBuf = appendVarInt(headerBuf, uint64(nameIdx))
			headerBuf = appendVarInt(headerBuf, uint64(len(value)))
			headerBuf = append(headerBuf, value...)
			// Emit instruction to insert into dynamic table (insert with name)
			instrBuf = append(instrBuf, qpackOpInsertWithName)
			instrBuf = appendVarInt(instrBuf, uint64(nameIdx))
			instrBuf = appendVarInt(instrBuf, uint64(len(value)))
			instrBuf = append(instrBuf, value...)
			// Also add locally so subsequent headers in same block can reference it
			q.addToDynamicTable(&HeaderField{Name: name, Value: value})
			continue
		}

		// 4) no name match — insert full literal into dynamic table and emit insertion tag 0x20
		headerBuf = append(headerBuf, 0x20)
		headerBuf = appendVarInt(headerBuf, uint64(len(name)))
		headerBuf = append(headerBuf, name...)
		headerBuf = appendVarInt(headerBuf, uint64(len(value)))
		headerBuf = append(headerBuf, value...)
		// Emit instruction to insert literal name+value into dynamic table
		instrBuf = append(instrBuf, qpackOpInsertWithLiteralName)
		instrBuf = appendVarInt(instrBuf, uint64(len(name)))
		instrBuf = append(instrBuf, name...)
		instrBuf = appendVarInt(instrBuf, uint64(len(value)))
		instrBuf = append(instrBuf, value...)
		q.addToDynamicTable(&HeaderField{Name: name, Value: value})
	}

	// Combine: [varint: instrLen][instr bytes][headerBuf]
	combined := make([]byte, 0)
	combined = appendVarInt(combined, uint64(len(instrBuf)))
	combined = append(combined, instrBuf...)
	combined = append(combined, headerBuf...)
	return combined
}

// DecodeHeaders decodes the minimal QPACK-like format produced by EncodeHeaders.
func (q *QPACKAdapter) DecodeHeaders(data []byte) (map[string]string, error) {
	headers := make(map[string]string)
	off := 0

	static := initStaticTable()

	// Read instruction stream length and process instructions first
	instrLen, ni := decodeVarInt(data, off)
	if ni == 0 {
		return nil, fmt.Errorf("invalid qpack header block: malformed instr len")
	}
	off += ni
	instrEnd := off + int(instrLen)
	if instrEnd > len(data) {
		return nil, fmt.Errorf("instruction stream overflow")
	}

	// Process instruction stream
	for off < instrEnd {
		op := data[off]
		off++
		switch op {
		case qpackOpInsertWithName:
			nameIdx, nn := decodeVarInt(data, off)
			if nn == 0 {
				return nil, fmt.Errorf("invalid instr: name idx")
			}
			off += nn
			valLen, nv := decodeVarInt(data, off)
			if nv == 0 {
				return nil, fmt.Errorf("invalid instr: val len")
			}
			off += nv
			if off+int(valLen) > instrEnd {
				return nil, fmt.Errorf("instr value overflow")
			}
			value := string(data[off : off+int(valLen)])
			off += int(valLen)
			if int(nameIdx) <= 0 || int(nameIdx) > len(static) {
				return nil, fmt.Errorf("instr name idx out of range: %d", nameIdx)
			}
			name := static[int(nameIdx)-1].Name
			q.addToDynamicTable(&HeaderField{Name: name, Value: value})
		case qpackOpInsertWithLiteralName:
			nameLen, nn := decodeVarInt(data, off)
			if nn == 0 {
				return nil, fmt.Errorf("invalid instr: name len")
			}
			off += nn
			if off+int(nameLen) > instrEnd {
				return nil, fmt.Errorf("instr name overflow")
			}
			name := string(data[off : off+int(nameLen)])
			off += int(nameLen)
			valLen, nv := decodeVarInt(data, off)
			if nv == 0 {
				return nil, fmt.Errorf("invalid instr: val len")
			}
			off += nv
			if off+int(valLen) > instrEnd {
				return nil, fmt.Errorf("instr value overflow")
			}
			value := string(data[off : off+int(valLen)])
			off += int(valLen)
			q.addToDynamicTable(&HeaderField{Name: name, Value: value})
		default:
			return nil, fmt.Errorf("unknown instruction opcode: %x", op)
		}
	}

	// Now off points to beginning of header block
	count, n := decodeVarInt(data, off)
	if n == 0 {
		return nil, fmt.Errorf("invalid qpack header block: malformed count")
	}
	off += n

	for i := uint64(0); i < count; i++ {
		if off >= len(data) {
			return nil, fmt.Errorf("truncated header block")
		}
		tag := data[off]
		off++
		switch tag {
		case 0x80:
			// indexed
			idx, ni := decodeVarInt(data, off)
			if ni == 0 {
				return nil, fmt.Errorf("invalid qpack header block: indexed idx")
			}
			off += ni
			if int(idx) <= len(static) && idx > 0 {
				f := static[int(idx)-1]
				headers[f.Name] = f.Value
			} else {
				return nil, fmt.Errorf("indexed static table out of range: %d", idx)
			}
		case 0x00:
			// literal name+value
			nameLen, nn := decodeVarInt(data, off)
			if nn == 0 {
				return nil, fmt.Errorf("invalid qpack header block: name len")
			}
			off += nn
			if off+int(nameLen) > len(data) {
				return nil, fmt.Errorf("invalid qpack header block: name overflow")
			}
			name := string(data[off : off+int(nameLen)])
			off += int(nameLen)

			valueLen, nv := decodeVarInt(data, off)
			if nv == 0 {
				return nil, fmt.Errorf("invalid qpack header block: value len")
			}
			off += nv
			if off+int(valueLen) > len(data) {
				return nil, fmt.Errorf("invalid qpack header block: value overflow")
			}
			value := string(data[off : off+int(valueLen)])
			off += int(valueLen)

			headers[name] = value
		case 0x40:
			// name-indexed literal
			nameIdx, ni := decodeVarInt(data, off)
			if ni == 0 {
				return nil, fmt.Errorf("invalid qpack header block: name index")
			}
			off += ni
			if int(nameIdx) <= 0 || int(nameIdx) > len(static) {
				return nil, fmt.Errorf("name index out of range: %d", nameIdx)
			}
			valLen, nv := decodeVarInt(data, off)
			if nv == 0 {
				return nil, fmt.Errorf("invalid qpack header block: value len")
			}
			off += nv
			if off+int(valLen) > len(data) {
				return nil, fmt.Errorf("invalid qpack header block: value overflow")
			}
			value := string(data[off : off+int(valLen)])
			off += int(valLen)

			f := static[int(nameIdx)-1]
			headers[f.Name] = value
		case 0x20:
			// insertion literal (name + value) -> add to dynamic table
			nameLen, nn := decodeVarInt(data, off)
			if nn == 0 {
				return nil, fmt.Errorf("invalid qpack header block: name len")
			}
			off += nn
			if off+int(nameLen) > len(data) {
				return nil, fmt.Errorf("invalid qpack header block: name overflow")
			}
			name := string(data[off : off+int(nameLen)])
			off += int(nameLen)

			valueLen, nv := decodeVarInt(data, off)
			if nv == 0 {
				return nil, fmt.Errorf("invalid qpack header block: value len")
			}
			off += nv
			if off+int(valueLen) > len(data) {
				return nil, fmt.Errorf("invalid qpack header block: value overflow")
			}
			value := string(data[off : off+int(valueLen)])
			off += int(valueLen)

			q.addToDynamicTable(&HeaderField{Name: name, Value: value})
			headers[name] = value
		case 0xC0:
			// dynamic indexed
			dIdx, ndi := decodeVarInt(data, off)
			if ndi == 0 {
				return nil, fmt.Errorf("invalid qpack header block: dynamic idx")
			}
			off += ndi
			q.dynMu.RLock()
			if int(dIdx) <= 0 || int(dIdx) > len(q.dynamicTable) {
				q.dynMu.RUnlock()
				return nil, fmt.Errorf("dynamic index out of range: %d", dIdx)
			}
			f := q.dynamicTable[int(dIdx)-1]
			q.dynMu.RUnlock()
			headers[f.Name] = f.Value
		default:
			return nil, fmt.Errorf("unknown qpack tag: %x", tag)
		}
	}

	return headers, nil
}

// findStaticIndex finds exact name+value match in static table (1-indexed)
func findStaticIndex(static []*HeaderField, name, value string) int {
	for i, f := range static {
		if f.Name == name && f.Value == value {
			return i + 1
		}
	}
	return 0
}

// findStaticNameIndex finds a static table entry matching the name (first match), returns 1-indexed index or 0
func findStaticNameIndex(static []*HeaderField, name string) int {
	for i, f := range static {
		if f.Name == name {
			return i + 1
		}
	}
	return 0
}

// findDynamicIndex finds exact name+value match in dynamic table (1-indexed)
func findDynamicIndex(dynamic []*HeaderField, name, value string) int {
	for i, f := range dynamic {
		if f.Name == name && f.Value == value {
			return i + 1
		}
	}
	return 0
}

// addToDynamicTable adds a field to the adapter's dynamic table with eviction
func (q *QPACKAdapter) addToDynamicTable(field *HeaderField) {
	if q == nil || field == nil {
		return
	}
	size := len(field.Name) + len(field.Value)

	q.dynMu.Lock()
	defer q.dynMu.Unlock()

	if size > q.maxDynamicSize {
		// cannot insert oversized entry
		return
	}

	// Evict oldest entries until there is room (we treat index 1 as most-recent)
	for q.currentDynSize+size > q.maxDynamicSize && len(q.dynamicTable) > 0 {
		// remove last (oldest)
		removed := q.dynamicTable[len(q.dynamicTable)-1]
		q.dynamicTable = q.dynamicTable[:len(q.dynamicTable)-1]
		q.currentDynSize -= len(removed.Name) + len(removed.Value)
	}

	// Prepend new entry (most-recent at index 0)
	q.dynamicTable = append([]*HeaderField{field}, q.dynamicTable...)
	q.currentDynSize += size
}

// appendVarInt appends a simple varint (7-bit continuation) to buf and returns new slice.
func appendVarInt(buf []byte, v uint64) []byte {
	if v < 0x80 {
		return append(buf, byte(v))
	}
	for v >= 0x80 {
		b := byte((v & 0x7f) | 0x80)
		buf = append(buf, b)
		v >>= 7
	}
	buf = append(buf, byte(v))
	return buf
}

// decodeVarInt decodes a varint from data starting at off.
// Returns value and number of bytes consumed (0 on error).
func decodeVarInt(data []byte, off int) (uint64, int) {
	if off >= len(data) {
		return 0, 0
	}
	var v uint64
	var shift uint
	i := off
	for i < len(data) {
		b := data[i]
		v |= uint64(b&0x7f) << shift
		i++
		if b&0x80 == 0 {
			return v, i - off
		}
		shift += 7
		if shift > 63 {
			return 0, 0
		}
	}
	return 0, 0
}

// ErrUnknownCodec is returned when an unsupported codec is requested
var ErrUnknownCodec = fmt.Errorf("unknown header codec")
