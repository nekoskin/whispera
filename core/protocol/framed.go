package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const KeepAliveProtoBit byte = 0x20

const (
	framedWireTarget  = 5 + 16384 + 1 + 16
	framedPlainTarget = 16384
	framedMaxData     = framedPlainTarget - 5 - 2

	shapePadMin     = 111
	shapePadMax     = 1111
	shapePadRecords = 3

	shapeChunkMin = 4096
	shapeChunkMax = framedMaxData

	framedSwitchMarker = 0xFFFF
	framedFillerMarker = 0xFFFE
)

type ShapeKnobs struct {
	records atomic.Int32
	min     atomic.Int32
	max     atomic.Int32

	fillIdle     atomic.Int32
	fillInterval atomic.Int32
	fillMin      atomic.Int32
	fillMax      atomic.Int32

	// Payload length range per record. Zero fills every record to the brim.
	chunkMin atomic.Int32
	chunkMax atomic.Int32

	// Draw from chunkShape instead of the range above.
	chunkShaped atomic.Bool
}

// 5 TLS header, 1 content type, 16 AEAD tag, 7 ours.
const chunkWireOverhead = 29

// Record sizes of real browsing, measured by neural/fast.py diff.
// Bounds are wire sizes, weights percent.
var chunkShape = []struct {
	lo, hi int
	w      float64
}{
	{0, 64, 7.2},
	{64, 128, 2.3},
	{128, 256, 1.6},
	{256, 512, 3.1},
	{512, 1024, 4.1},
	{1024, 2048, 52.7},
	{2048, 4096, 1.2},
	{4096, 8192, 7.0},
	{8192, 16000, 1.0},
	{16000, framedMaxData + chunkWireOverhead, 19.7},
}

func shapedChunk(left int) int {
	total := 0.0
	for _, c := range chunkShape {
		total += c.w
	}
	r := mrand.Float64() * total
	for _, c := range chunkShape {
		r -= c.w
		if r > 0 {
			continue
		}
		lo, hi := c.lo-chunkWireOverhead, c.hi-chunkWireOverhead
		if lo < 1 {
			lo = 1
		}
		if hi > framedMaxData {
			hi = framedMaxData
		}
		if hi <= lo {
			hi = lo + 1
		}
		n := lo + mrand.Intn(hi-lo)
		if n < left {
			return n
		}
		return left
	}
	return left
}

var Shape = newShapeKnobs()

func newShapeKnobs() *ShapeKnobs {
	k := &ShapeKnobs{}
	k.records.Store(shapePadRecords)
	k.min.Store(shapePadMin)
	k.max.Store(shapePadMax)
	if strings.TrimSpace(os.Getenv("WHISPERA_CHUNK")) == "shape" {
		k.chunkShaped.Store(true)
	}
	lo, hi := chunkDefaults()
	k.chunkMin.Store(int32(lo))
	k.chunkMax.Store(int32(hi))
	return k
}

// chunkDefaults reads WHISPERA_CHUNK as "min-max", or a single number, or "0"
// to fill every record. Anything unparsable keeps the built-in range.
func chunkDefaults() (min, max int) {
	min, max = shapeChunkMin, shapeChunkMax
	v := strings.TrimSpace(os.Getenv("WHISPERA_CHUNK"))
	if v == "" {
		return min, max
	}
	lo, hi := v, v
	if i := strings.IndexByte(v, '-'); i > 0 {
		lo, hi = v[:i], v[i+1:]
	}
	a, err1 := strconv.Atoi(lo)
	b, err2 := strconv.Atoi(hi)
	if err1 != nil || err2 != nil || a < 0 || b < 0 || b > framedMaxData || (b > 0 && a > b) {
		return min, max
	}
	return a, b
}

func (k *ShapeKnobs) Get() (records, min, max int) {
	return int(k.records.Load()), int(k.min.Load()), int(k.max.Load())
}

func (k *ShapeKnobs) Chunk() (min, max int) {
	return int(k.chunkMin.Load()), int(k.chunkMax.Load())
}

func (k *ShapeKnobs) SetChunk(min, max int) error {
	if min < 0 || max < 0 || max > framedMaxData || (max > 0 && min > max) {
		return errShapeRange
	}
	k.chunkMin.Store(int32(min))
	k.chunkMax.Store(int32(max))
	return nil
}

// chunkTrace records the lengths actually chosen, so they can be matched against
// the record lengths on the wire. Off unless WHISPERA_CHUNK_TRACE names a file.
var chunkTrace struct {
	once sync.Once
	mu   sync.Mutex
	file *os.File
}

func chunkTraceFile() *os.File {
	chunkTrace.once.Do(func() {
		path := os.Getenv("WHISPERA_CHUNK_TRACE")
		if path == "" {
			return
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		chunkTrace.file = f
	})
	return chunkTrace.file
}

func noteChunk(n int) {
	f := chunkTraceFile()
	if f == nil {
		return
	}
	chunkTrace.mu.Lock()
	fmt.Fprintln(f, n)
	chunkTrace.mu.Unlock()
}

// chunkLen is how much data the next record carries, given what is left.
func chunkLen(left int) int {
	if Shape.chunkShaped.Load() {
		n := shapedChunk(left)
		noteChunk(n)
		return n
	}
	min, max := Shape.Chunk()
	if max <= 0 {
		return left
	}
	if min < 1 {
		min = 1
	}
	want := min
	if max > min {
		want = min + mrand.Intn(max-min+1)
	}
	if want < left {
		noteChunk(want)
		return want
	}
	noteChunk(left)
	return left
}

func (k *ShapeKnobs) Filler() (idleMs, intervalMs, min, max int) {
	return int(k.fillIdle.Load()), int(k.fillInterval.Load()), int(k.fillMin.Load()), int(k.fillMax.Load())
}

func (k *ShapeKnobs) SetFiller(idleMs, intervalMs, min, max int) error {
	if idleMs < 0 || intervalMs < 0 || intervalMs > 60000 {
		return errShapeRange
	}
	if min < 0 || max > framedMaxData || min > max {
		return errShapeRange
	}
	k.fillIdle.Store(int32(idleMs))
	k.fillInterval.Store(int32(intervalMs))
	k.fillMin.Store(int32(min))
	k.fillMax.Store(int32(max))
	return nil
}

func (k *ShapeKnobs) Set(records, min, max int) error {
	if records < 0 || records > 64 {
		return errShapeRange
	}
	if min < 0 || max > framedMaxData || min > max {
		return errShapeRange
	}
	k.records.Store(int32(records))
	k.min.Store(int32(min))
	k.max.Store(int32(max))
	return nil
}

var errShapeRange = errors.New("whispera: shape value out of range")

func ShapePadLen(room int) int {
	if room <= 0 {
		return 0
	}
	min, max := int(Shape.min.Load()), int(Shape.max.Load())
	if max <= min {
		return 0
	}
	pad := min + mrand.Intn(max-min+1)
	if pad > room {
		pad = room
	}
	return pad
}

func AppendShapePad(out []byte, n int) []byte {
	if n <= 0 {
		return out
	}
	start := len(out)
	out = append(out, make([]byte, n)...)
	for i := start; i < len(out); i += 8 {
		var word [8]byte
		binary.BigEndian.PutUint64(word[:], mrand.Uint64())
		copy(out[i:], word[:])
	}
	return out
}

// ShapeBudget is how many records still get padded, counted per connection
// rather than per stream. A keep-alive connection has no "first few records"
// after every request, so restarting the count for each stream drew the same
// opening pattern over and over on one socket.
type ShapeBudget struct{ left atomic.Int32 }

func NewShapeBudget() *ShapeBudget {
	b := &ShapeBudget{}
	b.left.Store(Shape.records.Load())
	return b
}

func (b *ShapeBudget) take() bool {
	if b == nil {
		return false
	}
	for {
		v := b.left.Load()
		if v <= 0 {
			return false
		}
		if b.left.CompareAndSwap(v, v-1) {
			return true
		}
	}
}

var errFramedBadRecord = errors.New("whispera: bad framed record")

var ErrSwitchRaw = errors.New("whispera: framed switched to raw")

type FramedConn struct {
	net.Conn

	rmu  sync.Mutex
	rbuf []byte
	rrec []byte
	done bool

	wmu      sync.Mutex
	batch    []byte
	batchRef *[]byte
	ended    bool
	endErr   error
	switched bool
	pad      *ShapeBudget

	lastWrite atomic.Int64
	stop      chan struct{}
	stopOnce  sync.Once
	filling   atomic.Bool
}

func NewFramedConn(c net.Conn, pad *ShapeBudget) *FramedConn {
	// The batch buffer is grown on the first write: half of these connections
	// only ever read — the upstream half of a spliced stream, for one — and a
	// 16K buffer each adds up once streams come in thousands.
	fc := &FramedConn{Conn: c, pad: pad}
	fc.lastWrite.Store(time.Now().UnixNano())
	fc.stop = make(chan struct{})
	fc.armFiller()
	return fc
}

// armFiller starts the loop only once the filler is actually switched on. It
// used to run for every connection: with the filler off it never wrote, so it
// never saw the connection die and never left. A stream that ends through
// EndStream rather than Close left one such goroutine behind for good.
func (c *FramedConn) armFiller() {
	if _, intervalMs, _, _ := Shape.Filler(); intervalMs <= 0 {
		return
	}
	if c.filling.Swap(true) {
		return
	}
	go c.fillLoop()
}

// A stream carries its own 16K record buffer, and in a per-flow datapath every
// flow is a new stream: that buffer was allocated and thrown away once per
// flow. It now comes from a pool and goes back when the stream ends.
var framedBatchPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, framedPlainTarget)
		return &b
	},
}

func (c *FramedConn) releaseBatchLocked() {
	if c.batchRef == nil {
		return
	}
	*c.batchRef = c.batch[:0]
	framedBatchPool.Put(c.batchRef)
	c.batchRef, c.batch = nil, nil
}

func (c *FramedConn) fillLoop() {
	defer c.filling.Store(false)

	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		idleMs, intervalMs, min, max := Shape.Filler()
		if intervalMs <= 0 {
			return
		}
		timer.Reset(time.Duration(intervalMs) * time.Millisecond)
		select {
		case <-c.stop:
			return
		case <-timer.C:
		}
		if time.Since(time.Unix(0, c.lastWrite.Load())) < time.Duration(idleMs)*time.Millisecond {
			continue
		}
		pad := min
		if max > min {
			pad += mrand.Intn(max - min + 1)
		}
		if err := c.writeFiller(pad); err != nil {
			return
		}
	}
}

func (c *FramedConn) writeFiller(pad int) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.ended {
		return io.ErrClosedPipe
	}
	return WriteFillerRecord(c.Conn, pad)
}

func WriteFillerRecord(w io.Writer, pad int) error {
	out := make([]byte, 0, 5+2+pad)
	out = append(out, 0x17, 0x03, 0x03)
	out = binary.BigEndian.AppendUint16(out, uint16(2+pad))
	out = binary.BigEndian.AppendUint16(out, framedFillerMarker)
	out = AppendShapePad(out, pad)
	_, err := w.Write(out)
	return err
}

func FillerPad() (int, bool) {
	_, intervalMs, min, max := Shape.Filler()
	if intervalMs <= 0 {
		return 0, false
	}
	pad := min
	if max > min {
		pad += mrand.Intn(max - min + 1)
	}
	return pad, true
}

func SkipFillerRecord(r io.Reader) bool {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return false
	}
	body := int(binary.BigEndian.Uint16(size[:]))
	if body < 2 || body > framedWireTarget {
		return false
	}
	rec := make([]byte, body)
	if _, err := io.ReadFull(r, rec); err != nil {
		return false
	}
	return binary.BigEndian.Uint16(rec[0:2]) == framedFillerMarker
}

func (c *FramedConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.ended {
		return 0, io.ErrClosedPipe
	}
	if c.batch == nil {
		bp := framedBatchPool.Get().(*[]byte)
		c.batchRef = bp
		c.batch = (*bp)[:0]
	}
	c.lastWrite.Store(time.Now().UnixNano())
	c.armFiller()
	sent := 0
	for len(b) > 0 {
		n := chunkLen(len(b))
		if n > framedMaxData {
			n = framedMaxData
		}
		pad := 0
		if c.pad.take() {
			pad = ShapePadLen(framedMaxData - n)
		}
		out := c.batch[:0]
		out = append(out, 0x17, 0x03, 0x03)
		out = binary.BigEndian.AppendUint16(out, uint16(2+n+pad))
		out = binary.BigEndian.AppendUint16(out, uint16(n))
		out = append(out, b[:n]...)
		out = AppendShapePad(out, pad)
		if _, err := c.Conn.Write(out); err != nil {
			c.batch = out[:0]
			return sent, err
		}
		c.batch = out[:0]
		sent += n
		b = b[n:]
	}
	return sent, nil
}

func (c *FramedConn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.rbuf) > 0 {
		n := copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	if c.done {
		return 0, io.EOF
	}
	data, err := c.readRecord()
	if err != nil {
		return 0, err
	}
	if len(data) == 0 {
		c.done = true
		return 0, io.EOF
	}
	n := copy(b, data)
	if n < len(data) {
		c.rbuf = append(c.rbuf[:0], data[n:]...)
	}
	return n, nil
}

func (c *FramedConn) readRecord() ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x17 {
		return nil, errFramedBadRecord
	}
	body := int(binary.BigEndian.Uint16(hdr[3:5]))
	if body < 2 || body > framedWireTarget {
		return nil, errFramedBadRecord
	}
	if cap(c.rrec) < body {
		c.rrec = make([]byte, body)
	}
	rec := c.rrec[:body]
	if _, err := io.ReadFull(c.Conn, rec); err != nil {
		return nil, err
	}
	dataLen := int(binary.BigEndian.Uint16(rec[0:2]))
	if dataLen == framedSwitchMarker {
		return nil, ErrSwitchRaw
	}
	if dataLen == framedFillerMarker {
		return c.readRecord()
	}
	if 2+dataLen > body {
		return nil, errFramedBadRecord
	}
	return rec[2 : 2+dataLen], nil
}

func (c *FramedConn) SwitchRaw() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.ended {
		return nil
	}
	c.ended, c.switched = true, true
	return c.writeMarker(framedSwitchMarker)
}

func (c *FramedConn) SwitchedRaw() bool {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.switched
}

func (c *FramedConn) writeMarker(marker uint16) error {
	pad := 0
	if c.pad.take() {
		pad = ShapePadLen(framedMaxData)
	}
	out := make([]byte, 0, 5+2+pad)
	out = append(out, 0x17, 0x03, 0x03)
	out = binary.BigEndian.AppendUint16(out, uint16(2+pad))
	out = binary.BigEndian.AppendUint16(out, marker)
	out = AppendShapePad(out, pad)
	_, err := c.Conn.Write(out)
	return err
}

func (c *FramedConn) EndStream() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.ended {
		return c.endErr
	}
	c.ended = true
	c.endErr = c.writeMarker(0)
	c.releaseBatchLocked()
	return c.endErr
}

func (c *FramedConn) StreamDone() bool {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return c.done
}

func (c *FramedConn) Reusable() bool {
	c.rmu.Lock()
	done := c.done
	c.rmu.Unlock()
	c.wmu.Lock()
	ended, switched := c.ended, c.switched
	c.wmu.Unlock()
	return done && ended && !switched
}

func (c *FramedConn) Close() error {
	c.stopFiller()
	return c.EndStream()
}

func (c *FramedConn) CloseUnderlying() error {
	c.stopFiller()
	return c.Conn.Close()
}

func (c *FramedConn) stopFiller() {
	if c.stop != nil {
		c.stopOnce.Do(func() { close(c.stop) })
	}
}

func (c *FramedConn) Reset() {
	c.rmu.Lock()
	c.done = false
	c.rbuf = nil
	c.rmu.Unlock()
	c.wmu.Lock()
	c.ended = false
	c.wmu.Unlock()
}
