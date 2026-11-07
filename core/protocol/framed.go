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

	openingFillMin      = 32
	openingFillMax      = 160
	openingEveryDefault = 5
	openingMaxFillers   = 64

	framedSwitchMarker  = 0xFFFF
	framedFillerMarker  = 0xFFFE
	framedMigrateMarker = 0xFFFD
)

type ShapeKnobs struct {
	records atomic.Int32
	min     atomic.Int32
	max     atomic.Int32

	fillIdle     atomic.Int32
	fillInterval atomic.Int32
	fillMin      atomic.Int32
	fillMax      atomic.Int32

	openMs    atomic.Int32
	openEvery atomic.Int32

	chunkMin atomic.Int32
	chunkMax atomic.Int32

	chunkShaped atomic.Bool
}

const chunkWireOverhead = 29

var chunkShape = []struct {
	lo, hi int
	w      float64
}{
	{0, 64, 20.0},
	{64, 128, 4.8},
	{128, 256, 3.0},
	{256, 512, 3.4},
	{512, 1024, 3.0},
	{1024, 2048, 10.7},
	{2048, 4096, 5.6},
	{4096, 8192, 8.4},
	{8192, 16000, 14.4},
	{16000, framedMaxData + chunkWireOverhead, 26.8},
}

func shapedTarget() int {
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
		return lo + mrand.Intn(hi-lo)
	}
	return framedMaxData
}

func shapedPlan(left int) (data, pad int) {
	target := shapedTarget()
	if target >= left {
		noteChunk(left)
		return left, target - left
	}
	noteChunk(target)
	return target, 0
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
	openMs, openEvery := 300, openingEveryDefault
	if v := strings.TrimSpace(os.Getenv("WHISPERA_OPENING_FILL_MS")); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms >= 0 {
			openMs = ms
		}
	}
	if v := strings.TrimSpace(os.Getenv("WHISPERA_OPENING_EVERY_MS")); v != "" {
		if e, err := strconv.Atoi(v); err == nil && e > 0 {
			openEvery = e
		}
	}
	k.openMs.Store(int32(openMs))
	k.openEvery.Store(int32(openEvery))
	return k
}

func (k *ShapeKnobs) Opening() (windowMs, everyMs, min, max int) {
	return int(k.openMs.Load()), int(k.openEvery.Load()), openingFillMin, openingFillMax
}

// SetOpening sets the opening-window ping-pong: for windowMs after a stream
// opens, emit a small filler every everyMs. windowMs 0 turns it off.
func (k *ShapeKnobs) SetOpening(windowMs, everyMs int) error {
	if windowMs < 0 || windowMs > 60000 || everyMs < 0 {
		return errShapeRange
	}
	if windowMs > 0 && everyMs <= 0 {
		everyMs = openingEveryDefault
	}
	k.openMs.Store(int32(windowMs))
	k.openEvery.Store(int32(everyMs))
	return nil
}

// SetChunkShaped draws record sizes from the measured real distribution when on,
// instead of the plain min-max range.
func (k *ShapeKnobs) SetChunkShaped(on bool) {
	k.chunkShaped.Store(on)
}

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

func chunkLen(left int) int {
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

var ErrMigrate = errors.New("whispera: framed stream migrating")

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
	shapeSet bool
	shaped   bool

	lastWrite  atomic.Int64
	createdAt  int64
	openFill   bool
	openFilled int
	rxWire     atomic.Int64
	stop       chan struct{}
	stopOnce   sync.Once
	filling    atomic.Bool
}

func (c *FramedConn) RxWire() int64 { return c.rxWire.Load() }

func (c *FramedConn) ShapeRecords(on bool) {
	c.wmu.Lock()
	c.shapeSet, c.shaped = true, on
	c.wmu.Unlock()
}

func NewFramedConn(c net.Conn, pad *ShapeBudget) *FramedConn {
	return newFramedConn(c, pad, false)
}

// NewFramedConnFilling marks the main outbound flow, which also trickles
// opening-window fillers to break up the encapsulated-handshake burst. Only a
// writable primary stream opts in — never a read-only or spliced half.
func NewFramedConnFilling(c net.Conn, pad *ShapeBudget) *FramedConn {
	return newFramedConn(c, pad, true)
}

func newFramedConn(c net.Conn, pad *ShapeBudget, openFill bool) *FramedConn {
	fc := &FramedConn{Conn: c, pad: pad, openFill: openFill}
	now := time.Now().UnixNano()
	fc.lastWrite.Store(now)
	fc.createdAt = now
	fc.stop = make(chan struct{})
	fc.armFiller()
	return fc
}

func (c *FramedConn) armFiller() {
	intervalMs := int(Shape.fillInterval.Load())
	openMs := int(Shape.openMs.Load())
	if intervalMs <= 0 && !(c.openFill && openMs > 0) {
		return
	}
	if c.filling.Swap(true) {
		return
	}
	go c.fillLoop()
}

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
		openMs, openEvery, openMin, openMax := Shape.Opening()
		if c.opening(openMs) {
			timer.Reset(time.Duration(openEvery) * time.Millisecond)
		} else if intervalMs > 0 {
			timer.Reset(time.Duration(intervalMs) * time.Millisecond)
		} else {
			return
		}
		select {
		case <-c.stop:
			return
		case <-timer.C:
		}
		if c.opening(openMs) {
			c.openFilled++
			if err := c.writeFiller(fillPad(openMin, openMax)); err != nil {
				return
			}
			continue
		}
		if intervalMs <= 0 {
			return
		}
		if time.Since(time.Unix(0, c.lastWrite.Load())) < time.Duration(idleMs)*time.Millisecond {
			continue
		}
		if err := c.writeFiller(fillPad(min, max)); err != nil {
			return
		}
	}
}

func (c *FramedConn) inOpening(windowMs int) bool {
	return windowMs > 0 && time.Since(time.Unix(0, c.createdAt)) < time.Duration(windowMs)*time.Millisecond
}

// opening is true while the opening window is still open and the per-connection
// filler ceiling has not been hit, so a dense cadence cannot flood the link.
func (c *FramedConn) opening(windowMs int) bool {
	return c.openFill && c.openFilled < openingMaxFillers && c.inOpening(windowMs)
}

func fillPad(min, max int) int {
	if max > min {
		return min + mrand.Intn(max-min+1)
	}
	return min
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
	shaped := Shape.chunkShaped.Load()
	if c.shapeSet {
		shaped = c.shaped
	}
	sent := 0
	for len(b) > 0 {
		var n, pad int
		if shaped {
			n, pad = shapedPlan(len(b))
		} else {
			n = chunkLen(len(b))
		}
		if n > framedMaxData {
			n = framedMaxData
		}
		if pad > framedMaxData-n {
			pad = framedMaxData - n
		}
		if c.pad.take() {
			pad += ShapePadLen(framedMaxData - n - pad)
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
	c.rxWire.Add(int64(len(hdr)))
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
	c.rxWire.Add(int64(body))
	dataLen := int(binary.BigEndian.Uint16(rec[0:2]))
	if dataLen == framedSwitchMarker {
		return nil, ErrSwitchRaw
	}
	if dataLen == framedMigrateMarker {
		return nil, ErrMigrate
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

func (c *FramedConn) Migrate() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.ended {
		return c.endErr
	}
	c.ended = true
	c.endErr = c.writeMarker(framedMigrateMarker)
	c.releaseBatchLocked()
	return c.endErr
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
