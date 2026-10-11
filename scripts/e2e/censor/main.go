package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/bits"
	mrand "math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var leadingPacketLimit = 3

const (
	modePackets     = "packets"
	modeSNI         = "sni"
	modeShape       = "shape"
	modeFingerprint = "fingerprint"
	modeJA3         = "ja3"
	modeJA4         = "ja4"
	modeTLSInTLS    = "tlsintls"
	modeBigHello    = "bighello"
	modeFreeze      = "freeze"
	modeAll         = "all"
)

const silentHold = 20 * time.Second

const (
	shapeSamples = 6
	shapeSpread  = 32
)

var (
	mode         atomic.Value
	blockSNI     []byte
	blockedFP    map[string]bool
	blockedJA3   map[string]bool
	blockedJA4   map[string]bool
	blockedJA4B  map[string]bool
	maxHello     int
	punishMode   string
	freezeBytes  int
	throttleKBps int
	reassemble   bool
	observe      bool

	banFor time.Duration
	banned sync.Map

	resetOnRotate bool
	live          sync.Map
)

func currentMode() string { return mode.Load().(string) }

func active(mode, rule string) bool {
	for len(mode) > 0 {
		part := mode
		if i := strings.IndexByte(mode, '+'); i >= 0 {
			part, mode = mode[:i], mode[i+1:]
		} else {
			mode = ""
		}
		if part == rule || part == modeAll {
			return true
		}
	}
	return false
}

func rotate(modes []string, every time.Duration) {
	for i := 1; ; i++ {
		time.Sleep(every)
		next := modes[i%len(modes)]
		mode.Store(next)
		log.Printf("MODE %s", next)
		if resetOnRotate {
			n := 0
			live.Range(func(k, _ any) bool {
				if tc, ok := k.(*net.TCPConn); ok {
					tc.SetLinger(0)
				}
				k.(net.Conn).Close()
				n++
				return true
			})
			log.Printf("RESET %d live connections", n)
		}
	}
}

func avgBitsSet(p []byte) float64 {
	if len(p) == 0 {
		return 0
	}
	total := 0
	for _, b := range p {
		total += bits.OnesCount8(b)
	}
	return float64(total) / float64(len(p))
}

func isPrintable(b byte) bool { return b >= 0x20 && b <= 0x7e }

func fracPrintable(p []byte) float64 {
	if len(p) == 0 {
		return 0
	}
	n := 0
	for _, b := range p {
		if isPrintable(b) {
			n++
		}
	}
	return float64(n) / float64(len(p))
}

func maxContiguousPrintable(p []byte) int {
	best, run := 0, 0
	for _, b := range p {
		if isPrintable(b) {
			run++
			if run > best {
				best = run
			}
		} else {
			run = 0
		}
	}
	return best
}

func firstSixPrintable(p []byte) bool {
	if len(p) < 6 {
		return false
	}
	for _, b := range p[:6] {
		if !isPrintable(b) {
			return false
		}
	}
	return true
}

func looksTLS(p []byte) bool {
	return len(p) >= 3 && (p[0] == 0x16 || p[0] == 0x17) &&
		p[1] == 0x03 && p[2] <= 0x09
}

func looksHTTP(p []byte) bool {
	for _, m := range [][]byte{
		[]byte("GET "), []byte("POST"), []byte("PUT "), []byte("HEAD"),
		[]byte("DELE"), []byte("OPTI"), []byte("CONN"), []byte("TRAC"), []byte("PATC"),
	} {
		if len(p) >= len(m) && string(p[:len(m)]) == string(m) {
			return true
		}
	}
	return false
}

func exemptReason(p []byte) string {
	if b := avgBitsSet(p); b <= 3.4 || b >= 4.6 {
		return "ex1_popcount"
	}
	if firstSixPrintable(p) {
		return "ex2_ascii_prefix"
	}
	if fracPrintable(p) > 0.5 {
		return "ex3_ascii_majority"
	}
	if maxContiguousPrintable(p) >= 20 {
		return "ex4_ascii_run"
	}
	if looksTLS(p) || looksHTTP(p) {
		return "ex5_protocol"
	}
	return ""
}

func handle(c net.Conn, upstream string) {
	defer c.Close()
	m := currentMode()
	sampled := verdictJudge.sampled()
	live.Store(c, struct{}{})
	defer live.Delete(c)
	up, err := net.DialTimeout("tcp", upstream, 5*time.Second)
	if err != nil {
		log.Printf("upstream dial failed: %v", err)
		return
	}
	defer up.Close()

	var wg sync.WaitGroup
	var serverSpoke atomic.Bool

	var hs *hsWatch
	if active(m, modeTLSInTLS) {
		hs = newHSWatch()
		defer func() {
			log.Printf("TLSINTLS %s %s", c.RemoteAddr(), hs.report())
			if sampled {
				var tells []string
				if hs.encapsulatedLocked() {
					tells = append(tells, "encap")
				}
				if hs.splitLocked() {
					tells = append(tells, "tlsintls-split")
				}
				verdictJudge.note(c, tells)
			}
		}()
	}

	var rtt *rttWatch
	if rttEnabled() {
		rtt = &rttWatch{}
		defer func() { log.Printf("RTTDIFF %s %s", c.RemoteAddr(), rtt.report()) }()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		var down int64
		frozen := false
		for {
			n, rerr := up.Read(buf)
			if n > 0 {
				if hs != nil {
					hs.feedDown(buf[:n])
				}
				if rtt != nil {
					rtt.feedDown(time.Now())
				}
				serverSpoke.Store(true)
				down += int64(n)
				if active(currentMode(), modeFreeze) && down > int64(freezeBytes) {
					if !frozen {
						frozen = true
						if observe {
							log.Printf("WOULDFREEZE %s past %d bytes downstream", c.RemoteAddr(), down)
						} else {
							log.Printf("FREEZE %s %d bytes downstream, nothing more gets through", c.RemoteAddr(), down)
						}
					}
					if !observe {
						continue
					}
				}
				if throttleKBps > 0 && !observe {
					time.Sleep(time.Duration(n) * time.Second / time.Duration(throttleKBps*1024))
				}
				if _, werr := c.Write(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				if tc, ok := c.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
				return
			}
		}
	}()

	if clientIsBanned(c) {
		log.Printf("DROP  %s ip is out of service", c.RemoteAddr())
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		return
	}

	tmp := make([]byte, 32<<10)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	n, rerr := c.Read(tmp)
	reads := 1
	if n > 0 {
		if hs != nil {
			hs.feedUp(tmp[:n])
		}
		if rtt != nil {
			rtt.feedUp(time.Now())
		}
		first := tmp[:n]
		forward, judged := first, first
		if reassemble {
			var whole []byte
			forward, whole, reads = reassembleHello(c, first)
			if whole != nil {
				judged = whole
			}
			if active(m, modePackets) && reads >= leadingPacketLimit {
				if punishf(c, "hello split across %d packets before any reply — fragmented handshake", reads) {
					return
				}
			}
		}
		reason := exemptReason(first)
		if reason == "" {
			if punishf(c, "first packet %d bytes, bits/byte %.2f, printable %.0f%% — no exemption",
				n, avgBitsSet(first), fracPrintable(first)*100) {
				return
			}
		}
		if active(m, modeSNI) && len(blockSNI) > 0 && bytes.Contains(first, blockSNI) {
			if punishf(c, "server name %q sits whole in the first packet", blockSNI) {
				return
			}
		}
		if active(m, modeFingerprint) && helloWhole(judged) {
			if b := browserOf(judged); b != "" && blockedFP[b] {
				if punishf(c, "hello fingerprint %q is on the list", b) {
					return
				}
			}
		}
		if active(m, modeJA3) && helloWhole(judged) {
			if h, ok := ja3(judged); ok && blockedJA3[h] {
				if punishf(c, "ja3 %s is on the list", h) {
					return
				}
			}
		}
		if active(m, modeJA4) && helloWhole(judged) {
			if h, ok := ja4(judged); ok {
				if blockedJA4[h] {
					if punishf(c, "ja4 %s is on the list", h) {
						return
					}
				}
				if blockedJA4B[ja4Ciphers(h)] {
					if punishf(c, "ja4 cipher hash %s is on the list", ja4Ciphers(h)) {
						return
					}
				}
			}
		}
		if active(m, modeBigHello) {
			if size := helloRecordLen(judged); size > maxHello {
				if punishf(c, "hello record %d bytes, over %d", size, maxHello) {
					return
				}
			}
		}
		fp, j3, j4 := "split", "-", "-"
		if helloWhole(judged) {
			if fp = browserOf(judged); fp == "" {
				fp = "unparsed"
			}
			if h, ok := ja3(judged); ok {
				j3 = h
			}
			if h, ok := ja4(judged); ok {
				j4 = h
			}
		}
		if sampled {
			tells := []string{"fp:" + fp}
			if j4 != "-" {
				tells = append(tells, "ja4:"+j4)
			}
			if reads >= leadingPacketLimit {
				tells = append(tells, "hellofrag")
			}
			if size := helloRecordLen(judged); size > maxHello {
				tells = append(tells, "bighello")
			}
			verdictJudge.note(c, tells)
		}
		log.Printf("PASS  %s trust first packet %d bytes via %s, hello %s, ja3 %s, ja4 %s", c.RemoteAddr(), n, reason, fp, j3, j4)
		if _, werr := up.Write(forward); werr != nil {
			return
		}
	}
	if rerr != nil {
		return
	}
	c.SetReadDeadline(time.Time{})

	leading := reads
	var sizes []int
	for {
		n, rerr := c.Read(tmp)
		if n > 0 {
			if hs != nil {
				hs.feedUp(tmp[:n])
			}
			if rtt != nil {
				rtt.feedUp(time.Now())
			}
			if active(m, modePackets) && !serverSpoke.Load() {
				leading++
				if leading >= leadingPacketLimit {
					if punishf(c, "hello split across %d packets before any reply — fragmented handshake", leading) {
						return
					}
				}
			}
			if active(m, modeShape) && serverSpoke.Load() && len(sizes) < shapeSamples {
				sizes = append(sizes, n)
				if len(sizes) == shapeSamples {
					lo, hi := sizes[0], sizes[0]
					for _, v := range sizes {
						if v < lo {
							lo = v
						}
						if v > hi {
							hi = v
						}
					}
					if hi-lo < shapeSpread {
						if punishf(c, "first %d records span %d bytes — the datapath has one shape", shapeSamples, hi-lo) {
							return
						}
					}
					log.Printf("PASS  datapath records span %d bytes", hi-lo)
				}
			}
			if _, werr := up.Write(tmp[:n]); werr != nil {
				return
			}
		}
		if rerr != nil {
			if tc, ok := up.(*net.TCPConn); ok {
				tc.CloseWrite()
			}
			break
		}
	}
	wg.Wait()
}

func clientIP(c net.Conn) string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}

func banClient(c net.Conn) {
	if banFor == 0 {
		return
	}
	ip := clientIP(c)
	var until time.Time
	if banFor > 0 {
		until = time.Now().Add(banFor)
	}
	if _, already := banned.Load(ip); !already {
		if until.IsZero() {
			log.Printf("BAN   %s out of service for good", ip)
		} else {
			log.Printf("BAN   %s out of service for %s", ip, banFor)
		}
	}
	banned.Store(ip, until)
}

func clientIsBanned(c net.Conn) bool {
	if banFor == 0 {
		return false
	}
	ip := clientIP(c)
	v, ok := banned.Load(ip)
	if !ok {
		return false
	}
	until := v.(time.Time)
	if until.IsZero() {
		return true
	}
	if time.Now().After(until) {
		banned.Delete(ip)
		return false
	}
	return true
}

func punishf(c net.Conn, format string, args ...any) bool {
	if observe {
		log.Printf("WOULDBLOCK %s "+format, append([]any{c.RemoteAddr()}, args...)...)
		return false
	}
	banClient(c)
	log.Printf("DROP  %s untrusted "+format, append([]any{c.RemoteAddr()}, args...)...)
	if punishMode == "silent" {
		time.Sleep(silentHold)
		return true
	}
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
	return true
}

type verdictState struct {
	mu        sync.Mutex
	on        bool
	rate      float64
	window    time.Duration
	thresh    int
	hits      map[string][]time.Time
	firstSeen map[string]time.Time
	banned    map[string]bool
}

var verdictJudge = &verdictState{
	hits:      map[string][]time.Time{},
	firstSeen: map[string]time.Time{},
	banned:    map[string]bool{},
}

func (v *verdictState) sampled() bool { return v.on && mrand.Float64() < v.rate }

func (v *verdictState) note(c net.Conn, tells []string) {
	if !v.on || len(tells) == 0 {
		return
	}
	ip := clientIP(c)
	now := time.Now()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.banned[ip] {
		return
	}
	if _, ok := v.firstSeen[ip]; !ok {
		v.firstSeen[ip] = now
	}
	cut := now.Add(-v.window)
	for _, t := range tells {
		key := ip + "|" + t
		ts := v.hits[key]
		i := 0
		for i < len(ts) && ts[i].Before(cut) {
			i++
		}
		ts = append(ts[i:], now)
		v.hits[key] = ts
		if len(ts) >= v.thresh {
			v.banned[ip] = true
			banClient(c)
			log.Printf("BANIP %s tell=%s hits=%d in %ds, after %.1fs of sampling",
				ip, t, len(ts), int(v.window.Seconds()), now.Sub(v.firstSeen[ip]).Seconds())
			return
		}
	}
}

const (
	extRecordSizeLimit = 0x001c
	extALPSOld         = 0x4469
	extALPSNew         = 0x44cd
)

func isGREASE(v uint16) bool { return byte(v>>8) == byte(v) && v&0x0f0f == 0x0a0a }

func helloRecordLen(first []byte) int {
	if len(first) < 5 || first[0] != 0x16 {
		return 0
	}
	return int(first[3])<<8 | int(first[4])
}

func helloWhole(first []byte) bool {
	size := helloRecordLen(first)
	return size > 0 && 5+size <= len(first)
}

const reassembleMax = 64 << 10

var reassembleWait = 3 * time.Second

const (
	helloIncomplete = iota
	helloComplete
	helloMalformed
)

func joinHelloRecords(raw []byte) ([]byte, int) {
	var payload []byte
	for pos := 0; pos+5 <= len(raw); {
		if raw[pos] != 0x16 {
			return nil, helloMalformed
		}
		size := int(raw[pos+3])<<8 | int(raw[pos+4])
		if pos+5+size > len(raw) {
			break
		}
		payload = append(payload, raw[pos+5:pos+5+size]...)
		pos += 5 + size
	}
	if len(payload) < 4 {
		return nil, helloIncomplete
	}
	need := 4 + (int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3]))
	if need > reassembleMax {
		return nil, helloMalformed
	}
	if len(payload) < need {
		return nil, helloIncomplete
	}
	hello := make([]byte, 0, 5+need)
	hello = append(hello, 0x16, 0x03, 0x01, byte(need>>8), byte(need))
	return append(hello, payload[:need]...), helloComplete
}

func reassembleHello(c net.Conn, first []byte) (raw, whole []byte, reads int) {
	raw = append([]byte(nil), first...)
	reads = 1
	if len(raw) < 6 || raw[0] != 0x16 || raw[5] != 0x01 {
		return raw, nil, reads
	}
	buf := make([]byte, 16<<10)
	for {
		hello, state := joinHelloRecords(raw)
		if state == helloComplete {
			return raw, hello, reads
		}
		if state == helloMalformed || len(raw) >= reassembleMax {
			return raw, nil, reads
		}
		c.SetReadDeadline(time.Now().Add(reassembleWait))
		n, err := c.Read(buf)
		if n > 0 {
			raw = append(raw, buf[:n]...)
			reads++
		}
		if err != nil {
			return raw, nil, reads
		}
	}
}

func helloExtensions(rec []byte) ([]uint16, bool) {
	b := rec
	if len(b) >= 5 && b[0] == 0x16 {
		b = b[5:]
	}
	if len(b) < 4 || b[0] != 0x01 {
		return nil, false
	}
	b = b[4:]
	if len(b) < 34 {
		return nil, false
	}
	b = b[34:]
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return nil, false
	}
	b = b[1+int(b[0]):]
	if len(b) < 2 {
		return nil, false
	}
	suites := int(b[0])<<8 | int(b[1])
	if len(b) < 2+suites {
		return nil, false
	}
	b = b[2+suites:]
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return nil, false
	}
	b = b[1+int(b[0]):]
	if len(b) < 2 {
		return nil, false
	}
	b = b[2:]
	var out []uint16
	for len(b) >= 4 {
		t := uint16(b[0])<<8 | uint16(b[1])
		size := int(b[2])<<8 | int(b[3])
		if len(b) < 4+size {
			break
		}
		out = append(out, t)
		b = b[4+size:]
	}
	return out, len(out) > 0
}

func ja3(rec []byte) (string, bool) {
	b := rec
	if len(b) >= 5 && b[0] == 0x16 {
		b = b[5:]
	}
	if len(b) < 4 || b[0] != 0x01 {
		return "", false
	}
	b = b[4:]
	if len(b) < 34 {
		return "", false
	}
	version := int(b[0])<<8 | int(b[1])
	b = b[34:]
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return "", false
	}
	b = b[1+int(b[0]):]

	if len(b) < 2 {
		return "", false
	}
	csLen := int(b[0])<<8 | int(b[1])
	if len(b) < 2+csLen {
		return "", false
	}
	var ciphers []int
	for i := 2; i+1 < 2+csLen; i += 2 {
		v := uint16(b[i])<<8 | uint16(b[i+1])
		if !isGREASE(v) {
			ciphers = append(ciphers, int(v))
		}
	}
	b = b[2+csLen:]

	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return "", false
	}
	b = b[1+int(b[0]):]

	if len(b) < 2 {
		return "", false
	}
	b = b[2:]
	var exts, curves, formats []int
	for len(b) >= 4 {
		t := uint16(b[0])<<8 | uint16(b[1])
		size := int(b[2])<<8 | int(b[3])
		if len(b) < 4+size {
			break
		}
		body := b[4 : 4+size]
		if !isGREASE(t) {
			exts = append(exts, int(t))
		}
		switch t {
		case 0x0a:
			if len(body) >= 2 {
				n := int(body[0])<<8 | int(body[1])
				for i := 2; i+1 < 2+n && i+1 < len(body); i += 2 {
					v := uint16(body[i])<<8 | uint16(body[i+1])
					if !isGREASE(v) {
						curves = append(curves, int(v))
					}
				}
			}
		case 0x0b:
			if len(body) >= 1 {
				n := int(body[0])
				for i := 1; i < 1+n && i < len(body); i++ {
					formats = append(formats, int(body[i]))
				}
			}
		}
		b = b[4+size:]
	}

	s := strconv.Itoa(version) + "," + joinInts(ciphers) + "," +
		joinInts(exts) + "," + joinInts(curves) + "," + joinInts(formats)
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:]), true
}

func joinInts(v []int) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, "-")
}

func ja4(rec []byte) (string, bool) {
	b := rec
	if len(b) >= 5 && b[0] == 0x16 {
		b = b[5:]
	}
	if len(b) < 4 || b[0] != 0x01 {
		return "", false
	}
	b = b[4:]
	if len(b) < 34 {
		return "", false
	}
	legacy := int(b[0])<<8 | int(b[1])
	b = b[34:]
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return "", false
	}
	b = b[1+int(b[0]):]

	if len(b) < 2 {
		return "", false
	}
	csLen := int(b[0])<<8 | int(b[1])
	if len(b) < 2+csLen {
		return "", false
	}
	var ciphers []int
	for i := 2; i+1 < 2+csLen; i += 2 {
		v := uint16(b[i])<<8 | uint16(b[i+1])
		if !isGREASE(v) {
			ciphers = append(ciphers, int(v))
		}
	}
	b = b[2+csLen:]

	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return "", false
	}
	b = b[1+int(b[0]):]

	if len(b) < 2 {
		return "", false
	}
	b = b[2:]

	var exts []int
	extCount := 0
	version := legacy
	hasSNI := false
	alpn := "00"
	var sigAlgs []int
	for len(b) >= 4 {
		t := uint16(b[0])<<8 | uint16(b[1])
		size := int(b[2])<<8 | int(b[3])
		if len(b) < 4+size {
			break
		}
		body := b[4 : 4+size]
		if !isGREASE(t) {
			extCount++
			switch t {
			case 0x0000:
				hasSNI = true
			case 0x0010:
				if len(body) >= 2 {
					n := int(body[0])<<8 | int(body[1])
					if n >= 1 && 2 < len(body) {
						l := int(body[2])
						if 3+l <= len(body) && l > 0 {
							v := body[3 : 3+l]
							alpn = string([]byte{v[0], v[len(v)-1]})
						}
					}
				}
			case 0x002b:
				for i := 1; i+1 < len(body); i += 2 {
					v := uint16(body[i])<<8 | uint16(body[i+1])
					if !isGREASE(v) && int(v) > version {
						version = int(v)
					}
				}
			case 0x000d:
				if len(body) >= 2 {
					n := int(body[0])<<8 | int(body[1])
					for i := 2; i+1 < 2+n && i+1 < len(body); i += 2 {
						sigAlgs = append(sigAlgs, int(uint16(body[i])<<8|uint16(body[i+1])))
					}
				}
				exts = append(exts, int(t))
			default:
				exts = append(exts, int(t))
			}
		}
		b = b[4+size:]
	}

	ver := "00"
	switch version {
	case 0x0304:
		ver = "13"
	case 0x0303:
		ver = "12"
	case 0x0302:
		ver = "11"
	case 0x0301:
		ver = "10"
	}
	sni := "i"
	if hasSNI {
		sni = "d"
	}
	a := "t" + ver + sni + cap2(len(ciphers)) + cap2(extCount) + alpn

	sort.Ints(ciphers)
	sort.Ints(exts)
	b12 := sha12(hexList(ciphers))
	c12 := sha12(hexList(exts) + "_" + hexList(sigAlgs))
	return a + "_" + b12 + "_" + c12, true
}

func ja4Ciphers(h string) string {
	first := strings.IndexByte(h, '_')
	if first < 0 || first+13 > len(h) {
		return ""
	}
	return h[first+1 : first+13]
}

func cap2(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func hexList(v []int) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprintf("%04x", x)
	}
	return strings.Join(parts, ",")
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func browserOf(rec []byte) string {
	exts, ok := helloExtensions(rec)
	if !ok {
		return ""
	}
	grease := false
	for _, t := range exts {
		switch {
		case t == extRecordSizeLimit:
			return "firefox"
		case t == extALPSOld, t == extALPSNew:
			return "chrome"
		case isGREASE(t):
			grease = true
		}
	}
	if grease {
		return "safari"
	}
	return "chrome"
}

func main() {
	listen := os.Getenv("CENSOR_LISTEN")
	if listen == "" {
		listen = ":8443"
	}
	modes := []string{modePackets}
	if v := os.Getenv("CENSOR_MODE"); v != "" {
		modes = modes[:0]
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				modes = append(modes, name)
			}
		}
	}
	resetOnRotate = os.Getenv("CENSOR_RESET_ON_ROTATE") == "1"
	reassemble = os.Getenv("CENSOR_REASSEMBLE") == "1"
	observe = os.Getenv("CENSOR_OBSERVE") == "1"
	verdictJudge.on = os.Getenv("CENSOR_VERDICT") == "1"
	verdictJudge.rate = 0.2
	if v := os.Getenv("CENSOR_SAMPLE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 1 {
			verdictJudge.rate = f
		}
	}
	verdictJudge.window = 30 * time.Second
	if v := os.Getenv("CENSOR_VERDICT_WINDOW"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			verdictJudge.window = time.Duration(n) * time.Second
		}
	}
	verdictJudge.thresh = 5
	if v := os.Getenv("CENSOR_VERDICT_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			verdictJudge.thresh = n
		}
	}
	if verdictJudge.on {
		log.Printf("VERDICT sampling %.0f%%, ban IP at %d hits of one tell in %s",
			verdictJudge.rate*100, verdictJudge.thresh, verdictJudge.window)
	}
	mode.Store(modes[0])
	log.Printf("MODE %s", modes[0])
	blockedFP = map[string]bool{}
	for _, name := range strings.Split(os.Getenv("CENSOR_BLOCK_FP"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			blockedFP[name] = true
		}
	}
	if len(blockedFP) == 0 {
		blockedFP["chrome"] = true
	}
	blockedJA3 = map[string]bool{}
	for _, h := range strings.Split(os.Getenv("CENSOR_BLOCK_JA3"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			blockedJA3[h] = true
		}
	}
	blockedJA4 = map[string]bool{}
	for _, h := range strings.Split(os.Getenv("CENSOR_BLOCK_JA4"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			blockedJA4[h] = true
		}
	}
	blockedJA4B = map[string]bool{}
	for _, h := range strings.Split(os.Getenv("CENSOR_BLOCK_JA4B"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			blockedJA4B[h] = true
		}
	}
	maxHello = 2048
	if v := os.Getenv("CENSOR_MAX_HELLO"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxHello = n
		}
	}
	if v := os.Getenv("CENSOR_PACKET_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 2 {
			leadingPacketLimit = n
		}
	}
	if v := os.Getenv("CENSOR_BAN_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n != 0 {
			banFor = time.Duration(n) * time.Second
		}
	}
	punishMode = strings.TrimSpace(os.Getenv("CENSOR_PUNISH"))
	freezeBytes = 16 << 10
	if v := os.Getenv("CENSOR_FREEZE_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			freezeBytes = n
		}
	}
	if v := os.Getenv("CENSOR_THROTTLE_KBPS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			throttleKBps = n
		}
	}
	blockSNI = []byte(os.Getenv("CENSOR_BLOCK_SNI"))
	if len(blockSNI) == 0 {
		blockSNI = []byte("origin")
	}
	upstream := os.Getenv("CENSOR_UPSTREAM")
	if upstream == "" {
		upstream = "server:443"
	}

	if every, err := time.ParseDuration(os.Getenv("CENSOR_ROTATE")); err == nil && every > 0 && len(modes) > 1 {
		go rotate(modes, every)
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("censor on %s -> %s, modes %v, GFW first-packet exemption rules", listen, upstream, modes)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(c, upstream)
	}
}
