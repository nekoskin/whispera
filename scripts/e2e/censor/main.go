package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/bits"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A browser sends the hello in one packet, two at most. More before the server
// replies is a deliberate split. Tightening this to 2 makes a two-packet hello
// suspicious as well, which is a rule a controller trained on the looser one
// has never seen.
var leadingPacketLimit = 3

// packets: count segments before the reply. sni: block a whole name in the
// first packet. shape: drop a datapath whose records are all one size.
const (
	modePackets     = "packets"
	modeSNI         = "sni"
	modeShape       = "shape"
	modeFingerprint = "fingerprint"
	modeJA3         = "ja3"
	modeJA4         = "ja4"
	modeBigHello    = "bighello"
	modeFreeze      = "freeze"
	// Every rule against every connection, which is how a real DPI works: it
	// pulls the parameters it cares about out of each flow and checks them all,
	// rather than having one rule switched on at a time.
	modeAll = "all"
)

// How long a silently dropped connection is held open before it is let go. The
// client is meant to hit its own handshake timeout first.
const silentHold = 20 * time.Second

// The shape rule is synthetic, built to be visible to the knobs we have. It is a
// test of the machinery, not evidence about a real censor.
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
	maxHello     int
	punishMode   string
	freezeBytes  int
	throttleKBps int

	// A caught client is out for a while, the way the GFW holds a triple of
	// client, destination and port for 180 s. One bad arm then costs every
	// dial until the ban lapses, not just the dial that tripped it.
	banFor time.Duration
	banned sync.Map

	// Tear down live flows on a mode switch, or keep-alive hides the client
	// from a handshake-only detector and the rotation measures nothing.
	resetOnRotate bool
	live          sync.Map
)

func currentMode() string { return mode.Load().(string) }

// A rotation entry may join several rules with "+", so they apply together.
// Rules taking turns cannot corner a controller holding two arms that cover
// each other: whichever rule is up, one of the two is safe. Split by hand
// rather than with strings.Split because the freeze rule is checked on every
// packet read.
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

// rotate switches the detector on a timer, so the stand has an opponent that
// moves instead of one rule held for the whole run.
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

// GFW fully-encrypted-traffic detector from "How the Great Firewall of China
// Detects and Blocks Fully Encrypted Traffic" (USENIX Security 2023): pass the
// first data packet if any exemption holds, else drop. Real TLS trips Ex5.

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

// exemptReason returns the first exemption a packet satisfies, or "" to block.
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

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		var down int64
		frozen := false
		for {
			n, rerr := up.Read(buf)
			if n > 0 {
				serverSpoke.Store(true)
				down += int64(n)
				// Past the byte limit the connection stops carrying anything
				// back, with no reset: the client waits for a timeout instead.
				if active(currentMode(), modeFreeze) && down > int64(freezeBytes) {
					if !frozen {
						log.Printf("FREEZE %s %d bytes downstream, nothing more gets through", c.RemoteAddr(), down)
						frozen = true
					}
					continue
				}
				if throttleKBps > 0 {
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

	// An address already caught is out of service: nothing it sends is looked
	// at. Killed directly rather than through punishf, or every retry would
	// push the ban further out and it would never lapse.
	if clientIsBanned(c) {
		log.Printf("DROP  %s ip is out of service", c.RemoteAddr())
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		return
	}

	// Judge the first data packet, then count how many more arrive before the
	// server answers: a split hello shows up here.
	tmp := make([]byte, 32<<10)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	n, rerr := c.Read(tmp)
	if n > 0 {
		first := tmp[:n]
		reason := exemptReason(first)
		if reason == "" {
			punishf(c, "first packet %d bytes, bits/byte %.2f, printable %.0f%% — no exemption",
				n, avgBitsSet(first), fracPrintable(first)*100)
			return
		}
		if active(m, modeSNI) && len(blockSNI) > 0 && bytes.Contains(first, blockSNI) {
			punishf(c, "server name %q sits whole in the first packet", blockSNI)
			return
		}
		// Only a whole hello gives up its fingerprint. A split one gets past
		// this and is caught by the packet count instead, which is the trade
		// the controller has to find.
		if active(m, modeFingerprint) && helloWhole(first) {
			if b := browserOf(first); b != "" && blockedFP[b] {
				punishf(c, "hello fingerprint %q is on the list", b)
				return
			}
		}
		if active(m, modeJA3) && helloWhole(first) {
			if h, ok := ja3(first); ok && blockedJA3[h] {
				punishf(c, "ja3 %s is on the list", h)
				return
			}
		}
		if active(m, modeJA4) && helloWhole(first) {
			if h, ok := ja4(first); ok && blockedJA4[h] {
				punishf(c, "ja4 %s is on the list", h)
				return
			}
		}
		if active(m, modeBigHello) {
			if size := helloRecordLen(first); size > maxHello {
				punishf(c, "hello record %d bytes, over %d", size, maxHello)
				return
			}
		}
		fp, j3, j4 := "split", "-", "-"
		if helloWhole(first) {
			if fp = browserOf(first); fp == "" {
				fp = "unparsed"
			}
			if h, ok := ja3(first); ok {
				j3 = h
			}
			if h, ok := ja4(first); ok {
				j4 = h
			}
		}
		log.Printf("PASS  %s trust first packet %d bytes via %s, hello %s, ja3 %s, ja4 %s", c.RemoteAddr(), n, reason, fp, j3, j4)
		if _, werr := up.Write(first); werr != nil {
			return
		}
	}
	if rerr != nil {
		return
	}
	c.SetReadDeadline(time.Time{})

	leading := 1
	var sizes []int
	for {
		n, rerr := c.Read(tmp)
		if n > 0 {
			if active(m, modePackets) && !serverSpoke.Load() {
				leading++
				if leading >= leadingPacketLimit {
					punishf(c, "hello split across %d packets before any reply — fragmented handshake", leading)
					return
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
						punishf(c, "first %d records span %d bytes — the datapath has one shape", shapeSamples, hi-lo)
						return
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

// punishf ends a connection the way the censor has been told to. A reset is the
// loud way; "silent" is what the Russian TSPU does instead — nothing comes
// back and the client sits there until its own timeout fires, which is a
// different signal to the controller than a reset (net4people/bbs#490).
func clientIP(c net.Conn) string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}

// banClient puts the address out of service. Not extended on later attempts:
// the ban runs from the detection, as the reported GFW behavior does. A
// negative banFor never lapses, which is how an IP or AS filter behaves.
func banClient(c net.Conn) {
	if banFor == 0 {
		return
	}
	ip := clientIP(c)
	var until time.Time // zero means it never lapses
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

func punishf(c net.Conn, format string, args ...any) {
	banClient(c)
	log.Printf("DROP  %s untrusted "+format, append([]any{c.RemoteAddr()}, args...)...)
	if punishMode == "silent" {
		time.Sleep(silentHold)
		return
	}
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
}

const (
	extRecordSizeLimit = 0x001c
	extALPSOld         = 0x4469
	extALPSNew         = 0x44cd
)

func isGREASE(v uint16) bool { return byte(v>>8) == byte(v) && v&0x0f0f == 0x0a0a }

// helloRecordLen is the length the hello record claims, 0 if this is not one.
func helloRecordLen(first []byte) int {
	if len(first) < 5 || first[0] != 0x16 {
		return 0
	}
	return int(first[3])<<8 | int(first[4])
}

// helloWhole reports whether the record arrived in one piece.
func helloWhole(first []byte) bool {
	size := helloRecordLen(first)
	return size > 0 && 5+size <= len(first)
}

// helloExtensions lists the extension types the hello carries. Written out here
// rather than imported from the client: a censor sharing code with what it
// judges would measure agreement, not detection.
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

// ja3 is the exact JA3 hash of a whole ClientHello, the way real DPI keys on a
// fingerprint: version,ciphers,extensions,curves,pointformats joined and
// MD5'd, with GREASE values dropped. A hash, not a class, so a rule can ban one
// tool's fingerprint without taking every browser that shares its family — and
// so a preset that truly replicates a browser lands on that browser's hash,
// where banning it is collateral the censor has to eat.
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
	b = b[1+int(b[0]):] // session id

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
	b = b[1+int(b[0]):] // compression methods

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
		case 0x0a: // supported_groups
			if len(body) >= 2 {
				n := int(body[0])<<8 | int(body[1])
				for i := 2; i+1 < 2+n && i+1 < len(body); i += 2 {
					v := uint16(body[i])<<8 | uint16(body[i+1])
					if !isGREASE(v) {
						curves = append(curves, int(v))
					}
				}
			}
		case 0x0b: // ec_point_formats
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

// ja4 is the FoxIO JA4 fingerprint of a ClientHello. Unlike JA3 it SORTS the
// cipher and extension lists, so the extension shuffling that Chrome does per
// connection — which makes JA3 a fresh hash every time — does not move it. That
// is why real DPI moved to JA4, and why a shuffle is no defense against it.
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
	b = b[1+int(b[0]):] // session id

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
	b = b[1+int(b[0]):] // compression

	if len(b) < 2 {
		return "", false
	}
	b = b[2:]

	var exts []int // for the sorted hash, excluding SNI and ALPN
	extCount := 0  // all non-GREASE extensions, for the count field
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
			case 0x0000: // SNI, counted but not in the sorted hash
				hasSNI = true
			case 0x0010: // ALPN, counted but not in the sorted hash
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
			case 0x002b: // supported_versions: the real negotiated max
				for i := 1; i+1 < len(body); i += 2 {
					v := uint16(body[i])<<8 | uint16(body[i+1])
					if !isGREASE(v) && int(v) > version {
						version = int(v)
					}
				}
			case 0x000d: // signature_algorithms, kept in order
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

// browserOf names the client the way JA3-style fingerprinting does: by the
// extensions it carries, not by anything it claims.
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
	maxHello = 1400
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
	// Positive: seconds out of service. Negative: never lapses. Empty or 0: off.
	if v := os.Getenv("CENSOR_BAN_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n != 0 {
			banFor = time.Duration(n) * time.Second
		}
	}
	punishMode = strings.TrimSpace(os.Getenv("CENSOR_PUNISH"))
	// 16 KB is where the reported Russian limit sits.
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
