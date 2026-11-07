package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

type Symptom string

const (
	SymptomOK            Symptom = "ok"
	SymptomLocal         Symptom = "local"
	SymptomError         Symptom = "error"
	SymptomTCPSilent     Symptom = "tcp_silent"
	SymptomTCPReset      Symptom = "tcp_reset"
	SymptomHelloReset    Symptom = "hello_reset"
	SymptomHelloSilent   Symptom = "hello_silent"
	SymptomHelloRejected Symptom = "hello_rejected"
	SymptomLiveReset     Symptom = "live_reset"
	SymptomStallVolume   Symptom = "stall_volume"
	SymptomStall         Symptom = "stall"
)

const (
	volumeFreezeMinBytes = 12 << 10
	volumeFreezeMaxBytes = 24 << 10

	StreamStallSilence = 5 * time.Second

	tlsRecordHeaderLen = 5
)

type recordCursor struct {
	header [tlsRecordHeaderLen]byte
	have   int
	left   int
}

func (r *recordCursor) feed(b []byte) {
	for len(b) > 0 {
		if r.left > 0 {
			step := min(r.left, len(b))
			r.left -= step
			b = b[step:]
			continue
		}
		r.header[r.have] = b[0]
		r.have++
		b = b[1:]
		if r.have == tlsRecordHeaderLen {
			r.left = int(binary.BigEndian.Uint16(r.header[3:]))
			r.have = 0
		}
	}
}

func (r *recordCursor) inside() bool { return r.left > 0 || r.have > 0 }

func inVolumeWindow(down int64) bool {
	return down >= volumeFreezeMinBytes && down <= volumeFreezeMaxBytes
}

func isLocalDialError(s string) bool {
	return strings.Contains(s, "context canceled") || strings.Contains(s, "abort") ||
		strings.Contains(s, "unreachable") || strings.Contains(s, "network is down") || isFirewallRefusal(s)
}

func isFirewallRefusal(s string) bool {
	return strings.Contains(s, "forbidden by its access permissions") || strings.Contains(s, "operation not permitted")
}

func FirewallRefused(err error) bool { return err != nil && isFirewallRefusal(err.Error()) }

func isPeerReset(s string) bool {
	return strings.Contains(s, "reset") || strings.Contains(s, "broken pipe") || strings.Contains(s, "forcibly closed")
}

func connectSymptom(err error) Symptom {
	s := err.Error()
	switch {
	case isLocalDialError(s):
		return SymptomLocal
	case strings.Contains(s, "refused"), isPeerReset(s):
		return SymptomTCPReset
	case strings.Contains(s, "deadline exceeded"), strings.Contains(s, "timeout"), strings.Contains(s, "timed out"):
		return SymptomTCPSilent
	default:
		return SymptomError
	}
}

func helloSymptom(result HandshakeResult, err error) Symptom {
	switch result {
	case HandshakeOK:
		return SymptomOK
	case HandshakeLocal:
		return SymptomLocal
	case HandshakeResetFast:
		return SymptomHelloReset
	case HandshakeIncomplete:
		return SymptomHelloSilent
	case HandshakeRejected:
		return SymptomHelloRejected
	default:
		if err != nil && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isPeerReset(err.Error())) {
			return SymptomHelloReset
		}
		return SymptomError
	}
}

type LiveEnd struct {
	Dur       time.Duration
	Moved     int64
	Down      int64
	Reset     bool
	Stalled   bool
	MidRecord bool
}

func (e LiveEnd) Symptom() Symptom {
	switch {
	case e.Reset:
		return SymptomLiveReset
	case e.Stalled && e.MidRecord && inVolumeWindow(e.Down):
		return SymptomStallVolume
	case e.Stalled:
		return SymptomStall
	default:
		return SymptomOK
	}
}

func NoteStall(c net.Conn) {
	for c != nil {
		if l, ok := c.(*livenessConn); ok {
			l.stalled.Store(true)
			return
		}
		nc, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return
		}
		c = nc.NetConn()
	}
}
