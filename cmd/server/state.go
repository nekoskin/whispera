package main

import (
	"crypto/rand"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
	aeadpkg "whispera/internal/crypto"
)

// maxUDPPacket задает максимальный размер UDP-пакета, который мы читаем/пишем.
// По умолчанию 65535, но может быть уменьшен в рантайме на основе MTU.
var maxUDPPacket = 65535

func setMaxUDPPacket(mtu int) {
	if mtu <= 0 {
		return
	}
	if mtu > 65535 {
		mtu = 65535
	}
	maxUDPPacket = mtu
}

// ChaffRuntimeConfig хранит параметры server-originated chaff traffic.
type ChaffRuntimeConfig struct {
	Sec      int
	Dist     string  // "const", "exp", "pareto"
	Alpha    float64 // pareto shape parameter
	Xm       float64 // pareto scale parameter (seconds)
	SizeMin  int
	SizeMax  int
	DutyOn   int
	DutyOff  int
}

var chaffRuntimeConfig atomic.Value

func init() {
	// Инициализируем пустую конфигурацию по умолчанию.
	chaffRuntimeConfig.Store(&ChaffRuntimeConfig{Dist: "const"})
}

func setChaffRuntimeConfig(sec int, dist string, alpha, xm float64, sizeMin, sizeMax, dutyOn, dutyOff int) {
	cfg := &ChaffRuntimeConfig{
		Sec:     sec,
		Dist:    dist,
		Alpha:   alpha,
		Xm:      xm,
		SizeMin: sizeMin,
		SizeMax: sizeMax,
		DutyOn:  dutyOn,
		DutyOff: dutyOff,
	}
	chaffRuntimeConfig.Store(cfg)
}

func getChaffRuntimeConfig() *ChaffRuntimeConfig {
	v := chaffRuntimeConfig.Load()
	if v == nil {
		return &ChaffRuntimeConfig{Dist: "const"}
	}
	return v.(*ChaffRuntimeConfig)
}

// calculateChaffInterval вычисляет следующий интервал для chaff на основе распределения.
func calculateChaffInterval(cfg *ChaffRuntimeConfig) time.Duration {
	if cfg.Sec <= 0 {
		return 0
	}
	baseSec := float64(cfg.Sec)

	switch cfg.Dist {
	case "exp", "exponential":
		// Exponential distribution: lambda = 1 / mean
		lambda := 1.0 / baseSec
		// Generate random float64 [0,1) using crypto/rand
		buf := make([]byte, 8)
		_, _ = rand.Read(buf)
		u := float64(uint64(buf[0])|uint64(buf[1])<<8|uint64(buf[2])<<16|uint64(buf[3])<<24|uint64(buf[4])<<32|uint64(buf[5])<<40|uint64(buf[6])<<48|uint64(buf[7])<<56) / (1 << 63)
		if u == 0 {
			u = 0.0001 // Avoid log(0)
		}
		interval := -math.Log(u) / lambda
		// Clamp to reasonable range (0.1 * baseSec to 3 * baseSec)
		if interval < baseSec*0.1 {
			interval = baseSec * 0.1
		}
		if interval > baseSec*3 {
			interval = baseSec * 3
		}
		return time.Duration(interval * float64(time.Second))

	case "pareto":
		// Pareto distribution: xm (scale) and alpha (shape)
		// PDF: f(x) = (alpha * xm^alpha) / x^(alpha+1) for x >= xm
		// CDF: F(x) = 1 - (xm/x)^alpha
		// Inverse CDF: x = xm / (1-u)^(1/alpha)
		if cfg.Alpha <= 0 {
			cfg.Alpha = 1.5 // Default
		}
		if cfg.Xm <= 0 {
			cfg.Xm = 1.0 // Default
		}
		// Generate random float64 [0,1) using crypto/rand
		buf := make([]byte, 8)
		_, _ = rand.Read(buf)
		u := float64(uint64(buf[0])|uint64(buf[1])<<8|uint64(buf[2])<<16|uint64(buf[3])<<24|uint64(buf[4])<<32|uint64(buf[5])<<40|uint64(buf[6])<<48|uint64(buf[7])<<56) / (1 << 63)
		if u == 0 {
			u = 0.0001
		}
		if u >= 1.0 {
			u = 0.9999
		}
		// Use xm as base scale, but scale by baseSec
		xmScaled := cfg.Xm * baseSec
		interval := xmScaled / math.Pow(1.0-u, 1.0/cfg.Alpha)
		// Clamp to reasonable range
		if interval < baseSec*0.1 {
			interval = baseSec * 0.1
		}
		if interval > baseSec*10 {
			interval = baseSec * 10
		}
		return time.Duration(interval * float64(time.Second))

	default: // "const"
		return time.Duration(cfg.Sec) * time.Second
	}
}

// AntiAmplificationRuntimeConfig хранит лимиты anti-amplification для handshake.
type AntiAmplificationRuntimeConfig struct {
	MaxRatio float64
	MaxBytes int
}

var ampRuntimeConfig atomic.Value

func init() {
	ampRuntimeConfig.Store(&AntiAmplificationRuntimeConfig{MaxRatio: 3.0, MaxBytes: 2048})
}

func setAmpRuntimeConfig(maxRatio float64, maxBytes int) {
	cfg := &AntiAmplificationRuntimeConfig{
		MaxRatio: maxRatio,
		MaxBytes: maxBytes,
	}
	ampRuntimeConfig.Store(cfg)
}

func getAmpRuntimeConfig() *AntiAmplificationRuntimeConfig {
	v := ampRuntimeConfig.Load()
	if v == nil {
		return &AntiAmplificationRuntimeConfig{MaxRatio: 3.0, MaxBytes: 2048}
	}
	return v.(*AntiAmplificationRuntimeConfig)
}

type ServerProxyConnection struct {
	ID         uint32
	Target     net.Conn
	WSConn     *websocket.Conn
	UDPConn    *net.UDPConn
	ClientAddr *net.UDPAddr
	AEADState  *aeadpkg.AEADState
	SessionID  uint32
	SeqSend    *uint32
	SeqMutex   sync.Mutex
	Closed     chan struct{}
}

var (
	serverProxyConnections = make(map[uint32]*ServerProxyConnection)
	serverProxyMutex       = sync.Mutex{}
	auditFlag              *bool
	dnsUpstreamAddr        *string
)
