package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/nekoskin/whispera/common/dns"
	"github.com/nekoskin/whispera/core/tunnel"
	"sync"
	"sync/atomic"
	"time"
)

type connStatus string

const (
	connStatusConnecting   connStatus = "connecting"
	connStatusConnected    connStatus = "connected"
	connStatusDisconnected connStatus = "disconnected"
	connStatusFailed       connStatus = "failed"
	connStatusStandby      connStatus = "standby"
	connStatusRST          connStatus = "rst"
)

type entryView struct {
	ID                string               `json:"id"`
	Transport         string               `json:"transport"`
	Server            string               `json:"server"`
	Status            connStatus           `json:"status"`
	Enabled           bool                 `json:"enabled"`
	Obfuscated        bool                 `json:"obfuscated"`
	Mux               bool                 `json:"mux"`
	RateLimitKB       int                  `json:"rate_limit_kb"`
	SNI               string               `json:"sni"`
	BytesUp           uint64               `json:"bytes_up"`
	BytesDown         uint64               `json:"bytes_down"`
	ConnectedAt       time.Time            `json:"connected_at,omitempty"`
	Error             string               `json:"error,omitempty"`
	ForceObfuscation  bool                 `json:"force_obfuscation"`
	BehavioralProfile string               `json:"behavioral_profile,omitempty"`
	NoSNI             bool                 `json:"no_sni"`
	QualityRTTMs      int64                `json:"quality_rtt_ms,omitempty"`
	QualityMissedKAs  int                  `json:"quality_missed_kas,omitempty"`
	Failure           *tunnel.FailureCause `json:"failure,omitempty"`
}

type TransportEntry struct {
	ID          string     `json:"id"`
	Transport   string     `json:"transport"`
	Server      string     `json:"server"`
	Status      connStatus `json:"status"`
	Enabled     bool       `json:"enabled"`
	Obfuscated  bool       `json:"obfuscated"`
	Mux         bool       `json:"mux"`
	RateLimitKB int        `json:"rate_limit_kb"`
	SNI         string     `json:"sni"`
	BytesUp     uint64     `json:"bytes_up"`
	BytesDown   uint64     `json:"bytes_down"`
	ConnectedAt time.Time  `json:"connected_at,omitempty"`
	Error       string     `json:"error,omitempty"`

	ForceObfuscation bool `json:"force_obfuscation"`

	BehavioralProfile string `json:"behavioral_profile,omitempty"`

	NoSNI bool `json:"no_sni"`

	mgr    *tunnel.Manager
	cancel context.CancelFunc
	mu     sync.Mutex

	restarting int32
}

type TransportPool struct {
	mu      sync.RWMutex
	entries map[string]*TransportEntry
	counter uint64
}

var globalForceSNI atomic.Value

func getGlobalSNI() string {
	if v := globalForceSNI.Load(); v != nil {
		return v.(string)
	}
	return ""
}

var pool = &TransportPool{
	entries: make(map[string]*TransportEntry),
}

var reconnectEntry func(e *TransportEntry)

var controlAddr = "127.0.0.1:10801"

var globalDNS *dns.Resolver

var socksUser string
var socksPass string

func generateSocksAuth() {
	if *connKey != "" {
		socksUser = "whisp"
		h := sha256.Sum256([]byte(*connKey))
		socksPass = hex.EncodeToString(h[:])
		return
	}
	b := make([]byte, 16)
	rand.Read(b)
	socksUser = "w"
	socksPass = hex.EncodeToString(b)
}

func (p *TransportPool) Add(entry *TransportEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries[entry.ID] = entry
}

func (p *TransportPool) List() []*TransportEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*TransportEntry, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, e)
	}
	return out
}

func (p *TransportPool) NextID() string {
	n := atomic.AddUint64(&p.counter, 1)
	return fmt.Sprintf("conn-%d", n)
}

func (p *TransportPool) AnyConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, e := range p.entries {
		e.mu.Lock()
		connected := e.Status == connStatusConnected && e.Enabled
		e.mu.Unlock()
		if connected {
			return true
		}
	}
	return false
}

func toView(e *TransportEntry) entryView {
	e.mu.Lock()
	defer e.mu.Unlock()
	var qualityRTT int64
	var missedKAs int
	var failure *tunnel.FailureCause
	status := e.Status
	if e.mgr != nil {
		failure = e.mgr.LastFailure()
		e.BytesUp, e.BytesDown = e.mgr.Stats()
		e.ForceObfuscation = e.mgr.IsForceObfuscation()
		rtt, missed := e.mgr.GetQualityMetrics()
		qualityRTT = rtt.Milliseconds()
		missedKAs = missed

		if status == connStatusConnected && !e.mgr.IsConnected() {
			status = connStatusDisconnected
		}
	}
	return entryView{
		ID: e.ID, Transport: e.Transport, Server: e.Server,
		Status: status, Enabled: e.Enabled, Obfuscated: e.Obfuscated,
		Mux: e.Mux, RateLimitKB: e.RateLimitKB, SNI: e.SNI,
		BytesUp: e.BytesUp, BytesDown: e.BytesDown,
		ConnectedAt: e.ConnectedAt, Error: e.Error,
		ForceObfuscation:  e.ForceObfuscation,
		BehavioralProfile: e.BehavioralProfile,
		NoSNI:             e.NoSNI,
		QualityRTTMs:      qualityRTT,
		QualityMissedKAs:  missedKAs,
		Failure:           failure,
	}
}
