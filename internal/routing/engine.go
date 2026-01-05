// Package routing provides routing engine for traffic management
package routing

import (
	"net"
	"sync"

	routing_core "whispera/internal/routing/core"
)

// OutboundManager manages outbound session mappings
type OutboundManager struct {
	mu       sync.RWMutex
	sessions map[string]uint32 // tag -> sessionID
}

// NewOutboundManager creates a new outbound manager
func NewOutboundManager() *OutboundManager {
	return &OutboundManager{
		sessions: make(map[string]uint32),
	}
}

// GetSessionID returns session ID for given outbound tag
func (om *OutboundManager) GetSessionID(tag string) (uint32, bool) {
	om.mu.RLock()
	defer om.mu.RUnlock()
	id, ok := om.sessions[tag]
	return id, ok
}

// RegisterSession registers a session for outbound tag
func (om *OutboundManager) RegisterSession(tag string, sessionID uint32) {
	om.mu.Lock()
	defer om.mu.Unlock()
	om.sessions[tag] = sessionID
}

// Engine is the main routing engine
type Engine struct {
	mu              sync.RWMutex
	rules           []*routing_core.Rule
	outboundManager *OutboundManager
	defaultOutbound string
}

// NewEngine creates a new routing engine
func NewEngine() *Engine {
	return &Engine{
		rules:           make([]*routing_core.Rule, 0),
		outboundManager: NewOutboundManager(),
		defaultOutbound: "direct",
	}
}

// GetOutboundManager returns the outbound manager
func (e *Engine) GetOutboundManager() *OutboundManager {
	return e.outboundManager
}

// AddRule adds a routing rule
func (e *Engine) AddRule(rule *routing_core.Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// Route determines the outbound tag for given packet info
// Returns: outboundTag, balancerTag (if any), matched
func (e *Engine) Route(info *routing_core.PacketInfo) (string, string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.rules {
		if e.matchRule(rule, info) {
			return rule.OutboundTag, rule.BalancerTag, true
		}
	}

	return e.defaultOutbound, "", false
}

func (e *Engine) matchRule(rule *routing_core.Rule, info *routing_core.PacketInfo) bool {
	// Domain matching
	if len(rule.Domains) > 0 {
		matched := false
		for _, d := range rule.Domains {
			if d == info.Domain {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// IP matching
	if len(rule.IPs) > 0 && info.DstIP != nil {
		matched := false
		for _, ipStr := range rule.IPs {
			_, cidr, err := net.ParseCIDR(ipStr)
			if err != nil {
				if net.ParseIP(ipStr).Equal(info.DstIP) {
					matched = true
					break
				}
				continue
			}
			if cidr.Contains(info.DstIP) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Port matching
	if len(rule.Ports) > 0 && info.DstPort > 0 {
		matched := false
		for _, p := range rule.Ports {
			if p == info.DstPort {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// SetDefaultOutbound sets the default outbound tag
func (e *Engine) SetDefaultOutbound(tag string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.defaultOutbound = tag
}
