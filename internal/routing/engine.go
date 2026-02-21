package routing

import (
	"net"
	"sync"

	routing_core "whispera/internal/routing/core"
)

type OutboundManager struct {
	mu       sync.RWMutex
	sessions map[string]uint32
}

func NewOutboundManager() *OutboundManager {
	return &OutboundManager{
		sessions: make(map[string]uint32),
	}
}

func (om *OutboundManager) GetSessionID(tag string) (uint32, bool) {
	om.mu.RLock()
	defer om.mu.RUnlock()
	id, ok := om.sessions[tag]
	return id, ok
}

func (om *OutboundManager) RegisterSession(tag string, sessionID uint32) {
	om.mu.Lock()
	defer om.mu.Unlock()
	om.sessions[tag] = sessionID
}

type Engine struct {
	mu              sync.RWMutex
	rules           []*routing_core.Rule
	outboundManager *OutboundManager
	defaultOutbound string
}

func NewEngine() *Engine {
	return &Engine{
		rules:           make([]*routing_core.Rule, 0),
		outboundManager: NewOutboundManager(),
		defaultOutbound: "direct",
	}
}

func (e *Engine) GetOutboundManager() *OutboundManager {
	return e.outboundManager
}

func (e *Engine) AddRule(rule *routing_core.Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

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

func (e *Engine) SetDefaultOutbound(tag string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.defaultOutbound = tag
}
