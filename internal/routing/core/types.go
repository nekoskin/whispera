// Package core provides core routing types
package core

import "net"

// PacketInfo contains information about a packet for routing decisions
type PacketInfo struct {
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	Protocol   string
	Domain     string
	UserID     string
	InboundTag string
}

// Rule represents a routing rule
type Rule struct {
	Name        string
	Priority    int
	Domains     []string
	IPs         []string
	Ports       []uint16
	Protocols   []string
	Users       []string
	InboundTags []string
	OutboundTag string
	BalancerTag string
}

// RoutingContext provides context for routing decision
type RoutingContext struct {
	Info       *PacketInfo
	Attributes map[string]interface{}
}

// NewRoutingContext creates a new routing context
func NewRoutingContext(info *PacketInfo) *RoutingContext {
	return &RoutingContext{
		Info:       info,
		Attributes: make(map[string]interface{}),
	}
}
