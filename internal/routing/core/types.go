package core

import "net"

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

type RoutingContext struct {
	Info       *PacketInfo
	Attributes map[string]interface{}
}

func NewRoutingContext(info *PacketInfo) *RoutingContext {
	return &RoutingContext{
		Info:       info,
		Attributes: make(map[string]interface{}),
	}
}
