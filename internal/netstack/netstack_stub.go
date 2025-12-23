//go:build !with_gvisor

package netstack

import (
	"io"
)

// Config describes basic parameters for userspace gVisor netstack.
type Config struct {
	MTU            uint32
	EnableIPv6     bool
	Debug          bool
	TCPMaxInFlight int
}

// DefaultConfig returns minimal default configuration.
func DefaultConfig() Config {
	return Config{
		MTU:            1500,
		EnableIPv6:     true,
		Debug:          false,
		TCPMaxInFlight: 1024,
	}
}

// TCPConnHandler is called when a new incoming TCP connection appears in netstack.
type TCPConnHandler func(flow interface{}, ep interface{})

// UDPConnHandler is called when a new UDP session appears.
type UDPConnHandler func(flow interface{}, ep interface{})

// Stack is a stub implementation when gVisor is not available.
type Stack struct{}

// NewStack returns a stub Stack when gVisor is not available.
func NewStack(tun io.ReadWriter, cfg Config) (*Stack, error) {
	return &Stack{}, nil
}

// SetTCPHandler registers callback for new TCP connections.
func (ns *Stack) SetTCPHandler(h TCPConnHandler) {}

// SetUDPHandler registers callback for new UDP sessions.
func (ns *Stack) SetUDPHandler(h UDPConnHandler) {}

// Close stops background goroutines and releases resources.
func (ns *Stack) Close() {}

// InjectInboundPacket injects raw IP packet into netstack through NIC.
func (ns *Stack) InjectInboundPacket(pkt []byte) error {
	return nil
}

// StartNICToTUN starts background goroutine that reads outbound packets
// from NIC and sends them to TUN as raw IP.
func (ns *Stack) StartNICToTUN() {}

// Run starts main loop: reads IP packets from TUN and injects them into netstack.
func (ns *Stack) Run() error {
	return nil
}

