//go:build !with_gvisor

package tunstack

import (
	"context"
	"fmt"
	"io"
)

// Stack is a stub implementation when gVisor is not available.
// All methods are no-ops to allow server/client binaries to build
// without gVisor functionality.
type Stack struct{}

// NewStack returns a stub Stack when gVisor is not available.
func NewStack(tunDevice io.ReadWriter, mtu uint32, tcpHandler, udpHandler HandlerFunc) (*Stack, error) { //nolint:revive
	return &Stack{}, nil
}

// Start is a no-op when gVisor is not available.
func (s *Stack) Start(ctx context.Context) {} //nolint:revive

// Run is a no-op when gVisor is not available.
func (s *Stack) Run() error { //nolint:revive
	return nil
}

// SetPacketHandler is a legacy stub.
func (s *Stack) SetPacketHandler(_ interface{}) {}

// IsActive returns false for stub implementation.
func (s *Stack) IsActive() bool {
	return false
}

// HandleIncomingPacket is a no-op stub when gVisor is not available.
func (s *Stack) HandleIncomingPacket(packet []byte) error {
	// Stub implementation - always returns error to trigger fallback
	return fmt.Errorf("gVisor not available")
}

