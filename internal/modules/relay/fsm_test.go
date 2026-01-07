package relay

import (
	"testing"
)

func TestFSMTransitions(t *testing.T) {
	// Create properly initialized stream
	stream := NewStream(1, ProtoTCP, "127.0.0.1", 80, ProfileBalanced, nil)
	fsm := stream.fsm

	// Test: Idle -> Connecting
	if err := fsm.Event(EventStartConnect); err != nil {
		t.Fatalf("Failed Idle->Connecting: %v", err)
	}
	if fsm.CurrentState() != StateConnecting {
		t.Fatalf("Expected Connecting, got %s", fsm.CurrentState())
	}

	// Test: Invalid transition (Data in Connecting)
	if err := fsm.Event(EventData); err == nil {
		t.Fatal("Expected error for invalid transition Data in Connecting")
	}

	// Test: Connecting -> Connected
	if err := fsm.Event(EventConnectOK); err != nil {
		t.Fatalf("Failed Connecting->Connected: %v", err)
	}
	if fsm.CurrentState() != StateConnected {
		t.Fatalf("Expected Connected, got %s", fsm.CurrentState())
	}

	// Test: Connected -> Connected (Data) - stays in same state
	if err := fsm.Event(EventData); err != nil {
		t.Fatalf("Failed Data in Connected: %v", err)
	}
	if fsm.CurrentState() != StateConnected {
		t.Fatalf("Expected still Connected after Data event, got %s", fsm.CurrentState())
	}
}

func TestFSMConnectFail(t *testing.T) {
	stream := NewStream(2, ProtoTCP, "127.0.0.1", 80, ProfileBalanced, nil)
	fsm := stream.fsm

	fsm.Event(EventStartConnect)

	// Simulate connection failure
	if err := fsm.Event(EventConnectFail); err != nil {
		t.Fatalf("Failed ConnectFail: %v", err)
	}

	if fsm.CurrentState() != StateClosed {
		t.Fatalf("Expected Closed after ConnectFail, got %s", fsm.CurrentState())
	}
}

func TestFSMSelfCheck(t *testing.T) {
	stream := NewStream(3, ProtoTCP, "127.0.0.1", 80, ProfileBalanced, nil)
	fsm := stream.fsm

	if err := fsm.SelfCheck(); err != nil {
		t.Fatalf("SelfCheck failed on valid state: %v", err)
	}
}

func TestFSMIsClosed(t *testing.T) {
	stream := NewStream(4, ProtoTCP, "127.0.0.1", 80, ProfileBalanced, nil)
	fsm := stream.fsm

	// Not closed initially
	if fsm.IsClosed() {
		t.Fatal("FSM should not be closed initially")
	}

	// Move to Closed via ConnectFail
	fsm.Event(EventStartConnect)
	fsm.Event(EventConnectFail)

	if !fsm.IsClosed() {
		t.Fatal("FSM should be closed after ConnectFail")
	}
}
