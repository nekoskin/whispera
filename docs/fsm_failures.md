# FSM Failure Path Documentation

This document describes the Finite State Machine (FSM) transitions for failure scenarios in the Whispera relay protocol.

## Connection Failures

### 1. Target Unreachable (Network Error)
- **Initial State**: `Connecting`
- **Trigger**: `net.Dial` returns error (e.g., connection refused, timeout).
- **Event**: `EventConnectFail`
- **Actions**:
  1. Send `CONNECT_FAIL` frame to client.
  2. Transition to `Closed`.
  3. Close any open resources.

### 2. Connection Timeout (Stale)
- **Initial State**: `Connecting`
- **Trigger**: `StreamManager` cleanup loop detects `Connecting` state > 30s.
- **Event**: `EventTimeout`
- **Actions**:
  1. Transition to `Closed`.
  2. (Optionally) Send `CLOSE` frame if not already closed.
  3. Close resources.

## Runtime Failures

### 3. Peer Reset (RST)
- **Initial State**: `Connected`
- **Trigger**: `Conn.Read` returns generic error (non-EOF).
- **Event**: `EventError`
- **Actions**:
  1. Send `CLOSE` frame (flag: `RST`) to client (fail-silent: generic close).
  2. Transition to `Closed`.
  3. Close resources.

### 4. Idle Timeout
- **Initial State**: `Connected`
- **Trigger**: `StreamManager` cleanup loop detects inactivity > 5 mins (or profile-specific).
- **Event**: `EventTimeout`
- **Actions**:
  1. Send `CLOSE` frame to client.
  2. Transition to `Closed`.

## Protocol Violations

### 5. Invalid Transitions
- **Trigger**: Event triggered in invalid state (e.g., `EventData` while `Connecting`).
- **Result**: `ErrInvalidTransition` returned.
- **Handling**: Caller logs error; Stream usually remains in current state or is forced closed by `StreamManager` if critical.
