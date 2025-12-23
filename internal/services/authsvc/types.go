package authsvc

import "time"

// SessionOpenRequest mirrors api/proto/auth.proto.
type SessionOpenRequest struct {
	Token      string
	ClientID   string
	Connection ConnectionInfo
	Metadata   map[string]string
}

type ConnectionInfo struct {
	Protocol         string
	RemoteAddress    string
	RequestedProfile string
	P2PEnabled       bool
}

type SessionOpenResponse struct {
	SessionID  string
	AEADKey    []byte
	Seed       []byte
	InitialSeq uint32
	ExpiresAt  time.Time
}

type SessionRefreshRequest struct {
	SessionID  string
	AckedSeq   uint64
	ForceRekey bool
}

type SessionRefreshResponse struct {
	Renewed    bool
	ExpiresAt  time.Time
	NewAEADKey []byte
	NewSeq     uint32
}

type SessionCloseRequest struct {
	SessionID string
	Reason    string
}

type SessionCloseResponse struct {
	Closed bool
}

type SessionEventType int

const (
	SessionEventTypeUnspecified SessionEventType = iota
	SessionEventTypeRekey
	SessionEventTypeSuspend
	SessionEventTypeResume
	SessionEventTypeRevoke
)

type SessionEvent struct {
	Type      SessionEventType
	SessionID string
	Seq       uint32
	Timestamp time.Time
	Reason    string
	AEADKey   []byte
}
