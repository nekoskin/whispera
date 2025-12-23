package authsvc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	aeadpkg "whispera/internal/crypto"
	srvpkg "whispera/internal/server"
	"whispera/internal/util"
)

// ErrSessionLimitReached indicates session manager refused a new session.
var ErrSessionLimitReached = errors.New("session limit reached")

// Service implements session lifecycle management.
type Service struct {
	sessions   *srvpkg.SessionManager
	validator  TokenValidator
	defaultTTL time.Duration

	eventSubsMu sync.RWMutex
	eventSubs   map[string][]chan SessionEvent
}

// NewService creates a new Auth service.
func NewService(sessionMgr *srvpkg.SessionManager, validator TokenValidator, defaultTTL time.Duration) *Service {
	if validator == nil {
		validator = AllowAllValidator{}
	}
	if defaultTTL <= 0 {
		defaultTTL = time.Hour
	}
	return &Service{
		sessions:   sessionMgr,
		validator:  validator,
		defaultTTL: defaultTTL,
		eventSubs:  make(map[string][]chan SessionEvent),
	}
}

// OpenSession creates or resumes a session and returns derived key material.
func (s *Service) OpenSession(ctx context.Context, req SessionOpenRequest) (*SessionOpenResponse, error) {
	if err := s.validator.Validate(ctx, req.Token, req.ClientID); err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Generate new session ID regardless of existing sessions to avoid collisions.
	var idBuf [4]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return nil, fmt.Errorf("session id entropy failed: %w", err)
	}
	sessionIDUint := binary.BigEndian.Uint32(idBuf[:])
	if sessionIDUint == 0 {
		sessionIDUint = 1
	}

	session := s.sessions.GetOrCreateSession(sessionIDUint)
	if session == nil {
		return nil, ErrSessionLimitReached
	}

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("seed entropy failed: %w", err)
	}

	sendKeys, recvKeys, err := aeadpkg.DeriveDirectionalKeys(seed, false /* server perspective */)
	if err != nil {
		return nil, fmt.Errorf("derive keys failed: %w", err)
	}
	aeadState, err := aeadpkg.NewAEADState(sendKeys, recvKeys)
	if err != nil {
		return nil, fmt.Errorf("aead init failed: %w", err)
	}

	s.sessions.UpdateSession(sessionIDUint, nil, aeadState, seed)

	// ОПТИМИЗАЦИЯ: Используем кэшированное время
	timeCache := util.GetGlobalTimeCache()
	now := timeCache.Now()
	expiry := now.Add(s.defaultTTL)
	session.Mu.Lock()
	session.SeqSend = 1
	session.LastActivity = now
	session.Mu.Unlock()

	resp := &SessionOpenResponse{
		SessionID:  hex.EncodeToString(idBuf[:]),
		AEADKey:    sendKeys.Key,
		Seed:       seed,
		InitialSeq: 1,
		ExpiresAt:  expiry,
	}

	s.publishEvent(SessionEvent{
		Type:      SessionEventTypeResume,
		SessionID: resp.SessionID,
		Seq:       resp.InitialSeq,
		Timestamp: time.Now(),
		AEADKey:   resp.AEADKey,
	})

	return resp, nil
}

// RefreshSession extends TTL or triggers rekey.
func (s *Service) RefreshSession(ctx context.Context, req SessionRefreshRequest) (*SessionRefreshResponse, error) {
	if req.SessionID == "" {
		return nil, errors.New("session id required")
	}
	sessionUint, err := parseSessionID(req.SessionID)
	if err != nil {
		return nil, err
	}
	session := s.sessions.GetSession(sessionUint)
	if session == nil {
		return nil, fmt.Errorf("session %s not found", req.SessionID)
	}

	resp := &SessionRefreshResponse{
		Renewed:   true,
		ExpiresAt: time.Now().Add(s.defaultTTL),
		NewSeq:    session.SeqSend,
	}

	if req.ForceRekey {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("seed entropy failed: %w", err)
		}
		sendKeys, recvKeys, err := aeadpkg.DeriveDirectionalKeys(seed, false)
		if err != nil {
			return nil, fmt.Errorf("derive keys failed: %w", err)
		}
		aeadState, err := aeadpkg.NewAEADState(sendKeys, recvKeys)
		if err != nil {
			return nil, fmt.Errorf("aead init failed: %w", err)
		}
		s.sessions.UpdateSession(sessionUint, nil, aeadState, seed)
		resp.NewAEADKey = sendKeys.Key
		resp.NewSeq = 1

		s.publishEvent(SessionEvent{
			Type:      SessionEventTypeRekey,
			SessionID: req.SessionID,
			Seq:       resp.NewSeq,
			Timestamp: time.Now(),
			AEADKey:   resp.NewAEADKey,
		})
	}

	return resp, nil
}

// CloseSession terminates session state.
func (s *Service) CloseSession(ctx context.Context, req SessionCloseRequest) (*SessionCloseResponse, error) {
	if req.SessionID == "" {
		return nil, errors.New("session id required")
	}
	sessionUint, err := parseSessionID(req.SessionID)
	if err != nil {
		return nil, err
	}

	s.sessions.RemoveSession(sessionUint)

	s.publishEvent(SessionEvent{
		Type:      SessionEventTypeRevoke,
		SessionID: req.SessionID,
		Timestamp: time.Now(),
		Reason:    req.Reason,
	})

	return &SessionCloseResponse{Closed: true}, nil
}

// SubscribeSessionEvents registers listener for session events.
func (s *Service) SubscribeSessionEvents(sessionID string) (<-chan SessionEvent, func()) {
	ch := make(chan SessionEvent, 16)
	s.eventSubsMu.Lock()
	s.eventSubs[sessionID] = append(s.eventSubs[sessionID], ch)
	s.eventSubsMu.Unlock()

	cancel := func() {
		s.eventSubsMu.Lock()
		subs := s.eventSubs[sessionID]
		out := make([]chan SessionEvent, 0, len(subs))
		for _, c := range subs {
			if c != ch {
				out = append(out, c)
			}
		}
		if len(out) == 0 {
			delete(s.eventSubs, sessionID)
		} else {
			s.eventSubs[sessionID] = out
		}
		s.eventSubsMu.Unlock()
		close(ch)
	}
	return ch, cancel
}

// AttachClientAddress associates resolved remote address with session.
func (s *Service) AttachClientAddress(sessionHex string, addr *net.UDPAddr) error {
	if sessionHex == "" || addr == nil {
		return nil
	}
	sessionUint, err := parseSessionID(sessionHex)
	if err != nil {
		return err
	}
	session := s.sessions.GetSession(sessionUint)
	if session == nil {
		return fmt.Errorf("session %s not found", sessionHex)
	}
	s.sessions.UpdateSession(sessionUint, addr, session.AEADState, session.Seed)
	return nil
}

func (s *Service) publishEvent(event SessionEvent) {
	s.eventSubsMu.RLock()
	defer s.eventSubsMu.RUnlock()

	subs := s.eventSubs[event.SessionID]
	for _, ch := range subs {
		select {
		case ch <- event:
		default:
			// drop if subscriber is slow
		}
	}
}

func parseSessionID(hexID string) (uint32, error) {
	if len(hexID) != 8 {
		return 0, fmt.Errorf("invalid session id length: %q", hexID)
	}
	raw, err := hex.DecodeString(hexID)
	if err != nil {
		return 0, fmt.Errorf("invalid session id: %w", err)
	}
	return binary.BigEndian.Uint32(raw), nil
}
