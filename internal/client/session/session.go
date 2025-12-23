package session

import (
	"sync/atomic"

	aeadpkg "whispera/internal/crypto"
	"whispera/internal/proto"
)

// SessionCtx инкапсулирует общее состояние сессии клиента:
//   - один SessionID для всех транспортов;
//   - один AEADState (Noise/PSK) для всех туннелей;
//   - единый глобальный счётчик SeqSend, используемый всеми транспортами.
//
// Это позволяет прозрачно мигрировать между UDP/TCP/WS/WS2, сохраняя
// согласованный порядок пакетов и единое sliding-окно для приёма.
type SessionCtx struct {
	// Immutable after handshake
	SessionID uint32
	AEAD      *aeadpkg.AEADState

	// Global send sequence number shared across all transports.
	// MUST be incremented атомарно через atomic.AddUint32.
	SeqSend uint32

	// Per-session receive window and reassembler.
	RecvWin *aeadpkg.SlidingWindow
	Reasm   *proto.Reassembler
}

// NextSeq атомарно увеличивает глобальный счётчик и возвращает новое значение.
func (s *SessionCtx) NextSeq() uint32 {
	if s == nil {
		return 0
	}
	return atomic.AddUint32(&s.SeqSend, 1)
}

