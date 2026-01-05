package proto

// Re-exports from internal subpackages for convenience
// This allows code to use proto.StreamCommand instead of multi.StreamCommand

import (
	"whispera/internal/proto/headers"
	"whispera/internal/proto/multi"
)

// Re-export from headers
type PacketHeader = headers.PacketHeader

const (
	Version     = headers.Version
	HeaderLen   = headers.HeaderLen
	FlagControl = headers.FlagControl

	Version2      = headers.Version2
	FlagControlV2 = headers.FlagControlV2
	FlagStreamV2  = headers.FlagStreamV2
	FlagObfsPadV2 = headers.FlagObfsPadV2
)

// PutHeaderBuffer returns buffer to pool
var PutHeaderBuffer = headers.PutHeaderBuffer

// Re-export from multi
type StreamCommand = multi.StreamCommand
type StreamMultiplexer = multi.StreamMultiplexer

const (
	StreamOpen         = multi.StreamOpen
	StreamData         = multi.StreamData
	StreamClose        = multi.StreamClose
	StreamOpenDomain   = multi.StreamOpenDomain
	StreamWindowUpdate = multi.StreamWindowUpdate
	TunStreamID        = multi.TunStreamID
	DefaultWindowSize  = multi.DefaultWindowSize
)

// NewStreamMultiplexer creates a new stream multiplexer
var NewStreamMultiplexer = multi.NewStreamMultiplexer

// EncodeStreamControlFrame encodes a stream control frame
var EncodeStreamControlFrame = multi.EncodeStreamControlFrame

// EncodeStreamWindowUpdate encodes a window update
var EncodeStreamWindowUpdate = multi.EncodeStreamWindowUpdate

// DecodeStreamWindowUpdate decodes a window update
var DecodeStreamWindowUpdate = multi.DecodeStreamWindowUpdate
