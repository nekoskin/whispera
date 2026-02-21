package proto


import (
	"whispera/internal/proto/headers"
	"whispera/internal/proto/multi"
)

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

var PutHeaderBuffer = headers.PutHeaderBuffer

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

var NewStreamMultiplexer = multi.NewStreamMultiplexer

var EncodeStreamControlFrame = multi.EncodeStreamControlFrame

var EncodeStreamWindowUpdate = multi.EncodeStreamWindowUpdate

var DecodeStreamWindowUpdate = multi.DecodeStreamWindowUpdate
