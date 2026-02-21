package containers

import "errors"

type ContainerType int

const (
	FormatMPEGTS ContainerType = iota
	FormatFMP4
	FormatWebM
	FormatFLV
	FormatAVI
	FormatWMV
)

var (
	ErrInvalidFormat  = errors.New("invalid container format")
	ErrBufferTooSmall = errors.New("destination buffer too small")
)

type ContainerWrapper interface {
	GetInitSegment() ([]byte, error)

	WrapData(data []byte) ([]byte, error)

	UnwrapData(data []byte) ([]byte, error)

	ContentType() string
}
