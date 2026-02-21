package tunnel

import (
	"io"
	"whispera/internal/core/interfaces"
)

type deobfuscatingReader struct {
	r   io.Reader
	obf interfaces.Obfuscator
}

func (dr *deobfuscatingReader) Read(p []byte) (int, error) {
	tempBuf := make([]byte, len(p))

	n, err := dr.r.Read(tempBuf)
	if n > 0 {
		res, _, derr := dr.obf.Process(tempBuf[:n], interfaces.DirectionInbound)
		if derr != nil {
			return 0, derr
		}
		copy(p, res)
		return len(res), err
	}
	return n, err
}
