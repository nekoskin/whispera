package tunnel

import (
	"io"
	"whispera/internal/core/interfaces"
)

// DeobfuscatingReader wrapper
type deobfuscatingReader struct {
	r   io.Reader
	obf interfaces.Obfuscator
}

func (dr *deobfuscatingReader) Read(p []byte) (int, error) {
	// 1. Read raw data
	n, err := dr.r.Read(p)
	if n > 0 {
		// fmt.Printf("[DEBUG] DR: Read %d bytes from TCP\n", n)
		// 2. Deobfuscate in-place
		res, _, derr := dr.obf.Process(p[:n], interfaces.DirectionInbound)
		if derr != nil {
			// fmt.Printf("[ERROR] DR: Deobfuscation failed: %v\n", derr)
			return 0, derr
		}
		// fmt.Printf("[DEBUG] DR: Decrypted %d bytes\n", len(res))
		copy(p, res)
		return len(res), err
	}
	return n, err
}
