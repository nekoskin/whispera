package util

import (
	"encoding/hex"
	"errors"
)

func DecodeHexKey(s string, wantLen int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != wantLen {
		return nil, errors.New("invalid key length")
	}
	return b, nil
}
