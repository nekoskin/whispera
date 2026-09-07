package apiserver

import (
	"crypto/rand"
	"encoding/base64"
)

func randomBase64(n int) (string, error) {
	randomBase64 := make([]byte, n)
	if _, err := rand.Read(randomBase64); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(randomBase64), nil
}
