package protocol

import (
	"crypto/sha256"
	"io"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/crypto/hkdf"
)

type Keys struct {
	Auth []byte
}

var deriveKeysCache = func() *lru.Cache[[32]byte, *Keys] {
	l, _ := lru.New[[32]byte, *Keys](1024)
	return l
}()

func DeriveKeys(sharedSecret []byte) *Keys {
	cacheKey := sha256.Sum256(sharedSecret)
	if v, ok := deriveKeysCache.Get(cacheKey); ok {
		return v
	}

	derive := func(info string) []byte {
		h := hkdf.New(sha256.New, sharedSecret, nil, []byte(info))
		d := make([]byte, 32)
		if _, err := io.ReadFull(h, d); err != nil {
			panic("whispera hkdf: " + err.Error())
		}
		return d
	}

	keys := &Keys{Auth: derive("whispera-auth-v1")}
	deriveKeysCache.Add(cacheKey, keys)
	return keys
}
