package rekey

import (
	"crypto/sha256"
	"io"

	cryptopkg "whispera/internal/crypto"

	"golang.org/x/crypto/hkdf"
)

// DeriveRekey material from current seed and a 32-byte salt
func DeriveRekey(current, salt []byte, isClient bool) (send, recv cryptopkg.DirectionalKeys, err error) {
	info := []byte("whispera v1 rekey")
	r := hkdf.New(sha256.New, current, salt, info)
	buf := make([]byte, 72)
	if _, err = io.ReadFull(r, buf); err != nil {
		return
	}
	aKey := buf[0:32]
	aSalt := buf[32:36]
	bKey := buf[36:68]
	bSalt := buf[68:72]
	if isClient {
		copy(send.Salt4[:], aSalt)
		send.Key = append([]byte(nil), aKey...)
		copy(recv.Salt4[:], bSalt)
		recv.Key = append([]byte(nil), bKey...)
	} else {
		copy(send.Salt4[:], bSalt)
		send.Key = append([]byte(nil), bKey...)
		copy(recv.Salt4[:], aSalt)
		recv.Key = append([]byte(nil), aKey...)
	}
	return
}
