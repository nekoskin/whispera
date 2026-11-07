package camo

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	SelectorSize = 8
	MarkerSize   = 32 - SelectorSize
)

func ServerKeyFromSeed(seed []byte) (*ecdh.PrivateKey, error) {
	h := hkdf.New(sha256.New, seed, nil, []byte("whispera-selector-x25519-v1"))
	raw := make([]byte, 32)
	if _, err := io.ReadFull(h, raw); err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

func UserTag(psk []byte) [SelectorSize]byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("whispera-uid-v1"))
	var out [SelectorSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func selectorMask(shared []byte) [SelectorSize]byte {
	sum := sha256.Sum256(append([]byte("whispera-sel-v1"), shared...))
	var out [SelectorSize]byte
	copy(out[:], sum[:])
	return out
}

func xorTag(a, b [SelectorSize]byte) [SelectorSize]byte {
	var out [SelectorSize]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func BuildSelector(psk []byte, ephPriv *ecdh.PrivateKey, serverPub *ecdh.PublicKey) ([SelectorSize]byte, error) {
	var out [SelectorSize]byte
	shared, err := ephPriv.ECDH(serverPub)
	if err != nil {
		return out, err
	}
	return xorTag(UserTag(psk), selectorMask(shared)), nil
}

func OpenSelector(selector [SelectorSize]byte, serverPriv *ecdh.PrivateKey, keyShare []byte) ([SelectorSize]byte, error) {
	var out [SelectorSize]byte
	peer, err := ecdh.X25519().NewPublicKey(keyShare)
	if err != nil {
		return out, err
	}
	shared, err := serverPriv.ECDH(peer)
	if err != nil {
		return out, err
	}
	return xorTag(selector, selectorMask(shared)), nil
}

func markerFor(key []byte, window int64, keyShare []byte) [MarkerSize]byte {
	var out [MarkerSize]byte
	mac := hmac.New(sha256.New, key)
	var wb [8]byte
	binary.BigEndian.PutUint64(wb[:], uint64(window))
	mac.Write(wb[:])
	mac.Write(keyShare)
	copy(out[:], mac.Sum(nil))
	return out
}

const stampTimeBytes = 4

func stampMask(key, keyShare []byte) [stampTimeBytes]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("whispera-stamp-mask-v1"))
	mac.Write(keyShare)
	var out [stampTimeBytes]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func stampInto(dst, key, keyShare []byte, unix int64) {
	binary.BigEndian.PutUint32(dst[:stampTimeBytes], uint32(unix))
	mask := stampMask(key, keyShare)
	for i := 0; i < stampTimeBytes; i++ {
		dst[i] ^= mask[i]
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("whispera-stamp-mac-v1"))
	mac.Write(dst[:stampTimeBytes])
	mac.Write(keyShare)
	copy(dst[stampTimeBytes:], mac.Sum(nil))
}

func sealStamp(key, keyShare []byte, unix int64) [MarkerSize]byte {
	var out [MarkerSize]byte
	stampInto(out[:], key, keyShare, unix)
	return out
}

func openStamp(key, keyShare, marker []byte) (int64, bool) {
	macLen := len(marker) - stampTimeBytes
	if macLen <= 0 || macLen > sha256.Size {
		return 0, false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("whispera-stamp-mac-v1"))
	mac.Write(marker[:stampTimeBytes])
	mac.Write(keyShare)
	if !hmac.Equal(marker[stampTimeBytes:], mac.Sum(nil)[:macLen]) {
		return 0, false
	}
	mask := stampMask(key, keyShare)
	var t [stampTimeBytes]byte
	copy(t[:], marker[:stampTimeBytes])
	for i := 0; i < stampTimeBytes; i++ {
		t[i] ^= mask[i]
	}
	return int64(binary.BigEndian.Uint32(t[:])), true
}

func WriteRandomStamp(random []byte, sel [SelectorSize]byte, key, keyShare []byte, unix int64) bool {
	if len(random) != 32 {
		return false
	}
	marker := sealStamp(key, keyShare, unix)
	copy(random[:SelectorSize], sel[:])
	copy(random[SelectorSize:], marker[:])
	return true
}

func SplitRandom(random []byte) (sel [SelectorSize]byte, marker []byte, ok bool) {
	if len(random) != 32 {
		return sel, nil, false
	}
	copy(sel[:], random[:SelectorSize])
	return sel, random[SelectorSize:], true
}

func MarkerMatchesKey(key, marker, keyShare []byte, now int64) bool {
	if len(marker) != MarkerSize || len(key) == 0 || len(keyShare) == 0 {
		return false
	}

	if _, ok := openStamp(key, keyShare, marker); ok {
		return true
	}

	w := now / WindowSeconds
	for cand := w - WindowTol; cand <= w+WindowTol; cand++ {
		m := markerFor(key, cand, keyShare)
		if hmac.Equal(m[:], marker) {
			return true
		}
	}
	return false
}
