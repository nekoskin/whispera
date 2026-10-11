package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"
)

var serverNow = time.Now

const authTimeless int64 = 0

const helloReplayMemory = 2 * time.Hour

const authWindowSeconds = 30

const authWindowTolerance = 1

const clockDriftProbeWindows = 10

func AuthToken(authKey []byte, window int64, sessionID []byte) string {
	var wb [8]byte
	mac := hmac.New(sha256.New, authKey)
	binary.BigEndian.PutUint64(wb[:], uint64(window))
	mac.Write(wb[:])
	mac.Write(sessionID)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func ClientAuthToken(authKey, sessionID []byte) string {
	return AuthToken(authKey, time.Now().Unix()/authWindowSeconds, sessionID)
}

func VerifyAuthToken(authKey []byte, token string, sessionID []byte) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	return VerifyAuthTokenRaw(authKey, raw, sessionID)
}

func verifySessionToken(authKey []byte, token string, sessionID []byte) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	return verifySessionTokenRaw(authKey, raw, sessionID)
}

func verifySessionTokenRaw(authKey, raw, sessionID []byte) bool {
	return macMatches(authKey, authTimeless, sessionID, raw) || VerifyAuthTokenRaw(authKey, raw, sessionID)
}

func VerifyAuthTokenRaw(authKey, raw, sessionID []byte) bool {
	if len(raw) != 32 {
		return false
	}
	w := serverNow().Unix() / authWindowSeconds
	for candidate := w - authWindowTolerance; candidate <= w+authWindowTolerance; candidate++ {
		if macMatches(authKey, candidate, sessionID, raw) {
			return true
		}
	}
	return false
}

func macMatches(authKey []byte, window int64, sessionID, want []byte) bool {
	var wb [8]byte
	mac := hmac.New(sha256.New, authKey)
	binary.BigEndian.PutUint64(wb[:], uint64(window))
	mac.Write(wb[:])
	mac.Write(sessionID)
	return hmac.Equal(mac.Sum(nil), want)
}

func ProbeClockDrift(authKey []byte, token string, sessionID []byte) (driftWindows int64, found bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return 0, false
	}
	w := serverNow().Unix() / authWindowSeconds
	for offset := int64(authWindowTolerance + 1); offset <= clockDriftProbeWindows; offset++ {
		if macMatches(authKey, w+offset, sessionID, raw) {
			return offset, true
		}
		if macMatches(authKey, w-offset, sessionID, raw) {
			return -offset, true
		}
	}
	return 0, false
}
