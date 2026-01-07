// Package auth provides authentication and TOTP functionality
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TOTP implementation based on RFC 6238

// GenerateSecret generates a new random secret key for TOTP
func GenerateSecret() (string, error) {
	randomBytes := make([]byte, 20) // 160 bits
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes), nil
}

// GenerateQRCodeURL generates a Google Authenticator compatible URL
func GenerateQRCodeURL(issuer, user, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		issuer, user, secret, issuer)
}

// ValidateCode validates a TOTP code against a secret
// skew allows validation of codes from adjacent time windows (1 step = 30s)
func ValidateCode(secret, code string, skew int) (bool, error) {
	// Clean secret (remove spaces/dashes)
	secret = strings.TrimSpace(strings.ToUpper(secret))
	secret = strings.ReplaceAll(secret, " ", "")
	secret = strings.ReplaceAll(secret, "-", "")

	// Decode secret
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		// Try with standard padding if no-padding fails
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return false, fmt.Errorf("invalid secret format: %v", err)
		}
	}

	// Current time step
	now := time.Now().Unix()
	step := int64(30)
	currentInterval := now / step

	// Check window
	for i := -skew; i <= skew; i++ {
		interval := currentInterval + int64(i)
		generatedCode := generateTOTP(key, interval)
		if generatedCode == code {
			return true, nil
		}
	}

	return false, nil
}

// generateTOTP generates a code for a specific time interval
func generateTOTP(key []byte, interval int64) string {
	// Interval as 8-byte big-endian
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(interval))

	// HMAC-SHA1
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// Dynamic truncation
	offset := sum[len(sum)-1] & 0x0f
	codeInt := binary.BigEndian.Uint32(sum[offset : offset+4])
	codeInt &= 0x7fffffff
	codeInt %= 1000000 // 6 digits

	return fmt.Sprintf("%06d", codeInt)
}
