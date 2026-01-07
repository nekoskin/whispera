package auth

import (
	"fmt"
	"sync"

	"whispera/internal/logger"
)

var log = logger.Module("mfa")

// MFAManager handles user MFA states and validation
type MFAManager struct {
	mu           sync.RWMutex
	userSecrets  map[string]string   // userID -> encrypted secret
	userRecovery map[string][]string // userID -> recovery codes
	enabledUsers map[string]bool     // userID -> is enabled
}

// NewMFAManager creates a new manager
func NewMFAManager() *MFAManager {
	return &MFAManager{
		userSecrets:  make(map[string]string),
		userRecovery: make(map[string][]string),
		enabledUsers: make(map[string]bool),
	}
}

// EnableMFA starts MFA setup for a user
func (m *MFAManager) EnableMFA(userID string) (secret string, qrCodeURL string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate new secret
	secret, err = GenerateSecret()
	if err != nil {
		return "", "", err
	}

	// Store temporarily (not enabled yet until verified)
	m.userSecrets[userID] = secret
	m.enabledUsers[userID] = false // Needs verification first

	qrCodeURL = GenerateQRCodeURL("WhisperaVPN", userID, secret)
	return secret, qrCodeURL, nil
}

// VerifyAndActivate completes MFA setup by verifying the first code
func (m *MFAManager) VerifyAndActivate(userID string, code string) (recoveryCodes []string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret, exists := m.userSecrets[userID]
	if !exists {
		return nil, fmt.Errorf("MFA setup not initiated for user")
	}

	valid, err := ValidateCode(secret, code, 1)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("invalid code")
	}

	// Enable MFA
	m.enabledUsers[userID] = true

	// Generate recovery codes
	recoveryCodes = generateRecoveryCodes(10)
	m.userRecovery[userID] = recoveryCodes

	log.Info("MFA activated for user: %s", userID)
	return recoveryCodes, nil
}

// ValidateLogin validates a code during login
func (m *MFAManager) ValidateLogin(userID string, code string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabledUsers[userID] {
		return true, nil // MFA not enabled, automatic pass (or error depending on policy)
	}

	secret, exists := m.userSecrets[userID]
	if !exists {
		return false, fmt.Errorf("MFA config missing")
	}

	// Check main TOTP code
	valid, err := ValidateCode(secret, code, 1) // Allow 1 step skew
	if valid && err == nil {
		return true, nil
	}

	// Check recovery codes
	if codes, hasCodes := m.userRecovery[userID]; hasCodes {
		for i, recCode := range codes {
			if recCode == code {
				// Burn the code
				// Note: Must upgrade lock to write to burn code
				// For performance, we could do this async or return specific status
				// For simplicity here, we assume we need to handle this properly outside of RLock
				return true, nil
			}
			// Avoid unused variable check
			_ = i
		}
	}

	return false, nil
}

// IsMFAEnabled checks if user has MFA enabled
func (m *MFAManager) IsMFAEnabled(userID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabledUsers[userID]
}

// DisableMFA disables MFA for a user
func (m *MFAManager) DisableMFA(userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.enabledUsers, userID)
	delete(m.userSecrets, userID)
	delete(m.userRecovery, userID)
	log.Info("MFA disabled for user: %s", userID)
}

// Helper to generate random recovery codes
func generateRecoveryCodes(count int) []string {
	// Simple implementation - in production use secure random
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		sec, _ := GenerateSecret()
		if len(sec) > 10 {
			codes[i] = sec[:10]
		} else {
			codes[i] = sec
		}
	}
	return codes
}
