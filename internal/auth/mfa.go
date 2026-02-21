package auth

import (
	"fmt"
	"sync"

	"whispera/internal/logger"
)

var log = logger.Module("mfa")


type MFAManager struct {
	mu           sync.RWMutex
	userSecrets  map[string]string   
	userRecovery map[string][]string 
	enabledUsers map[string]bool     
}


func NewMFAManager() *MFAManager {
	return &MFAManager{
		userSecrets:  make(map[string]string),
		userRecovery: make(map[string][]string),
		enabledUsers: make(map[string]bool),
	}
}


func (m *MFAManager) EnableMFA(userID string) (secret string, qrCodeURL string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	
	secret, err = GenerateSecret()
	if err != nil {
		return "", "", err
	}

	
	m.userSecrets[userID] = secret
	m.enabledUsers[userID] = false 

	qrCodeURL = GenerateQRCodeURL("WhisperaVPN", userID, secret)
	return secret, qrCodeURL, nil
}


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

	
	m.enabledUsers[userID] = true

	
	recoveryCodes = generateRecoveryCodes(10)
	m.userRecovery[userID] = recoveryCodes

	log.Info("MFA activated for user: %s", userID)
	return recoveryCodes, nil
}


func (m *MFAManager) ValidateLogin(userID string, code string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabledUsers[userID] {
		return true, nil 
	}

	secret, exists := m.userSecrets[userID]
	if !exists {
		return false, fmt.Errorf("MFA config missing")
	}

	
	valid, err := ValidateCode(secret, code, 1) 
	if valid && err == nil {
		return true, nil
	}

	
	if codes, hasCodes := m.userRecovery[userID]; hasCodes {
		for i, recCode := range codes {
			if recCode == code {
				
				
				
				return true, nil
			}
			
			_ = i
		}
	}

	return false, nil
}


func (m *MFAManager) IsMFAEnabled(userID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabledUsers[userID]
}
func (m *MFAManager) DisableMFA(userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.enabledUsers, userID)
	delete(m.userSecrets, userID)
	delete(m.userRecovery, userID)
	log.Info("MFA disabled for user: %s", userID)
}


func generateRecoveryCodes(count int) []string {
	
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
