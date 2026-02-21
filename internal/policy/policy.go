package policy

import (
	"sync"
	"time"
)

type Policy struct {
	MaxUploadSpeed   int64
	MaxDownloadSpeed int64
	MaxUploadBytes   int64
	MaxDownloadBytes int64

	MaxConnections      int
	MaxConnectionsPerIP int

	AllowedHours []TimeRange
	AllowedDays  []time.Weekday

	ExpiresAt *time.Time

	mu sync.RWMutex
}

type TimeRange struct {
	Start time.Time
	End   time.Time
}

type PolicyManager struct {
	policies map[string]*Policy
	mu       sync.RWMutex
}

func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		policies: make(map[string]*Policy),
	}
}

func (pm *PolicyManager) SetPolicy(userID string, policy *Policy) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.policies[userID] = policy
}

func (pm *PolicyManager) GetPolicy(userID string) *Policy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.policies[userID]
}

func (pm *PolicyManager) RemovePolicy(userID string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.policies, userID)
}

func (p *Policy) CheckBandwidthLimit(uploadBytes, downloadBytes int64) (uploadAllowed, downloadAllowed bool, uploadRemaining, downloadRemaining int64) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.MaxUploadBytes > 0 {
		if uploadBytes >= p.MaxUploadBytes {
			return false, true, 0, p.MaxDownloadBytes - downloadBytes
		}
		uploadRemaining = p.MaxUploadBytes - uploadBytes
	} else {
		uploadRemaining = -1
	}

	if p.MaxDownloadBytes > 0 {
		if downloadBytes >= p.MaxDownloadBytes {
			return true, false, uploadRemaining, 0
		}
		downloadRemaining = p.MaxDownloadBytes - downloadBytes
	} else {
		downloadRemaining = -1
	}

	uploadAllowed = true
	downloadAllowed = true

	return
}

func (p *Policy) CheckTimeBasedPolicy(now time.Time) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.ExpiresAt != nil && now.After(*p.ExpiresAt) {
		return false
	}

	if len(p.AllowedDays) > 0 {
		allowed := false
		for _, day := range p.AllowedDays {
			if now.Weekday() == day {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	if len(p.AllowedHours) > 0 {
		currentTime := time.Date(0, 1, 1, now.Hour(), now.Minute(), now.Second(), 0, time.UTC)
		allowed := false
		for _, tr := range p.AllowedHours {
			startTime := time.Date(0, 1, 1, tr.Start.Hour(), tr.Start.Minute(), tr.Start.Second(), 0, time.UTC)
			endTime := time.Date(0, 1, 1, tr.End.Hour(), tr.End.Minute(), tr.End.Second(), 0, time.UTC)

			if startTime.Before(endTime) {
				if currentTime.After(startTime) && currentTime.Before(endTime) {
					allowed = true
					break
				}
			} else {
				if currentTime.After(startTime) || currentTime.Before(endTime) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			return false
		}
	}

	return true
}

func (p *Policy) CheckConnectionLimit(currentConnections int) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.MaxConnections > 0 && currentConnections >= p.MaxConnections {
		return false
	}

	return true
}

func NewPolicy() *Policy {
	return &Policy{
		MaxUploadSpeed:      0,
		MaxDownloadSpeed:    0,
		MaxUploadBytes:      0,
		MaxDownloadBytes:    0,
		MaxConnections:      0,
		MaxConnectionsPerIP: 0,
		AllowedHours:        nil,
		AllowedDays:         nil,
		ExpiresAt:           nil,
	}
}
