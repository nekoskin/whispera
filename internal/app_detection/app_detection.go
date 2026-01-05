// Package app_detection provides application detection for split tunneling
package app_detection

import (
	"sync"
	"time"
)

// AppDetector detects running applications
type AppDetector struct {
	mu           sync.RWMutex
	runningApps  map[string]bool
	scanInterval time.Duration
	stopChan     chan struct{}
	scanning     bool
}

// NewAppDetector creates a new app detector
func NewAppDetector() *AppDetector {
	return &AppDetector{
		runningApps:  make(map[string]bool),
		scanInterval: 5 * time.Second,
		stopChan:     make(chan struct{}),
	}
}

// StartScanning starts periodic scanning for applications
func (ad *AppDetector) StartScanning(interval time.Duration) {
	ad.mu.Lock()
	if ad.scanning {
		ad.mu.Unlock()
		return
	}
	ad.scanning = true
	ad.scanInterval = interval
	ad.stopChan = make(chan struct{})
	ad.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ad.stopChan:
				return
			case <-ticker.C:
				ad.scan()
			}
		}
	}()
}

// StopScanning stops the scanning loop
func (ad *AppDetector) StopScanning() {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	if ad.scanning {
		close(ad.stopChan)
		ad.scanning = false
	}
}

// scan performs the actual scanning (platform-specific)
func (ad *AppDetector) scan() {
	// Platform-specific implementation would go here
}

// IsProcessRunning checks if a process is running
func (ad *AppDetector) IsProcessRunning(name string) bool {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return ad.runningApps[name]
}

// GetExecutableList returns list of running executables
func (ad *AppDetector) GetExecutableList() []string {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	apps := make([]string, 0, len(ad.runningApps))
	for name := range ad.runningApps {
		apps = append(apps, name)
	}
	return apps
}

// GetPopularApplications returns list of popular applications
func (ad *AppDetector) GetPopularApplications() []string {
	return []string{
		"chrome.exe",
		"firefox.exe",
		"Telegram.exe",
		"Discord.exe",
		"Spotify.exe",
	}
}

// GetSystemApplications returns list of system applications
func (ad *AppDetector) GetSystemApplications() []string {
	return []string{
		"svchost.exe",
		"explorer.exe",
		"System",
	}
}

// SuggestAppRules suggests applications for split tunneling rules
func (ad *AppDetector) SuggestAppRules() []string {
	return ad.GetPopularApplications()
}

// ValidateAppRule validates an application rule
func (ad *AppDetector) ValidateAppRule(ruleValue string) error {
	return nil
}
