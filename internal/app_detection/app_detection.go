package app_detection

import (
	"sync"
	"time"
)


type AppDetector struct {
	mu           sync.RWMutex
	runningApps  map[string]bool
	scanInterval time.Duration
	stopChan     chan struct{}
	scanning     bool
}


func NewAppDetector() *AppDetector {
	return &AppDetector{
		runningApps:  make(map[string]bool),
		scanInterval: 5 * time.Second,
		stopChan:     make(chan struct{}),
	}
}


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


func (ad *AppDetector) StopScanning() {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	if ad.scanning {
		close(ad.stopChan)
		ad.scanning = false
	}
}


func (ad *AppDetector) scan() {
	
}


func (ad *AppDetector) IsProcessRunning(name string) bool {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return ad.runningApps[name]
}


func (ad *AppDetector) GetExecutableList() []string {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	apps := make([]string, 0, len(ad.runningApps))
	for name := range ad.runningApps {
		apps = append(apps, name)
	}
	return apps
}


func (ad *AppDetector) GetPopularApplications() []string {
	return []string{
		"chrome.exe",
		"firefox.exe",
		"Telegram.exe",
		"Discord.exe",
		"Spotify.exe",
	}
}


func (ad *AppDetector) GetSystemApplications() []string {
	return []string{
		"svchost.exe",
		"explorer.exe",
		"System",
	}
}


func (ad *AppDetector) SuggestAppRules() []string {
	return ad.GetPopularApplications()
}
func (ad *AppDetector) ValidateAppRule(ruleValue string) error {
	return nil
}
