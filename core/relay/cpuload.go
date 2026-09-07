package relay

import (
	"runtime"
	"sync"
	"time"
)

const cpuBusyShare = 0.5

var cpuLoad struct {
	mu    sync.Mutex
	time  time.Time
	spent time.Duration
	busy  bool
}

func cpuBusy() bool {
	now := time.Now()

	cpuLoad.mu.Lock()
	defer cpuLoad.mu.Unlock()

	if !cpuLoad.time.IsZero() && now.Sub(cpuLoad.time) < time.Second {
		return cpuLoad.busy
	}

	spent := processCPU()
	if spent == 0 {
		return false
	}
	if !cpuLoad.time.IsZero() {
		wall := now.Sub(cpuLoad.time)
		cores := float64(runtime.GOMAXPROCS(0))
		cpuLoad.busy = float64(spent-cpuLoad.spent)/float64(wall)/cores >= cpuBusyShare
	}
	cpuLoad.time, cpuLoad.spent = now, spent
	return cpuLoad.busy
}
