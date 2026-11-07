package main

import (
	"net"
	"sync"
	"testing"
)

func resetConnLimiter() {
	connLimiterPerIP = make(map[string]int)
}

func TestAcquireConnSlotHonoursCap(t *testing.T) {
	resetConnLimiter()
	addr := &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 1}

	var mu sync.Mutex
	var granted []func()
	var wg sync.WaitGroup
	for range maxTCPConnsPerIP * 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, ok := acquireConnSlot(addr)
			if !ok {
				return
			}
			mu.Lock()
			granted = append(granted, release)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(granted) != maxTCPConnsPerIP {
		t.Fatalf("granted %d slots, cap is %d", len(granted), maxTCPConnsPerIP)
	}
	for _, release := range granted {
		release()
	}
}
