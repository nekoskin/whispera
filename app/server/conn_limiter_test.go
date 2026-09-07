package main

import (
	"net"
	"sync"
	"testing"
)

func resetConnLimiter() {
	connLimiterPerIP = make(map[string]int)
}

func TestAcquireConnSlotConcurrent(t *testing.T) {
	resetConnLimiter()
	addr := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 1}

	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if release, ok := acquireConnSlot(addr); ok {
				release()
			}
		}()
	}
	wg.Wait()

	left := connLimiterPerIP["203.0.113.7"]
	if left != 0 {
		t.Fatalf("counter is %d after every slot was released, want 0", left)
	}
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
