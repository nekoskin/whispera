package behavioral

import (
	"crypto/rand"
	"sync"
	"sync/atomic"
	"time"
)

type CoverTrafficGenerator struct {
	profile  *MessengerProfile
	engine   *BehaviorEngine
	mu       sync.RWMutex
	running  atomic.Bool
	stopCh   chan struct{}
	packetCh chan CoverPacket

	stats CoverStats
}

type CoverPacket struct {
	Data      []byte
	Size      int
	Delay     time.Duration
	Direction string
	Purpose   string
}

type CoverStats struct {
	PacketsGenerated uint64
	BytesGenerated   uint64
	HeartbeatsSent   uint64
	CoverSent        uint64
}

func NewCoverTrafficGenerator(profile *MessengerProfile) *CoverTrafficGenerator {
	return &CoverTrafficGenerator{
		profile:  profile,
		engine:   NewBehaviorEngine(profile),
		stopCh:   make(chan struct{}),
		packetCh: make(chan CoverPacket, 100),
	}
}

func (g *CoverTrafficGenerator) Start() {
	if g.running.Swap(true) {
		return
	}

	go g.generateLoop()
	go g.heartbeatLoop()
	go g.backgroundConnectionsLoop()
}

func (g *CoverTrafficGenerator) Stop() {
	if !g.running.Swap(false) {
		return
	}
	close(g.stopCh)
}

func (g *CoverTrafficGenerator) GetPacketChannel() <-chan CoverPacket {
	return g.packetCh
}

func (g *CoverTrafficGenerator) GetStats() CoverStats {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.stats
}

func (g *CoverTrafficGenerator) generateLoop() {
	for {
		select {
		case <-g.stopCh:
			return
		default:
		}

		delay := g.engine.NextPacketDelay()

		select {
		case <-g.stopCh:
			return
		case <-time.After(delay):
			state := g.engine.GetCurrentState()
			if g.shouldGenerateCover(state) {
				packet := g.generateCoverPacket()
				g.sendPacket(packet)
			}

			g.engine.TransitionState()
		}
	}
}

func (g *CoverTrafficGenerator) heartbeatLoop() {
	g.mu.RLock()
	hbConfig := g.profile.Application.Heartbeat
	g.mu.RUnlock()

	interval := hbConfig.BackgroundInterval
	jitterRange := float64(interval) * hbConfig.BackgroundJitter

	for {
		jitter := time.Duration(sampleUniform(-jitterRange, jitterRange))
		actualInterval := interval + jitter
		if actualInterval < time.Second {
			actualInterval = time.Second
		}

		select {
		case <-g.stopCh:
			return
		case <-time.After(actualInterval):
			packet := g.generateHeartbeatPacket()
			g.sendPacket(packet)

			g.mu.Lock()
			g.stats.HeartbeatsSent++
			g.mu.Unlock()
		}
	}
}

func (g *CoverTrafficGenerator) backgroundConnectionsLoop() {
	g.mu.RLock()
	bgConfig := g.profile.Context.Background
	g.mu.RUnlock()

	for _, conn := range bgConfig.Connections {
		go g.simulateBackgroundConnection(conn)
	}

	<-g.stopCh
}

func (g *CoverTrafficGenerator) simulateBackgroundConnection(conn BackgroundConnection) {
	for {
		select {
		case <-g.stopCh:
			return
		case <-time.After(conn.Interval):
			size := int(conn.Size.Sample())
			if size < 16 {
				size = 16
			}

			packet := CoverPacket{
				Data:      g.generateRandomData(size),
				Size:      size,
				Delay:     0,
				Direction: "outbound",
				Purpose:   conn.Purpose,
			}
			g.sendPacket(packet)
		}
	}
}

func (g *CoverTrafficGenerator) shouldGenerateCover(state string) bool {
	switch state {
	case "idle":
		return sampleUniform(0, 1) < 0.30
	case "typing":
		return sampleUniform(0, 1) < 0.10
	case "receiving":
		return sampleUniform(0, 1) < 0.20
	default:
		return sampleUniform(0, 1) < 0.05
	}
}

func (g *CoverTrafficGenerator) generateCoverPacket() CoverPacket {
	size := g.engine.NextPacketSize()
	if size < 16 {
		size = 16
	}
	if size > 4096 {
		size = 4096
	}

	return CoverPacket{
		Data:      g.generateRandomData(size),
		Size:      size,
		Delay:     0,
		Direction: "outbound",
		Purpose:   "cover",
	}
}

func (g *CoverTrafficGenerator) generateHeartbeatPacket() CoverPacket {
	size := 32 + int(sampleUniform(0, 32))

	return CoverPacket{
		Data:      g.generateRandomData(size),
		Size:      size,
		Delay:     0,
		Direction: "outbound",
		Purpose:   "heartbeat",
	}
}

func (g *CoverTrafficGenerator) generateRandomData(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

func (g *CoverTrafficGenerator) sendPacket(packet CoverPacket) {
	select {
	case g.packetCh <- packet:
		g.mu.Lock()
		g.stats.PacketsGenerated++
		g.stats.BytesGenerated += uint64(packet.Size)
		if packet.Purpose == "cover" {
			g.stats.CoverSent++
		}
		g.mu.Unlock()
	default:
	}
}


type DailyPatternGenerator struct {
	*CoverTrafficGenerator
	hourlyMultiplier float64
}

func NewDailyPatternGenerator(profile *MessengerProfile) *DailyPatternGenerator {
	return &DailyPatternGenerator{
		CoverTrafficGenerator: NewCoverTrafficGenerator(profile),
		hourlyMultiplier:      1.0,
	}
}

func (g *DailyPatternGenerator) Start() {
	g.CoverTrafficGenerator.Start()
	go g.updateHourlyMultiplierLoop()
}

func (g *DailyPatternGenerator) updateHourlyMultiplierLoop() {
	for {
		select {
		case <-g.stopCh:
			return
		case <-time.After(time.Minute):
			hour := time.Now().Hour()

			g.mu.Lock()
			g.hourlyMultiplier = g.profile.Timing.DailyPattern.HourlyActivity[hour]

			weekday := time.Now().Weekday()
			if weekday == time.Saturday || weekday == time.Sunday {
				g.hourlyMultiplier *= g.profile.Timing.DailyPattern.WeekendModifier
			}
			g.mu.Unlock()
		}
	}
}

func (g *DailyPatternGenerator) GetActivityMultiplier() float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.hourlyMultiplier
}


type AdaptiveCoverGenerator struct {
	*DailyPatternGenerator

	realPacketsPerMin  float64
	coverRatio         float64
	lastRealPacketTime time.Time
}

func NewAdaptiveCoverGenerator(profile *MessengerProfile, coverRatio float64) *AdaptiveCoverGenerator {
	if coverRatio <= 0 {
		coverRatio = 0.3
	}

	return &AdaptiveCoverGenerator{
		DailyPatternGenerator: NewDailyPatternGenerator(profile),
		coverRatio:            coverRatio,
		lastRealPacketTime:    time.Now(),
	}
}

func (g *AdaptiveCoverGenerator) OnRealPacket() {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(g.lastRealPacketTime).Minutes()
	if elapsed > 0 {
		g.realPacketsPerMin = 0.9*g.realPacketsPerMin + 0.1*(1.0/elapsed)
	}
	g.lastRealPacketTime = now
}

func (g *AdaptiveCoverGenerator) GetTargetCoverRate() float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	targetRate := g.realPacketsPerMin * g.coverRatio * g.hourlyMultiplier

	if targetRate < 0.1 {
		targetRate = 0.1
	}
	if targetRate > 60 {
		targetRate = 60
	}

	return targetRate
}
