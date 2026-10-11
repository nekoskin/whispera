package camo

import "sync"

const replayShardCount = 16

type replaySighting struct {
	at     int64
	sender string
}

type replayShard struct {
	mu   sync.Mutex
	seen map[[32]byte]replaySighting
}

type ReplayGuard struct {
	ttlSec int64
	shards [replayShardCount]replayShard
}

func NewReplayGuard(ttlSec int64) *ReplayGuard {
	g := &ReplayGuard{ttlSec: ttlSec}
	for i := range g.shards {
		g.shards[i].seen = make(map[[32]byte]replaySighting)
	}
	return g
}

func (g *ReplayGuard) FirstSighting(random []byte, sender string, now int64) bool {
	if len(random) != 32 {
		return false
	}
	var key [32]byte
	copy(key[:], random)
	shard := &g.shards[key[len(key)-1]%replayShardCount]

	shard.mu.Lock()
	defer shard.mu.Unlock()
	if prev, ok := shard.seen[key]; ok && now-prev.at < g.ttlSec {
		return sender != "" && prev.sender == sender
	}
	shard.seen[key] = replaySighting{at: now, sender: sender}
	return true
}

func (g *ReplayGuard) Sweep(now int64) {
	for i := range g.shards {
		shard := &g.shards[i]
		shard.mu.Lock()
		for key, s := range shard.seen {
			if now-s.at >= g.ttlSec {
				delete(shard.seen, key)
			}
		}
		shard.mu.Unlock()
	}
}
