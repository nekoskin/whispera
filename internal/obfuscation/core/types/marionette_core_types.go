package types

import (
	"context"
	"sync"
	"time"
)

// This file formerly contained the Marionette struct, which has been moved to
// internal/obfuscation/core/evasion to resolve circular dependencies and method definition issues.

// ruleCacheKey представляет ключ для кэша правил
type RuleCacheKey struct {
	Size      int
	Direction string
	RuleCount int
}

// Context and sync imports are kept if needed for other types, otherwise unused imports might occur.
var _ context.Context
var _ sync.Mutex
var _ time.Time
