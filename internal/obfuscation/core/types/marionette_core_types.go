package types

import (
	"context"
	"sync"
	"time"
)


type RuleCacheKey struct {
	Size      int
	Direction string
	RuleCount int
}

var _ context.Context
var _ sync.Mutex
var _ time.Time
