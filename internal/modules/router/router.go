// Package router provides the routing module
package router

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

const (
	ModuleName    = "routing.engine"
	ModuleVersion = "1.0.0"
)

// Config holds router configuration
type Config struct {
	DefaultDestination interfaces.Destination
	MaxRules           int
	EnableCache        bool
	CacheSize          int
}

// DefaultConfig returns default router configuration
func DefaultConfig() *Config {
	return &Config{
		DefaultDestination: interfaces.Destination{
			Type: interfaces.DestinationDirect,
		},
		MaxRules:    1000,
		EnableCache: true,
		CacheSize:   10000,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.MaxRules <= 0 {
		c.MaxRules = 1000
	}
	if c.CacheSize <= 0 {
		c.CacheSize = 10000
	}
	return nil
}

// Engine implements interfaces.Router
type Engine struct {
	*base.Module
	config *Config

	mu    sync.RWMutex
	rules []interfaces.RoutingRule
	byID  map[string]*interfaces.RoutingRule

	// Domain cache for fast lookups
	domainCache   map[string]*interfaces.Destination
	domainCacheMu sync.RWMutex

	// IP cache
	ipCache   map[string]*interfaces.Destination
	ipCacheMu sync.RWMutex

	// Stats
	routeHits   uint64
	routeMisses uint64
	cacheHits   uint64
	cacheMisses uint64
}

// New creates a new routing engine
func New(cfg *Config) (*Engine, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	e := &Engine{
		Module:      base.NewModule(ModuleName, ModuleVersion, nil),
		config:      cfg,
		rules:       make([]interfaces.RoutingRule, 0),
		byID:        make(map[string]*interfaces.RoutingRule),
		domainCache: make(map[string]*interfaces.Destination),
		ipCache:     make(map[string]*interfaces.Destination),
	}

	return e, nil
}

// Init initializes the router
func (e *Engine) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := e.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if routerCfg, ok := cfg.(*Config); ok {
		e.config = routerCfg
	}

	return nil
}

// Start starts the router
func (e *Engine) Start() error {
	if err := e.Module.Start(); err != nil {
		return err
	}

	e.SetHealthy(true, "router running")
	e.PublishEvent(events.EventTypeModuleStarted, nil)
	return nil
}

// Stop stops the router
func (e *Engine) Stop() error {
	e.PublishEvent(events.EventTypeModuleStopped, nil)
	return e.Module.Stop()
}

// Route determines the destination for a packet
func (e *Engine) Route(ctx context.Context, packet *interfaces.Packet) (*interfaces.Destination, error) {
	e.UpdateActivity()

	// Check cache first if enabled
	if e.config.EnableCache {
		if dest := e.checkCache(packet); dest != nil {
			atomic.AddUint64(&e.cacheHits, 1)
			atomic.AddUint64(&e.routeHits, 1)
			return dest, nil
		}
		atomic.AddUint64(&e.cacheMisses, 1)
	}

	// Evaluate rules
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	for _, rule := range rules {
		if e.matchRule(&rule, packet) {
			atomic.AddUint64(&e.routeHits, 1)
			dest := &rule.Destination

			// Cache the result
			if e.config.EnableCache {
				e.updateCache(packet, dest)
			}

			return dest, nil
		}
	}

	// No rule matched, use default
	atomic.AddUint64(&e.routeMisses, 1)
	return &e.config.DefaultDestination, nil
}

// matchRule checks if a packet matches a rule
func (e *Engine) matchRule(rule *interfaces.RoutingRule, packet *interfaces.Packet) bool {
	for _, cond := range rule.Conditions {
		if !e.matchCondition(&cond, packet) {
			return false
		}
	}
	return true
}

// matchCondition checks if a packet matches a condition
func (e *Engine) matchCondition(cond *interfaces.RuleCondition, packet *interfaces.Packet) bool {
	switch cond.Field {
	case "dst_ip":
		return e.matchIP(packet.DstAddr, cond)
	case "src_ip":
		return e.matchIP(packet.SrcAddr, cond)
	case "dst_port":
		return e.matchPort(packet.DstAddr, cond)
	case "src_port":
		return e.matchPort(packet.SrcAddr, cond)
	case "domain":
		return e.matchDomain(cond)
	case "protocol":
		return e.matchProtocol(packet, cond)
	case "session_id":
		return e.matchSessionID(packet, cond)
	default:
		return false
	}
}

// matchIP matches IP address conditions
func (e *Engine) matchIP(addr net.Addr, cond *interfaces.RuleCondition) bool {
	if addr == nil {
		return false
	}

	var ip net.IP
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	default:
		return false
	}

	switch cond.Operator {
	case "eq":
		if s, ok := cond.Value.(string); ok {
			return ip.String() == s
		}
	case "cidr":
		if s, ok := cond.Value.(string); ok {
			_, cidr, err := net.ParseCIDR(s)
			if err != nil {
				return false
			}
			return cidr.Contains(ip)
		}
	case "in":
		if list, ok := cond.Value.([]string); ok {
			for _, v := range list {
				if ip.String() == v {
					return true
				}
			}
		}
	}

	return false
}

// matchPort matches port conditions
func (e *Engine) matchPort(addr net.Addr, cond *interfaces.RuleCondition) bool {
	if addr == nil {
		return false
	}

	var port int
	switch a := addr.(type) {
	case *net.UDPAddr:
		port = a.Port
	case *net.TCPAddr:
		port = a.Port
	default:
		return false
	}

	switch cond.Operator {
	case "eq":
		if v, ok := cond.Value.(int); ok {
			return port == v
		}
	case "in":
		if list, ok := cond.Value.([]int); ok {
			for _, v := range list {
				if port == v {
					return true
				}
			}
		}
	case "range":
		if r, ok := cond.Value.([]int); ok && len(r) == 2 {
			return port >= r[0] && port <= r[1]
		}
	}

	return false
}

// matchDomain matches domain conditions
func (e *Engine) matchDomain(cond *interfaces.RuleCondition) bool {
	domain, ok := cond.Value.(string)
	if !ok {
		return false
	}

	// Domain matching would need to be extracted from packet payload
	// or from metadata. This is a placeholder implementation.

	switch cond.Operator {
	case "eq":
		// Exact match
		return false // Would compare with extracted domain
	case "contains":
		// Substring match
		return false
	case "suffix":
		// Suffix match (e.g., ".google.com")
		return false
	case "regex":
		// Regex match
		return false
	}

	_ = domain
	return false
}

// matchProtocol matches protocol conditions
func (e *Engine) matchProtocol(packet *interfaces.Packet, cond *interfaces.RuleCondition) bool {
	// Would extract protocol from IP packet header
	// This is a placeholder
	return false
}

// matchSessionID matches session ID conditions
func (e *Engine) matchSessionID(packet *interfaces.Packet, cond *interfaces.RuleCondition) bool {
	switch cond.Operator {
	case "eq":
		if v, ok := cond.Value.(uint32); ok {
			return packet.SessionID == v
		}
	case "in":
		if list, ok := cond.Value.([]uint32); ok {
			for _, v := range list {
				if packet.SessionID == v {
					return true
				}
			}
		}
	}
	return false
}

// checkCache checks the routing cache
func (e *Engine) checkCache(packet *interfaces.Packet) *interfaces.Destination {
	// Check IP cache
	if packet.DstAddr != nil {
		e.ipCacheMu.RLock()
		if dest, ok := e.ipCache[packet.DstAddr.String()]; ok {
			e.ipCacheMu.RUnlock()
			return dest
		}
		e.ipCacheMu.RUnlock()
	}
	return nil
}

// updateCache updates the routing cache
func (e *Engine) updateCache(packet *interfaces.Packet, dest *interfaces.Destination) {
	if packet.DstAddr != nil {
		e.ipCacheMu.Lock()
		if len(e.ipCache) >= e.config.CacheSize {
			// Simple eviction: clear half the cache
			newCache := make(map[string]*interfaces.Destination)
			count := 0
			for k, v := range e.ipCache {
				if count >= e.config.CacheSize/2 {
					break
				}
				newCache[k] = v
				count++
			}
			e.ipCache = newCache
		}
		e.ipCache[packet.DstAddr.String()] = dest
		e.ipCacheMu.Unlock()
	}
}

// AddRule adds a routing rule
func (e *Engine) AddRule(rule interfaces.RoutingRule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.byID[rule.ID]; exists {
		return fmt.Errorf("rule %s already exists", rule.ID)
	}

	if len(e.rules) >= e.config.MaxRules {
		return fmt.Errorf("max rules reached (%d)", e.config.MaxRules)
	}

	e.rules = append(e.rules, rule)
	e.byID[rule.ID] = &e.rules[len(e.rules)-1]

	// Sort by priority
	sort.Slice(e.rules, func(i, j int) bool {
		return e.rules[i].Priority > e.rules[j].Priority
	})

	// Rebuild byID map after sort
	e.byID = make(map[string]*interfaces.RoutingRule)
	for i := range e.rules {
		e.byID[e.rules[i].ID] = &e.rules[i]
	}

	// Clear cache on rule change
	e.clearCache()

	e.UpdateActivity()
	return nil
}

// RemoveRule removes a routing rule by ID
func (e *Engine) RemoveRule(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.byID[id]; !exists {
		return fmt.Errorf("rule %s not found", id)
	}

	// Remove from slice
	newRules := make([]interfaces.RoutingRule, 0, len(e.rules)-1)
	for _, r := range e.rules {
		if r.ID != id {
			newRules = append(newRules, r)
		}
	}
	e.rules = newRules

	// Remove from map
	delete(e.byID, id)

	// Clear cache on rule change
	e.clearCache()

	e.UpdateActivity()
	return nil
}

// UpdateRules replaces all rules
func (e *Engine) UpdateRules(rules []interfaces.RoutingRule) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Validate all rules first
	seen := make(map[string]bool)
	for _, r := range rules {
		if r.ID == "" {
			return fmt.Errorf("rule ID is required")
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule ID: %s", r.ID)
		}
		seen[r.ID] = true
	}

	// Sort by priority
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})

	e.rules = rules
	e.byID = make(map[string]*interfaces.RoutingRule)
	for i := range e.rules {
		e.byID[e.rules[i].ID] = &e.rules[i]
	}

	// Clear cache on rule change
	e.clearCache()

	e.UpdateActivity()
	return nil
}

// GetRules returns all current rules
func (e *Engine) GetRules() []interfaces.RoutingRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]interfaces.RoutingRule, len(e.rules))
	copy(rules, e.rules)
	return rules
}

// GetRule returns a specific rule by ID
func (e *Engine) GetRule(id string) (*interfaces.RoutingRule, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rule, exists := e.byID[id]
	if !exists {
		return nil, false
	}
	return rule, true
}

// clearCache clears all routing caches
func (e *Engine) clearCache() {
	e.ipCacheMu.Lock()
	e.ipCache = make(map[string]*interfaces.Destination)
	e.ipCacheMu.Unlock()

	e.domainCacheMu.Lock()
	e.domainCache = make(map[string]*interfaces.Destination)
	e.domainCacheMu.Unlock()
}

// CacheDomain caches a domain -> destination mapping
func (e *Engine) CacheDomain(domain string, dest *interfaces.Destination) {
	domain = strings.ToLower(domain)

	e.domainCacheMu.Lock()
	defer e.domainCacheMu.Unlock()

	if len(e.domainCache) >= e.config.CacheSize {
		// Simple eviction
		newCache := make(map[string]*interfaces.Destination)
		count := 0
		for k, v := range e.domainCache {
			if count >= e.config.CacheSize/2 {
				break
			}
			newCache[k] = v
			count++
		}
		e.domainCache = newCache
	}

	e.domainCache[domain] = dest
}

// LookupDomain looks up a domain in the cache
func (e *Engine) LookupDomain(domain string) (*interfaces.Destination, bool) {
	domain = strings.ToLower(domain)

	e.domainCacheMu.RLock()
	defer e.domainCacheMu.RUnlock()

	dest, ok := e.domainCache[domain]
	return dest, ok
}

// HealthCheck returns health status
func (e *Engine) HealthCheck() interfaces.HealthStatus {
	status := e.Module.HealthCheck()

	e.mu.RLock()
	ruleCount := len(e.rules)
	e.mu.RUnlock()

	e.ipCacheMu.RLock()
	ipCacheSize := len(e.ipCache)
	e.ipCacheMu.RUnlock()

	e.domainCacheMu.RLock()
	domainCacheSize := len(e.domainCache)
	e.domainCacheMu.RUnlock()

	status.Details["rule_count"] = ruleCount
	status.Details["ip_cache_size"] = ipCacheSize
	status.Details["domain_cache_size"] = domainCacheSize
	status.Details["route_hits"] = atomic.LoadUint64(&e.routeHits)
	status.Details["route_misses"] = atomic.LoadUint64(&e.routeMisses)
	status.Details["cache_hits"] = atomic.LoadUint64(&e.cacheHits)
	status.Details["cache_misses"] = atomic.LoadUint64(&e.cacheMisses)

	return status
}

// Stats returns router statistics
type Stats struct {
	RuleCount       int
	IPCacheSize     int
	DomainCacheSize int
	RouteHits       uint64
	RouteMisses     uint64
	CacheHits       uint64
	CacheMisses     uint64
}

// GetStats returns router statistics
func (e *Engine) GetStats() Stats {
	e.mu.RLock()
	ruleCount := len(e.rules)
	e.mu.RUnlock()

	e.ipCacheMu.RLock()
	ipCacheSize := len(e.ipCache)
	e.ipCacheMu.RUnlock()

	e.domainCacheMu.RLock()
	domainCacheSize := len(e.domainCache)
	e.domainCacheMu.RUnlock()

	return Stats{
		RuleCount:       ruleCount,
		IPCacheSize:     ipCacheSize,
		DomainCacheSize: domainCacheSize,
		RouteHits:       atomic.LoadUint64(&e.routeHits),
		RouteMisses:     atomic.LoadUint64(&e.routeMisses),
		CacheHits:       atomic.LoadUint64(&e.cacheHits),
		CacheMisses:     atomic.LoadUint64(&e.cacheMisses),
	}
}

// Factory creates router modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
