package xhttp

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"whispera/internal/routing"
)

// ExtraMetadata represents per-connection extra JSON metadata from Xray-core
type ExtraMetadata struct {
	// Original JSON string
	RawJSON string

	// Parsed fields
	Data map[string]interface{}

	// Routing hints
	Policy      string // Policy name/id for routing
	Destination string // Destination address/domain
	User        string // User identifier
	InboundTag  string // Inbound tag for routing
	OutboundTag string // Outbound tag preference
	Domain      string // Domain for SNI/routing
	IP          string // IP address
	Port        uint16 // Port number
	Protocol    string // Protocol hint (tcp/udp/http/tls/etc)

	// Custom fields
	Custom map[string]string

	// Metadata
	ParsedAt  time.Time
	ExpiresAt time.Time
}

// MetadataRouter handles routing decisions based on extra metadata
type MetadataRouter struct {
	mu              sync.RWMutex
	routes          map[string]*RoutingRule
	defaultRoute    *RoutingRule
	policyEngine    PolicyEngine
	engine          *routing.Engine
	lookupCache     map[string]*RoutingDecision
	cacheTTL        time.Duration
	lastCleanupTime time.Time
}

// RoutingRule represents a rule for routing based on metadata
type RoutingRule struct {
	Name       string
	Conditions MetadataConditions
	Target     RoutingTarget
	Priority   int
	Enabled    bool
}

// MetadataConditions represents conditions for matching metadata
type MetadataConditions struct {
	Policies      []string // Match any of these policies
	Domains       []string // Match any of these domains (supports wildcards)
	IPs           []string // Match any of these IPs (supports CIDR)
	Ports         []uint16 // Match any of these ports
	Users         []string // Match any of these users
	InboundTags   []string // Match any of these inbound tags
	Protocols     []string // Match any of these protocols
	CustomMatches map[string]string
}

// RoutingTarget specifies where to route matched traffic
type RoutingTarget struct {
	OutboundTag string
	Server      string
	Port        uint16
	Direct      bool // Direct connection without proxy
}

// RoutingDecision is the result of routing decision
type RoutingDecision struct {
	Target          RoutingTarget
	MatchedRuleName string
	CachedAt        time.Time
}

// PolicyEngine interface for policy-based routing
type PolicyEngine interface {
	GetPolicy(name string) (Policy, error)
	EvaluatePolicy(metadata *ExtraMetadata) RoutingTarget
}

// Policy represents a routing policy
type Policy struct {
	Name        string
	Description string
	Rules       []RoutingRule
	Default     RoutingTarget
}

// NewMetadataRouter creates new metadata router
func NewMetadataRouter(policyEngine PolicyEngine) *MetadataRouter {
	return &MetadataRouter{
		routes:       make(map[string]*RoutingRule),
		policyEngine: policyEngine,
		lookupCache:  make(map[string]*RoutingDecision),
		cacheTTL:     5 * time.Minute,
	}
}

// Package-level default metadata router (can be set by main)
var defaultMetadataRouter *MetadataRouter

// SetDefaultMetadataRouter sets the package default router
func SetDefaultMetadataRouter(r *MetadataRouter) {
	defaultMetadataRouter = r
}

// GetDefaultMetadataRouter returns package default router
func GetDefaultMetadataRouter() *MetadataRouter {
	return defaultMetadataRouter
}

// SetEngine attaches a routing Engine to the MetadataRouter for resolution
func (mr *MetadataRouter) SetEngine(engine *routing.Engine) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.engine = engine
}

// ParseExtraMetadata parses JSON extra metadata
func ParseExtraMetadata(rawJSON string) (*ExtraMetadata, error) {
	if rawJSON == "" {
		return &ExtraMetadata{
			RawJSON:  "",
			Data:     make(map[string]interface{}),
			Custom:   make(map[string]string),
			ParsedAt: time.Now(),
		}, nil
	}

	metadata := &ExtraMetadata{
		RawJSON:  rawJSON,
		Data:     make(map[string]interface{}),
		Custom:   make(map[string]string),
		ParsedAt: time.Now(),
	}

	// Parse JSON
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(rawJSON), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse extra metadata JSON: %w", err)
	}

	metadata.Data = raw

	// Extract known fields
	if policy, ok := raw["policy"].(string); ok {
		metadata.Policy = policy
	}
	if dest, ok := raw["destination"].(string); ok {
		metadata.Destination = dest
	}
	if user, ok := raw["user"].(string); ok {
		metadata.User = user
	}
	if inboundTag, ok := raw["inboundTag"].(string); ok {
		metadata.InboundTag = inboundTag
	}
	if outboundTag, ok := raw["outboundTag"].(string); ok {
		metadata.OutboundTag = outboundTag
	}
	if domain, ok := raw["domain"].(string); ok {
		metadata.Domain = domain
	}
	if ip, ok := raw["ip"].(string); ok {
		metadata.IP = ip
	}
	if port, ok := raw["port"].(float64); ok {
		metadata.Port = uint16(port)
	}
	if protocol, ok := raw["protocol"].(string); ok {
		metadata.Protocol = protocol
	}

	// Extract custom fields (anything not recognized)
	for key, value := range raw {
		switch key {
		case "policy", "destination", "user", "inboundTag", "outboundTag",
			"domain", "ip", "port", "protocol":
			// Already extracted above
		default:
			if strVal, ok := value.(string); ok {
				metadata.Custom[key] = strVal
			} else {
				metadata.Custom[key] = fmt.Sprintf("%v", value)
			}
		}
	}

	return metadata, nil
}

// RegisterRule registers a new routing rule
func (mr *MetadataRouter) RegisterRule(rule *RoutingRule) {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	mr.routes[rule.Name] = rule
}

// SetDefaultRoute sets default routing target
func (mr *MetadataRouter) SetDefaultRoute(target *RoutingRule) {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	mr.defaultRoute = target
}

// Route makes routing decision based on metadata
func (mr *MetadataRouter) Route(metadata *ExtraMetadata) RoutingTarget {
	if metadata == nil {
		return RoutingTarget{}
	}
	// If an Engine is attached, prefer ResolveWithEngine which can consult engine/outbound manager
	mr.mu.RLock()
	eng := mr.engine
	mr.mu.RUnlock()
	if eng != nil {
		if decision, err := mr.ResolveWithEngine(eng, metadata); err == nil && decision != nil {
			return decision.Target
		}
	}

	// Check cache first
	cacheKey := metadata.Policy + ":" + metadata.Destination
	if decision, ok := mr.lookupCache[cacheKey]; ok {
		if time.Since(decision.CachedAt) < mr.cacheTTL {
			return decision.Target
		}
	}

	// Find matching rule with highest priority
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	var bestRule *RoutingRule
	for _, rule := range mr.routes {
		if !rule.Enabled {
			continue
		}

		if mr.matchesConditions(metadata, rule.Conditions) {
			if bestRule == nil || rule.Priority > bestRule.Priority {
				bestRule = rule
			}
		}
	}

	// Use matched rule or default
	target := RoutingTarget{}
	ruleName := "default"

	if bestRule != nil {
		target = bestRule.Target
		ruleName = bestRule.Name
	} else if mr.defaultRoute != nil {
		target = mr.defaultRoute.Target
	}

	// Cache decision
	mr.lookupCache[cacheKey] = &RoutingDecision{
		Target:          target,
		MatchedRuleName: ruleName,
		CachedAt:        time.Now(),
	}

	return target
}

// ResolveWithEngine resolves routing decision using the provided routing Engine.
// It takes explicit outbound tags, policy hints and falls back to Engine.Rule matching.
func (mr *MetadataRouter) ResolveWithEngine(engine *routing.Engine, metadata *ExtraMetadata) (*RoutingDecision, error) {
	if metadata == nil {
		return nil, fmt.Errorf("metadata is nil")
	}

	cacheKey := metadata.Policy + ":" + metadata.Destination
	if decision, ok := mr.lookupCache[cacheKey]; ok {
		if time.Since(decision.CachedAt) < mr.cacheTTL {
			return decision, nil
		}
	}

	// 1) If explicit outboundTag is provided in metadata - honor it if possible
	if metadata.OutboundTag != "" {
		// Verify outbound exists when engine available
		if engine != nil && engine.GetOutboundManager() != nil {
			if _, ok := engine.GetOutboundManager().GetSessionID(metadata.OutboundTag); ok {
				d := &RoutingDecision{Target: RoutingTarget{OutboundTag: metadata.OutboundTag}, MatchedRuleName: "explicit_outbound", CachedAt: time.Now()}
				mr.lookupCache[cacheKey] = d
				return d, nil
			}
		}
		// Even if not registered, return the requested outbound tag as intent
		d := &RoutingDecision{Target: RoutingTarget{OutboundTag: metadata.OutboundTag}, MatchedRuleName: "explicit_outbound_unregistered", CachedAt: time.Now()}
		mr.lookupCache[cacheKey] = d
		return d, nil
	}

	// 2) If policy engine exists and metadata contains a policy, evaluate it
	if metadata.Policy != "" && mr.policyEngine != nil {
		t := mr.policyEngine.EvaluatePolicy(metadata)
		d := &RoutingDecision{Target: t, MatchedRuleName: "policy_engine", CachedAt: time.Now()}
		mr.lookupCache[cacheKey] = d
		return d, nil
	}

	// 3) Try routing via Engine rules using PacketInfo constructed from metadata
	if engine != nil {
		info := &routing.PacketInfo{
			Domain:     metadata.Domain,
			UserID:     metadata.User,
			InboundTag: metadata.InboundTag,
			Protocol:   metadata.Protocol,
		}

		if metadata.IP != "" {
			info.DstIP = net.ParseIP(metadata.IP)
		}
		if metadata.Port > 0 {
			info.DstPort = metadata.Port
		}

		outboundTag, balancerTag, matched := engine.Route(info)
		if matched {
			rt := RoutingTarget{OutboundTag: outboundTag}
			ruleName := "engine_rule"
			if balancerTag != "" {
				ruleName = "engine_balancer:" + balancerTag
			}
			d := &RoutingDecision{Target: rt, MatchedRuleName: ruleName, CachedAt: time.Now()}
			mr.lookupCache[cacheKey] = d
			return d, nil
		}
	}

	// 4) Fallback to default route if configured
	var rt RoutingTarget
	if mr.defaultRoute != nil {
		rt = mr.defaultRoute.Target
	}
	d := &RoutingDecision{Target: rt, MatchedRuleName: "default", CachedAt: time.Now()}
	mr.lookupCache[cacheKey] = d
	return d, nil
}

// matchesConditions checks if metadata matches rule conditions
func (mr *MetadataRouter) matchesConditions(metadata *ExtraMetadata, conditions MetadataConditions) bool {
	// Policy matching
	if len(conditions.Policies) > 0 && metadata.Policy != "" {
		if !contains(conditions.Policies, metadata.Policy) {
			return false
		}
	}

	// Domain matching
	if len(conditions.Domains) > 0 && metadata.Domain != "" {
		if !matchDomainPattern(conditions.Domains, metadata.Domain) {
			return false
		}
	}

	// IP matching (simplified, in production use proper CIDR parsing)
	if len(conditions.IPs) > 0 && metadata.IP != "" {
		if !contains(conditions.IPs, metadata.IP) {
			return false
		}
	}

	// Port matching
	if len(conditions.Ports) > 0 && metadata.Port > 0 {
		if !containsPort(conditions.Ports, metadata.Port) {
			return false
		}
	}

	// User matching
	if len(conditions.Users) > 0 && metadata.User != "" {
		if !contains(conditions.Users, metadata.User) {
			return false
		}
	}

	// Inbound tag matching
	if len(conditions.InboundTags) > 0 && metadata.InboundTag != "" {
		if !contains(conditions.InboundTags, metadata.InboundTag) {
			return false
		}
	}

	// Protocol matching
	if len(conditions.Protocols) > 0 && metadata.Protocol != "" {
		if !contains(conditions.Protocols, metadata.Protocol) {
			return false
		}
	}

	// Custom matching
	for key, expectedVal := range conditions.CustomMatches {
		actualVal, ok := metadata.Custom[key]
		if !ok || actualVal != expectedVal {
			return false
		}
	}

	return true
}

// matchDomainPattern checks if domain matches patterns (supports * wildcard)
func matchDomainPattern(patterns []string, domain string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		if pattern == domain {
			return true
		}
		// Simple wildcard matching: *.example.com matches a.example.com
		if len(pattern) > 0 && pattern[0] == '*' {
			suffix := pattern[1:]
			if len(domain) >= len(suffix) && domain[len(domain)-len(suffix):] == suffix {
				return true
			}
		}
	}
	return false
}

// contains checks if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// containsPort checks if slice contains port
func containsPort(slice []uint16, port uint16) bool {
	for _, p := range slice {
		if p == port {
			return true
		}
	}
	return false
}

// CleanupCache cleans expired cache entries
func (mr *MetadataRouter) CleanupCache() {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	now := time.Now()
	for key, decision := range mr.lookupCache {
		if now.Sub(decision.CachedAt) > mr.cacheTTL {
			delete(mr.lookupCache, key)
		}
	}
	mr.lastCleanupTime = now
}

// ExtraMetadataExtractor extracts metadata from HTTP headers/requests
type ExtraMetadataExtractor struct {
	headerNames map[string]string // HTTP header name -> metadata field name
}

// NewExtraMetadataExtractor creates new metadata extractor
func NewExtraMetadataExtractor() *ExtraMetadataExtractor {
	return &ExtraMetadataExtractor{
		headerNames: map[string]string{
			"X-Xhttp-Policy":      "policy",
			"X-Xhttp-Destination": "destination",
			"X-Xhttp-User":        "user",
			"X-Xhttp-InboundTag":  "inboundTag",
			"X-Xhttp-OutboundTag": "outboundTag",
			"X-Xhttp-Domain":      "domain",
			"X-Xhttp-Protocol":    "protocol",
		},
	}
}

// ExtractFromHeaders extracts metadata from HTTP headers
func (eme *ExtraMetadataExtractor) ExtractFromHeaders(headers map[string]string) *ExtraMetadata {
	metadata := &ExtraMetadata{
		Data:     make(map[string]interface{}),
		Custom:   make(map[string]string),
		ParsedAt: time.Now(),
	}

	// Extract known headers
	for headerName, fieldName := range eme.headerNames {
		if value, ok := headers[headerName]; ok {
			metadata.Data[fieldName] = value

			// Set corresponding field
			switch fieldName {
			case "policy":
				metadata.Policy = value
			case "destination":
				metadata.Destination = value
			case "user":
				metadata.User = value
			case "inboundTag":
				metadata.InboundTag = value
			case "outboundTag":
				metadata.OutboundTag = value
			case "domain":
				metadata.Domain = value
			case "protocol":
				metadata.Protocol = value
			}
		}
	}

	// Extract custom headers (anything with X-Xhttp- prefix not in known list)
	for headerName, value := range headers {
		if len(headerName) >= 8 && headerName[:8] == "X-Xhttp-" {
			customKey := headerName[8:] // Remove X-Xhttp- prefix
			if _, ok := eme.headerNames[headerName]; !ok {
				metadata.Custom[customKey] = value
			}
		}
	}

	return metadata
}

// MetadataCarrier carries metadata through connection lifecycle
type MetadataCarrier struct {
	mu       sync.RWMutex
	metadata map[string]*ExtraMetadata // Connection ID -> metadata
}

// NewMetadataCarrier creates new metadata carrier
func NewMetadataCarrier() *MetadataCarrier {
	return &MetadataCarrier{
		metadata: make(map[string]*ExtraMetadata),
	}
}

// StoreMetadata stores metadata for connection
func (mc *MetadataCarrier) StoreMetadata(connID string, metadata *ExtraMetadata) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.metadata[connID] = metadata
}

// GetMetadata retrieves metadata for connection
func (mc *MetadataCarrier) GetMetadata(connID string) *ExtraMetadata {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return mc.metadata[connID]
}

// RemoveMetadata removes metadata for connection
func (mc *MetadataCarrier) RemoveMetadata(connID string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	delete(mc.metadata, connID)
}

// Size returns number of stored metadata entries
func (mc *MetadataCarrier) Size() int {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return len(mc.metadata)
}
