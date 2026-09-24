package split_tunnel

import (
	"bytes"
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type SplitTunnelRule struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority"`
	Created     int64  `json:"created"`
	Modified    int64  `json:"modified"`
}

type SplitTunnelConfig struct {
	Mode          string            `json:"mode"`
	Rules         []SplitTunnelRule `json:"rules"`
	DefaultAction string            `json:"default_action"`
	Enabled       bool              `json:"enabled"`
	Version       string            `json:"version"`
}

type SplitTunnelManager struct {
	mu        sync.RWMutex
	config    *SplitTunnelConfig
	rules     []SplitTunnelRule
	snap      atomic.Pointer[ruleSnapshot]
	geo       *GeoIPSet
	resolve   ResolveFunc
	byCountry bool
	cached    CachedFunc
	verdicts  *verdictCache
	pending   map[string]bool
}

type idxRange struct {
	lo, hi [16]byte
	idx    int
}

type kwRule struct {
	value string
	idx   int
}

// ruleSnapshot is published atomically and never mutated afterwards, so the
// lookup path reads it without taking a lock.
type ruleSnapshot struct {
	enabled   bool
	byCountry bool
	geo       *GeoIPSet
	resolve   ResolveFunc
	cached    CachedFunc
	suffix    map[string]int
	exact     map[string]int
	keyword   []kwRule
	ranges    []idxRange
	direct    []bool
}

type ResolveFunc func(ctx context.Context, host string) ([]net.IP, error)

// CachedFunc answers from what the resolver already knows, without going to the
// network. The country list only matters for addresses inside it, and a name we
// have not looked up cannot be inside anything — so it goes through the tunnel
// and nobody waits.
type CachedFunc func(host string) ([]net.IP, bool)

const verdictShards = 64

type verdictShard struct {
	mu sync.RWMutex
	m  map[string]verdict
}

// verdictCache spreads hosts over shards so that learning one of them does not
// stop lookups of the others. The whole page load is new hosts, and under one
// lock that turned every fresh name into a stop-the-world.
type verdictCache struct {
	shards [verdictShards]verdictShard
}

func newVerdictCache() *verdictCache {
	c := &verdictCache{}
	for i := range c.shards {
		c.shards[i].m = make(map[string]verdict)
	}
	return c
}

func (c *verdictCache) shardFor(host string) *verdictShard {
	h := uint32(2166136261)
	for i := 0; i < len(host); i++ {
		h ^= uint32(host[i])
		h *= 16777619
	}
	return &c.shards[h%verdictShards]
}

func (c *verdictCache) get(host string) (verdict, bool) {
	sh := c.shardFor(host)
	sh.mu.RLock()
	v, ok := sh.m[host]
	sh.mu.RUnlock()
	return v, ok
}

func (c *verdictCache) put(host string, v verdict) {
	sh := c.shardFor(host)
	sh.mu.Lock()
	if len(sh.m) >= verdictMax/verdictShards {
		now := time.Now()
		for h, old := range sh.m {
			if now.After(old.expires) {
				delete(sh.m, h)
			}
		}
		if len(sh.m) >= verdictMax/verdictShards {
			sh.m = make(map[string]verdict)
		}
	}
	sh.m[host] = v
	sh.mu.Unlock()
}

func (c *verdictCache) len() int {
	total := 0
	for i := range c.shards {
		c.shards[i].mu.RLock()
		total += len(c.shards[i].m)
		c.shards[i].mu.RUnlock()
	}
	return total
}

func (c *verdictCache) reset() {
	for i := range c.shards {
		c.shards[i].mu.Lock()
		c.shards[i].m = make(map[string]verdict)
		c.shards[i].mu.Unlock()
	}
}

type verdict struct {
	bypass  bool
	expires time.Time
}

const (
	// Shorter than the resolver cache (5m) on purpose: a verdict that outlives
	// the addresses it was computed from always expires into a DNS miss, and a
	// miss routes one connection through the tunnel before it learns.
	verdictTTL      = 1 * time.Minute
	resolveTimeout  = 3 * time.Second
	verdictMax      = 4096
	appRulePriority = 200
)

func NewSplitTunnelManager() *SplitTunnelManager {
	return &SplitTunnelManager{
		config: &SplitTunnelConfig{
			Mode:          "exclude",
			DefaultAction: "tunnel",
			Enabled:       false,
			Version:       "1.0",
			Rules:         []SplitTunnelRule{},
		},
		rules:     []SplitTunnelRule{},
		verdicts:  newVerdictCache(),
		byCountry: true,
	}
}

func (stm *SplitTunnelManager) LoadConfig(filename string) error {
	if filename == "" {
		return nil
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read split tunnel config: %w", err)
	}

	var config SplitTunnelConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse split tunnel config: %w", err)
	}

	stm.mu.Lock()
	if config.Mode != "" {
		stm.config.Mode = config.Mode
	}
	if config.DefaultAction != "" {
		stm.config.DefaultAction = config.DefaultAction
	}
	stm.rules = append(stm.rules, config.Rules...)
	sortRulesByPriority(stm.rules)
	stm.recompileLocked()
	stm.mu.Unlock()

	return nil
}

func (stm *SplitTunnelManager) AddRule(rule *SplitTunnelRule) {
	rule.Created = time.Now().Unix()
	rule.Modified = time.Now().Unix()
	stm.mu.Lock()
	stm.rules = append(stm.rules, *rule)
	sortRulesByPriority(stm.rules)
	stm.recompileLocked()
	stm.mu.Unlock()
}

type ruleKey struct{ kind, value string }

func keyOf(r SplitTunnelRule) ruleKey {
	value := strings.ToLower(r.Value)
	if r.Type == "domain" {
		value = strings.TrimPrefix(value, "*.")
	}
	return ruleKey{kind: r.Type, value: value}
}

func (stm *SplitTunnelManager) recompileLocked() {
	seen := make(map[ruleKey]struct{}, len(stm.rules))
	unique := stm.rules[:0]
	for _, r := range stm.rules {
		key := keyOf(r)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, r)
	}
	stm.rules = unique
	stm.publishLocked()
}

func (stm *SplitTunnelManager) publishLocked() {
	snap := &ruleSnapshot{
		enabled:   stm.config.Enabled,
		byCountry: stm.byCountry,
		geo:       stm.geo,
		resolve:   stm.resolve,
		cached:    stm.cached,
		suffix:    make(map[string]int),
		exact:     make(map[string]int),
		direct:    make([]bool, len(stm.rules)),
	}
	var raw []idxRange
	for i, r := range stm.rules {
		snap.direct[i] = r.Action == "direct"
		if !r.Enabled {
			continue
		}
		switch r.Type {
		case "domain":
			v := strings.ToLower(strings.TrimPrefix(r.Value, "*."))
			if _, seen := snap.suffix[v]; !seen {
				snap.suffix[v] = i
			}
		case "domain-exact":
			v := strings.ToLower(r.Value)
			if _, seen := snap.exact[v]; !seen {
				snap.exact[v] = i
			}
		case "domain-keyword":
			snap.keyword = append(snap.keyword, kwRule{value: strings.ToLower(r.Value), idx: i})
		case "ip":
			if _, network, err := net.ParseCIDR(r.Value); err == nil {
				if rg, ok := rangeOf(network); ok {
					raw = append(raw, idxRange{lo: rg.lo, hi: rg.hi, idx: i})
				}
				continue
			}
			if ip := net.ParseIP(r.Value); ip != nil {
				var a [16]byte
				copy(a[:], ip.To16())
				raw = append(raw, idxRange{lo: a, hi: a, idx: i})
			}
		}
	}
	snap.ranges = flattenRanges(raw, len(stm.rules))
	stm.snap.Store(snap)
}

func incAddr(a [16]byte) ([16]byte, bool) {
	for i := 15; i >= 0; i-- {
		a[i]++
		if a[i] != 0 {
			return a, true
		}
	}
	return a, false
}

func decAddr(a [16]byte) [16]byte {
	for i := 15; i >= 0; i-- {
		if a[i] != 0 {
			a[i]--
			return a
		}
		a[i] = 0xff
	}
	return a
}

type rangeEvent struct {
	at    [16]byte
	idx   int
	start bool
}

type ruleHeap []int

func (h ruleHeap) Len() int            { return len(h) }
func (h ruleHeap) Less(i, j int) bool  { return h[i] < h[j] }
func (h ruleHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *ruleHeap) Push(x interface{}) { *h = append(*h, x.(int)) }
func (h *ruleHeap) Pop() interface{} {
	old := *h
	n := len(old)
	v := old[n-1]
	*h = old[:n-1]
	return v
}

// flattenRanges turns possibly overlapping rule ranges into disjoint ones, each
// carrying the winning rule. Priority is resolved here, once, so a lookup is a
// plain binary search. A sweep over the range boundaries keeps the smallest
// active rule at hand, which is the one that would have matched first.
func flattenRanges(raw []idxRange, ruleCount int) []idxRange {
	if len(raw) == 0 {
		return nil
	}
	events := make([]rangeEvent, 0, len(raw)*2)
	for _, r := range raw {
		events = append(events, rangeEvent{at: r.lo, idx: r.idx, start: true})
		if next, ok := incAddr(r.hi); ok {
			events = append(events, rangeEvent{at: next, idx: r.idx})
		}
	}
	sort.Slice(events, func(i, j int) bool {
		if c := bytes.Compare(events[i].at[:], events[j].at[:]); c != 0 {
			return c < 0
		}
		return events[i].start && !events[j].start
	})

	active := &ruleHeap{}
	ended := make([]bool, ruleCount)
	var out []idxRange
	for i := 0; i < len(events); {
		at := events[i].at
		for ; i < len(events) && events[i].at == at; i++ {
			if events[i].start {
				heap.Push(active, events[i].idx)
				continue
			}
			ended[events[i].idx] = true
		}
		for active.Len() > 0 && ended[(*active)[0]] {
			heap.Pop(active)
		}
		if active.Len() == 0 {
			continue
		}
		best := (*active)[0]

		end := [16]byte{}
		if i < len(events) {
			end = decAddr(events[i].at)
		} else {
			for j := range end {
				end[j] = 0xff
			}
		}
		if n := len(out); n > 0 && out[n-1].idx == best {
			if next, ok := incAddr(out[n-1].hi); ok && next == at {
				out[n-1].hi = end
				continue
			}
		}
		out = append(out, idxRange{lo: at, hi: end, idx: best})
	}
	return out
}

func sortRulesByPriority(rules []SplitTunnelRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})
}

func (stm *SplitTunnelManager) SetMode(mode string) {
	stm.mu.Lock()
	stm.config.Mode = mode
	stm.mu.Unlock()
}

func (stm *SplitTunnelManager) SetEnabled(enabled bool) {
	stm.mu.Lock()
	stm.config.Enabled = enabled
	stm.publishLocked()
	stm.mu.Unlock()
}

func (stm *SplitTunnelManager) isEnabled() bool {
	stm.mu.RLock()
	defer stm.mu.RUnlock()
	return stm.config.Enabled
}

func (stm *SplitTunnelManager) ShouldBypass(addr string, port uint16) bool {
	snap := stm.snap.Load()
	if snap == nil || !snap.enabled {
		return false
	}
	if looksLikeIP(addr) {
		if ip := net.ParseIP(addr); ip != nil {
			return stm.bypassIP(snap, ip)
		}
	}
	return stm.bypassHost(snap, addr)
}

// looksLikeIP keeps net.ParseIP away from host names. On anything that is not
// an address ParseIP builds an error value that is thrown away at once, and
// that allocation lands on every dial we make by name.
func looksLikeIP(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ':' {
			return true
		}
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func (stm *SplitTunnelManager) ShouldBypassByIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	snap := stm.snap.Load()
	if snap == nil || !snap.enabled {
		return false
	}
	return stm.bypassIP(snap, ip)
}

func (stm *SplitTunnelManager) bypassIP(snap *ruleSnapshot, ip net.IP) bool {
	var addr [16]byte
	copy(addr[:], ip.To16())
	i := sort.Search(len(snap.ranges), func(i int) bool {
		return bytes.Compare(snap.ranges[i].hi[:], addr[:]) >= 0
	})
	if i < len(snap.ranges) && bytes.Compare(snap.ranges[i].lo[:], addr[:]) <= 0 {
		return snap.direct[snap.ranges[i].idx]
	}
	if snap.geo != nil && snap.byCountry {
		return snap.geo.Contains(ip)
	}
	return false
}

func (stm *SplitTunnelManager) SetGeoIP(geo *GeoIPSet) {
	stm.mu.Lock()
	stm.geo = geo
	stm.publishLocked()
	stm.mu.Unlock()
}

func (stm *SplitTunnelManager) ShouldBypassByHostname(hostname string) bool {
	snap := stm.snap.Load()
	if snap == nil || !snap.enabled {
		return false
	}
	return stm.bypassHost(snap, hostname)
}

func (stm *SplitTunnelManager) bypassHost(snap *ruleSnapshot, hostname string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))

	best := -1
	if i, ok := snap.exact[hostname]; ok {
		best = i
	}
	for h := hostname; ; {
		if i, ok := snap.suffix[h]; ok && (best < 0 || i < best) {
			best = i
		}
		dot := strings.IndexByte(h, '.')
		if dot < 0 {
			break
		}
		h = h[dot+1:]
	}
	for _, k := range snap.keyword {
		if best >= 0 && k.idx > best {
			continue
		}
		if strings.Contains(hostname, k.value) {
			best = k.idx
		}
	}
	if best >= 0 {
		return snap.direct[best]
	}
	return stm.byCountryVerdict(snap, hostname)
}

func (stm *SplitTunnelManager) byCountryVerdict(snap *ruleSnapshot, hostname string) bool {
	if !snap.byCountry {
		return false
	}
	geo, resolve, cached := snap.geo, snap.resolve, snap.cached
	if v, ok := stm.verdicts.get(hostname); ok && time.Now().Before(v.expires) {
		return v.bypass
	}
	if geo == nil || geo.Len() == 0 {
		return false
	}

	// The address is usually known already: our own resolver handled this name
	// for the application a moment ago. Then the verdict costs a lookup in a
	// table. Only when it is not known does the question arise at all, and the
	// answer is not worth a DNS round trip on the connection path — the tunnel
	// is always correct, and the verdict is learned behind it for next time.
	if cached != nil {
		if ips, found := cached(hostname); found {
			return stm.recordCountry(hostname, geo, ips)
		}
	}
	if resolve != nil {
		stm.learnInBackground(hostname, geo, resolve)
	}
	return false
}

func (stm *SplitTunnelManager) learnInBackground(hostname string, geo *GeoIPSet, resolve ResolveFunc) {
	stm.mu.Lock()
	if stm.pending == nil {
		stm.pending = make(map[string]bool)
	}
	if stm.pending[hostname] {
		stm.mu.Unlock()
		return
	}
	stm.pending[hostname] = true
	stm.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
		defer cancel()
		ips, err := resolve(ctx, hostname)
		if err == nil {
			stm.recordCountry(hostname, geo, ips)
		}
		stm.mu.Lock()
		delete(stm.pending, hostname)
		stm.mu.Unlock()
	}()
}

func (stm *SplitTunnelManager) recordCountry(hostname string, geo *GeoIPSet, ips []net.IP) bool {
	bypass := false
	for _, ip := range ips {
		if geo.Contains(ip) {
			bypass = true
			break
		}
	}

	stm.verdicts.put(hostname, verdict{bypass: bypass, expires: time.Now().Add(verdictTTL)})

	return bypass
}

func (stm *SplitTunnelManager) SetCachedResolver(fn CachedFunc) {
	stm.mu.Lock()
	stm.cached = fn
	stm.publishLocked()
	stm.mu.Unlock()
}

func (stm *SplitTunnelManager) SetResolver(fn ResolveFunc) {
	stm.mu.Lock()
	stm.resolve = fn
	stm.publishLocked()
	stm.mu.Unlock()
	stm.verdicts.reset()
}

type appRule struct {
	Kind    string `json:"kind"`
	Suffix  string `json:"suffix,omitempty"`
	Keyword string `json:"keyword,omitempty"`
	Domain  string `json:"domain,omitempty"`
	CIDR    string `json:"cidr,omitempty"`
	Action  string `json:"action"`
}

func (stm *SplitTunnelManager) LoadAppRules(data string) error {
	if strings.TrimSpace(data) == "" {
		return nil
	}
	var in []appRule
	if err := json.Unmarshal([]byte(data), &in); err != nil {
		return fmt.Errorf("failed to parse app rules: %w", err)
	}

	byCountry := false
	converted := make([]SplitTunnelRule, 0, len(in))
	for _, r := range in {
		if r.Kind == "geoip" {
			byCountry = strings.EqualFold(r.Action, "DIRECT")
			continue
		}
		action := "tunnel"
		switch strings.ToUpper(r.Action) {
		case "DIRECT":
			action = "direct"
		case "REJECT", "BLOCK":
			continue
		}

		var kind, value string
		switch r.Kind {
		case "domain-suffix":
			kind, value = "domain", r.Suffix
		case "domain-exact":
			kind, value = "domain-exact", r.Domain
		case "domain-keyword":
			kind, value = "domain-keyword", r.Keyword
		case "ip-cidr":
			kind, value = "ip", r.CIDR
		}
		if value == "" {
			continue
		}
		converted = append(converted, SplitTunnelRule{
			Type: kind, Value: value, Action: action, Enabled: true, Priority: appRulePriority,
		})
	}

	stm.mu.Lock()
	stm.rules = append(stm.rules, converted...)
	sortRulesByPriority(stm.rules)
	stm.byCountry = byCountry
	stm.recompileLocked()
	stm.mu.Unlock()
	stm.verdicts.reset()
	return nil
}

func (stm *SplitTunnelManager) CreateDefaultRules() {
	rule := SplitTunnelRule{
		Type:        "ip",
		Value:       "192.168.0.0/16",
		Action:      "direct",
		Description: "Local network (192.168.x.x)",
		Enabled:     true,
		Priority:    100,
	}
	stm.AddRule(&rule)

	rule = SplitTunnelRule{
		Type:        "ip",
		Value:       "10.0.0.0/8",
		Action:      "direct",
		Description: "Local network (10.x.x.x)",
		Enabled:     true,
		Priority:    100,
	}
	stm.AddRule(&rule)

	rule = SplitTunnelRule{
		Type:        "ip",
		Value:       "172.16.0.0/12",
		Action:      "direct",
		Description: "Local network (172.16-31.x.x)",
		Enabled:     true,
		Priority:    100,
	}
	stm.AddRule(&rule)

	rule = SplitTunnelRule{
		Type:        "ip",
		Value:       "127.0.0.0/8",
		Action:      "direct",
		Description: "Localhost",
		Enabled:     true,
		Priority:    100,
	}
	stm.AddRule(&rule)
}
