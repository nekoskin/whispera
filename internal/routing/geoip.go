// Package routing provides advanced routing with GeoIP and domain matching
package routing

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// RuleType defines the type of routing rule
type RuleType string

const (
	RuleTypeDomain        RuleType = "domain"         // Exact domain match
	RuleTypeDomainSuffix  RuleType = "domain-suffix"  // Domain suffix match
	RuleTypeDomainKeyword RuleType = "domain-keyword" // Domain keyword match
	RuleTypeDomainRegex   RuleType = "domain-regex"   // Domain regex match
	RuleTypeIP            RuleType = "ip"             // IP or CIDR match
	RuleTypeGeoIP         RuleType = "geoip"          // GeoIP country code
	RuleTypeGeoSite       RuleType = "geosite"        // GeoSite category
	RuleTypePort          RuleType = "port"           // Port match
	RuleTypeFinal         RuleType = "final"          // Default rule
)

// Action defines what to do with matched traffic
type Action string

const (
	ActionDirect Action = "direct" // Direct connection (bypass VPN)
	ActionProxy  Action = "proxy"  // Through VPN
	ActionReject Action = "reject" // Block connection
)

// Rule represents a routing rule
type Rule struct {
	Type   RuleType
	Value  string
	Action Action
	Tag    string         // Optional tag for identification
	regex  *regexp.Regexp // Compiled regex for regex rules
}

// GeoIPDatabase holds GeoIP data
type GeoIPDatabase struct {
	mu       sync.RWMutex
	ipRanges map[string][]*net.IPNet // country code -> IP ranges
	loaded   bool
}

// GeoSiteDatabase holds domain lists by category
type GeoSiteDatabase struct {
	mu       sync.RWMutex
	domains  map[string][]string         // category -> domains
	suffixes map[string][]string         // category -> domain suffixes
	keywords map[string][]string         // category -> keywords
	regexps  map[string][]*regexp.Regexp // category -> compiled regexps
	loaded   bool
}

// Router handles routing decisions
type Router struct {
	rules   []Rule
	geoIP   *GeoIPDatabase
	geoSite *GeoSiteDatabase
	mu      sync.RWMutex

	// Stats
	matches uint64
	misses  uint64
}

// NewRouter creates a new router
func NewRouter() *Router {
	return &Router{
		rules: make([]Rule, 0),
		geoIP: &GeoIPDatabase{ipRanges: make(map[string][]*net.IPNet)},
		geoSite: &GeoSiteDatabase{
			domains:  make(map[string][]string),
			suffixes: make(map[string][]string),
			keywords: make(map[string][]string),
			regexps:  make(map[string][]*regexp.Regexp),
		},
	}
}

// AddRule adds a routing rule
func (r *Router) AddRule(rule Rule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Compile regex if needed
	if rule.Type == RuleTypeDomainRegex {
		re, err := regexp.Compile(rule.Value)
		if err != nil {
			return err
		}
		rule.regex = re
	}

	r.rules = append(r.rules, rule)
	return nil
}

// LoadGeoIPFile loads GeoIP data from a file
// Format: country_code,cidr (one per line)
func (r *Router) LoadGeoIPFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	r.geoIP.mu.Lock()
	defer r.geoIP.mu.Unlock()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			continue
		}

		code := strings.ToUpper(strings.TrimSpace(parts[0]))
		cidr := strings.TrimSpace(parts[1])

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		r.geoIP.ipRanges[code] = append(r.geoIP.ipRanges[code], ipNet)
	}

	r.geoIP.loaded = true
	return scanner.Err()
}

// LoadGeoSiteFile loads GeoSite data from a file
// Format: category:type:value (one per line)
// Types: domain, suffix, keyword, regexp
func (r *Router) LoadGeoSiteFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	r.geoSite.mu.Lock()
	defer r.geoSite.mu.Unlock()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			continue
		}

		category := strings.ToLower(parts[0])
		ruleType := "domain"
		value := parts[1]

		if len(parts) == 3 {
			ruleType = parts[1]
			value = parts[2]
		}

		switch ruleType {
		case "domain":
			r.geoSite.domains[category] = append(r.geoSite.domains[category], strings.ToLower(value))
		case "suffix":
			r.geoSite.suffixes[category] = append(r.geoSite.suffixes[category], strings.ToLower(value))
		case "keyword":
			r.geoSite.keywords[category] = append(r.geoSite.keywords[category], strings.ToLower(value))
		case "regexp":
			if re, err := regexp.Compile(value); err == nil {
				r.geoSite.regexps[category] = append(r.geoSite.regexps[category], re)
			}
		}
	}

	r.geoSite.loaded = true
	return scanner.Err()
}

// LoadGeoData loads GeoIP and GeoSite from a directory
func (r *Router) LoadGeoData(dir string) error {
	geoIPPath := filepath.Join(dir, "geoip.txt")
	geoSitePath := filepath.Join(dir, "geosite.txt")

	if _, err := os.Stat(geoIPPath); err == nil {
		if err := r.LoadGeoIPFile(geoIPPath); err != nil {
			return err
		}
	}

	if _, err := os.Stat(geoSitePath); err == nil {
		if err := r.LoadGeoSiteFile(geoSitePath); err != nil {
			return err
		}
	}

	return nil
}

// Match finds the action for a given destination
func (r *Router) Match(destIP net.IP, destDomain string, destPort int) Action {
	r.mu.RLock()
	defer r.mu.RUnlock()

	domain := strings.ToLower(destDomain)

	for _, rule := range r.rules {
		matched := false

		switch rule.Type {
		case RuleTypeDomain:
			matched = domain == strings.ToLower(rule.Value)

		case RuleTypeDomainSuffix:
			suffix := strings.ToLower(rule.Value)
			matched = domain == suffix || strings.HasSuffix(domain, "."+suffix)

		case RuleTypeDomainKeyword:
			matched = strings.Contains(domain, strings.ToLower(rule.Value))

		case RuleTypeDomainRegex:
			if rule.regex != nil {
				matched = rule.regex.MatchString(domain)
			}

		case RuleTypeIP:
			if destIP != nil {
				_, ipNet, err := net.ParseCIDR(rule.Value)
				if err == nil {
					matched = ipNet.Contains(destIP)
				} else {
					// Try as single IP
					ruleIP := net.ParseIP(rule.Value)
					matched = ruleIP != nil && ruleIP.Equal(destIP)
				}
			}

		case RuleTypeGeoIP:
			if destIP != nil {
				matched = r.matchGeoIP(destIP, rule.Value)
			}

		case RuleTypeGeoSite:
			matched = r.matchGeoSite(domain, rule.Value)

		case RuleTypePort:
			// Parse port or port range
			matched = r.matchPort(destPort, rule.Value)

		case RuleTypeFinal:
			matched = true
		}

		if matched {
			r.matches++
			return rule.Action
		}
	}

	r.misses++
	return ActionProxy // Default to proxy
}

// matchGeoIP checks if IP matches a country code
func (r *Router) matchGeoIP(ip net.IP, code string) bool {
	r.geoIP.mu.RLock()
	defer r.geoIP.mu.RUnlock()

	code = strings.ToUpper(code)
	ranges, ok := r.geoIP.ipRanges[code]
	if !ok {
		return false
	}

	for _, ipNet := range ranges {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// matchGeoSite checks if domain matches a category
func (r *Router) matchGeoSite(domain string, category string) bool {
	r.geoSite.mu.RLock()
	defer r.geoSite.mu.RUnlock()

	category = strings.ToLower(category)

	// Check exact domains
	if domains, ok := r.geoSite.domains[category]; ok {
		for _, d := range domains {
			if domain == d {
				return true
			}
		}
	}

	// Check suffixes
	if suffixes, ok := r.geoSite.suffixes[category]; ok {
		for _, s := range suffixes {
			if domain == s || strings.HasSuffix(domain, "."+s) {
				return true
			}
		}
	}

	// Check keywords
	if keywords, ok := r.geoSite.keywords[category]; ok {
		for _, k := range keywords {
			if strings.Contains(domain, k) {
				return true
			}
		}
	}

	// Check regexps
	if regexps, ok := r.geoSite.regexps[category]; ok {
		for _, re := range regexps {
			if re.MatchString(domain) {
				return true
			}
		}
	}

	return false
}

// matchPort checks if port matches value (single or range)
func (r *Router) matchPort(port int, value string) bool {
	if strings.Contains(value, "-") {
		// Port range
		parts := strings.SplitN(value, "-", 2)
		if len(parts) == 2 {
			var start, end int
			if _, err := parseIntFromString(parts[0], &start); err != nil {
				return false
			}
			if _, err := parseIntFromString(parts[1], &end); err != nil {
				return false
			}
			return port >= start && port <= end
		}
	}

	// Single port
	var rulePort int
	if _, err := parseIntFromString(value, &rulePort); err != nil {
		return false
	}
	return port == rulePort
}

func parseIntFromString(s string, result *int) (bool, error) {
	s = strings.TrimSpace(s)
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return false, nil
		}
		n = n*10 + int(c-'0')
	}
	*result = n
	return true, nil
}

// Stats returns routing statistics
func (r *Router) Stats() (matches, misses uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.matches, r.misses
}

// GetCategories returns available GeoSite categories
func (r *Router) GetCategories() []string {
	r.geoSite.mu.RLock()
	defer r.geoSite.mu.RUnlock()

	categories := make(map[string]bool)
	for k := range r.geoSite.domains {
		categories[k] = true
	}
	for k := range r.geoSite.suffixes {
		categories[k] = true
	}

	result := make([]string, 0, len(categories))
	for k := range categories {
		result = append(result, k)
	}
	return result
}

// GetCountries returns available GeoIP country codes
func (r *Router) GetCountries() []string {
	r.geoIP.mu.RLock()
	defer r.geoIP.mu.RUnlock()

	result := make([]string, 0, len(r.geoIP.ipRanges))
	for k := range r.geoIP.ipRanges {
		result = append(result, k)
	}
	return result
}
