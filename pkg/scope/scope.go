package scope

import (
	"net"
	"net/url"
	"strings"
)

// ScopeConfig defines target inclusion and exclusion rules.
type ScopeConfig struct {
	TargetDomain    string   `json:"target_domain"`
	IncludedHosts   []string `json:"included_hosts"`
	ExcludedHosts   []string `json:"excluded_hosts"`
	AllowSubdomains bool     `json:"allow_subdomains"`
	AllowedCIDRs    []string `json:"allowed_cidrs"`
	RateLimitRPS    int      `json:"rate_limit_rps"`
}

// ScopeManager validates if an asset or URL is within authorized scope.
type ScopeManager struct {
	Config ScopeConfig
}

func NewScopeManager(cfg ScopeConfig) *ScopeManager {
	if cfg.RateLimitRPS <= 0 {
		cfg.RateLimitRPS = 10
	}
	return &ScopeManager{Config: cfg}
}

// IsInScope checks if a hostname, IP, or full URL is authorized.
func (sm *ScopeManager) IsInScope(hostOrIPOrURL string) bool {
	raw := strings.ToLower(strings.TrimSpace(hostOrIPOrURL))
	if raw == "" {
		return false
	}

	host := raw
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err == nil {
			host = u.Hostname()
		}
	} else if strings.Contains(raw, "/") {
		idx := strings.Index(raw, "/")
		host = raw[:idx]
	}

	// Remove port if present
	if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(host)
		if err == nil {
			host = h
		}
	}

	// 1. Check explicit exclusions
	for _, excl := range sm.Config.ExcludedHosts {
		excl = strings.ToLower(strings.TrimSpace(excl))
		if host == excl || strings.HasSuffix(host, "."+excl) {
			return false
		}
	}

	// 2. Direct domain match
	target := strings.ToLower(strings.TrimSpace(sm.Config.TargetDomain))
	if host == target {
		return true
	}

	// 3. Subdomain match
	if sm.Config.AllowSubdomains && strings.HasSuffix(host, "."+target) {
		return true
	}

	// 4. Check included host list
	for _, inc := range sm.Config.IncludedHosts {
		if host == strings.ToLower(strings.TrimSpace(inc)) {
			return true
		}
	}

	// 5. Check CIDR ranges for IP addresses
	ip := net.ParseIP(host)
	if ip != nil {
		for _, cidr := range sm.Config.AllowedCIDRs {
			_, subnet, err := net.ParseCIDR(cidr)
			if err == nil && subnet.Contains(ip) {
				return true
			}
		}
	}

	return false
}
