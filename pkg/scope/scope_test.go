package scope

import (
	"testing"
)

func TestScopeManager(t *testing.T) {
	cfg := ScopeConfig{
		TargetDomain:    "target.com",
		AllowSubdomains: true,
		ExcludedHosts:   []string{"admin.target.com", "vpn.target.com"},
		AllowedCIDRs:    []string{"192.168.1.0/24"},
	}
	sm := NewScopeManager(cfg)

	tests := []struct {
		host     string
		expected bool
	}{
		{"target.com", true},
		{"api.target.com", true},
		{"dev.api.target.com", true},
		{"admin.target.com", false},      // explicitly excluded
		{"sub.admin.target.com", false},  // child of excluded
		{"evil.com", false},              // out of scope
		{"target.com.attacker.com", false},// domain spoofing attempt
		{"192.168.1.50", true},           // within CIDR
		{"10.0.0.1", false},              // outside CIDR
	}

	for _, tc := range tests {
		result := sm.IsInScope(tc.host)
		if result != tc.expected {
			t.Errorf("IsInScope(%q) = %v; want %v", tc.host, result, tc.expected)
		}
	}
}
