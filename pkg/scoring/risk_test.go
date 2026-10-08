package scoring

import (
	"testing"
	"surface-intel/pkg/models"
)

func TestGenerateDedupHash(t *testing.T) {
	hash1 := GenerateDedupHash("tgt_1", "https://example.com/api", "xss-template", "Reflected XSS")
	hash2 := GenerateDedupHash("tgt_1", "HTTPS://EXAMPLE.COM/API", "XSS-TEMPLATE", "reflected xss")

	if hash1 != hash2 {
		t.Errorf("Expected deterministic hashes to match regardless of case, got %s vs %s", hash1, hash2)
	}
}

func TestCalculateTargetRiskScore(t *testing.T) {
	findings := []models.Finding{
		{Severity: "Critical", CVSSScore: 9.8},
		{Severity: "High", CVSSScore: 7.5},
	}

	score := CalculateTargetRiskScore(findings, 5)
	if score <= 0 || score > 10.0 {
		t.Errorf("Expected risk score between 0.0 and 10.0, got %f", score)
	}
}
