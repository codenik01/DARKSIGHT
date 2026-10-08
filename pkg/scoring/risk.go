package scoring

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"surface-intel/pkg/models"
)

// GenerateDedupHash creates a deterministic SHA-256 fingerprint for a finding.
func GenerateDedupHash(targetID, assetURL, templateID, title string) string {
	raw := fmt.Sprintf("%s|%s|%s|%s", targetID, strings.ToLower(assetURL), strings.ToLower(templateID), strings.ToLower(title))
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash)
}

// CalculateTargetRiskScore calculates a weighted risk score (0.0 to 10.0) based on severity distribution and asset posture.
func CalculateTargetRiskScore(findings []models.Finding, totalServices int) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	var totalWeight float64

	severityWeights := map[string]float64{
		"CRITICAL": 10.0,
		"HIGH":     7.5,
		"MEDIUM":   4.5,
		"LOW":      2.0,
		"INFO":     0.5,
	}

	for _, f := range findings {
		sevUpper := strings.ToUpper(f.Severity)
		weight, ok := severityWeights[sevUpper]
		if !ok {
			weight = 1.0
		}
		if f.CVSSScore > 0 {
			weight = f.CVSSScore
		}
		totalWeight += weight
	}

	// Dynamic logarithmic scaling to prevent overflow on large finding counts
	score := math.Log10(1.0+totalWeight) * 4.0
	if score > 10.0 {
		score = 10.0
	}

	return math.Round(score*10) / 10
}
