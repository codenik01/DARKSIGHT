package agent

import (
	"strings"
	"time"
)

type AIAnalyzer struct{}

func NewAIAnalyzer() *AIAnalyzer {
	return &AIAnalyzer{}
}

// AnalyzeProbeOutcome inspects probe output and synthesizes a CandidateBug if patterns match.
func (a *AIAnalyzer) AnalyzeProbeOutcome(hyp Hypothesis, statusCode int, headers map[string]string, body string) *CandidateBug {
	lowerBody := strings.ToLower(body)

	// 1. Analyze Environment File Hypothesis
	if strings.Contains(hyp.Theory, "Environment file") {
		if statusCode == 200 && (strings.Contains(body, "APP_KEY=") || strings.Contains(body, "DB_PASSWORD=") || strings.Contains(body, "AWS_ACCESS_KEY")) {
			return &CandidateBug{
				HypothesisID: hyp.ID,
				Title:        "Environment Configuration File Exposure (.env)",
				CWE:          "CWE-552",
				Severity:     "High",
				TargetURL:    hyp.TargetURL,
				RawEvidence:  body[:min(len(body), 512)],
				ToolPath:     []string{hyp.ToolSelected, "pattern_matcher"},
				DiscoveredAt: time.Now(),
			}
		}
	}

	// 2. Analyze Telemetry Metrics Hypothesis
	if strings.Contains(hyp.Theory, "Prometheus") {
		if statusCode == 200 && (strings.Contains(body, "# HELP") || strings.Contains(body, "go_goroutines") || strings.Contains(body, "http_requests_total")) {
			return &CandidateBug{
				HypothesisID: hyp.ID,
				Title:        "Unauthenticated Prometheus Telemetry Metrics Endpoint",
				CWE:          "CWE-200",
				Severity:     "Medium",
				TargetURL:    hyp.TargetURL,
				RawEvidence:  body[:min(len(body), 256)],
				ToolPath:     []string{hyp.ToolSelected},
				DiscoveredAt: time.Now(),
			}
		}
	}

	// 3. Analyze OpenAPI Specification Hypothesis
	if strings.Contains(hyp.Theory, "OpenAPI") || strings.Contains(hyp.Theory, "Swagger") {
		if statusCode == 200 && (strings.Contains(lowerBody, `"openapi":`) || strings.Contains(lowerBody, `"swagger":`)) {
			return &CandidateBug{
				HypothesisID: hyp.ID,
				Title:        "Open API Documentation Disclosed",
				CWE:          "CWE-200",
				Severity:     "Info",
				TargetURL:    hyp.TargetURL,
				RawEvidence:  "OpenAPI JSON specification detected",
				ToolPath:     []string{hyp.ToolSelected},
				DiscoveredAt: time.Now(),
			}
		}
	}

	// 4. Analyze Security Headers Hypothesis
	if strings.Contains(hyp.Theory, "Missing Security Headers") && statusCode == 200 {
		var missing []string
		if strings.HasPrefix(hyp.TargetURL, "https://") && headers["Strict-Transport-Security"] == "" {
			missing = append(missing, "Strict-Transport-Security (HSTS)")
		}
		if headers["X-Frame-Options"] == "" && !strings.Contains(headers["Content-Security-Policy"], "frame-ancestors") {
			missing = append(missing, "X-Frame-Options (Clickjacking Protection)")
		}

		if len(missing) > 0 {
			return &CandidateBug{
				HypothesisID: hyp.ID,
				Title:        "Missing Core Web Security Headers (" + strings.Join(missing, ", ") + ")",
				CWE:          "CWE-693",
				Severity:     "Low",
				TargetURL:    hyp.TargetURL,
				RawEvidence:  "Server response lacks: " + strings.Join(missing, ", "),
				ToolPath:     []string{hyp.ToolSelected, "header_inspector"},
				DiscoveredAt: time.Now(),
			}
		}
	}

	return nil
}
