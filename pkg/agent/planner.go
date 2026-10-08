package agent

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"surface-intel/pkg/graph"
	"surface-intel/pkg/memory"
)

type AIPlanner struct {
	ExperienceDB *memory.ExperienceDB
}

func NewAIPlanner(expDB *memory.ExperienceDB) *AIPlanner {
	return &AIPlanner{ExperienceDB: expDB}
}

// FormulatePlan analyzes the Asset Graph and generates ranked Hypotheses using 4-tier memory.
func (p *AIPlanner) FormulatePlan(g *graph.AssetGraph) []Hypothesis {
	var hypotheses []Hypothesis

	endpoints := g.GetNodesByType(graph.NodeEndpoint)
	services := g.GetNodesByType(graph.NodeService)

	// 1. Analyze Active HTTP Services for Security Posture Hypotheses
	for _, svc := range services {
		svcURL := svc.Label
		contextStr := "Active Web Service"
		toolRankings := p.ExperienceDB.GetToolRankings(contextStr)

		// Best tool choice
		bestTool := "http_probe"
		if toolRankings["nuclei"] > toolRankings["http_probe"] {
			bestTool = "nuclei"
		}

		// Security header hypothesis
		h := Hypothesis{
			ID:              fmt.Sprintf("hyp_%d", time.Now().UnixNano()),
			Context:         contextStr,
			TargetURL:       svcURL,
			Theory:          "Missing Security Headers (HSTS / Clickjacking frame-ancestors)",
			PreferredAction: "Inspect HTTP response headers for Strict-Transport-Security & X-Frame-Options",
			ToolSelected:    bestTool,
			Confidence:      88.0,
			PriorityScore:   60.0,
			CreatedAt:       time.Now(),
		}
		hypotheses = append(hypotheses, h)
	}

	// 2. Analyze Crawled Endpoints for Tactical Hypotheses
	for _, ep := range endpoints {
		epURL := ep.Label
		lowerURL := strings.ToLower(epURL)

		// Context A: REST API with object / user ID
		if strings.Contains(lowerURL, "/users/") || strings.Contains(lowerURL, "/user/") || strings.Contains(lowerURL, "/orders/") || strings.Contains(lowerURL, "/account/") {
			contextStr := "REST API + numeric object IDs"
			strategies := p.ExperienceDB.QueryStrategies(contextStr)
			toolRankings := p.ExperienceDB.GetToolRankings("REST API target")

			bestAction := "HTTP request + compare authenticated/unauthenticated behavior"
			confidence := 73.0
			if len(strategies) > 0 {
				bestAction = strategies[0].BestAction
				confidence = strategies[0].SuccessRate
			}

			// Choose best tool
			bestTool := "http_probe"
			if toolRankings["browser"] > toolRankings["http_probe"] {
				bestTool = "browser"
			}

			// Check past failure memory to avoid repeated false positives
			failures := p.ExperienceDB.RetrieveRelevantFailures(contextStr, "IDOR")
			penalty := 0.0
			if len(failures) > 2 {
				penalty = 15.0 // De-prioritize if history shows frequent false positives
			}

			h := Hypothesis{
				ID:              fmt.Sprintf("hyp_%d", time.Now().UnixNano()),
				Context:         contextStr,
				TargetURL:       epURL,
				Theory:          "Authorization bypass / IDOR on user object",
				PreferredAction: bestAction,
				ToolSelected:    bestTool,
				Confidence:      confidence - penalty,
				PriorityScore:   85.0 - penalty,
				CreatedAt:       time.Now(),
			}
			hypotheses = append(hypotheses, h)
		}

		// Context B: Exposed Environment Configuration
		if strings.Contains(lowerURL, "/.env") || strings.Contains(lowerURL, "/config") {
			contextStr := "Static server configuration paths"
			strategies := p.ExperienceDB.QueryStrategies(contextStr)
			toolRankings := p.ExperienceDB.GetToolRankings("Static asset")

			confidence := 35.0
			bestAction := "HTTP GET /.env + verify key patterns (APP_KEY, DB_PASSWORD)"
			if len(strategies) > 0 {
				bestAction = strategies[0].BestAction
				confidence = strategies[0].SuccessRate
			}

			bestTool := "http_probe"
			if toolRankings["nuclei"] > toolRankings["http_probe"] {
				bestTool = "nuclei"
			}

			h := Hypothesis{
				ID:              fmt.Sprintf("hyp_%d", time.Now().UnixNano()),
				Context:         contextStr,
				TargetURL:       epURL,
				Theory:          "Environment file exposure (.env, config.json)",
				PreferredAction: bestAction,
				ToolSelected:    bestTool,
				Confidence:      confidence,
				PriorityScore:   75.0,
				CreatedAt:       time.Now(),
			}
			hypotheses = append(hypotheses, h)
		}

		// Context C: Telemetry & Metrics
		if strings.Contains(lowerURL, "/metrics") {
			contextStr := "Application runtime metrics"
			h := Hypothesis{
				ID:              fmt.Sprintf("hyp_%d", time.Now().UnixNano()),
				Context:         contextStr,
				TargetURL:       epURL,
				Theory:          "Unauthenticated Prometheus Telemetry Exposure",
				PreferredAction: "HTTP GET /metrics + check for # HELP / go_goroutines",
				ToolSelected:    "http_probe",
				Confidence:      70.0,
				PriorityScore:   50.0,
				CreatedAt:       time.Now(),
			}
			hypotheses = append(hypotheses, h)
		}

		// Context D: Swagger / OpenAPI specification
		if strings.Contains(lowerURL, "/swagger.json") || strings.Contains(lowerURL, "/api-docs") {
			contextStr := "API schema documentation"
			h := Hypothesis{
				ID:              fmt.Sprintf("hyp_%d", time.Now().UnixNano()),
				Context:         contextStr,
				TargetURL:       epURL,
				Theory:          "Public OpenAPI / Swagger Specification Disclosure",
				PreferredAction: "HTTP GET /swagger.json + check for openapi/swagger schema",
				ToolSelected:    "http_probe",
				Confidence:      80.0,
				PriorityScore:   45.0,
				CreatedAt:       time.Now(),
			}
			hypotheses = append(hypotheses, h)
		}
	}

	// Sort hypotheses descending by priority and confidence
	sort.Slice(hypotheses, func(i, j int) bool {
		return hypotheses[i].PriorityScore > hypotheses[j].PriorityScore
	})

	return hypotheses
}
