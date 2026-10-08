package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"surface-intel/pkg/graph"
	"surface-intel/pkg/memory"
	"surface-intel/pkg/models"
	"surface-intel/pkg/scope"
)

type AutonomousEngine struct {
	ScopeManager   *scope.ScopeManager
	AssetGraph     *graph.AssetGraph
	Planner        *AIPlanner
	Analyzer       *AIAnalyzer
	Verifier       *Verifier
	ExperienceDB   *memory.ExperienceDB
	LearningEngine *memory.LearningEngine
	httpClient     *http.Client
}

func NewAutonomousEngine(sm *scope.ScopeManager, ag *graph.AssetGraph, expDB *memory.ExperienceDB) *AutonomousEngine {
	if sm == nil {
		sm = scope.NewScopeManager(scope.ScopeConfig{AllowSubdomains: true})
	}
	if ag == nil {
		ag = graph.NewAssetGraph()
	}
	if expDB == nil {
		expDB = memory.NewExperienceDB()
	}

	return &AutonomousEngine{
		ScopeManager:   sm,
		AssetGraph:     ag,
		Planner:        NewAIPlanner(expDB),
		Analyzer:       NewAIAnalyzer(),
		Verifier:       NewVerifier(),
		ExperienceDB:   expDB,
		LearningEngine: memory.NewLearningEngine(expDB),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// BuildGraphFromRecon populates the Asset Graph from discovery results.
func (ae *AutonomousEngine) BuildGraphFromRecon(targetDomain string, subdomains []models.Subdomain, services []models.HTTPService, endpoints []models.Endpoint) {
	targetNodeID := fmt.Sprintf("target_%s", targetDomain)
	ae.AssetGraph.AddNode(graph.Node{
		ID:    targetNodeID,
		Type:  graph.NodeTarget,
		Label: targetDomain,
		Properties: map[string]interface{}{
			"domain": targetDomain,
		},
	})

	for _, sub := range subdomains {
		hostNodeID := fmt.Sprintf("host_%s", sub.Host)
		ipsStr := strings.Join(sub.IPs, ",")
		ae.AssetGraph.AddNode(graph.Node{
			ID:    hostNodeID,
			Type:  graph.NodeHost,
			Label: sub.Host,
			Properties: map[string]interface{}{
				"source": sub.Source,
				"ip":     ipsStr,
			},
		})
		ae.AssetGraph.AddEdge(targetNodeID, hostNodeID, "RESOLVES_TO")
	}

	for _, svc := range services {
		svcNodeID := fmt.Sprintf("svc_%s", svc.URL)
		ae.AssetGraph.AddNode(graph.Node{
			ID:    svcNodeID,
			Type:  graph.NodeService,
			Label: svc.URL,
			Properties: map[string]interface{}{
				"status_code": svc.StatusCode,
				"title":       svc.Title,
				"web_server":  svc.WebServer,
			},
		})

		// Connect to corresponding host
		for _, sub := range subdomains {
			if strings.Contains(svc.URL, sub.Host) {
				hostNodeID := fmt.Sprintf("host_%s", sub.Host)
				ae.AssetGraph.AddEdge(hostNodeID, svcNodeID, "EXPOSES")
				break
			}
		}

		for _, tech := range svc.TechStack {
			techNodeID := fmt.Sprintf("tech_%s", strings.ToLower(tech))
			ae.AssetGraph.AddNode(graph.Node{
				ID:    techNodeID,
				Type:  graph.NodeTech,
				Label: tech,
			})
			ae.AssetGraph.AddEdge(svcNodeID, techNodeID, "DETECTED")
		}
	}

	for _, ep := range endpoints {
		epNodeID := fmt.Sprintf("ep_%s", ep.URL)
		ae.AssetGraph.AddNode(graph.Node{
			ID:    epNodeID,
			Type:  graph.NodeEndpoint,
			Label: ep.URL,
			Properties: map[string]interface{}{
				"method": ep.Method,
				"params": ep.Params,
			},
		})

		for _, svc := range services {
			if strings.HasPrefix(ep.URL, svc.URL) {
				svcNodeID := fmt.Sprintf("svc_%s", svc.URL)
				ae.AssetGraph.AddEdge(svcNodeID, epNodeID, "ROUTES_TO")
				break
			}
		}

		for _, param := range ep.Params {
			paramNodeID := fmt.Sprintf("param_%s_%s", ep.URL, param)
			ae.AssetGraph.AddNode(graph.Node{
				ID:    paramNodeID,
				Type:  graph.NodeParameter,
				Label: param,
			})
			ae.AssetGraph.AddEdge(epNodeID, paramNodeID, "ACCEPTS")
		}
	}
}

// ExecutionCycle runs the AI Planner -> Tool -> AI Analyzer -> Verifier -> Learning Engine cycle.
func (ae *AutonomousEngine) RunCycle(ctx context.Context, eventChan chan<- models.PipelineEvent) []models.Finding {
	var confirmedFindings []models.Finding

	eventChan <- models.PipelineEvent{
		Stage:     models.StageVulnScan,
		Level:     "INFO",
		Message:   "[AI PLANNER] Evaluating Asset Graph nodes and consulting 4-Tier Memory...",
		Timestamp: time.Now(),
	}

	// 1. AI PLANNER: Formulate ranked Hypotheses
	hypotheses := ae.Planner.FormulatePlan(ae.AssetGraph)
	eventChan <- models.PipelineEvent{
		Stage:     models.StageVulnScan,
		Level:     "INFO",
		Message:   fmt.Sprintf("[AI PLANNER] Formulated %d prioritized hypotheses with strategic confidence weighting", len(hypotheses)),
		Timestamp: time.Now(),
	}

	for _, hyp := range hypotheses {
		select {
		case <-ctx.Done():
			return confirmedFindings
		default:
		}

		// Verify Scope Manager constraints
		if !ae.ScopeManager.IsInScope(hyp.TargetURL) {
			continue
		}

		eventChan <- models.PipelineEvent{
			Stage:     models.StageVulnScan,
			Level:     "INFO",
			Message:   fmt.Sprintf("[DISPATCH] Testing Hypothesis: '%s' | Tool: [%s] | Target: %s", hyp.Theory, hyp.ToolSelected, hyp.TargetURL),
			Timestamp: time.Now(),
		}

		// 2. TOOL EXECUTION LAYER: Execute selected probe
		statusCode, headers, body := ae.executeProbe(ctx, hyp.TargetURL)

		// 3. AI ANALYZER: Find patterns and construct Candidate Bug
		candidate := ae.Analyzer.AnalyzeProbeOutcome(hyp, statusCode, headers, body)
		if candidate == nil {
			// Record trial with no confirmation to update Learning Engine
			ae.LearningEngine.LearnFromExecution(
				hyp.Context,
				hyp.Theory,
				hyp.PreferredAction,
				hyp.ToolSelected,
				false,
				"Probe returned non-matching status or missing target pattern",
				"No exposure detected",
				hyp.TargetURL,
			)
			continue
		}

		eventChan <- models.PipelineEvent{
			Stage:     models.StageVulnScan,
			Level:     "WARN",
			Message:   fmt.Sprintf("[AI ANALYZER] Synthesized Candidate Bug: '%s' on %s. Forwarding to Verifier...", candidate.Title, candidate.TargetURL),
			Timestamp: time.Now(),
		}

		// 4. VERIFIER: Evidence check, reproduction, and false positive reduction
		vResult := ae.Verifier.VerifyCandidate(candidate)

		if vResult.Confirmed {
			eventChan <- models.PipelineEvent{
				Stage:     models.StageVulnScan,
				Level:     "SUCCESS",
				Message:   fmt.Sprintf("[VERIFIER - CONFIRMED] %s | CVSS: %.1f | %s", candidate.Title, vResult.CVSSScore, vResult.ReproducedProof),
				Timestamp: time.Now(),
			}

			// Add to Finding Memory
			findingMem := memory.FindingMemory{
				ID:          fmt.Sprintf("fmem_%d", time.Now().UnixNano()),
				Type:        candidate.Title,
				CWE:         candidate.CWE,
				Confirmed:   true,
				Pattern:     hyp.Context,
				TargetURL:   candidate.TargetURL,
				Evidence:    candidate.RawEvidence,
				ToolPath:    candidate.ToolPath,
				Remediation: strings.Join(vResult.RemediationSteps, "; "),
				RecordedAt:  time.Now(),
			}
			ae.ExperienceDB.AddFinding(findingMem)

			// Update Learning Engine (Positive Bayesian adjustment)
			ae.LearningEngine.LearnFromExecution(
				hyp.Context,
				hyp.Theory,
				hyp.PreferredAction,
				hyp.ToolSelected,
				true,
				vResult.Reason,
				"",
				candidate.TargetURL,
			)

			confirmedFindings = append(confirmedFindings, models.Finding{
				AssetURL:    candidate.TargetURL,
				Title:       candidate.Title,
				Severity:    candidate.Severity,
				CVSSScore:   vResult.CVSSScore,
				TemplateID:  strings.ToLower(strings.ReplaceAll(candidate.Title, " ", "-")),
				Description: vResult.Reason,
				MatchString: candidate.RawEvidence,
				Evidence: models.Evidence{
					ResponseText: candidate.RawEvidence,
					CurlCommand:  fmt.Sprintf("curl -i %s", candidate.TargetURL),
				},
				Status: "Open",
			})
		} else {
			eventChan <- models.PipelineEvent{
				Stage:     models.StageVulnScan,
				Level:     "INFO",
				Message:   fmt.Sprintf("[VERIFIER - REJECTED FP] %s | Reason: %s", candidate.Title, vResult.Reason),
				Timestamp: time.Now(),
			}

			// Update Learning Engine (Failure memory + penalty adjustment)
			ae.LearningEngine.LearnFromExecution(
				hyp.Context,
				hyp.Theory,
				hyp.PreferredAction,
				hyp.ToolSelected,
				false,
				vResult.Reason,
				vResult.ActualIssue,
				candidate.TargetURL,
			)
		}
	}

	eventChan <- models.PipelineEvent{
		Stage:     models.StageVulnScan,
		Level:     "INFO",
		Message:   fmt.Sprintf("[LEARNING ENGINE] Experience DB updated. 4-Tier Memory synchronised for future planning cycles."),
		Timestamp: time.Now(),
	}

	return confirmedFindings
}

func (ae *AutonomousEngine) executeProbe(ctx context.Context, targetURL string) (int, map[string]string, string) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return 0, nil, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Darksight-AutonomousProbe/1.0)")

	resp, err := ae.httpClient.Do(req)
	if err != nil {
		return 0, nil, ""
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	return resp.StatusCode, headers, string(bodyBytes)
}
