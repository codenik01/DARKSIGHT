package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"surface-intel/pkg/agent"
	"surface-intel/pkg/ai"
	"surface-intel/pkg/db"
	"surface-intel/pkg/graph"
	"surface-intel/pkg/memory"
	"surface-intel/pkg/models"
	"surface-intel/pkg/scope"
	"surface-intel/pkg/scoring"
)

type PipelineOrchestrator struct {
	store            *db.Store
	runner           *ToolRunner
	aiClient         *ai.AIClient
	subscribers      map[chan models.PipelineEvent]struct{}
	subMu            sync.Mutex
	assetGraph       *graph.AssetGraph
	experienceDB     *memory.ExperienceDB
	autonomousEngine *agent.AutonomousEngine
	scopeManager     *scope.ScopeManager
}

func NewPipelineOrchestrator(store *db.Store, runner *ToolRunner, aiClient *ai.AIClient) *PipelineOrchestrator {
	if aiClient == nil {
		aiClient = ai.NewAIClient()
	}
	ag := graph.NewAssetGraph()
	expDB := memory.NewExperienceDB()
	sm := scope.NewScopeManager(scope.ScopeConfig{AllowSubdomains: true})
	ae := agent.NewAutonomousEngine(sm, ag, expDB)

	return &PipelineOrchestrator{
		store:            store,
		runner:           runner,
		aiClient:         aiClient,
		subscribers:      make(map[chan models.PipelineEvent]struct{}),
		assetGraph:       ag,
		experienceDB:     expDB,
		autonomousEngine: ae,
		scopeManager:     sm,
	}
}

func (po *PipelineOrchestrator) GetAssetGraph() *graph.AssetGraph {
	return po.assetGraph
}

func (po *PipelineOrchestrator) GetExperienceDB() *memory.ExperienceDB {
	return po.experienceDB
}

// Subscribe returns a channel that receives live pipeline events.
func (po *PipelineOrchestrator) Subscribe() chan models.PipelineEvent {
	po.subMu.Lock()
	defer po.subMu.Unlock()
	ch := make(chan models.PipelineEvent, 100)
	po.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes an event listener.
func (po *PipelineOrchestrator) Unsubscribe(ch chan models.PipelineEvent) {
	po.subMu.Lock()
	defer po.subMu.Unlock()
	delete(po.subscribers, ch)
	close(ch)
}

func (po *PipelineOrchestrator) broadcast(event models.PipelineEvent) {
	po.subMu.Lock()
	defer po.subMu.Unlock()
	for ch := range po.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

// CleanDomain strips protocol schemes, trailing slashes, and ports from input.
func CleanDomain(input string) string {
	d := strings.TrimSpace(input)
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	if idx := strings.Index(d, "/"); idx != -1 {
		d = d[:idx]
	}
	if idx := strings.Index(d, ":"); idx != -1 {
		d = d[:idx]
	}
	return d
}

// ExecuteRun executes the full multi-stage research and intelligence pipeline on a target domain.
func (po *PipelineOrchestrator) ExecuteRun(ctx context.Context, inputDomain string, workflow string) (*models.PipelineRun, error) {
	domain := CleanDomain(inputDomain)
	runID := fmt.Sprintf("run_%d", time.Now().UnixNano())

	target, err := po.store.GetTargetByDomain(domain)
	if err != nil {
		target = &models.Target{
			ID:          fmt.Sprintf("tgt_%s", runID),
			Domain:      domain,
			Name:        domain,
			Description: "Target research scope",
		}
		if err := po.store.SaveTarget(target); err != nil {
			return nil, fmt.Errorf("failed to save target: %w", err)
		}
		target, _ = po.store.GetTargetByDomain(domain)
	}
	po.scopeManager = scope.NewScopeManager(scope.ScopeConfig{
		TargetDomain:    domain,
		AllowSubdomains: true,
	})
	po.autonomousEngine.ScopeManager = po.scopeManager

	run := &models.PipelineRun{
		ID:           runID,
		TargetID:     target.ID,
		Workflow:     workflow,
		Status:       "Running",
		ProgressPct:  5,
		CurrentStage: string(models.StageSubdomainDiscovery),
		StartTime:    time.Now(),
	}
	_ = po.store.SavePipelineRun(run)

	eventChan := make(chan models.PipelineEvent, 50)
	go func() {
		for ev := range eventChan {
			ev.RunID = runID
			po.broadcast(ev)
		}
	}()

	po.broadcast(models.PipelineEvent{
		RunID:     runID,
		Stage:     models.StageSubdomainDiscovery,
		Level:     "INFO",
		Message:   fmt.Sprintf("Pipeline started for target domain %s [Run ID: %s]", domain, runID),
		Progress:  5,
		Timestamp: time.Now(),
	})

	// Stage 1: Subdomain Discovery
	subdomains, err := po.runner.RunSubdomainDiscovery(ctx, domain, eventChan)
	if err != nil {
		run.Status = "Failed"
		_ = po.store.SavePipelineRun(run)
		close(eventChan)
		return run, err
	}

	for i := range subdomains {
		subdomains[i].ID = fmt.Sprintf("sub_%s_%d", runID, i)
		subdomains[i].TargetID = target.ID
		_ = po.store.SaveSubdomain(&subdomains[i])
	}
	run.TotalSubdomains = len(subdomains)
	run.ProgressPct = 30
	run.CurrentStage = string(models.StageHTTPResolution)
	_ = po.store.SavePipelineRun(run)

	// Stage 2: HTTP Resolution & Tech Detection
	var hostList []string
	for _, sub := range subdomains {
		hostList = append(hostList, sub.Host)
	}

	services, err := po.runner.RunHTTPResolution(ctx, hostList, eventChan)
	if err != nil {
		run.Status = "Failed"
		_ = po.store.SavePipelineRun(run)
		close(eventChan)
		return run, err
	}

	// Link services back to subdomains
	subMap := make(map[string]string)
	for _, sub := range subdomains {
		subMap[sub.Host] = sub.ID
	}

	for i := range services {
		services[i].ID = fmt.Sprintf("svc_%s_%d", runID, i)
		// Extract host from URL
		host := services[i].URL
		for h, subID := range subMap {
			if host == h || host == "http://"+h || host == "https://"+h {
				services[i].SubdomainID = subID
				break
			}
		}
		if services[i].SubdomainID == "" && len(subdomains) > 0 {
			services[i].SubdomainID = subdomains[0].ID
		}
		_ = po.store.SaveHTTPService(&services[i])
	}
	run.TotalServices = len(services)
	run.ProgressPct = 55
	run.CurrentStage = string(models.StageEndpointCrawl)
	_ = po.store.SavePipelineRun(run)

	// Stage 3: Endpoint & JS Discovery
	endpoints, err := po.runner.RunEndpointCrawl(ctx, services, eventChan)
	if err != nil {
		run.Status = "Failed"
		_ = po.store.SavePipelineRun(run)
		close(eventChan)
		return run, err
	}

	for i := range endpoints {
		endpoints[i].ID = fmt.Sprintf("ep_%s_%d", runID, i)
		if endpoints[i].HTTPServiceID == "" && len(services) > 0 {
			endpoints[i].HTTPServiceID = services[0].ID
		}
		_ = po.store.SaveEndpoint(&endpoints[i])
	}
	run.TotalEndpoints = len(endpoints)
	run.ProgressPct = 80
	run.CurrentStage = string(models.StageVulnScan)
	_ = po.store.SavePipelineRun(run)

	// Stage 4: Asset Graph Construction & Autonomous AI Reasoning Loop
	eventChan <- models.PipelineEvent{
		Stage:     models.StageVulnScan,
		Level:     "INFO",
		Message:   fmt.Sprintf("[ASSET GRAPH] Populating multi-hop topology graph (%d subdomains, %d services, %d endpoints)...", len(subdomains), len(services), len(endpoints)),
		Timestamp: time.Now(),
	}
	po.autonomousEngine.BuildGraphFromRecon(domain, subdomains, services, endpoints)

	// Execute AI Planner -> Tools -> AI Analyzer -> Verifier -> Learning Engine cycle
	rawFindings := po.autonomousEngine.RunCycle(ctx, eventChan)

	// If Nuclei is installed, run additional active checks and verify candidates
	if po.runner.IsToolAvailable(po.runner.Config.NucleiPath) {
		nucleiFindings, nErr := po.runner.RunVulnScan(ctx, endpoints, eventChan)
		if nErr == nil {
			for _, nf := range nucleiFindings {
				cand := &agent.CandidateBug{
					HypothesisID: "nuclei_template",
					Title:        nf.Title,
					CWE:          "CWE-200",
					Severity:     nf.Severity,
					TargetURL:    nf.AssetURL,
					RawEvidence:  nf.MatchString,
					ToolPath:     []string{"nuclei"},
					DiscoveredAt: time.Now(),
				}
				vResult := po.autonomousEngine.Verifier.VerifyCandidate(cand)
				if vResult.Confirmed {
					nf.CVSSScore = vResult.CVSSScore
					rawFindings = append(rawFindings, nf)
				}
			}
		}
	}

	// Stage 5: Deduplication & Contextual Risk Scoring
	eventChan <- models.PipelineEvent{
		Stage:     models.StageRiskScoring,
		Level:     "INFO",
		Message:   "Deduplicating security observations and calculating target risk score...",
		Timestamp: time.Now(),
	}

	for i := range rawFindings {
		f := rawFindings[i]
		f.ID = fmt.Sprintf("fnd_%s_%d", runID, i)
		f.TargetID = target.ID
		f.DedupHash = scoring.GenerateDedupHash(target.ID, f.AssetURL, f.TemplateID, f.Title)
		if err := po.store.SaveFinding(&f); err != nil {
			eventChan <- models.PipelineEvent{
				Stage:     models.StageRiskScoring,
				Level:     "ERROR",
				Message:   fmt.Sprintf("Failed to save finding %s: %v", f.Title, err),
				Timestamp: time.Now(),
			}
		}
	}

	allFindings, err := po.store.ListFindings(target.ID)
	if err != nil {
		eventChan <- models.PipelineEvent{
			Stage:     models.StageRiskScoring,
			Level:     "ERROR",
			Message:   fmt.Sprintf("Failed to list findings: %v", err),
			Timestamp: time.Now(),
		}
	}
	targetRiskScore := scoring.CalculateTargetRiskScore(allFindings, len(services))
	_ = po.store.UpdateTargetRiskScore(target.ID, targetRiskScore)

	// Stage 6: AI Automated Security Triage & Posture Analysis
	eventChan <- models.PipelineEvent{
		Stage:     models.StageAITriage,
		Level:     "INFO",
		Message:   "Engaging AI model (model.gguf) for automated finding triage and risk analysis...",
		Timestamp: time.Now(),
	}

	for i, f := range allFindings {
		if f.AITriage == "" {
			triageResult, err := po.aiClient.AnalyzeFinding(ctx, f)
			if err == nil {
				triageBytes, _ := json.Marshal(triageResult)
				allFindings[i].AITriage = string(triageBytes)
				_ = po.store.SaveFinding(&allFindings[i])

				eventChan <- models.PipelineEvent{
					Stage:     models.StageAITriage,
					Level:     "INFO",
					Message:   fmt.Sprintf("[AI Model Triage] Evaluated %s - AI Confidence: %d%% | Remediation steps: %d", f.Title, triageResult.ConfidenceScore, len(triageResult.RemediationSteps)),
					Timestamp: time.Now(),
				}
			}
		}
	}

	run.TotalFindings = len(allFindings)
	run.ProgressPct = 100
	run.CurrentStage = string(models.StageAITriage)
	run.Status = "Completed"
	run.EndTime = time.Now()
	_ = po.store.SavePipelineRun(run)

	po.broadcast(models.PipelineEvent{
		RunID:     runID,
		Stage:     models.StageAITriage,
		Level:     "SUCCESS",
		Message:   fmt.Sprintf("Pipeline completed successfully! Target Risk Score: %.1f/10 | Subdomains: %d | Services: %d | Endpoints: %d | AI Triaged Findings: %d", targetRiskScore, len(subdomains), len(services), len(endpoints), len(allFindings)),
		Progress:  100,
		Timestamp: time.Now(),
	})

	close(eventChan)
	return run, nil
}
