package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"surface-intel/pkg/ai"
	"surface-intel/pkg/db"
	"surface-intel/pkg/models"
	"surface-intel/pkg/runner"
)

type Server struct {
	store        *db.Store
	orchestrator *runner.PipelineOrchestrator
	aiClient     *ai.AIClient
	port         int
}

func NewServer(store *db.Store, orchestrator *runner.PipelineOrchestrator, aiClient *ai.AIClient, port int) *Server {
	if port <= 0 {
		port = 8080
	}
	if aiClient == nil {
		aiClient = ai.NewAIClient()
	}
	return &Server{
		store:        store,
		orchestrator: orchestrator,
		aiClient:     aiClient,
		port:         port,
	}
}

func (s *Server) Start(indexHTML []byte) error {
	mux := http.NewServeMux()

	// Static Web Dashboard
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})

	// REST API Endpoints
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/targets", s.handleTargets)
	mux.HandleFunc("/api/subdomains", s.handleSubdomains)
	mux.HandleFunc("/api/services", s.handleServices)
	mux.HandleFunc("/api/endpoints", s.handleEndpoints)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/events", s.handleSSEEvents)
	mux.HandleFunc("/api/ai/summary", s.handleAISummary)
	mux.HandleFunc("/api/clear", s.handleClear)
	mux.HandleFunc("/api/report", s.handleReport)

	// Darksight Asset Graph & Experience Memory API
	mux.HandleFunc("/api/graph", s.handleGraph)
	mux.HandleFunc("/api/memory/stats", s.handleMemoryStats)
	mux.HandleFunc("/api/memory/strategies", s.handleMemoryStrategies)
	mux.HandleFunc("/api/memory/failures", s.handleMemoryFailures)
	mux.HandleFunc("/api/memory/tools", s.handleMemoryTools)

	addr := fmt.Sprintf(":%d", s.port)
	fmt.Printf("[+] Darksight Local Web Console listening on http://localhost:%d\n", s.port)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		targetID := r.URL.Query().Get("id")
		if targetID == "" {
			http.Error(w, "Target ID is required", http.StatusBadRequest)
			return
		}
		if err := s.store.DeleteTarget(targetID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "id": targetID})
		return
	}

	targets, err := s.store.ListTargets()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(targets)
}

func (s *Server) handleSubdomains(w http.ResponseWriter, r *http.Request) {
	targetID := r.URL.Query().Get("target_id")
	subs, err := s.store.ListSubdomains(targetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(subs)
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	targetID := r.URL.Query().Get("target_id")
	svcs, err := s.store.ListHTTPServices(targetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(svcs)
}

func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	targetID := r.URL.Query().Get("target_id")
	eps, err := s.store.ListEndpoints(targetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(eps)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	targetID := r.URL.Query().Get("target_id")
	fnds, err := s.store.ListFindings(targetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fnds)
}

type ScanRequest struct {
	Domain   string `json:"domain"`
	Workflow string `json:"workflow"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "Invalid domain provided", http.StatusBadRequest)
		return
	}

	if req.Workflow == "" {
		req.Workflow = "full"
	}

	// Trigger async pipeline run
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		_, _ = s.orchestrator.ExecuteRun(ctx, req.Domain, req.Workflow)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "queued",
		"message": fmt.Sprintf("Pipeline scan initiated for domain %s", req.Domain),
	})
}

func (s *Server) handleSSEEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	eventChan := s.orchestrator.Subscribe()
	defer s.orchestrator.Unsubscribe(eventChan)

	notify := r.Context().Done()
	for {
		select {
		case ev, open := <-eventChan:
			if !open {
				return
			}
			bytes, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", string(bytes))
			flusher.Flush()
		case <-notify:
			return
		}
	}
}

func (s *Server) handleAISummary(w http.ResponseWriter, r *http.Request) {
	targetID := r.URL.Query().Get("target_id")
	var target *models.Target
	var err error

	if targetID != "" {
		target, err = s.store.GetTargetByID(targetID)
	} else {
		targets, _ := s.store.ListTargets()
		if len(targets) > 0 {
			target = &targets[0]
		}
	}

	if target == nil || err != nil {
		http.Error(w, "No target found", http.StatusNotFound)
		return
	}

	findings, _ := s.store.ListFindings(target.ID)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	summary, err := s.aiClient.GenerateTargetSummary(ctx, *target, findings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

func (s *Server) handleClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.store.ClearAllData(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "cleared", "message": "All records purged successfully"})
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	targetID := r.URL.Query().Get("target_id")
	var target *models.Target
	var err error

	if targetID != "" {
		target, err = s.store.GetTargetByID(targetID)
	} else {
		targets, _ := s.store.ListTargets()
		if len(targets) > 0 {
			target = &targets[0]
		}
	}

	if target == nil || err != nil {
		http.Error(w, "Target not found", http.StatusNotFound)
		return
	}

	subs, _ := s.store.ListSubdomains(target.ID)
	svcs, _ := s.store.ListHTTPServices(target.ID)
	eps, _ := s.store.ListEndpoints(target.ID)
	fnds, _ := s.store.ListFindings(target.ID)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	aiSummary, _ := s.aiClient.GenerateTargetSummary(ctx, *target, fnds)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	renderHTMLReport(w, target, subs, svcs, eps, fnds, aiSummary)
}

func renderHTMLReport(w http.ResponseWriter, t *models.Target, subs []models.Subdomain, svcs []models.HTTPService, eps []models.Endpoint, fnds []models.Finding, aiSummary ai.AITargetSummary) {
	headerHTML := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Darksight Security Intelligence Report - %s</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 40px; color: #1e293b; background: #fff; line-height: 1.5; }
        .header { border-bottom: 2px solid #6366f1; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: flex-start; }
        h1 { margin: 0 0 5px 0; color: #0f172a; font-size: 26px; }
        .subtitle { color: #64748b; font-size: 14px; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
        .badge-critical { background: #ffe4e6; color: #e11d48; border: 1px solid #fda4af; }
        .badge-high { background: #ffedd5; color: #ea580c; border: 1px solid #fdba74; }
        .badge-medium { background: #fef3c7; color: #d97706; border: 1px solid #fde68a; }
        .badge-low { background: #e0f2fe; color: #0284c7; border: 1px solid #bae6fd; }
        .badge-info { background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; }
        .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }
        .card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; }
        .card-num { font-size: 24px; font-weight: bold; color: #0f172a; margin-top: 5px; }
        .card-title { font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; }
        .ai-box { background: #eef2ff; border: 1px solid #c7d2fe; border-radius: 8px; padding: 20px; margin-bottom: 30px; }
        .ai-title { color: #4338ca; font-weight: bold; font-size: 15px; margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
        table { width: 100%%; border-collapse: collapse; margin-bottom: 30px; font-size: 13px; }
        th { background: #f1f5f9; text-align: left; padding: 10px 12px; border-bottom: 2px solid #cbd5e1; color: #475569; font-size: 11px; text-transform: uppercase; }
        td { padding: 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
        .finding-title { font-weight: 600; color: #0f172a; }
        .finding-url { font-family: monospace; color: #0284c7; font-size: 12px; }
        .finding-steps { margin-top: 6px; font-size: 12px; color: #334155; }
        .no-print { position: fixed; top: 20px; right: 20px; z-index: 100; }
        .btn-print { background: #4f46e5; color: white; border: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; cursor: pointer; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
        @media print {
            .no-print { display: none !important; }
            body { padding: 0; }
            @page { margin: 1.5cm; }
        }
    </style>
</head>
<body>
    <div class="no-print">
        <button class="btn-print" onclick="window.print()">🖨️ Print / Save as PDF</button>
    </div>

    <div class="header">
        <div>
            <h1>SurfaceIntel Intelligence Audit Report</h1>
            <div class="subtitle">Target Scope: <strong>%s</strong> | Report Date: %s</div>
        </div>
        <div>
            <span class="badge" style="background: #4f46e5; color: white; font-size: 14px;">Risk Score: %.1f / 10</span>
        </div>
    </div>`, t.Domain, t.Domain, time.Now().Format("Jan 02, 2006 15:04 MST"), t.RiskScore)

	w.Write([]byte(headerHTML))

	fmt.Fprintf(w, `
    <div class="grid">
        <div class="card">
            <div class="card-title">Discovered Subdomains</div>
            <div class="card-num">%d</div>
        </div>
        <div class="card">
            <div class="card-title">Active HTTP Services</div>
            <div class="card-num">%d</div>
        </div>
        <div class="card">
            <div class="card-title">Crawled Endpoints</div>
            <div class="card-num">%d</div>
        </div>
        <div class="card">
            <div class="card-title">Security Observations</div>
            <div class="card-num" style="color: #e11d48;">%d</div>
        </div>
    </div>

    <div class="ai-box">
        <div class="ai-title">🤖 AI Security Model Posture Assessment (%s)</div>
        <div style="font-size: 14px; color: #1e1b4b; margin-bottom: 12px;">%s</div>
        <div style="font-size: 12px; font-weight: bold; color: #4338ca; margin-bottom: 4px;">Recommended Defensive Roadmap:</div>
        <ul style="margin: 0; padding-left: 20px; font-size: 13px; color: #312e81;">`,
		len(subs), len(svcs), len(eps), len(fnds), aiSummary.ModelUsed, aiSummary.ExecutiveSummary)

	for _, step := range aiSummary.ActionPlan {
		fmt.Fprintf(w, "<li>%s</li>", step)
	}
	fmt.Fprintf(w, `</ul></div>`)

	fmt.Fprintf(w, `<h2>Security Findings & Vulnerability Evidence</h2>`)
	if len(fnds) == 0 {
		fmt.Fprintf(w, `<div style="padding: 20px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; color: #166534; font-weight: 500;">
            ✓ Clean Security Posture: No unauthenticated vulnerability exposures or security header deficiencies were detected on active services.
        </div>`)
	} else {
		fmt.Fprintf(w, `<table>
            <thead>
                <tr>
                    <th style="width: 120px;">Severity</th>
                    <th>Vulnerability Title & Technical Proof</th>
                    <th style="width: 280px;">Affected Asset & Template</th>
                </tr>
            </thead>
            <tbody>`)

		for _, f := range fnds {
			sevBadge := "badge-info"
			s := strings.ToUpper(f.Severity)
			if s == "CRITICAL" {
				sevBadge = "badge-critical"
			} else if s == "HIGH" {
				sevBadge = "badge-high"
			} else if s == "MEDIUM" {
				sevBadge = "badge-medium"
			} else if s == "LOW" {
				sevBadge = "badge-low"
			}

			aiTriageText := ""
			if f.AITriage != "" {
				var triage ai.AITriageResult
				if err := json.Unmarshal([]byte(f.AITriage), &triage); err == nil {
					aiTriageText = fmt.Sprintf(`<div style="margin-top: 6px; font-size: 11px; color: #4f46e5;"><strong>AI Evaluation (%d%% confidence):</strong> %s</div>`, triage.ConfidenceScore, triage.Summary)
				}
			}

			fmt.Fprintf(w, `<tr>
                <td><span class="badge %s">%s</span></td>
                <td>
                    <div class="finding-title">%s</div>
                    <div style="font-size: 12px; color: #64748b; margin-top: 3px;">%s</div>
                    %s
                </td>
                <td>
                    <div class="finding-url">%s</div>
                    <div style="font-size: 11px; color: #94a3b8; margin-top: 3px;">Template: %s</div>
                </td>
            </tr>`, sevBadge, f.Severity, f.Title, f.Description, aiTriageText, f.AssetURL, f.TemplateID)
		}
		fmt.Fprintf(w, `</tbody></table>`)
	}

	fmt.Fprintf(w, `</body></html>`)
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	g := s.orchestrator.GetAssetGraph()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(g)
}

func (s *Server) handleMemoryStats(w http.ResponseWriter, r *http.Request) {
	mem := s.orchestrator.GetExperienceDB()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mem.Stats())
}

func (s *Server) handleMemoryStrategies(w http.ResponseWriter, r *http.Request) {
	mem := s.orchestrator.GetExperienceDB()
	var list []interface{}
	for _, st := range mem.Strategies {
		list = append(list, st)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func (s *Server) handleMemoryFailures(w http.ResponseWriter, r *http.Request) {
	mem := s.orchestrator.GetExperienceDB()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mem.Failures)
}

func (s *Server) handleMemoryTools(w http.ResponseWriter, r *http.Request) {
	mem := s.orchestrator.GetExperienceDB()
	var list []interface{}
	for _, te := range mem.ToolEffectiveness {
		list = append(list, te)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}
