package agent

import (
	"testing"

	"surface-intel/pkg/graph"
	"surface-intel/pkg/memory"
)

func TestAIPlannerAndLearningEngine(t *testing.T) {
	expDB := memory.NewExperienceDB()
	le := memory.NewLearningEngine(expDB)
	planner := NewAIPlanner(expDB)

	ag := graph.NewAssetGraph()
	ag.AddNode(graph.Node{
		ID:    "target_1",
		Type:  graph.NodeTarget,
		Label: "example.com",
	})
	ag.AddNode(graph.Node{
		ID:    "svc_1",
		Type:  graph.NodeService,
		Label: "https://example.com",
	})
	ag.AddNode(graph.Node{
		ID:    "ep_1",
		Type:  graph.NodeEndpoint,
		Label: "https://example.com/api/users/42",
	})

	// Formulate hypotheses
	hyps := planner.FormulatePlan(ag)
	if len(hyps) == 0 {
		t.Fatalf("expected hypotheses to be generated, got 0")
	}

	foundIDOR := false
	for _, h := range hyps {
		if h.Context == "REST API + numeric object IDs" {
			foundIDOR = true
			if h.Confidence <= 0 {
				t.Errorf("expected positive confidence score, got %f", h.Confidence)
			}
		}
	}
	if !foundIDOR {
		t.Errorf("expected REST API IDOR hypothesis to be generated")
	}

	// Test Learning Engine update
	initialRate := expDB.Strategies["REST_NUMERIC_ID|IDOR"].SuccessRate
	le.LearnFromExecution(
		"REST API + numeric object IDs",
		"Authorization bypass / IDOR on user object",
		"Differential authorization test",
		"http_probe",
		true,
		"Access permitted without token",
		"",
		"https://example.com/api/users/42",
	)

	newRate := expDB.Strategies["REST_NUMERIC_ID|IDOR"].SuccessRate
	if newRate <= 0 {
		t.Errorf("expected valid recalculation of success rate, got %f (init: %f)", newRate, initialRate)
	}

	// Verify that Failure Memory records rejected trials
	initialFailures := len(expDB.Failures)
	le.LearnFromExecution(
		"Static server configuration paths",
		"Environment file exposure",
		"HTTP GET /.env",
		"http_probe",
		false,
		"Returned soft-404 page",
		"Catch-all SPA router",
		"https://example.com/.env",
	)
	if len(expDB.Failures) != initialFailures+1 {
		t.Errorf("expected Failure Memory to record rejection, got %d failures", len(expDB.Failures))
	}
}

func TestAnalyzer(t *testing.T) {
	analyzer := NewAIAnalyzer()

	hyp := Hypothesis{
		ID:           "hyp_test",
		Theory:       "Environment file exposure (.env, config.json)",
		TargetURL:    "https://example.com/.env",
		ToolSelected: "http_probe",
	}

	// Match genuine credentials
	cand := analyzer.AnalyzeProbeOutcome(hyp, 200, map[string]string{}, "APP_KEY=base64:xyz\nDB_PASSWORD=secret")
	if cand == nil {
		t.Fatalf("expected candidate bug for real .env credentials")
	}
	if cand.Severity != "High" {
		t.Errorf("expected High severity, got %s", cand.Severity)
	}

	// Match non-credential content -> should be nil
	cand2 := analyzer.AnalyzeProbeOutcome(hyp, 200, map[string]string{}, "Welcome to our blog!")
	if cand2 != nil {
		t.Errorf("expected nil candidate bug for non-matching body, got %v", cand2)
	}
}
