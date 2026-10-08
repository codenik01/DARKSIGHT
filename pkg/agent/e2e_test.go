package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"surface-intel/pkg/graph"
	"surface-intel/pkg/memory"
	"surface-intel/pkg/models"
	"surface-intel/pkg/scope"
)

func TestAutonomousCycleWithMockServers(t *testing.T) {
	// 1. Create a server that simulates a genuine exposed Prometheus metrics endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("# HELP go_goroutines Number of goroutines.\n# TYPE go_goroutines gauge\ngo_goroutines 12\nhttp_requests_total 450\n"))
		case "/.env":
			// Simulate a SPA router that returns 200 OK with HTML (soft 404 / false positive)
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<!doctype html><html><head><title>404 Page Not Found</title></head><body>App Catchall</body></html>"))
		case "/api/users/100":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":100,"username":"admin","email":"admin@corp.internal"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	expDB := memory.NewExperienceDB()
	sm := scope.NewScopeManager(scope.ScopeConfig{
		AllowSubdomains: true,
	})
	ag := graph.NewAssetGraph()
	ae := NewAutonomousEngine(sm, ag, expDB)

	// Build Asset Graph with server URLs
	serverHost := strings.TrimPrefix(server.URL, "http://")
	subdomains := []models.Subdomain{{Host: serverHost, IPs: []string{"127.0.0.1"}}}
	services := []models.HTTPService{{URL: server.URL, StatusCode: 200, WebServer: "httptest"}}
	endpoints := []models.Endpoint{
		{URL: server.URL + "/metrics", Method: "GET"},
		{URL: server.URL + "/.env", Method: "GET"},
		{URL: server.URL + "/api/users/100", Method: "GET"},
	}

	ae.BuildGraphFromRecon("127.0.0.1", subdomains, services, endpoints)

	// Ensure ScopeManager allows 127.0.0.1
	sm.Config.TargetDomain = serverHost
	sm.Config.IncludedHosts = []string{serverHost, "127.0.0.1"}

	// Run Autonomous Cycle
	eventChan := make(chan models.PipelineEvent, 50)
	go func() {
		for range eventChan {
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings := ae.RunCycle(ctx, eventChan)

	// Assertions:
	// 1. Prometheus /metrics should be CONFIRMED because it returns genuine metrics
	foundMetrics := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Prometheus") {
			foundMetrics = true
		}
	}
	if !foundMetrics {
		t.Errorf("expected genuine Prometheus metrics finding to be confirmed by Verifier")
	}

	// 2. /.env MUST be REJECTED as False Positive by Verifier (due to soft 404 / HTML catch-all)
	for _, f := range findings {
		if strings.Contains(f.Title, ".env") {
			t.Errorf("expected /.env soft-404 to be REJECTED by Verifier, but was confirmed: %s", f.Title)
		}
	}

	// 3. Experience DB should have recorded the finding in Finding Memory
	if len(expDB.Findings) == 0 {
		t.Errorf("expected Finding Memory to record verified finding")
	}

	fmt.Printf("[+] Verified Findings Recorded in Memory: %d\n", len(expDB.Findings))
	for _, f := range expDB.Findings {
		fmt.Printf("    • %s (CWE: %s | URL: %s)\n", f.Type, f.CWE, f.TargetURL)
	}
}
