package ai

import (
	"context"
	"testing"

	"surface-intel/pkg/models"
)

func TestAIClientDiscovery(t *testing.T) {
	client := NewAIClient()

	if !client.HasGGUFModel() {
		t.Fatalf("expected HasGGUFModel to return true when models/model exists")
	}

	if client.ModelPath == "" {
		t.Fatalf("expected resolved ModelPath to be non-empty")
	}

	t.Logf("[+] Discovered GGUF model at: %s", client.ModelPath)

	// Test fallback triage calculation
	f := models.Finding{
		AssetURL:    "http://example.com/admin",
		Title:       "Administrative Portal Exposed",
		Severity:    "High",
		TemplateID:  "admin-exposure",
		Description: "Unauthenticated admin interface exposed",
	}

	triage, err := client.AnalyzeFinding(context.Background(), f)
	if err != nil {
		t.Fatalf("AnalyzeFinding failed: %v", err)
	}

	if triage.ConfidenceScore <= 0 {
		t.Errorf("expected positive confidence score, got %d", triage.ConfidenceScore)
	}
	if len(triage.RemediationSteps) == 0 {
		t.Errorf("expected remediation steps to be populated")
	}

	t.Logf("[+] AI Triage Result: Model Used: %s | Confidence: %d%%", triage.ModelUsed, triage.ConfidenceScore)
}
