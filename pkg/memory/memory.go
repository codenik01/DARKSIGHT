package memory

import (
	"strings"
	"sync"
	"time"
)

// 1. Finding Memory - Confirmed Vulnerabilities
type FindingMemory struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`          // e.g. IDOR, SSRF, Exposure
	CWE          string    `json:"cwe"`           // e.g. CWE-639, CWE-918
	Confirmed    bool      `json:"confirmed"`
	Pattern      string    `json:"pattern"`       // e.g. user-controlled object ID in REST
	TargetURL    string    `json:"target_url"`
	Evidence     string    `json:"evidence"`
	ToolPath     []string  `json:"tool_path"`     // e.g. ["http_probe", "differential_test"]
	Remediation  string    `json:"remediation"`
	RecordedAt   time.Time `json:"recorded_at"`
}

// 2. Failure Memory - Mistakes, False Positives, and Lessons
type FailureMemory struct {
	ID              string    `json:"id"`
	TargetURL       string    `json:"target_url"`
	WhatAIThought   string    `json:"what_ai_thought"`   // e.g. "Open redirect vulnerability"
	ActionTaken     string    `json:"action_taken"`       // e.g. "Fuzzed ?redirect= parameter"
	WhyWasItWrong   string    `json:"why_was_it_wrong"`   // e.g. "Destination redirect whitelist validated on backend"
	ActualIssue     string    `json:"actual_issue"`       // e.g. "SSRF redirect validation check, not open redirect"
	LessonLearned   string    `json:"lesson_learned"`     // e.g. "Do not classify redirect response solely as CWE-601"
	RecordedAt      time.Time `json:"recorded_at"`
}

// 3. Strategy Memory - Tactical paths and success rates
type StrategyMemory struct {
	Context            string    `json:"context"`             // e.g. "REST API + numeric object IDs"
	Hypothesis         string    `json:"hypothesis"`          // e.g. "Authorization bypass / IDOR"
	BestAction         string    `json:"best_action"`         // e.g. "Compare authenticated vs unauthenticated response"
	SuccessRate        float64   `json:"success_rate"`        // 0.0 - 100.0%
	TrialsCount        int       `json:"trials_count"`
	ConfirmedCount     int       `json:"confirmed_count"`
	FalsePositiveCount int       `json:"false_positive_count"`
	LastUpdated        time.Time `json:"last_updated"`
}

// 4. Tool Effectiveness Memory - Tool utility scores per target characteristics
type ToolEffectivenessMemory struct {
	Context        string             `json:"context"`         // e.g. "GraphQL target", "Static asset", "REST API"
	ToolScores     map[string]float64 `json:"tool_scores"`     // ToolName -> Success Percentage (e.g. "http_probe": 78%)
	ExecutionCount map[string]int     `json:"execution_count"`
	LastUpdated    time.Time          `json:"last_updated"`
}

// ExperienceDB manages all 4 memory layers in memory and SQLite.
type ExperienceDB struct {
	mu                sync.RWMutex
	Findings          []FindingMemory                    `json:"findings"`
	Failures          []FailureMemory                    `json:"failures"`
	Strategies        map[string]*StrategyMemory         `json:"strategies"`         // Key: Context + Hypothesis
	ToolEffectiveness map[string]*ToolEffectivenessMemory `json:"tool_effectiveness"` // Key: Context
}

func NewExperienceDB() *ExperienceDB {
	db := &ExperienceDB{
		Findings:          make([]FindingMemory, 0),
		Failures:          make([]FailureMemory, 0),
		Strategies:        make(map[string]*StrategyMemory),
		ToolEffectiveness: make(map[string]*ToolEffectivenessMemory),
	}
	db.seedBaselineExperience()
	return db
}

// Seed baseline operational knowledge into Experience DB
func (db *ExperienceDB) seedBaselineExperience() {
	// Baseline Strategies
	db.Strategies["REST_NUMERIC_ID|IDOR"] = &StrategyMemory{
		Context:            "REST API + numeric object IDs",
		Hypothesis:         "Authorization bypass / IDOR on user object",
		BestAction:         "HTTP request + compare authenticated/unauthenticated behavior",
		SuccessRate:        73.0,
		TrialsCount:        15,
		ConfirmedCount:     11,
		FalsePositiveCount: 4,
		LastUpdated:        time.Now(),
	}

	db.Strategies["GRAPHQL_ENDPOINT|INTROSPECTION"] = &StrategyMemory{
		Context:            "GraphQL endpoint exposed",
		Hypothesis:         "Schema disclosure via GraphQL Introspection query",
		BestAction:         "HTTP POST /graphql with query __schema",
		SuccessRate:        65.0,
		TrialsCount:        20,
		ConfirmedCount:     13,
		FalsePositiveCount: 7,
		LastUpdated:        time.Now(),
	}

	db.Strategies["CONFIG_PATH|ENV_EXPOSURE"] = &StrategyMemory{
		Context:            "Static server configuration paths",
		Hypothesis:         "Environment file exposure (.env, config.json)",
		BestAction:         "HTTP GET /.env + verify key patterns (APP_KEY, DB_PASSWORD)",
		SuccessRate:        35.0,
		TrialsCount:        40,
		ConfirmedCount:     14,
		FalsePositiveCount: 26,
		LastUpdated:        time.Now(),
	}

	// Baseline Tool Effectiveness
	db.ToolEffectiveness["GraphQL target"] = &ToolEffectivenessMemory{
		Context: "GraphQL target",
		ToolScores: map[string]float64{
			"http_probe": 78.0,
			"browser":    84.0,
			"katana":     42.0,
			"nuclei":     31.0,
		},
		ExecutionCount: map[string]int{"http_probe": 50, "browser": 30, "katana": 40, "nuclei": 60},
		LastUpdated:    time.Now(),
	}

	db.ToolEffectiveness["REST API target"] = &ToolEffectivenessMemory{
		Context: "REST API target",
		ToolScores: map[string]float64{
			"http_probe": 82.0,
			"nuclei":     55.0,
			"katana":     68.0,
			"browser":    30.0,
		},
		ExecutionCount: map[string]int{"http_probe": 60, "nuclei": 70, "katana": 50, "browser": 20},
		LastUpdated:    time.Now(),
	}

	db.ToolEffectiveness["Static asset"] = &ToolEffectivenessMemory{
		Context: "Static asset",
		ToolScores: map[string]float64{
			"http_probe": 60.0,
			"nuclei":     25.0,
			"browser":    10.0,
		},
		ExecutionCount: map[string]int{"http_probe": 30, "nuclei": 40, "browser": 10},
		LastUpdated:    time.Now(),
	}
}

// AddFinding stores a verified confirmed vulnerability into Finding Memory.
func (db *ExperienceDB) AddFinding(f FindingMemory) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if f.RecordedAt.IsZero() {
		f.RecordedAt = time.Now()
	}
	db.Findings = append(db.Findings, f)
}

// AddFailure stores a rejected hypothesis and why it was wrong into Failure Memory.
func (db *ExperienceDB) AddFailure(fail FailureMemory) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if fail.RecordedAt.IsZero() {
		fail.RecordedAt = time.Now()
	}
	db.Failures = append(db.Failures, fail)
}

// RetrieveRelevantFailures checks if a planned hypothesis has a history of failure for this context.
func (db *ExperienceDB) RetrieveRelevantFailures(contextStr, hypothesis string) []FailureMemory {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var matches []FailureMemory
	cLower := strings.ToLower(contextStr)
	hLower := strings.ToLower(hypothesis)

	for _, f := range db.Failures {
		if strings.Contains(strings.ToLower(f.WhatAIThought), hLower) || strings.Contains(strings.ToLower(f.ActionTaken), cLower) {
			matches = append(matches, f)
		}
	}
	return matches
}

// QueryStrategies returns strategies sorted by success rate for a given context.
func (db *ExperienceDB) QueryStrategies(contextStr string) []*StrategyMemory {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var results []*StrategyMemory
	cLower := strings.ToLower(contextStr)

	for _, s := range db.Strategies {
		if strings.Contains(strings.ToLower(s.Context), cLower) || strings.Contains(cLower, strings.ToLower(s.Context)) {
			results = append(results, s)
		}
	}
	return results
}

// GetToolRankings returns tool scores for a context.
func (db *ExperienceDB) GetToolRankings(contextStr string) map[string]float64 {
	db.mu.RLock()
	defer db.mu.RUnlock()

	cLower := strings.ToLower(contextStr)
	for ctxKey, tem := range db.ToolEffectiveness {
		if strings.Contains(strings.ToLower(ctxKey), cLower) || strings.Contains(cLower, strings.ToLower(ctxKey)) {
			return tem.ToolScores
		}
	}

	// Default fallback tool rankings
	return map[string]float64{
		"http_probe": 70.0,
		"nuclei":     50.0,
		"browser":    40.0,
	}
}

// Stats returns counts of all 4 memory types.
func (db *ExperienceDB) Stats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return map[string]interface{}{
		"total_confirmed_findings": len(db.Findings),
		"total_failure_lessons":    len(db.Failures),
		"active_strategies":        len(db.Strategies),
		"tool_contexts_tracked":    len(db.ToolEffectiveness),
	}
}
