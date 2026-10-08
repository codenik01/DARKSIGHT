package models

import "time"

// StageType identifies pipeline execution steps.
type StageType string

const (
	StageSubdomainDiscovery StageType = "subdomain_discovery"
	StageHTTPResolution     StageType = "http_resolution"
	StageEndpointCrawl      StageType = "endpoint_crawl"
	StageVulnScan           StageType = "vuln_scan"
	StageRiskScoring        StageType = "risk_scoring"
	StageAITriage           StageType = "ai_triage"
)

// PipelineEvent represents live logs and updates emitted during execution.
type PipelineEvent struct {
	RunID     string    `json:"run_id"`
	Stage     StageType `json:"stage"`
	Level     string    `json:"level"` // INFO, WARN, ERROR, SUCCESS
	Message   string    `json:"message"`
	Progress  int       `json:"progress"`
	Timestamp time.Time `json:"timestamp"`
}

// ToolConfig holds parameters for external security tools.
type ToolConfig struct {
	SubfinderPath string   `json:"subfinder_path"`
	HttpxPath     string   `json:"httpx_path"`
	KatanaPath    string   `json:"katana_path"`
	NucleiPath    string   `json:"nuclei_path"`
	CustomFlags   map[string]string `json:"custom_flags"`
	TimeoutSec    int      `json:"timeout_sec"`
}
