package models

import (
	"time"
)

// Target represents an overarching domain/scope being analyzed.
type Target struct {
	ID          string    `json:"id"`
	Domain      string    `json:"domain"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	RiskScore   float64   `json:"risk_score"`
}

// Subdomain represents a discovered host/subdomain under a Target.
type Subdomain struct {
	ID        string    `json:"id"`
	TargetID  string    `json:"target_id"`
	Host      string    `json:"host"`
	IPs       []string  `json:"ips"`
	Source    string    `json:"source"` // e.g. subfinder, dns
	IsAlive   bool      `json:"is_alive"`
	CreatedAt time.Time `json:"created_at"`
}

// HTTPService represents an active HTTP service detected on a Subdomain.
type HTTPService struct {
	ID          string    `json:"id"`
	SubdomainID string    `json:"subdomain_id"`
	URL         string    `json:"url"`
	StatusCode  int       `json:"status_code"`
	Title       string    `json:"title"`
	TechStack   []string  `json:"tech_stack"` // e.g. React, Nginx, PHP
	WebServer   string    `json:"web_server"`
	ContentLen  int64     `json:"content_len"`
	ResponseTime int64    `json:"response_time_ms"`
	CreatedAt   time.Time `json:"created_at"`
}

// Endpoint represents a discovered URL/API endpoint.
type Endpoint struct {
	ID            string    `json:"id"`
	HTTPServiceID string    `json:"http_service_id"`
	URL           string    `json:"url"`
	Method        string    `json:"method"`
	Params        []string  `json:"params"`
	Source        string    `json:"source"` // e.g. katana, js_analysis
	ContentType   string    `json:"content_type"`
	CreatedAt     time.Time `json:"created_at"`
}

// Finding represents a vulnerability or security observation.
type Finding struct {
	ID          string    `json:"id"`
	TargetID    string    `json:"target_id"`
	AssetURL    string    `json:"asset_url"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"` // Info, Low, Medium, High, Critical
	CVSSScore   float64   `json:"cvss_score"`
	TemplateID  string    `json:"template_id"` // e.g. nuclei template ID
	Description string    `json:"description"`
	MatchString string    `json:"match_string"`
	Evidence    Evidence  `json:"evidence"`
	DedupHash   string    `json:"dedup_hash"`
	Status      string    `json:"status"` // Open, Triaged, Remediated, FalsePositive
	AITriage    string    `json:"ai_triage"` // AI analysis JSON
	CreatedAt   time.Time `json:"created_at"`
}

// Evidence holds request/response proofs for a Finding.
type Evidence struct {
	RequestText  string `json:"request_text"`
	ResponseText string `json:"response_text"`
	ExtractedData string `json:"extracted_data"`
	CurlCommand  string `json:"curl_command"`
}

// PipelineRun tracks an execution run of the discovery & scanning workflow.
type PipelineRun struct {
	ID            string    `json:"id"`
	TargetID      string    `json:"target_id"`
	Workflow      string    `json:"workflow"`
	Status        string    `json:"status"` // Running, Completed, Failed
	ProgressPct   int       `json:"progress_pct"`
	CurrentStage  string    `json:"current_stage"`
	TotalSubdomains int     `json:"total_subdomains"`
	TotalServices   int     `json:"total_services"`
	TotalEndpoints  int     `json:"total_endpoints"`
	TotalFindings   int     `json:"total_findings"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
}
