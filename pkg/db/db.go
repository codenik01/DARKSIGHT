package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"surface-intel/pkg/models"
)

type Store struct {
	db *sql.DB
	mu sync.RWMutex
}

func NewStore(dbPath string) (*Store, error) {
	if dbPath == "" {
		dbPath = "surface-intel.db"
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	s := &Store{db: db}
	if err := s.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return s, nil
}

func (s *Store) initSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS targets (
			id TEXT PRIMARY KEY,
			domain TEXT UNIQUE NOT NULL,
			name TEXT,
			description TEXT,
			risk_score REAL DEFAULT 0.0,
			created_at DATETIME,
			updated_at DATETIME
		);`,
		`CREATE TABLE IF NOT EXISTS subdomains (
			id TEXT PRIMARY KEY,
			target_id TEXT NOT NULL,
			host TEXT NOT NULL,
			ips TEXT,
			source TEXT,
			is_alive INTEGER DEFAULT 0,
			created_at DATETIME,
			UNIQUE(target_id, host)
		);`,
		`CREATE TABLE IF NOT EXISTS http_services (
			id TEXT PRIMARY KEY,
			subdomain_id TEXT NOT NULL,
			url TEXT UNIQUE NOT NULL,
			status_code INTEGER,
			title TEXT,
			tech_stack TEXT,
			web_server TEXT,
			content_len INTEGER,
			response_time_ms INTEGER,
			created_at DATETIME
		);`,
		`CREATE TABLE IF NOT EXISTS endpoints (
			id TEXT PRIMARY KEY,
			http_service_id TEXT NOT NULL,
			url TEXT NOT NULL,
			method TEXT,
			params TEXT,
			source TEXT,
			content_type TEXT,
			created_at DATETIME,
			UNIQUE(http_service_id, url, method)
		);`,
		`CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			target_id TEXT NOT NULL,
			asset_url TEXT NOT NULL,
			title TEXT NOT NULL,
			severity TEXT NOT NULL,
			cvss_score REAL DEFAULT 0.0,
			template_id TEXT,
			description TEXT,
			match_string TEXT,
			evidence TEXT,
			dedup_hash TEXT UNIQUE NOT NULL,
			status TEXT DEFAULT 'Open',
			ai_triage TEXT,
			created_at DATETIME
		);`,
		`CREATE TABLE IF NOT EXISTS pipeline_runs (
			id TEXT PRIMARY KEY,
			target_id TEXT NOT NULL,
			workflow TEXT,
			status TEXT,
			progress_pct INTEGER,
			current_stage TEXT,
			total_subdomains INTEGER,
			total_services INTEGER,
			total_endpoints INTEGER,
			total_findings INTEGER,
			start_time DATETIME,
			end_time DATETIME
		);`,
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}

	// Auto-migration for schema updates
	_, _ = s.db.Exec("ALTER TABLE findings ADD COLUMN ai_triage TEXT;")

	return nil
}

// Target operations
func (s *Store) SaveTarget(t *models.Target) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now

	query := `INSERT INTO targets (id, domain, name, description, risk_score, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?)
			  ON CONFLICT(domain) DO UPDATE SET
			  name=excluded.name, description=excluded.description, risk_score=excluded.risk_score, updated_at=excluded.updated_at;`

	_, err := s.db.Exec(query, t.ID, t.Domain, t.Name, t.Description, t.RiskScore, t.CreatedAt, t.UpdatedAt)
	return err
}

func (s *Store) GetTargetByDomain(domain string) (*models.Target, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow("SELECT id, domain, name, description, risk_score, created_at, updated_at FROM targets WHERE domain = ?", domain)
	var t models.Target
	err := row.Scan(&t.ID, &t.Domain, &t.Name, &t.Description, &t.RiskScore, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) GetTargetByID(id string) (*models.Target, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow("SELECT id, domain, name, description, risk_score, created_at, updated_at FROM targets WHERE id = ?", id)
	var t models.Target
	err := row.Scan(&t.ID, &t.Domain, &t.Name, &t.Description, &t.RiskScore, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) ListTargets() ([]models.Target, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id, domain, name, description, risk_score, created_at, updated_at FROM targets ORDER BY updated_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.Target
	for rows.Next() {
		var t models.Target
		if err := rows.Scan(&t.ID, &t.Domain, &t.Name, &t.Description, &t.RiskScore, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		results = append(results, t)
	}
	return results, nil
}

// DeleteTarget removes a specific target and all associated assets, services, and findings.
func (s *Store) DeleteTarget(targetID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	queries := []string{
		"DELETE FROM pipeline_runs WHERE target_id = ?",
		"DELETE FROM findings WHERE target_id = ?",
		`DELETE FROM endpoints WHERE http_service_id IN (
			SELECT hs.id FROM http_services hs
			JOIN subdomains sd ON hs.subdomain_id = sd.id
			WHERE sd.target_id = ?
		)`,
		`DELETE FROM http_services WHERE subdomain_id IN (
			SELECT id FROM subdomains WHERE target_id = ?
		)`,
		"DELETE FROM subdomains WHERE target_id = ?",
		"DELETE FROM targets WHERE id = ?",
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q, targetID); err != nil {
			return err
		}
	}
	return nil
}

// ClearAllData completely wipes all targets, findings, and intelligence history.
func (s *Store) ClearAllData() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tables := []string{"pipeline_runs", "findings", "endpoints", "http_services", "subdomains", "targets"}
	for _, t := range tables {
		if _, err := s.db.Exec("DELETE FROM " + t); err != nil {
			return err
		}
	}
	_, _ = s.db.Exec("VACUUM")
	return nil
}

// Subdomain operations
func (s *Store) SaveSubdomain(sub *models.Subdomain) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ipsJSON, _ := json.Marshal(sub.IPs)
	isAlive := 0
	if sub.IsAlive {
		isAlive = 1
	}

	query := `INSERT INTO subdomains (id, target_id, host, ips, source, is_alive, created_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?)
			  ON CONFLICT(target_id, host) DO UPDATE SET
			  ips=excluded.ips, is_alive=excluded.is_alive;`

	_, err := s.db.Exec(query, sub.ID, sub.TargetID, sub.Host, string(ipsJSON), sub.Source, isAlive, time.Now())
	return err
}

func (s *Store) ListSubdomains(targetID string) ([]models.Subdomain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id, target_id, host, ips, source, is_alive, created_at FROM subdomains WHERE target_id = ?", targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []models.Subdomain
	for rows.Next() {
		var sub models.Subdomain
		var ipsRaw string
		var isAliveInt int
		if err := rows.Scan(&sub.ID, &sub.TargetID, &sub.Host, &ipsRaw, &sub.Source, &isAliveInt, &sub.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(ipsRaw), &sub.IPs)
		sub.IsAlive = isAliveInt == 1
		subs = append(subs, sub)
	}
	return subs, nil
}

// HTTP Service operations
func (s *Store) SaveHTTPService(svc *models.HTTPService) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	techJSON, _ := json.Marshal(svc.TechStack)

	query := `INSERT INTO http_services (id, subdomain_id, url, status_code, title, tech_stack, web_server, content_len, response_time_ms, created_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			  ON CONFLICT(url) DO UPDATE SET
			  status_code=excluded.status_code, title=excluded.title, tech_stack=excluded.tech_stack, web_server=excluded.web_server, response_time_ms=excluded.response_time_ms;`

	_, err := s.db.Exec(query, svc.ID, svc.SubdomainID, svc.URL, svc.StatusCode, svc.Title, string(techJSON), svc.WebServer, svc.ContentLen, svc.ResponseTime, time.Now())
	return err
}

func (s *Store) ListHTTPServices(targetID string) ([]models.HTTPService, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT hs.id, hs.subdomain_id, hs.url, hs.status_code, hs.title, hs.tech_stack, hs.web_server, hs.content_len, hs.response_time_ms, hs.created_at
			  FROM http_services hs
			  JOIN subdomains sd ON hs.subdomain_id = sd.id
			  WHERE sd.target_id = ?`

	rows, err := s.db.Query(query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var svcs []models.HTTPService
	for rows.Next() {
		var svc models.HTTPService
		var techRaw string
		if err := rows.Scan(&svc.ID, &svc.SubdomainID, &svc.URL, &svc.StatusCode, &svc.Title, &techRaw, &svc.WebServer, &svc.ContentLen, &svc.ResponseTime, &svc.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(techRaw), &svc.TechStack)
		svcs = append(svcs, svc)
	}
	return svcs, nil
}

// Endpoint operations
func (s *Store) SaveEndpoint(ep *models.Endpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	paramsJSON, _ := json.Marshal(ep.Params)

	query := `INSERT INTO endpoints (id, http_service_id, url, method, params, source, content_type, created_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			  ON CONFLICT(http_service_id, url, method) DO UPDATE SET
			  params=excluded.params;`

	_, err := s.db.Exec(query, ep.ID, ep.HTTPServiceID, ep.URL, ep.Method, string(paramsJSON), ep.Source, ep.ContentType, time.Now())
	return err
}

func (s *Store) ListEndpoints(targetID string) ([]models.Endpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT ep.id, ep.http_service_id, ep.url, ep.method, ep.params, ep.source, ep.content_type, ep.created_at
			  FROM endpoints ep
			  JOIN http_services hs ON ep.http_service_id = hs.id
			  JOIN subdomains sd ON hs.subdomain_id = sd.id
			  WHERE sd.target_id = ?`

	rows, err := s.db.Query(query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var eps []models.Endpoint
	for rows.Next() {
		var ep models.Endpoint
		var paramsRaw string
		if err := rows.Scan(&ep.ID, &ep.HTTPServiceID, &ep.URL, &ep.Method, &paramsRaw, &ep.Source, &ep.ContentType, &ep.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(paramsRaw), &ep.Params)
		eps = append(eps, ep)
	}
	return eps, nil
}

// Finding operations
func (s *Store) SaveFinding(f *models.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	evJSON, _ := json.Marshal(f.Evidence)

	query := `INSERT INTO findings (id, target_id, asset_url, title, severity, cvss_score, template_id, description, match_string, evidence, dedup_hash, status, ai_triage, created_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			  ON CONFLICT(dedup_hash) DO UPDATE SET
			  status=excluded.status, cvss_score=excluded.cvss_score, ai_triage=excluded.ai_triage;`

	_, err := s.db.Exec(query, f.ID, f.TargetID, f.AssetURL, f.Title, f.Severity, f.CVSSScore, f.TemplateID, f.Description, f.MatchString, string(evJSON), f.DedupHash, f.Status, f.AITriage, time.Now())
	return err
}

func (s *Store) ListFindings(targetID string) ([]models.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var query string
	var args []interface{}

	if targetID != "" {
		query = "SELECT id, target_id, asset_url, title, severity, cvss_score, template_id, description, match_string, evidence, dedup_hash, status, ai_triage, created_at FROM findings WHERE target_id = ? ORDER BY cvss_score DESC"
		args = append(args, targetID)
	} else {
		query = "SELECT id, target_id, asset_url, title, severity, cvss_score, template_id, description, match_string, evidence, dedup_hash, status, ai_triage, created_at FROM findings ORDER BY cvss_score DESC"
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		var evRaw string
		var aiTriage sql.NullString
		if err := rows.Scan(&f.ID, &f.TargetID, &f.AssetURL, &f.Title, &f.Severity, &f.CVSSScore, &f.TemplateID, &f.Description, &f.MatchString, &evRaw, &f.DedupHash, &f.Status, &aiTriage, &f.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(evRaw), &f.Evidence)
		if aiTriage.Valid {
			f.AITriage = aiTriage.String
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// Pipeline Run operations
func (s *Store) SavePipelineRun(run *models.PipelineRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT INTO pipeline_runs (id, target_id, workflow, status, progress_pct, current_stage, total_subdomains, total_services, total_endpoints, total_findings, start_time, end_time)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			  ON CONFLICT(id) DO UPDATE SET
			  status=excluded.status, progress_pct=excluded.progress_pct, current_stage=excluded.current_stage,
			  total_subdomains=excluded.total_subdomains, total_services=excluded.total_services,
			  total_endpoints=excluded.total_endpoints, total_findings=excluded.total_findings, end_time=excluded.end_time;`

	_, err := s.db.Exec(query, run.ID, run.TargetID, run.Workflow, run.Status, run.ProgressPct, run.CurrentStage, run.TotalSubdomains, run.TotalServices, run.TotalEndpoints, run.TotalFindings, run.StartTime, run.EndTime)
	return err
}

func (s *Store) GetPipelineRun(id string) (*models.PipelineRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow("SELECT id, target_id, workflow, status, progress_pct, current_stage, total_subdomains, total_services, total_endpoints, total_findings, start_time, end_time FROM pipeline_runs WHERE id = ?", id)
	var r models.PipelineRun
	err := row.Scan(&r.ID, &r.TargetID, &r.Workflow, &r.Status, &r.ProgressPct, &r.CurrentStage, &r.TotalSubdomains, &r.TotalServices, &r.TotalEndpoints, &r.TotalFindings, &r.StartTime, &r.EndTime)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) UpdateTargetRiskScore(targetID string, score float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("UPDATE targets SET risk_score = ?, updated_at = ? WHERE id = ?", score, time.Now(), targetID)
	return err
}

func (s *Store) GetStats() (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := make(map[string]interface{})

	var targetCount, subCount, svcCount, epCount, findingCount int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM targets").Scan(&targetCount)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM subdomains").Scan(&subCount)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM http_services").Scan(&svcCount)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM endpoints").Scan(&epCount)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM findings").Scan(&findingCount)

	stats["targets"] = targetCount
	stats["subdomains"] = subCount
	stats["services"] = svcCount
	stats["endpoints"] = epCount
	stats["findings"] = findingCount

	// Severity breakdown
	rows, err := s.db.Query("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
	if err == nil {
		sevMap := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
		for rows.Next() {
			var sev string
			var count int
			if err := rows.Scan(&sev, &count); err == nil {
				sevMap[strings.Title(strings.ToLower(sev))] += count
			}
		}
		rows.Close()
		stats["severity_breakdown"] = sevMap
	}

	return stats, nil
}
