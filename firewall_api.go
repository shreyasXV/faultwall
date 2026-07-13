package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/shreyasXV/faultwall/policygen/agent"
)

// handleFirewallAgents returns all known agents (active and historical)
// GET /api/firewall/agents
func handleFirewallAgents(w http.ResponseWriter, r *http.Request) {
	// Return persistent agent records (active + inactive)
	allAgents := agentTracker.GetAllAgents()

	// Also include live connections for active agents
	conns := agentTracker.GetConnections()

	type agentResponse struct {
		AgentID      string  `json:"agent_id"`
		LastMission  string  `json:"last_mission"`
		Active       bool    `json:"active"`
		FirstSeen    string  `json:"first_seen"`
		LastSeen     string  `json:"last_seen"`
		TotalQueries int     `json:"total_queries"`
		Violations   int     `json:"violations"`
		LastPID      int     `json:"last_pid"`
		LastClientIP string  `json:"last_client_ip"`
		Username     string  `json:"username"`
	}

	agents := make([]agentResponse, 0, len(allAgents))
	for _, rec := range allAgents {
		agents = append(agents, agentResponse{
			AgentID:      rec.AgentID,
			LastMission:  rec.LastMission,
			Active:       rec.Active,
			FirstSeen:    rec.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:     rec.LastSeen.UTC().Format(time.RFC3339),
			TotalQueries: rec.TotalQueries,
			Violations:   rec.Violations,
			LastPID:      rec.LastPID,
			LastClientIP: rec.LastClientIP,
			Username:     rec.Username,
		})
	}

	writeJSON(w, map[string]interface{}{
		"agents":             agents,
		"count":              len(agents),
		"active_connections": len(conns),
	})
}

// handleFirewallAgentQueries returns queries by a specific agent
// GET /api/firewall/agents/{agent_id}/queries
func handleFirewallAgentQueries(w http.ResponseWriter, r *http.Request) {
	// Parse agent_id from path: /api/firewall/agents/{agent_id}/queries
	path := strings.TrimPrefix(r.URL.Path, "/api/firewall/agents/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "agent_id required", http.StatusBadRequest)
		return
	}
	agentID := parts[0]

	conns := agentTracker.GetAgentConnections(agentID)
	writeJSON(w, map[string]interface{}{
		"agent_id":    agentID,
		"connections": conns,
		"count":       len(conns),
	})
}

// handlePolicies returns the current loaded policies
// GET /api/policies
func handlePolicies(w http.ResponseWriter, r *http.Request) {
	cfg := policyEngine.GetConfig()
	writeJSON(w, cfg)
}

// handlePoliciesYAML serves the raw on-disk policies file as downloadable YAML.
// GET /api/policies/yaml
func handlePoliciesYAML(w http.ResponseWriter, r *http.Request) {
	path := policyEngine.GetFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "could not read policies file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="policies.yaml"`)
	w.Write(data)
}

// handlePoliciesReload hot-reloads the policies.yaml file
// POST /api/policies/reload
func handlePoliciesReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	if err := policyEngine.Reload(); err != nil {
		writeJSON(w, map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	writeJSON(w, map[string]interface{}{
		"status":  "ok",
		"message": "Policies reloaded successfully",
	})
}

// handleViolations returns policy violations, optionally filtered by agent
// GET /api/violations
// GET /api/violations?agent=cursor-ai
func handleViolations(w http.ResponseWriter, r *http.Request) {
	agentFilter := r.URL.Query().Get("agent")

	var violations []PolicyViolation
	if agentFilter != "" {
		violations = policyEngine.GetViolationsByAgent(agentFilter)
	} else {
		violations = policyEngine.GetViolations()
	}

	// Return newest first, with PII annotations
	type violationWithPII struct {
		PolicyViolation
		HasPII     bool     `json:"has_pii"`
		PIIColumns []string `json:"pii_columns,omitempty"`
	}

	reversed := make([]violationWithPII, len(violations))
	for i, v := range violations {
		vp := violationWithPII{PolicyViolation: v}
		// Parse query to detect PII columns
		if v.Query != "" {
			parsed := ParseQuery(v.Query)
			vp.HasPII = parsed.HasPII
			vp.PIIColumns = parsed.PIIColumns
		}
		reversed[len(violations)-1-i] = vp
	}

	writeJSON(w, map[string]interface{}{
		"violations": reversed,
		"count":      len(reversed),
	})
}

// handleQWMFlags returns recent QWM shadow-mode risk flags, newest first,
// optionally filtered by agent. Observe-only telemetry (F11): these queries
// were scored above the QWM flag threshold but were NOT blocked by QWM.
// GET /api/qwm/flags
// GET /api/qwm/flags?agent=cursor-ai
func handleQWMFlags(w http.ResponseWriter, r *http.Request) {
	flags := GetQWMFlags(r.URL.Query().Get("agent"))
	writeJSON(w, map[string]interface{}{
		"flags":     flags,
		"count":     len(flags),
		"threshold": qwmFlagThreshold,
		"observe_only": true,
	})
}

// handleAPAProposals returns the local APA state so a self-host user can see
// what APA is proposing without a control plane or PR setup (Soumya request):
//   - per-agent allowed_fingerprints + pending_review (from the policy file)
//   - recent APA runs (from the local audit log: confidence, PR url, errors)
// GET /api/apa/proposals
func handleAPAProposals(w http.ResponseWriter, r *http.Request) {
	policyPath := os.Getenv("POLICY_FILE")
	if policyPath == "" {
		policyPath = "./policies.yaml"
	}
	auditPath := os.Getenv("APA_AUDIT_LOG")
	if auditPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			auditPath = home + "/.faultwall/apa_audit.jsonl"
		}
	}

	agents, err := agent.LoadAPAView(policyPath)
	if err != nil {
		agents = nil // policy unreadable — still return runs + empty agents
	}
	runs, _ := agent.LoadRecentAuditRecords(auditPath, 50)

	pendingTotal := 0
	for _, a := range agents {
		pendingTotal += len(a.PendingReview)
	}

	writeJSON(w, map[string]interface{}{
		"agents":        agents,
		"recent_runs":   runs,
		"pending_total": pendingTotal,
	})
}

// apaProposalDir resolves the file-drop proposal directory the same way the
// `apa` command does: APA_PROPOSAL_DIR env, else ~/.faultwall.
func apaProposalDir() string {
	if env := os.Getenv("APA_PROPOSAL_DIR"); env != "" {
		return env
	}
	if home, err := os.UserHomeDir(); err == nil {
		return home + "/.faultwall"
	}
	return ".faultwall"
}

// handleAPAProposalFiles lists file-drop APA proposals (the no-git review
// queue). Each entry is a downloadable, apply-ready policy YAML plus a diff.
// GET /api/apa/proposals/files
func handleAPAProposalFiles(w http.ResponseWriter, r *http.Request) {
	props, err := agent.ListProposals(apaProposalDir())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Summary view: omit the (potentially large) merged YAML from the list; it
	// is fetched on demand via the download endpoint.
	type summary struct {
		ID         string    `json:"id"`
		AgentID    string    `json:"agent_id"`
		Title      string    `json:"title"`
		Confidence float64   `json:"confidence"`
		DiffLines  int       `json:"diff_lines"`
		YAMLDiff   string    `json:"yaml_diff"`
		CreatedAt  time.Time `json:"created_at"`
		Status     string    `json:"status"`
		DownloadURL string   `json:"download_url"`
	}
	out := make([]summary, 0, len(props))
	for _, p := range props {
		out = append(out, summary{
			ID: p.ID, AgentID: p.AgentID, Title: p.Title, Confidence: p.Confidence,
			DiffLines: p.DiffLines, YAMLDiff: p.YAMLDiff, CreatedAt: p.CreatedAt,
			Status: p.Status, DownloadURL: "/api/apa/proposals/files/" + p.ID + "/download",
		})
	}
	writeJSON(w, map[string]interface{}{"proposals": out, "count": len(out)})
}

// handleAPAProposalFileAction serves a single file-drop proposal:
//   GET  /api/apa/proposals/files/{id}/download  → the proposed policies.yaml
//   POST /api/apa/proposals/files/{id}/apply     → mark applied
//   POST /api/apa/proposals/files/{id}/dismiss   → mark dismissed
func handleAPAProposalFileAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/apa/proposals/files/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 {
		http.Error(w, "expected /api/apa/proposals/files/{id}/{download|apply|dismiss}", http.StatusBadRequest)
		return
	}
	id, action := parts[0], parts[1]
	dir := apaProposalDir()

	switch action {
	case "download":
		p, err := agent.GetProposal(dir, id)
		if err != nil {
			http.Error(w, "proposal not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml")
		w.Header().Set("Content-Disposition", "attachment; filename=\"policies.proposed."+p.ID+".yaml\"")
		_, _ = w.Write([]byte(p.MergedYAML))
	case "apply", "dismiss":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		status := "applied"
		if action == "dismiss" {
			status = "dismissed"
		}
		if err := agent.SetProposalStatus(dir, id, status); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]interface{}{"id": id, "status": status})
	default:
		http.Error(w, "unknown action: "+action, http.StatusBadRequest)
	}
}

// handleAgentStats returns per-agent aggregated metrics
// GET /api/agents/stats
func handleAgentStats(w http.ResponseWriter, r *http.Request) {
	allAgents := agentTracker.GetAllAgents()

	costPerRow := 0.0001 // default $0.0001 per row

	type agentStats struct {
		AgentID        string  `json:"agent_id"`
		TotalQueries   int     `json:"total_queries"`
		TotalRows      int64   `json:"total_rows"`
		EstimatedCost  float64 `json:"estimated_cost"`
		TotalDurationMs float64 `json:"total_duration_ms"`
		AvgDurationMs  float64 `json:"avg_duration_ms"`
		Violations     int     `json:"violations"`
		Active         bool    `json:"active"`
		Paused         bool    `json:"paused"`
	}

	stats := make([]agentStats, 0, len(allAgents))
	for _, rec := range allAgents {
		avgDur := 0.0
		if rec.TotalQueries > 0 {
			avgDur = rec.TotalDurationMs / float64(rec.TotalQueries)
		}
		stats = append(stats, agentStats{
			AgentID:        rec.AgentID,
			TotalQueries:   rec.TotalQueries,
			TotalRows:      rec.TotalRows,
			EstimatedCost:  float64(rec.TotalRows) * costPerRow,
			TotalDurationMs: rec.TotalDurationMs,
			AvgDurationMs:  avgDur,
			Violations:     rec.Violations,
			Active:         rec.Active,
			Paused:         policyEngine.IsAgentPaused(rec.AgentID),
		})
	}

	writeJSON(w, map[string]interface{}{
		"agents":       stats,
		"count":        len(stats),
		"cost_per_row": costPerRow,
	})
}

// handleBlockRule adds a blocked query pattern to the agent's policy and persists it
// POST /api/rules/block
// Body: {"query_pattern": "...", "agent_id": "..."}
func handleBlockRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "failed to read body"})
		return
	}

	var req struct {
		QueryPattern string `json:"query_pattern"`
		AgentID      string `json:"agent_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "invalid JSON"})
		return
	}

	if req.QueryPattern == "" {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "query_pattern required"})
		return
	}

	// Extract tables from the query pattern to add to blocked_tables
	parsed := ParseQuery(req.QueryPattern)
	tables := parsed.Tables

	cfg := policyEngine.GetConfig()
	if cfg == nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "no policy config loaded"})
		return
	}

	// Add tables to the agent's blocked_tables (or unidentified if no agent)
	policyEngine.mu.Lock()
	if req.AgentID != "" && req.AgentID != "unidentified" {
		agent, exists := cfg.Agents[req.AgentID]
		if !exists {
			agent = AgentPolicy{Description: "Auto-created by block rule"}
		}
		for _, t := range tables {
			if !isTableBlocked(t, agent.BlockedTables) {
				agent.BlockedTables = append(agent.BlockedTables, t)
			}
		}
		cfg.Agents[req.AgentID] = agent
	}
	policyEngine.mu.Unlock()

	// Persist to file and reload
	if err := policyEngine.SaveToFile(); err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": err.Error()})
		return
	}
	if err := policyEngine.Reload(); err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": err.Error()})
		return
	}

	writeJSON(w, map[string]interface{}{
		"status":         "ok",
		"message":        "Block rule applied and persisted",
		"blocked_tables": tables,
		"agent_id":       req.AgentID,
	})
}

// handleRulePreview generates a YAML policy rule preview from a query without applying it
// POST /api/rules/preview
// Body: {"query": "...", "agent_id": "...", "action": "block_table|block_operation|block_function"}
func handleRulePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "failed to read body"})
		return
	}

	var req struct {
		Query   string `json:"query"`
		AgentID string `json:"agent_id"`
		Action  string `json:"action"` // block_table, block_operation, block_function
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "invalid JSON"})
		return
	}

	rule := generateRuleFromQuery(req.Query, req.AgentID, req.Action)
	writeJSON(w, rule)
}

// handleRuleCreate generates and applies a YAML policy rule from a query
// POST /api/rules/create
// Body: {"query": "...", "agent_id": "...", "action": "block_table|block_operation|block_function"}
func handleRuleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "failed to read body"})
		return
	}

	var req struct {
		Query   string `json:"query"`
		AgentID string `json:"agent_id"`
		Action  string `json:"action"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "invalid JSON"})
		return
	}

	if req.Query == "" || req.AgentID == "" {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "query and agent_id required"})
		return
	}

	rule := generateRuleFromQuery(req.Query, req.AgentID, req.Action)

	// Apply the rule to the live config
	cfg := policyEngine.GetConfig()
	if cfg == nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "no policy config loaded"})
		return
	}

	policyEngine.mu.Lock()
	agent, exists := cfg.Agents[req.AgentID]
	if !exists {
		agent = AgentPolicy{Description: "Auto-created by rule builder"}
	}

	blockedTables, _ := rule["blocked_tables"].([]string)
	for _, t := range blockedTables {
		if !isTableBlocked(t, agent.BlockedTables) {
			agent.BlockedTables = append(agent.BlockedTables, t)
		}
	}

	blockedOps, _ := rule["blocked_operations"].([]string)
	for _, op := range blockedOps {
		found := false
		for _, existing := range agent.BlockedOperations {
			if strings.EqualFold(existing, op) {
				found = true
				break
			}
		}
		if !found {
			agent.BlockedOperations = append(agent.BlockedOperations, op)
		}
	}

	blockedFuncs, _ := rule["blocked_functions"].([]string)
	if len(blockedFuncs) > 0 {
		for _, fn := range blockedFuncs {
			if !isFunctionBlocked(fn, cfg.BlockedFunctions) {
				cfg.BlockedFunctions = append(cfg.BlockedFunctions, fn)
			}
		}
	}

	cfg.Agents[req.AgentID] = agent
	policyEngine.mu.Unlock()

	if err := policyEngine.SaveToFile(); err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": err.Error()})
		return
	}
	if err := policyEngine.Reload(); err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": err.Error()})
		return
	}

	rule["status"] = "ok"
	rule["message"] = "Rule applied and persisted to " + policyEngine.GetFilePath()
	writeJSON(w, rule)
}

// generateRuleFromQuery analyzes a query and generates a policy rule
func generateRuleFromQuery(query, agentID, action string) map[string]interface{} {
	parsed := ParseQuery(query)

	result := map[string]interface{}{
		"agent_id":   agentID,
		"query":      query,
		"operation":  parsed.Operation,
		"tables":     parsed.Tables,
		"functions":  parsed.Functions,
		"columns":    parsed.Columns,
		"has_pii":    parsed.HasPII,
		"pii_columns": parsed.PIIColumns,
	}

	// Generate YAML preview
	var yamlLines []string
	yamlLines = append(yamlLines, "# Auto-generated rule for agent: "+agentID)
	yamlLines = append(yamlLines, "# Source query: "+truncateQuery(query))
	yamlLines = append(yamlLines, agentID+":")

	var blockedTables []string
	var blockedOps []string
	var blockedFuncs []string

	switch action {
	case "block_operation":
		if parsed.Operation != "" {
			blockedOps = append(blockedOps, parsed.Operation)
			yamlLines = append(yamlLines, "  blocked_operations:")
			yamlLines = append(yamlLines, "    - "+parsed.Operation)
		}
	case "block_function":
		blockedFuncs = parsed.Functions
		if len(parsed.Functions) > 0 {
			yamlLines = append(yamlLines, "  # Add to global blocked_functions:")
			for _, fn := range parsed.Functions {
				yamlLines = append(yamlLines, "  #   - "+fn)
			}
		}
	default: // block_table (default)
		blockedTables = parsed.Tables
		if len(parsed.Tables) > 0 {
			yamlLines = append(yamlLines, "  blocked_tables:")
			for _, t := range parsed.Tables {
				yamlLines = append(yamlLines, "    - "+t)
			}
		}
	}

	result["yaml_preview"] = strings.Join(yamlLines, "\n")
	result["blocked_tables"] = blockedTables
	result["blocked_operations"] = blockedOps
	result["blocked_functions"] = blockedFuncs
	result["action"] = action

	return result
}

// handlePauseAgent pauses or resumes an agent
// POST /api/agents/pause/{agent_id} — pause the agent
// DELETE /api/agents/pause/{agent_id} — resume the agent
// GET /api/agents/pause/{agent_id} — check pause status
func handlePauseAgent(w http.ResponseWriter, r *http.Request) {
	// Parse agent_id from path: /api/agents/pause/{agent_id}
	agentID := strings.TrimPrefix(r.URL.Path, "/api/agents/pause/")
	if agentID == "" {
		// Return list of all paused agents
		writeJSON(w, map[string]interface{}{
			"paused_agents": policyEngine.GetPausedAgents(),
		})
		return
	}

	switch r.Method {
	case http.MethodPost:
		policyEngine.SetAgentPaused(agentID, true)
		writeJSON(w, map[string]interface{}{
			"status":   "ok",
			"agent_id": agentID,
			"paused":   true,
			"message":  "Agent paused — all queries will be blocked",
		})
	case http.MethodDelete:
		policyEngine.SetAgentPaused(agentID, false)
		writeJSON(w, map[string]interface{}{
			"status":   "ok",
			"agent_id": agentID,
			"paused":   false,
			"message":  "Agent resumed",
		})
	case http.MethodGet:
		paused := policyEngine.IsAgentPaused(agentID)
		writeJSON(w, map[string]interface{}{
			"agent_id": agentID,
			"paused":   paused,
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
