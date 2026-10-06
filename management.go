package main

import (
	"log"
	"net"
	"net/http"
	"os"
)

func announceManagementDashboard(bind, port string) {
	ip := net.ParseIP(bind)
	if bind == "localhost" || (ip != nil && ip.IsLoopback()) {
		log.Printf("FaultWall dashboard: http://%s (operator token required)", net.JoinHostPort(bind, port))
		return
	}
	// Only advertise a network name when the operator explicitly binds
	// management to a network interface. The default is local-only.
	localHost := os.Getenv("FAULTWALL_HOSTNAME")
	if localHost == "" {
		localHost = defaultLocalHost
	}
	startMDNSResponder(localHost)
	log.Printf("FaultWall dashboard: %s (operator token required)", localDashboardURL(localHost, port))
}

// These constructors are used by the live servers and routing tests. Keep the
// authentication boundary outside the mux so routes cannot opt out by omission.
func proxyManagementHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"status": "ok", "mode": "proxy"})
	})
	mux.HandleFunc("/api/firewall/agents", handleFirewallAgents)
	mux.HandleFunc("/api/firewall/agents/", handleFirewallAgentQueries)
	mux.HandleFunc("/api/policies", handlePolicies)
	mux.HandleFunc("/api/policies/yaml", handlePoliciesYAML)
	mux.HandleFunc("/api/policies/reload", handlePoliciesReload)
	mux.HandleFunc("/api/agent-keys", handleAgentKeysStatus)
	mux.HandleFunc("/api/violations", handleViolations)
	mux.HandleFunc("/api/holds", handleHolds)
	mux.HandleFunc("/api/holds/", handleHoldAction)
	mux.HandleFunc("/api/qwm/flags", handleQWMFlags)
	mux.HandleFunc("/api/apa/proposals", handleAPAProposals)
	mux.HandleFunc("/api/apa/proposals/files", handleAPAProposalFiles)
	mux.HandleFunc("/api/apa/proposals/files/", handleAPAProposalFileAction)
	mux.HandleFunc("/api/rules/block", handleBlockRule)
	mux.HandleFunc("/api/rules/preview", handleRulePreview)
	mux.HandleFunc("/api/rules/create", handleRuleCreate)
	mux.HandleFunc("/api/agents/pause/", handlePauseAgent)
	mux.HandleFunc("/api/agents/stats", handleAgentStats)
	mux.HandleFunc("/api/tenants", handleTenants)
	mux.HandleFunc("/api/queries", handleQueries)
	mux.HandleFunc("/api/config", handleConfig)
	mux.HandleFunc("/api/export/csv", handleExportCSV)
	mux.HandleFunc("/api/export/json", handleExportJSON)
	mux.HandleFunc("/favicon.png", handleFavicon)
	mux.HandleFunc("/favicon.ico", handleFavicon)
	mux.HandleFunc("/", handleDashboard)
	return managementHandler(mux)
}

func dashboardManagementHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.png", handleFavicon)
	mux.HandleFunc("/favicon.ico", handleFavicon)
	mux.HandleFunc("/", handleDashboard)
	mux.HandleFunc("/api/tenants", handleTenants)
	mux.HandleFunc("/api/queries", handleQueries)
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/api/config", handleConfig)

	// Alerts
	mux.HandleFunc("/api/alerts", handleAlerts)
	mux.HandleFunc("/api/alerts/history", handleAlertsHistory)
	mux.HandleFunc("/api/alerts/rules", handleAlertsRules)

	// History / time-series
	mux.HandleFunc("/api/history", handleHistory)
	mux.HandleFunc("/api/history/overview", handleHistoryOverview)

	// Throttle
	mux.HandleFunc("/api/throttle/status", handleThrottleStatus)
	mux.HandleFunc("/api/throttle/config", handleThrottleConfig)

	// Cost attribution
	mux.HandleFunc("/api/costs", handleCosts)

	// Anomaly detection
	mux.HandleFunc("/api/anomalies", handleAnomalies)
	mux.HandleFunc("/api/anomalies/baseline", handleTenantBaseline)

	// Predictions
	mux.HandleFunc("/api/predictions", handlePredictions)

	// Agent-native API
	mux.HandleFunc("/api/agents/status", handleAgentStatus)
	mux.HandleFunc("/api/agents/noisy", handleAgentNoisy)
	mux.HandleFunc("/api/agents/tenant/", handleAgentTenant)
	mux.HandleFunc("/api/agents/costs", handleAgentCosts)
	mux.HandleFunc("/api/agents/recommendation", handleAgentRecommendation)
	mux.HandleFunc("/api/agents/anomalies", handleAgentAnomalies)
	mux.HandleFunc("/api/agents/predictions", handleAgentPredictions)

	// Firewall: agent identity + policy enforcement
	mux.HandleFunc("/api/firewall/agents", handleFirewallAgents)
	mux.HandleFunc("/api/firewall/agents/", handleFirewallAgentQueries)
	mux.HandleFunc("/api/policies", handlePolicies)
	mux.HandleFunc("/api/policies/yaml", handlePoliciesYAML)
	mux.HandleFunc("/api/policies/reload", handlePoliciesReload)
	mux.HandleFunc("/api/violations", handleViolations)
	mux.HandleFunc("/api/rules/block", handleBlockRule)
	mux.HandleFunc("/api/rules/preview", handleRulePreview)
	mux.HandleFunc("/api/rules/create", handleRuleCreate)
	mux.HandleFunc("/api/agents/pause/", handlePauseAgent)
	mux.HandleFunc("/api/agents/stats", handleAgentStats)
	mux.HandleFunc("/api/holds", handleHolds)
	mux.HandleFunc("/api/holds/", handleHoldAction)

	// Export
	mux.HandleFunc("/api/export/csv", handleExportCSV)
	mux.HandleFunc("/api/export/json", handleExportJSON)
	return managementHandler(mux)
}
