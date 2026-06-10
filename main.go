package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"
)

var (
	db               *sql.DB
	collector        *Collector
	detector         *Detector
	alertManager     *AlertManager
	historyStore     *HistoryStore
	slackBot         *SlackNotifier
	throttler        *Throttler
	costEstimator    *CostEstimator
	anomalyDetector  *AnomalyDetector
	predictor        *Predictor
	agentTracker     *AgentTracker
	policyEngine     *PolicyEngine
	observationStore   *ObservationStore
	qwmScorer          QWMScorer
	qwmStateSampler    *StateSampler
	qwmFlagThreshold   = 0.7 // shadow mode: flag but never block
)

func main() {
	// Subcommands (init, agent-url, version, help) — handled before flag parsing.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "init":
			if err := runInit(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "Error:", err)
				os.Exit(1)
			}
			return
		case "agent-url":
			if err := runAgentURL(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "Error:", err)
				os.Exit(1)
			}
			return
		case "version", "-v", "--version":
			fmt.Println("faultwall", Version)
			return
		case "help", "-h", "--help":
			printRootHelp()
			return
		case "apa":
			if err := runAPA(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "Error:", err)
				os.Exit(1)
			}
			return
		}
	}

	// Check for mode flags
	mcpMode := false
	tunerMode := false
	proxyMode := false
	proxyListen := ":5433"
	proxyUpstream := "localhost:5432"
	proxyPolicies := "./policies.yaml"
	tlsCert := os.Getenv("TLS_CERT_FILE")
	tlsKey := os.Getenv("TLS_KEY_FILE")
	upstreamTLS := os.Getenv("UPSTREAM_TLS") == "true"
	upstreamTLSSkipVerify := os.Getenv("UPSTREAM_TLS_SKIP_VERIFY") == "true"
	for i, arg := range os.Args[1:] {
		switch arg {
		case "--mcp":
			mcpMode = true
		case "--tune":
			tunerMode = true
		case "--proxy":
			proxyMode = true
		case "--listen":
			if i+1 < len(os.Args[1:])-0 {
				proxyListen = os.Args[i+2]
			}
		case "--upstream":
			if i+1 < len(os.Args[1:])-0 {
				proxyUpstream = os.Args[i+2]
			}
		case "--policies":
			if i+1 < len(os.Args[1:])-0 {
				proxyPolicies = os.Args[i+2]
			}
		case "--tls-cert":
			if i+1 < len(os.Args[1:])-0 {
				tlsCert = os.Args[i+2]
			}
		case "--tls-key":
			if i+1 < len(os.Args[1:])-0 {
				tlsKey = os.Args[i+2]
			}
		case "--upstream-tls":
			upstreamTLS = true
		case "--upstream-tls-skip-verify":
			upstreamTLSSkipVerify = true
		}
	}

	// Tuner mode — run autoresearch optimization, no DB needed
	if tunerMode {
		result := RunTuner(100, 50, 0.3)
		outPath := "tuner_results/latest.json"
		os.MkdirAll("tuner_results", 0755)
		if err := SaveTunerResult(result, outPath); err != nil {
			log.Fatalf("Error saving: %v", err)
		}
		fmt.Printf("  Results saved to: %s\n", outPath)
		return
	}

	// Proxy mode — inline L7 query firewall
	// If DATABASE_URL is set, also start the HTTP dashboard/API server
	if proxyMode {
		os.Setenv("POLICY_FILE", proxyPolicies)
		os.Setenv("POLICY_ENFORCEMENT", "enforce")
		policyEngine = NewPolicyEngine()
		agentTracker = NewAgentTracker()
		observationStore = NewObservationStore(os.Getenv("OBSERVATION_PATH"))

		// QWM: RFC-003 state-conditioned world model. Loads an optional trained
		// artifact (FW_QWM_MODEL or ~/.faultwall/qwm_world_model.json); otherwise
		// uses cold-start defaults. Falls back to the shape-based shadow scorer for
		// fingerprints with no learned base service, so we never regress.
		shapeFallback := NewShadowQWMScorer()
		wmArtifact := loadWorldModelArtifact()
		qwmScorer = NewWorldModelScorer(wmArtifact, shapeFallback)

		// Live DB-state sampler (~1s) feeding the world model. Uses DATABASE_URL
		// or a monitoring DSN derived from the upstream; degrades to queuing-prior
		// only if no monitoring connection is available.
		if dsn, ok := monitoringDSNFromUpstream(proxyUpstream); ok {
			if mdb, err := openMonitoringDB(dsn); err == nil {
				if perr := mdb.Ping(); perr == nil {
					cores := qwmConfiguredCores()
					qwmStateSampler = NewStateSampler(mdb, cores, time.Second)
					qwmStateSampler.Start()
					log.Printf("⚡ QWM world model active (SLO %.0fms, %.0f core(s)) — live state sampling on", wmArtifact.SLOms, cores)
				} else {
					mdb.Close()
					log.Printf("⚡ QWM world model active (queuing prior only) — monitoring DB ping failed: %v", perr)
				}
			} else {
				log.Printf("⚡ QWM world model active (queuing prior only) — monitoring DB open failed: %v", err)
			}
		} else {
			log.Printf("⚡ QWM world model active (queuing prior only) — no monitoring DSN")
		}
		go func() {
			ticker := time.NewTicker(60 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				if err := observationStore.Flush(); err != nil {
					log.Printf("observation flush: %v", err)
				}
			}
		}()
		log.Printf("🛡️  FaultWall L7 proxy mode (policies: %s)", proxyPolicies)

		// Optional control-plane telemetry (metadata only). Enabled when
		// ~/.faultwall/config.toml has a [control_plane] url+token (written by
		// install.sh) and telemetry_enabled is true. Fire-and-forget: never
		// blocks the query path.
		if cpCfg, ok := loadControlPlaneConfig(); ok {
			telemetryClient = NewTelemetryClient(cpCfg)
			telemetryClient.StartHeartbeat(60 * time.Second)
			log.Printf("📡 Control-plane telemetry enabled → %s (metadata only)", cpCfg.URL)
		}

		// Self-disabling feature guards (see guards.go). Each guard runs a
		// startup self-check; if the check fails, the new behavior turns
		// itself off and the proxy falls back to the prior safe path. We
		// run these BEFORE starting the proxy so the gates are settled
		// before any connection is accepted.
		InitUnqualifiedAllowGuard()                       // F2 (shipped: public-only)
		InitSearchPathAwareAllowGuard()                   // REAL-F2 (per-connection search_path)
		LogIdentitySpoofWarning(policyEngine.GetConfig()) // F3 (always)
		InitRequireAuthTokenGuard()                       // F3 (optional enforce)
		RunDBIsolationProbe(proxyUpstream)                // F9 (shipped: TCP probe)
		InitBypassDetectionGuard()                        // REAL-F9 (runtime bypass detection)

		// REAL-F9: poll pg_stat_activity and warn on agent-like sessions
		// the proxy did not originate. Uses a small monitoring DB pool
		// (same DSN strategy as the QWM state sampler — DATABASE_URL
		// preferred, falls back to upstream-derived). Observe-only.
		if IsBypassDetectionOn() {
			if dsn, ok := monitoringDSNFromUpstream(proxyUpstream); ok {
				if mdb, err := openMonitoringDB(dsn); err == nil {
					if perr := mdb.Ping(); perr == nil {
						interval := 30 * time.Second
						if v := os.Getenv("FW_BYPASS_DETECTION_INTERVAL"); v != "" {
							if d, err := time.ParseDuration(v); err == nil && d > 0 {
								interval = d
							}
						}
						bd := NewBypassDetector(proxyBackendRegistry, NewDBBypassRowSource(mdb), interval)
						bd.Start()
						log.Printf("🔍 REAL-F9 bypass detector running every %s (observe-only)", interval)
					} else {
						mdb.Close()
						log.Printf("⚠️  REAL-F9 bypass detector: monitoring DB ping failed: %v — detection skipped", perr)
					}
				} else {
					log.Printf("⚠️  REAL-F9 bypass detector: monitoring DB open failed: %v — detection skipped", err)
				}
			} else {
				log.Printf("⚠️  REAL-F9 bypass detector: no monitoring DSN — detection skipped")
			}
		}

		// Start proxy in a goroutine so we can also run the API server
		go runProxy(proxyListen, proxyUpstream, policyEngine, tlsCert, tlsKey, upstreamTLS, upstreamTLSSkipVerify)

		// If DATABASE_URL is set, start the full API server alongside the proxy
		// If not, start a minimal API server for violations/agents/policies only
		apiPort := os.Getenv("PORT")
		if apiPort == "" {
			apiPort = "8080"
		}
		apiBind := os.Getenv("BIND_ADDR")
		if apiBind == "" {
			apiBind = "0.0.0.0"
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]interface{}{"status": "ok", "mode": "proxy"})
		})
		mux.HandleFunc("/api/firewall/agents", handleFirewallAgents)
		mux.HandleFunc("/api/firewall/agents/", handleFirewallAgentQueries)
		mux.HandleFunc("/api/policies", handlePolicies)
		mux.HandleFunc("/api/policies/reload", handlePoliciesReload)
		mux.HandleFunc("/api/violations", handleViolations)
		mux.HandleFunc("/api/qwm/flags", handleQWMFlags)
		mux.HandleFunc("/api/apa/proposals", handleAPAProposals)
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

		apiAddr := fmt.Sprintf("%s:%s", apiBind, apiPort)

		// Advertise a friendly .local name via mDNS so customers open the
		// dashboard at http://faultwall.local:PORT instead of localhost. Override
		// with FAULTWALL_HOSTNAME. Best-effort; never blocks startup.
		localHost := os.Getenv("FAULTWALL_HOSTNAME")
		if localHost == "" {
			localHost = defaultLocalHost
		}
		startMDNSResponder(localHost)
		log.Printf("\U0001f4ca FaultWall dashboard: %s  (also http://localhost:%s)", localDashboardURL(localHost, apiPort), apiPort)
		srv := &http.Server{Addr: apiAddr, Handler: mux}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("API server error: %v", err)
			}
		}()

		<-ctx.Done()
		log.Println("Shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
		if observationStore != nil {
			if err := observationStore.Flush(); err != nil {
				log.Printf("observation shutdown flush: %v", err)
			}
		}
		if telemetryClient != nil {
			telemetryClient.Close()
		}
		return
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	// Default to sslmode=prefer if not specified (works for both local dev and cloud)
	if !strings.Contains(dbURL, "sslmode=") {
		sep := "?"
		if strings.Contains(dbURL, "?") {
			sep = "&"
		}
		dbURL += sep + "sslmode=prefer"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Optional env vars
	slackWebhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	alertWebhookURL := os.Getenv("ALERT_WEBHOOK_URL")

	var err error
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to open database connection: %v", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("✅ Connected to PostgreSQL")

	// Check pg_stat_statements
	var extExists bool
	err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')`).Scan(&extExists)
	if err != nil || !extExists {
		fmt.Println(`
⚠️  pg_stat_statements extension is NOT enabled.

To enable it, run as a superuser:
  CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

And add to postgresql.conf:
  shared_preload_libraries = 'pg_stat_statements'

Then restart PostgreSQL. FaultWall will run in degraded mode without query-level metrics.`)
	} else {
		log.Println("✅ pg_stat_statements extension detected")
	}

	// Initialize subsystems
	slackBot = NewSlackNotifier(slackWebhookURL)
	alertManager = NewAlertManager(alertWebhookURL, slackBot)
	historyStore = NewHistoryStore()
	throttler = NewThrottler(slackBot)
	costEstimator = NewCostEstimator()
	anomalyDetector = NewAnomalyDetector(slackBot)
	predictor = NewPredictor()

	if slackWebhookURL != "" {
		log.Println("✅ Slack notifications enabled")
	}
	if alertWebhookURL != "" {
		log.Printf("✅ Alert webhook configured: %s", alertWebhookURL)
	}
	log.Printf("✅ History store initialized (retention: %s)", os.Getenv("HISTORY_RETENTION"))
	log.Printf("✅ Throttler initialized (enabled: %v)", throttler.GetConfig().Enabled)
	log.Printf("✅ Cost estimator initialized (RDS hourly: $%.2f)", costEstimator.rdsHourlyCost)
	log.Printf("✅ Anomaly detector initialized (window: %d, sensitivity: %.1f)", anomalyDetector.windowSize, anomalyDetector.sensitivity)
	log.Printf("✅ Predictor initialized (threshold: %.0fms)", predictor.thresholdMs)

	agentTracker = NewAgentTracker()
	policyEngine = NewPolicyEngine()
	log.Printf("Policy engine initialized (enforcement: %s, file: %s)", policyEngine.enforcement, policyEngine.filePath)

	detector = NewDetector(db)
	collector = NewCollector(db)

	// Run initial detection
	if err := detector.Detect(); err != nil {
		log.Printf("⚠️  Tenant detection warning: %v", err)
	} else {
		log.Printf("🔍 Detected isolation pattern: %s", detector.Pattern)
		if len(detector.Tenants) > 0 {
			log.Printf("👥 Found %d tenants", len(detector.Tenants))
		}
	}

	// Get max connections for alert evaluation
	var maxConns int
	if err := db.QueryRow(`SHOW max_connections`).Scan(&maxConns); err != nil {
		maxConns = 100
	}

	// Graceful shutdown context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start background collection
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			if err := collector.Collect(detector); err != nil {
				log.Printf("Collection error: %v", err)
			} else {
				data := collector.GetData()
				historyStore.Record(data)
				alertManager.Evaluate(data, maxConns)
				throttler.Evaluate(db, detector)
				costEstimator.Estimate(data)
				anomalyDetector.Evaluate(data)
				predictor.Evaluate(data)
			}
			// Poll agent connections and enforce policies
			if err := agentTracker.Poll(db); err != nil {
				log.Printf("Agent tracker poll error: %v", err)
			} else {
				conns := agentTracker.GetConnections()
				if len(conns) > 0 {
					log.Printf("🔍 Agent poll: found %d agent connections", len(conns))
					for _, conn := range conns {
						log.Printf("  → pid=%d agent=%s state=%s query=%s", conn.PID, conn.ApplicationName, conn.State, conn.Query)
						policyEngine.EnforceOnConnection(db, conn)
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	// Run first collection immediately
	if err := collector.Collect(detector); err != nil {
		log.Printf("Initial collection warning: %v", err)
	} else {
		data := collector.GetData()
		historyStore.Record(data)
		costEstimator.Estimate(data)
	}

	// MCP mode: run JSON-RPC server over stdin/stdout
	if mcpMode {
		runMCP()
		return
	}

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
	mux.HandleFunc("/api/firewall/agents", bearerAuthMiddleware(handleFirewallAgents))
	mux.HandleFunc("/api/firewall/agents/", bearerAuthMiddleware(handleFirewallAgentQueries))
	mux.HandleFunc("/api/policies", handlePolicies)
	mux.HandleFunc("/api/policies/reload", bearerAuthMiddleware(handlePoliciesReload))
	mux.HandleFunc("/api/violations", bearerAuthMiddleware(handleViolations))
	mux.HandleFunc("/api/rules/block", bearerAuthMiddleware(handleBlockRule))
	mux.HandleFunc("/api/rules/preview", bearerAuthMiddleware(handleRulePreview))
	mux.HandleFunc("/api/rules/create", bearerAuthMiddleware(handleRuleCreate))
	mux.HandleFunc("/api/agents/pause/", bearerAuthMiddleware(handlePauseAgent))
	mux.HandleFunc("/api/agents/stats", handleAgentStats)

	// Export
	mux.HandleFunc("/api/export/csv", handleExportCSV)
	mux.HandleFunc("/api/export/json", handleExportJSON)

	bindAddr := os.Getenv("BIND_ADDR")
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	listenAddr := fmt.Sprintf("%s:%s", bindAddr, port)

	// Advertise a friendly .local name via mDNS so customers reach the dashboard
	// at http://faultwall.local:PORT instead of http://localhost:PORT. Override
	// with FAULTWALL_HOSTNAME; best-effort, never blocks startup.
	localHost := os.Getenv("FAULTWALL_HOSTNAME")
	if localHost == "" {
		localHost = defaultLocalHost
	}
	startMDNSResponder(localHost)
	log.Printf("\U0001f6e1\ufe0f  FaultWall dashboard: %s  (also http://localhost:%s)", localDashboardURL(localHost, port), port)

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	// Start server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt
	<-ctx.Done()
	log.Println("Shutting down gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
	log.Println("Server stopped")
}
