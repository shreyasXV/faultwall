package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// AlertLevel represents the severity of an alert
type AlertLevel string

const (
	AlertInfo     AlertLevel = "info"
	AlertWarning  AlertLevel = "warning"
	AlertCritical AlertLevel = "critical"
)

// AlertOperator for threshold comparison
type AlertOperator string

const (
	OpGT  AlertOperator = "gt"
	OpLT  AlertOperator = "lt"
	OpGTE AlertOperator = "gte"
	OpLTE AlertOperator = "lte"
)

// AlertMetric identifies which metric to watch
type AlertMetric string

const (
	MetricP99MS       AlertMetric = "p99_ms"
	MetricQueries     AlertMetric = "queries"
	MetricConnections AlertMetric = "connections"
	MetricCacheHit    AlertMetric = "cache_hit"
	MetricIOBytes     AlertMetric = "io_bytes"
)

// AlertRule defines a threshold rule
type AlertRule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Metric      AlertMetric   `json:"metric"`
	Threshold   float64       `json:"threshold"`
	Operator    AlertOperator `json:"operator"`
	Level       AlertLevel    `json:"level"`
	TenantMatch string        `json:"tenant_match"` // "" = all tenants, "tenant_x" = specific
}

// Alert is an active or historical alert instance
type Alert struct {
	ID         string      `json:"id"`
	RuleID     string      `json:"rule_id"`
	RuleName   string      `json:"rule_name"`
	TenantID   string      `json:"tenant_id"`
	Metric     AlertMetric `json:"metric"`
	Value      float64     `json:"value"`
	Threshold  float64     `json:"threshold"`
	Level      AlertLevel  `json:"level"`
	Message    string      `json:"message"`
	FiredAt    time.Time   `json:"fired_at"`
	ResolvedAt *time.Time  `json:"resolved_at,omitempty"`
	Active     bool        `json:"active"`
}

// AlertManager manages rules, active alerts, and history
type AlertManager struct {
	mu         sync.RWMutex
	rules      []AlertRule
	active     map[string]*Alert // key = ruleID + ":" + tenantID
	history    []*Alert
	webhookURL string
	slack      *SlackNotifier
	nextRuleID int
	startTime  time.Time
}

// NewAlertManager creates a manager with default rules
func NewAlertManager(webhookURL string, slack *SlackNotifier) *AlertManager {
	am := &AlertManager{
		active:     make(map[string]*Alert),
		webhookURL: webhookURL,
		slack:      slack,
		nextRuleID: 10,
		startTime:  time.Now(),
	}
	// Default rules
	am.rules = []AlertRule{
		{ID: "1", Name: "P99 High Latency (Warning)", Metric: MetricP99MS, Threshold: 500, Operator: OpGT, Level: AlertWarning},
		{ID: "2", Name: "P99 High Latency (Critical)", Metric: MetricP99MS, Threshold: 2000, Operator: OpGT, Level: AlertCritical},
		{ID: "3", Name: "Low Cache Hit Rate", Metric: MetricCacheHit, Threshold: 90, Operator: OpLT, Level: AlertWarning},
		{ID: "4", Name: "High Connection Usage", Metric: MetricConnections, Threshold: 80, Operator: OpGT, Level: AlertWarning},
	}
	return am
}

func (am *AlertManager) compareThreshold(value, threshold float64, op AlertOperator) bool {
	switch op {
	case OpGT:
		return value > threshold
	case OpLT:
		return value < threshold
	case OpGTE:
		return value >= threshold
	case OpLTE:
		return value <= threshold
	}
	return false
}

func (am *AlertManager) metricValue(rule AlertRule, t TenantMetrics, maxConns int) float64 {
	switch rule.Metric {
	case MetricP99MS:
		return t.P99Ms
	case MetricQueries:
		return float64(t.Queries)
	case MetricConnections:
		// Rule 4 (connections) uses percentage of max
		if rule.ID == "4" && maxConns > 0 {
			return float64(t.Connections) / float64(maxConns) * 100
		}
		return float64(t.Connections)
	case MetricCacheHit:
		return t.CacheHit
	case MetricIOBytes:
		return float64(t.IOBytes)
	}
	return 0
}

// Evaluate checks all rules against current data and fires/resolves alerts
func (am *AlertManager) Evaluate(data CollectorData, maxConns int) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Grace period: suppress cache_hit alerts for first 5 minutes after startup
	// (fresh installs always show 0% until the cache warms up)
	inGracePeriod := time.Since(am.startTime) < 5*time.Minute

	// Track which alert keys we saw this cycle (to resolve stale ones)
	seen := make(map[string]bool)

	for _, rule := range am.rules {
		// Skip cache_hit alerts during grace period
		if inGracePeriod && rule.Metric == MetricCacheHit {
			continue
		}

		for _, t := range data.Tenants {
			// Check tenant match filter
			if rule.TenantMatch != "" && rule.TenantMatch != t.TenantID {
				continue
			}

			value := am.metricValue(rule, t, maxConns)
			fired := am.compareThreshold(value, rule.Threshold, rule.Operator)
			alertKey := rule.ID + ":" + t.TenantID

			if fired {
				seen[alertKey] = true
				if _, exists := am.active[alertKey]; !exists {
					// New alert
					msg := am.buildMessage(rule, t.TenantID, value)
					a := &Alert{
						ID:        fmt.Sprintf("%s-%d", alertKey, time.Now().UnixNano()),
						RuleID:    rule.ID,
						RuleName:  rule.Name,
						TenantID:  t.TenantID,
						Metric:    rule.Metric,
						Value:     value,
						Threshold: rule.Threshold,
						Level:     rule.Level,
						Message:   msg,
						FiredAt:   time.Now(),
						Active:    true,
					}
					am.active[alertKey] = a
					log.Printf("ALERT: Alert fired: %s", msg)
					go am.notify(a, false)
				}
			}
		}
	}

	// Resolve alerts that no longer match
	for key, a := range am.active {
		if !seen[key] {
			now := time.Now()
			a.ResolvedAt = &now
			a.Active = false
			// Add to history
			am.addHistory(a)
			delete(am.active, key)
			log.Printf("Alert resolved: %s", a.Message)
			go am.notify(a, true)
		}
	}
}

func (am *AlertManager) buildMessage(rule AlertRule, tenantID string, value float64) string {
	var valStr string
	switch rule.Metric {
	case MetricP99MS:
		valStr = fmt.Sprintf("%.0fms", value)
	case MetricCacheHit:
		valStr = fmt.Sprintf("%.1f%%", value)
	case MetricConnections:
		if rule.ID == "4" {
			valStr = fmt.Sprintf("%.0f%%", value)
		} else {
			valStr = fmt.Sprintf("%.0f", value)
		}
	case MetricIOBytes:
		valStr = fmt.Sprintf("%.0f bytes", value)
	default:
		valStr = fmt.Sprintf("%.2f", value)
	}

	var threshStr string
	switch rule.Metric {
	case MetricP99MS:
		threshStr = fmt.Sprintf("%.0fms", rule.Threshold)
	case MetricCacheHit:
		threshStr = fmt.Sprintf("%.0f%%", rule.Threshold)
	default:
		threshStr = fmt.Sprintf("%.0f", rule.Threshold)
	}

	return fmt.Sprintf("Tenant '%s' %s is %s (threshold: %s)", tenantID, rule.Metric, valStr, threshStr)
}

func (am *AlertManager) addHistory(a *Alert) {
	am.history = append(am.history, a)
	if len(am.history) > 100 {
		am.history = am.history[len(am.history)-100:]
	}
}

// notify sends webhook and Slack notifications
func (am *AlertManager) notify(a *Alert, resolved bool) {
	payload := map[string]interface{}{
		"alert":    a,
		"resolved": resolved,
	}

	// Webhook notification
	if am.webhookURL != "" {
		body, _ := json.Marshal(payload)
		resp, err := http.Post(am.webhookURL, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("Alert webhook error: %v", err)
		} else {
			resp.Body.Close()
		}
	}

	// Slack notification
	if am.slack != nil {
		if resolved {
			am.slack.SendResolved(a)
		} else {
			am.slack.SendAlert(a)
		}
	}
}

// GetActiveAlerts returns a copy of active alerts
func (am *AlertManager) GetActiveAlerts() []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()
	result := make([]*Alert, 0, len(am.active))
	for _, a := range am.active {
		cp := *a
		result = append(result, &cp)
	}
	return result
}

// GetHistory returns alert history
func (am *AlertManager) GetHistory() []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()
	result := make([]*Alert, len(am.history))
	copy(result, am.history)
	return result
}

// AddRule adds a new alert rule
func (am *AlertManager) AddRule(r AlertRule) AlertRule {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.nextRuleID++
	r.ID = strconv.Itoa(am.nextRuleID)
	am.rules = append(am.rules, r)
	return r
}

// RemoveRule removes a rule by ID
func (am *AlertManager) RemoveRule(id string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	for i, r := range am.rules {
		if r.ID == id {
			am.rules = append(am.rules[:i], am.rules[i+1:]...)
			return true
		}
	}
	return false
}

// GetRules returns all rules
func (am *AlertManager) GetRules() []AlertRule {
	am.mu.RLock()
	defer am.mu.RUnlock()
	result := make([]AlertRule, len(am.rules))
	copy(result, am.rules)
	return result
}

// ── HTTP Handlers ──────────────────────────────────────────────────────

func handleAlerts(w http.ResponseWriter, r *http.Request) {
	if alertManager == nil {
		writeJSON(w, []interface{}{})
		return
	}
	writeJSON(w, alertManager.GetActiveAlerts())
}

func handleAlertsHistory(w http.ResponseWriter, r *http.Request) {
	if alertManager == nil {
		writeJSON(w, []interface{}{})
		return
	}
	writeJSON(w, alertManager.GetHistory())
}

func handleAlertsRules(w http.ResponseWriter, r *http.Request) {
	if alertManager == nil {
		http.Error(w, "alert manager not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, alertManager.GetRules())

	case http.MethodPost:
		var rule AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if rule.Metric == "" || rule.Operator == "" || rule.Level == "" {
			http.Error(w, "metric, operator, and level are required", http.StatusBadRequest)
			return
		}
		created := alertManager.AddRule(rule)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, created)

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id query param required", http.StatusBadRequest)
			return
		}
		if alertManager.RemoveRule(id) {
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "rule not found", http.StatusNotFound)
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
