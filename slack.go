package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// SlackNotifier sends alert notifications to a Slack webhook
type SlackNotifier struct {
	webhookURL string
	mu         sync.Mutex
	lastSent   map[string]time.Time // alertKey -> last sent time
}

// NewSlackNotifier creates a SlackNotifier. Returns nil if no URL.
func NewSlackNotifier(webhookURL string) *SlackNotifier {
	if webhookURL == "" {
		return nil
	}
	return &SlackNotifier{
		webhookURL: webhookURL,
		lastSent:   make(map[string]time.Time),
	}
}

// SendAlert sends a firing alert to Slack with rate limiting
func (s *SlackNotifier) SendAlert(a *Alert) {
	if s == nil {
		return
	}
	s.mu.Lock()
	key := a.RuleID + ":" + a.TenantID
	last, ok := s.lastSent[key]
	if ok && time.Since(last) < 5*time.Minute {
		s.mu.Unlock()
		return
	}
	s.lastSent[key] = time.Now()
	s.mu.Unlock()

	color := "#f5c542" // yellow = warning
	icon := "WARN:"
	levelStr := "WARNING"
	if a.Level == AlertCritical {
		color = "#e53e3e"
		icon = "FAIL"
		levelStr = "CRITICAL"
	} else if a.Level == AlertInfo {
		color = "#718096"
		icon = "INFO:"
		levelStr = "INFO"
	}

	title := fmt.Sprintf("[FaultWall ] %s %s: %s", icon, levelStr, a.Message)
	text := fmt.Sprintf("Metric: `%s` | Value: `%.2f` | Threshold: `%.2f` | Tenant: `%s`",
		a.Metric, a.Value, a.Threshold, a.TenantID)

	payload := slackPayload(title, text, color)
	s.send(payload)
}

// SendResolved sends a resolution notification to Slack
func (s *SlackNotifier) SendResolved(a *Alert) {
	if s == nil {
		return
	}
	title := fmt.Sprintf("[FaultWall ] RESOLVED: %s", a.Message)
	text := fmt.Sprintf("Alert resolved for tenant `%s`. Metric `%s` is back within threshold.", a.TenantID, a.Metric)
	payload := slackPayload(title, text, "#38a169")
	s.send(payload)
}

func slackPayload(title, text, color string) map[string]interface{} {
	return map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":    color,
				"fallback": title,
				"title":    title,
				"text":     text,
				"ts":       time.Now().Unix(),
				"footer": "FaultWall ",
			},
		},
	}
}

func (s *SlackNotifier) send(payload map[string]interface{}) {
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Slack marshal error: %v", err)
		return
	}
	resp, err := http.Post(s.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("Slack webhook error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("Slack webhook returned status %d", resp.StatusCode)
	}
}
