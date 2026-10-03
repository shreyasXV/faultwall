package main

// hold_cp.go — control-plane leg of live-query approvals.
//
// When the proxy is enrolled with a control plane (~/.faultwall/config.toml
// [control_plane] url+token, or FAULTWALL_CONTROL_PLANE_URL/TOKEN), every hold
// is POSTed to /v1/holds and the proxy long-polls /v1/holds/{id}/wait for the
// decision made in the dashboard queue or in Slack. The local API
// (/api/holds) stays live as a fallback, and the proxy's own timeout is
// authoritative: no answer in time => deny, whatever the network does.
//
// PRIVACY: unlike metadata telemetry, a hold carries the statement text, which
// is what the approver has to see. Set approvals.redact_query: true (or
// FW_HOLD_REDACT_QUERY=1) to send only the literal-stripped form
// (pg_query.Normalize: values become $1, $2 …). FAULTWALL_APPROVALS=local
// keeps holds entirely on the box (local API only).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// holdCPConfig is set at startup when a control plane is configured.
var holdCPConfig *ControlPlaneConfig

// initHoldControlPlane wires approvals to the control plane if configured.
func initHoldControlPlane() {
	if strings.EqualFold(os.Getenv("FAULTWALL_APPROVALS"), "local") {
		return
	}
	cfg, _ := loadControlPlaneConfig()
	if cfg.URL == "" || cfg.Token == "" {
		return
	}
	holdCPConfig = &cfg
	log.Printf("✋ Approvals: holds go to the control plane at %s (dashboard / Slack), local API /api/holds is the fallback", cfg.URL)
}

var holdHTTP = &http.Client{Timeout: 40 * time.Second}

type cpHoldCreate struct {
	InstallationID string   `json:"installation_id,omitempty"`
	LocalID        string   `json:"local_id"`
	Agent          string   `json:"agent"`
	Mission        string   `json:"mission,omitempty"`
	Query          string   `json:"query"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
	Operation      string   `json:"operation"`
	Tables         []string `json:"tables,omitempty"`
	Rule           string   `json:"rule"`
	Statements     int      `json:"statements"`
	InTxn          bool     `json:"in_txn"`
	TxnAgeMs       int64    `json:"txn_age_ms"`
	TimeoutMs      int64    `json:"timeout_ms"`
}

type cpHoldState struct {
	ID        string `json:"id"`
	Status    string `json:"status"` // pending | approved | denied | expired | cancelled
	DecidedBy string `json:"decided_by"`
	Reason    string `json:"reason"`
}

func cpDo(ctx context.Context, cfg *ControlPlaneConfig, method, path string, body interface{}, out interface{}) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(cfg.URL, "/")+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := holdHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	}
	return nil
}

// queryForControlPlane returns the text the approver sees.
func queryForControlPlane(pe *PolicyEngine, q string) string {
	if !holdRedactQuery(pe) {
		return q
	}
	if n, err := pg_query.Normalize(q); err == nil {
		return n
	}
	return "(query text withheld: redact_query is on and the statement could not be normalized)"
}

// startHoldControlPlane posts the hold and long-polls for a decision in the
// background. The returned stop func must be called once the hold is
// resolved (by any source); it tells the control plane how it ended when
// the decision did not come from there.
func startHoldControlPlane(pe *PolicyEngine, h *Hold) func(holdDecision) {
	cfg := holdCPConfig
	if cfg == nil {
		return func(holdDecision) {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	remoteID := ""
	fromRemote := false
	done := make(chan struct{})

	go func() {
		defer close(done)
		create := cpHoldCreate{
			InstallationID: cfg.InstallationID, LocalID: h.ID, Agent: h.Agent, Mission: h.Mission,
			Query: queryForControlPlane(pe, h.Query), Fingerprint: h.Fingerprint, Operation: h.Operation,
			Tables: h.Tables, Rule: h.Rule, Statements: h.Statements, InTxn: h.InTxn, TxnAgeMs: h.TxnAgeMs,
			TimeoutMs: time.Until(h.Expires).Milliseconds(),
		}
		var st cpHoldState
		for attempt := 0; ; attempt++ {
			cctx, ccancel := context.WithTimeout(ctx, 10*time.Second)
			err := cpDo(cctx, cfg, http.MethodPost, "/v1/holds", create, &st)
			ccancel()
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				return
			}
			if attempt == 0 {
				log.Printf("[HOLD] %s control plane unreachable (%v); retrying, local API /api/holds still works", h.ID, err)
			}
			if !sleepCtx(ctx, backoff(attempt)) {
				return
			}
		}
		mu.Lock()
		remoteID = st.ID
		mu.Unlock()
		holdReg.mu.Lock()
		if x := holdReg.holds[h.ID]; x != nil {
			x.RemoteID = st.ID
		}
		holdReg.mu.Unlock()

		for attempt := 0; ctx.Err() == nil; {
			var cur cpHoldState
			err := cpDo(ctx, cfg, http.MethodGet, "/v1/holds/"+st.ID+"/wait?timeout=25", nil, &cur)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				attempt++
				if !sleepCtx(ctx, backoff(attempt)) {
					return
				}
				continue
			}
			attempt = 0
			switch cur.Status {
			case "approved", "denied":
				d := holdDecision{Approve: cur.Status == "approved", By: cur.DecidedBy, Reason: cur.Reason, Kind: cur.Status}
				mu.Lock()
				fromRemote = true
				mu.Unlock()
				holdReg.resolve(h.ID, d)
				return
			case "expired", "cancelled":
				mu.Lock()
				fromRemote = true
				mu.Unlock()
				holdReg.resolve(h.ID, holdDecision{By: "timeout", Kind: "timeout"})
				return
			}
		}
	}()

	return func(d holdDecision) {
		cancel()
		<-done
		mu.Lock()
		rid, remote := remoteID, fromRemote
		mu.Unlock()
		if rid == "" || remote {
			return
		}
		// The decision came from the proxy side (timeout, client gone,
		// Ctrl-C, local API): close the hold upstream so the queue and Slack
		// message stop showing it as pending. Async: never delays the client.
		go func() {
			status := map[string]string{"approved": "approved", "denied": "denied", "timeout": "expired"}[d.Kind]
			if status == "" {
				status = "cancelled"
			}
			body := map[string]string{"status": status, "decided_by": d.By, "reason": nonEmpty(d.Reason, d.Kind)}
			cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer ccancel()
			if err := cpDo(cctx, cfg, http.MethodPost, "/v1/holds/"+rid+"/resolve", body, nil); err != nil {
				log.Printf("[HOLD] %s could not report outcome to control plane: %v", h.ID, err)
			}
		}()
	}
}

func backoff(attempt int) time.Duration {
	d := time.Duration(250*(1<<min(attempt, 4))) * time.Millisecond
	if d > 4*time.Second {
		d = 4 * time.Second
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
