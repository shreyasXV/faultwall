package main

// hold.go — live-query approvals: the in-proxy hold registry.
//
// A statement that matches an `action: hold` rule (hold_rules.go) is parked in
// its connection's request loop while a human decides. Decisions arrive from:
//   - the control plane (dashboard queue or Slack), long-polled by hold_cp.go
//   - the local HTTP API (GET /api/holds, POST /api/holds/{id}/approve|deny),
//     the fallback for `faultwall try` and installs without a control plane
//   - a CancelRequest (Ctrl-C) for the held connection -> deny with 57014
//   - the timeout -> deny (default deny, 120s unless configured)
//   - the client hanging up or sending Terminate -> drop, never execute
//
// Only the held connection waits; every other connection keeps flowing.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Hold is one statement (or one extended-protocol Sync group) awaiting a decision.
type Hold struct {
	ID          string    `json:"id"`
	RemoteID    string    `json:"remote_id,omitempty"` // control-plane hold id
	Agent       string    `json:"agent"`
	Mission     string    `json:"mission,omitempty"`
	Query       string    `json:"query"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Operation   string    `json:"operation"`
	Tables      []string  `json:"tables,omitempty"`
	Rule        string    `json:"rule"`
	Statements  int       `json:"statements"` // >1 when a pipelined batch holds several
	InTxn       bool      `json:"in_txn"`
	TxnAgeMs    int64     `json:"txn_age_ms"` // how long the agent's txn has been open (locks it holds stay held)
	Created     time.Time `json:"created_at"`
	Expires     time.Time `json:"expires_at"`

	connKey  string
	decision chan holdDecision
}

// holdDecision is the outcome of a hold.
type holdDecision struct {
	Approve bool
	By      string // who decided: email, slack user, "timeout", "client", "cancel"
	Reason  string
	Kind    string // approved | denied | timeout | cancelled | client_gone
}

type holdRegistry struct {
	mu    sync.Mutex
	holds map[string]*Hold
	byKey map[string]*Hold // BackendKeyData -> active hold, for CancelRequest
}

var holdReg = &holdRegistry{holds: map[string]*Hold{}, byKey: map[string]*Hold{}}

func newHoldID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "h_" + hex.EncodeToString(b)
}

func (r *holdRegistry) add(h *Hold) {
	h.decision = make(chan holdDecision, 1)
	r.mu.Lock()
	r.holds[h.ID] = h
	if h.connKey != "" {
		r.byKey[h.connKey] = h
	}
	r.mu.Unlock()
}

func (r *holdRegistry) remove(h *Hold) {
	r.mu.Lock()
	delete(r.holds, h.ID)
	if h.connKey != "" && r.byKey[h.connKey] == h {
		delete(r.byKey, h.connKey)
	}
	r.mu.Unlock()
}

// resolve delivers a decision. Returns false if the hold is gone or already decided.
func (r *holdRegistry) resolve(id string, d holdDecision) bool {
	r.mu.Lock()
	h := r.holds[id]
	if h == nil {
		for _, x := range r.holds { // accept the control-plane id too
			if x.RemoteID != "" && x.RemoteID == id {
				h = x
				break
			}
		}
	}
	r.mu.Unlock()
	if h == nil {
		return false
	}
	select {
	case h.decision <- d:
		return true
	default:
		return false
	}
}

// cancelByKey resolves the hold on the connection identified by its
// BackendKeyData (from a CancelRequest). Returns true if a hold was cancelled.
func (r *holdRegistry) cancelByKey(key string) bool {
	r.mu.Lock()
	h := r.byKey[key]
	r.mu.Unlock()
	if h == nil {
		return false
	}
	select {
	case h.decision <- holdDecision{Approve: false, By: "client", Kind: "cancelled", Reason: "canceled by user"}:
		return true
	default:
		return false
	}
}

func (r *holdRegistry) list() []*Hold {
	r.mu.Lock()
	out := make([]*Hold, 0, len(r.holds))
	for _, h := range r.holds {
		cp := *h
		out = append(out, &cp)
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// connBackendKeys maps a client connection to its upstream BackendKeyData so
// proxyQueryLoop can register holds for CancelRequest lookup.
var connBackendKeys sync.Map // net.Conn -> string

// holdErr is what the client is told when a held statement does not run.
type holdErr struct {
	Code string
	Msg  string
}

func denyError(h *Hold, d holdDecision, timeout time.Duration) holdErr {
	what := strings.TrimSpace(h.Operation)
	if len(h.Tables) > 0 {
		what += " on " + strings.Join(h.Tables, ", ")
	}
	if what == "" {
		what = "statement"
	}
	switch d.Kind {
	case "cancelled":
		return holdErr{Code: "57014", Msg: "canceling statement due to user request (" + what + " was held for approval by FaultWall)"}
	case "timeout":
		return holdErr{Code: "42501", Msg: fmt.Sprintf("[BLOCKED by FaultWall] %s was held for approval and nobody decided within %s, so it was denied by default. It did not run.", what, timeout)}
	default:
		msg := fmt.Sprintf("[BLOCKED by FaultWall] %s was held for approval and denied", what)
		if d.By != "" {
			msg += " by " + d.By
		}
		if d.Reason != "" {
			msg += ": " + d.Reason
		}
		return holdErr{Code: "42501", Msg: msg + ". It did not run."}
	}
}

// holdWaitResult is what awaitHold reports back to the request loop.
type holdWaitResult struct {
	Decision   holdDecision
	ClientGone bool
}

// awaitHold registers h, notifies decision sources and blocks until a
// decision, the timeout, or the client going away. clientEvents delivers the
// connection's reader-goroutine messages; anything that is not a
// Terminate/EOF is handed to stash so it is processed after the decision.
func awaitHold(pe *PolicyEngine, h *Hold, clientEvents <-chan wireMsg, stash func(wireMsg) bool) holdWaitResult {
	timeout := holdTimeout(pe)
	h.ID = newHoldID()
	h.Created = time.Now()
	h.Expires = h.Created.Add(timeout)
	holdReg.add(h)
	defer holdReg.remove(h)

	log.Printf("%s%s[HOLD]%s %s agent=%-20s rule=%q timeout=%s query=%s",
		colorYellow, colorBold, colorReset, h.ID, h.Agent, h.Rule, timeout, querySnippet(h.Query))

	stopCP := startHoldControlPlane(pe, h)

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	events := clientEvents
	var res holdWaitResult
wait:
	for {
		select {
		case d := <-h.decision:
			res.Decision = d
			break wait
		case <-timer.C:
			res.Decision = holdDecision{Approve: false, By: "timeout", Kind: "timeout"}
			break wait
		case m, ok := <-events:
			if !ok || m.err != nil || m.t == 'X' {
				res.Decision = holdDecision{Approve: false, By: "client", Kind: "client_gone", Reason: "client disconnected"}
				res.ClientGone = true
				break wait
			}
			if !stash(m) { // backlog full: stop reading, rely on timeout/decision
				events = nil
			}
		}
	}
	stopCP(res.Decision)

	took := time.Since(h.Created).Round(time.Millisecond)
	switch {
	case res.Decision.Approve:
		log.Printf("%s%s[HOLD]%s %s approved by %s after %s", colorGreen, colorBold, colorReset, h.ID, nonEmpty(res.Decision.By, "?"), took)
	case res.ClientGone:
		log.Printf("%s%s[HOLD]%s %s client disconnected while held after %s, dropping (never executed)", colorRed, colorBold, colorReset, h.ID, took)
	default:
		log.Printf("%s%s[HOLD]%s %s %s (by %s) after %s", colorRed, colorBold, colorReset, h.ID, res.Decision.Kind, nonEmpty(res.Decision.By, "?"), took)
	}
	recordHoldOutcome(pe, h, res.Decision)
	return res
}

// recordHoldOutcome feeds the local audit trail (violations) and metadata
// telemetry so the dashboard counters include held statements.
func recordHoldOutcome(pe *PolicyEngine, h *Hold, d holdDecision) {
	if pe != nil {
		action := "held:" + d.Kind
		pe.addViolation(PolicyViolation{
			AgentID: h.Agent, MissionID: h.Mission, Query: h.Query,
			Reason: "approval " + d.Kind + " (" + h.Rule + ")" + byStr(d.By), Table: strings.Join(h.Tables, ","),
			Operation: h.Operation, Action: action, Timestamp: time.Now(),
		})
	}
	decision := "block"
	if d.Approve {
		decision = "allow"
	}
	emitTelemetryEvent(TelemetryEvent{EventType: "held", Decision: decision, TableName: strings.Join(h.Tables, ","), OpType: h.Operation})
}

func byStr(by string) string {
	if by == "" {
		return ""
	}
	return " by " + by
}

// ── local HTTP API (try mode / no control plane) ──

// handleHolds serves GET /api/holds.
func handleHolds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{"holds": holdReg.list()})
}

// handleHoldAction serves POST /api/holds/{id}/approve|deny. Body (optional):
// {"by":"name","reason":"text"}.
func handleHoldAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/holds/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || (parts[1] != "approve" && parts[1] != "deny") {
		http.Error(w, "use POST /api/holds/{id}/approve or /deny", http.StatusNotFound)
		return
	}
	var body struct {
		By     string `json:"by"`
		Reason string `json:"reason"`
	}
	if r.ContentLength > 0 {
		_ = decodeJSONBody(r, &body)
	}
	by := strings.TrimSpace(body.By)
	if by == "" {
		by = "local API"
	}
	d := holdDecision{Approve: parts[1] == "approve", By: by, Reason: body.Reason, Kind: "denied"}
	if d.Approve {
		d.Kind = "approved"
	}
	if !holdReg.resolve(parts[0], d) {
		http.Error(w, "no such pending hold (already decided, timed out or the client left)", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]interface{}{"id": parts[0], "status": d.Kind})
}

func decodeJSONBody(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(v)
}
