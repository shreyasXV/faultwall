package main

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const managementTestToken = "synthetic-management-test-token"

// Use the same constructors as the actual HTTP servers, not a test-only mux.
var managementModes = []struct {
	name   string
	create func() http.Handler
}{
	{"proxy", proxyManagementHandler},
	{"dashboard", dashboardManagementHandler},
	{"try", func() http.Handler {
		return tryMux(&tryInfo{AgentURL: "postgres://operator:synthetic-db-password@localhost/demo"})
	}},
}

func managementRequest(handler http.Handler, method, path, auth, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://localhost:8080"+path, strings.NewReader(body))
	// The threat includes an agent sharing the host. Loopback must not bypass auth.
	req.RemoteAddr = "127.0.0.1:12345"
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestManagementRoutesRequireToken(t *testing.T) {
	paths := []string{
		"/", "/dashboard", "/try", "/favicon.png", "/favicon.ico",
		"/api/holds", "/api/holds/h_auth/approve", "/api/holds/h_auth/deny",
		"/api/policies", "/api/policies/yaml", "/api/policies/reload",
		"/api/rules/block", "/api/rules/preview", "/api/rules/create",
		"/api/agents/pause/bot", "/api/firewall/agents", "/api/firewall/agents/bot/queries",
		"/api/agent-keys", "/api/violations", "/api/agents/stats", "/api/tenants",
		"/api/queries", "/api/config", "/api/qwm/flags", "/api/apa/proposals",
		"/api/apa/proposals/files", "/api/apa/proposals/files/id/download",
		"/api/apa/proposals/files/id/apply", "/api/apa/proposals/files/id/dismiss",
		"/api/export/csv", "/api/export/json", "/api/try/info", "/api/try/activity",
		"/api/alerts", "/api/alerts/history", "/api/alerts/rules",
		"/api/history", "/api/history/overview", "/api/throttle/status",
		"/api/throttle/config", "/api/costs", "/api/anomalies", "/api/anomalies/baseline",
		"/api/predictions", "/api/agents/status", "/api/agents/noisy",
		"/api/agents/tenant/id", "/api/agents/costs", "/api/agents/recommendation",
		"/api/agents/anomalies", "/api/agents/predictions",
		// Unknown routes and noncanonical paths must not escape the outer boundary.
		"/api/future-route", "/api/health/../holds", "/api//holds",
		"/api/health/", "/api/health%2f..%2fholds",
	}
	for _, mode := range managementModes {
		t.Run(mode.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, token, auth string
				want              int
			}{
				{"unconfigured", "", "", http.StatusServiceUnavailable},
				{"unconfigured-with-credential", "", "Bearer " + managementTestToken, http.StatusServiceUnavailable},
				{"blank-token", " \t", "Bearer  \t", http.StatusServiceUnavailable},
				{"missing", managementTestToken, "", http.StatusUnauthorized},
				{"wrong", managementTestToken, "Bearer wrong-token", http.StatusUnauthorized},
				{"empty-bearer", managementTestToken, "Bearer ", http.StatusUnauthorized},
			} {
				t.Run(tc.name, func(t *testing.T) {
					t.Setenv("FAULTWALL_API_TOKEN", tc.token)
					handler := mode.create()
					for _, path := range paths {
						for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
							rec := managementRequest(handler, method, path, tc.auth, `{}`)
							if rec.Code != tc.want {
								t.Fatalf("%s %s: got %d, want %d", method, path, rec.Code, tc.want)
							}
							if rec.Header().Get("Cache-Control") != "no-store" {
								t.Fatalf("%s %s: management response could be cached", method, path)
							}
						}
					}
				})
			}
		})
	}
}

func TestManagementHealthIsPublicAndMinimal(t *testing.T) {
	for _, mode := range managementModes {
		t.Run(mode.name, func(t *testing.T) {
			for _, token := range []string{"", managementTestToken} {
				t.Setenv("FAULTWALL_API_TOKEN", token)
				handler := mode.create()
				for _, method := range []string{"GET", "HEAD"} {
					rec := managementRequest(handler, method, "/api/health", "", "")
					if rec.Code != http.StatusOK {
						t.Fatalf("%s health: %d", method, rec.Code)
					}
					var body map[string]any
					if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body) != 1 || body["status"] != "ok" {
						t.Fatalf("health must not expose workload data: %s (%v)", rec.Body.String(), err)
					}
				}
				if rec := managementRequest(handler, "POST", "/api/health", "", ""); rec.Code == http.StatusOK {
					t.Fatal("health exception must only permit GET/HEAD")
				}
			}
		})
	}
}

func managementPolicyFixture(t *testing.T) *PolicyEngine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policies.yaml")
	if err := os.WriteFile(path, []byte("default_policy: deny\nagents:\n  bot:\n    description: synthetic-private-policy\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pe := &PolicyEngine{filePath: path, enforcement: "enforce", pausedAgents: make(map[string]bool)}
	if err := pe.Reload(); err != nil {
		t.Fatal(err)
	}
	prev := policyEngine
	policyEngine = pe
	t.Cleanup(func() { policyEngine = prev })
	return pe
}

func TestManagementAuthenticatedHoldsAndPolicies(t *testing.T) {
	for _, mode := range managementModes {
		t.Run(mode.name, func(t *testing.T) {
			pe := managementPolicyFixture(t)
			h := &Hold{ID: "h_auth", Agent: "bot", Query: "UPDATE orders SET status='synthetic-private-value' WHERE id=1"}
			holdReg.add(h)
			t.Cleanup(func() { holdReg.remove(h) })

			// Missing configuration or an absent/wrong credential cannot
			// disclose policy/SQL or deliver any approval decision.
			for _, tc := range []struct{ token, auth string }{
				{"", ""}, {managementTestToken, ""}, {managementTestToken, "Bearer wrong"},
			} {
				t.Setenv("FAULTWALL_API_TOKEN", tc.token)
				handler := mode.create()
				for _, path := range []string{"/api/holds", "/api/policies", "/api/policies/yaml", "/api/try/info"} {
					rec := managementRequest(handler, "GET", path, tc.auth, "")
					if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusServiceUnavailable {
						t.Fatalf("unauthorized read %s: %d", path, rec.Code)
					}
					if strings.Contains(rec.Body.String(), "synthetic-private") || strings.Contains(rec.Body.String(), "synthetic-db-password") {
						t.Fatalf("private data disclosed by %s", path)
					}
				}
				for _, action := range []string{"approve", "deny"} {
					rec := managementRequest(handler, "POST", "/api/holds/"+h.ID+"/"+action, tc.auth, "")
					if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusServiceUnavailable {
						t.Fatalf("unauthorized %s: %d", action, rec.Code)
					}
				}
				select {
				case d := <-h.decision:
					t.Fatalf("unauthorized caller resolved hold: %+v", d)
				default:
				}
			}

			t.Setenv("FAULTWALL_API_TOKEN", managementTestToken)
			handler := mode.create()
			auth := "Bearer " + managementTestToken
			for _, tc := range []struct{ path, want string }{
				{"/api/holds", h.Query}, {"/api/policies", "synthetic-private-policy"},
			} {
				rec := managementRequest(handler, "GET", tc.path, auth, "")
				if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tc.want) {
					t.Fatalf("authenticated %s: %d %s", tc.path, rec.Code, rec.Body.String())
				}
			}
			rec := managementRequest(handler, "POST", "/api/holds/"+h.ID+"/approve", auth, `{"by":"reviewer"}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("authenticated approval: %d %s", rec.Code, rec.Body.String())
			}
			select {
			case d := <-h.decision:
				if !d.Approve || d.By != "reviewer" {
					t.Fatalf("wrong decision: %+v", d)
				}
			default:
				t.Fatal("authenticated approval did not reach registry")
			}
			if pe.GetConfig().Agents["bot"].Description != "synthetic-private-policy" {
				t.Fatal("read/hold operations unexpectedly changed policy")
			}
			if mode.name == "try" {
				rec := managementRequest(handler, "GET", "/api/try/info", auth, "")
				if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "synthetic-db-password") {
					t.Fatalf("authenticated try info: %d %s", rec.Code, rec.Body.String())
				}
				// Try deliberately does not register policy mutations.
				rec = managementRequest(handler, "POST", "/api/policies/reload", auth, "")
				if rec.Code != http.StatusNotFound {
					t.Fatalf("try unexpectedly enabled policy mutations: %d", rec.Code)
				}
			}
		})
	}
}

func TestManagementPolicyMutationsRequireToken(t *testing.T) {
	for _, mode := range managementModes[:2] {
		t.Run(mode.name, func(t *testing.T) {
			pe := managementPolicyFixture(t)
			original, err := os.ReadFile(pe.filePath)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"query":"SELECT * FROM orders","query_pattern":"SELECT * FROM orders","agent_id":"bot","action":"block_table"}`
			for _, tc := range []struct{ token, auth string }{
				{"", ""}, {managementTestToken, ""}, {managementTestToken, "Bearer wrong"},
			} {
				t.Setenv("FAULTWALL_API_TOKEN", tc.token)
				handler := mode.create()
				for _, path := range []string{"/api/rules/create", "/api/rules/block", "/api/policies/reload", "/api/agents/pause/bot"} {
					rec := managementRequest(handler, "POST", path, tc.auth, body)
					if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusServiceUnavailable {
						t.Fatalf("unauthorized mutation %s: %d", path, rec.Code)
					}
				}
				onDisk, err := os.ReadFile(pe.filePath)
				if err != nil || string(onDisk) != string(original) || len(pe.GetConfig().Agents["bot"].BlockedTables) != 0 || pe.IsAgentPaused("bot") {
					t.Fatal("unauthorized request modified policy or pause state")
				}
			}

			t.Setenv("FAULTWALL_API_TOKEN", managementTestToken)
			handler := mode.create()
			auth := "Bearer " + managementTestToken
			rec := managementRequest(handler, "GET", "/api/policies/yaml", auth, "")
			if rec.Code != http.StatusOK || rec.Body.String() != string(original) {
				t.Fatalf("authenticated policy download: %d %s", rec.Code, rec.Body.String())
			}
			rec = managementRequest(handler, "POST", "/api/rules/create", auth, body)
			if rec.Code != http.StatusOK || !isTableBlocked("orders", pe.GetConfig().Agents["bot"].BlockedTables) {
				t.Fatalf("authenticated rule was not applied: %d %s", rec.Code, rec.Body.String())
			}
			// Exercise reload with a different on-disk policy to prove the
			// authorized request reaches the actual handler.
			if err := os.WriteFile(pe.filePath, original, 0600); err != nil {
				t.Fatal(err)
			}
			rec = managementRequest(handler, "POST", "/api/policies/reload", auth, "")
			if rec.Code != http.StatusOK || len(pe.GetConfig().Agents["bot"].BlockedTables) != 0 {
				t.Fatalf("authenticated policy was not reloaded: %d %s", rec.Code, rec.Body.String())
			}
			rec = managementRequest(handler, "POST", "/api/agents/pause/bot", auth, "")
			if rec.Code != http.StatusOK || !pe.IsAgentPaused("bot") {
				t.Fatalf("authenticated pause failed: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestManagementBrowserAuth(t *testing.T) {
	for _, mode := range managementModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Setenv("FAULTWALL_API_TOKEN", managementTestToken)
			managementPolicyFixture(t)
			handler := mode.create()
			rec := managementRequest(handler, "GET", "/", "", "")
			if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Basic ") {
				t.Fatal("browser must receive a login challenge")
			}
			for _, tc := range []struct {
				name, user, password string
				want                 int
			}{
				{"correct", "faultwall", managementTestToken, http.StatusOK},
				{"wrong-user", "agent", managementTestToken, http.StatusUnauthorized},
				{"wrong-password", "faultwall", "wrong", http.StatusUnauthorized},
				{"empty-password", "faultwall", "", http.StatusUnauthorized},
			} {
				req := httptest.NewRequest("GET", "http://localhost:8080/", nil)
				req.SetBasicAuth(tc.user, tc.password)
				rec = httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != tc.want || strings.Contains(rec.Body.String(), managementTestToken) {
					t.Fatalf("%s browser auth: %d, want %d; token must not be in HTML", tc.name, rec.Code, tc.want)
				}
				if rec.Header().Get("X-Frame-Options") != "DENY" {
					t.Fatal("management UI must not be frameable")
				}
			}

			h := &Hold{ID: "h_browser", Agent: "bot"}
			holdReg.add(h)
			t.Cleanup(func() { holdReg.remove(h) })
			for _, tc := range []struct {
				origin string
				tls    bool
				want   int
			}{
				{"", false, http.StatusForbidden},
				{"null", false, http.StatusForbidden},
				{"http://agent.invalid", false, http.StatusForbidden},
				{"http://localhost:8081", false, http.StatusForbidden},
				{"https://localhost:8080", false, http.StatusForbidden},
				{"http://localhost:8080", true, http.StatusForbidden},
				{"http://localhost:8080/path", false, http.StatusForbidden},
				{"http://agent@localhost:8080", false, http.StatusForbidden},
				{"http://localhost:8080", false, http.StatusOK},
				{"https://localhost:8080", true, http.StatusOK},
			} {
				req := httptest.NewRequest("POST", "http://localhost:8080/api/holds/"+h.ID+"/approve", nil)
				req.SetBasicAuth("faultwall", managementTestToken)
				if tc.origin != "" {
					req.Header.Set("Origin", tc.origin)
				}
				if tc.tls {
					req.TLS = &tls.ConnectionState{}
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != tc.want {
					t.Fatalf("Origin %q TLS=%v: %d, want %d", tc.origin, tc.tls, rec.Code, tc.want)
				}
				select {
				case d := <-h.decision:
					if tc.want != http.StatusOK || !d.Approve {
						t.Fatalf("cross-origin request resolved hold: %+v", d)
					}
				default:
					if tc.want == http.StatusOK {
						t.Fatal("same-origin approval failed to reach registry")
					}
				}
			}
		})
	}
}

func TestManagementRejectsAmbiguousCredentials(t *testing.T) {
	t.Setenv("FAULTWALL_API_TOKEN", managementTestToken)
	handler := managementHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("ambiguous credentials reached handler")
	}))
	req := httptest.NewRequest("POST", "http://localhost:8080/api/holds/id/approve", nil)
	req.Header.Add("Authorization", "Bearer "+managementTestToken)
	req.Header.Add("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate Authorization: %d", rec.Code)
	}
	req = httptest.NewRequest("POST", "http://localhost:8080/api/holds/id/approve", nil)
	req.SetBasicAuth("faultwall", managementTestToken)
	req.Header.Add("Origin", "http://localhost:8080")
	req.Header.Add("Origin", "http://agent.invalid")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("duplicate Origin: %d", rec.Code)
	}
}

func TestManagementBindDefaultsToLoopback(t *testing.T) {
	t.Setenv("BIND_ADDR", "")
	t.Setenv("FAULTWALL_IN_CONTAINER", "1")
	opts, err := parseTryArgs([]string{"--listen", "0.0.0.0:5433"}, func(string) string { return "" })
	if err != nil || opts.Listen != "0.0.0.0:5433" {
		t.Fatalf("try SQL listener: %+v %v", opts, err)
	}
	if got := managementBindAddr(); got != "127.0.0.1" {
		t.Fatalf("container/SQL listener changed management bind: %s", got)
	}
	t.Setenv("BIND_ADDR", "0.0.0.0")
	if got := managementBindAddr(); got != "0.0.0.0" {
		t.Fatalf("explicit management override ignored: %s", got)
	}
}
