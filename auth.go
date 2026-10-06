package main

import (
	"crypto/subtle"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// managementHandler is the outer boundary for every management server, including
// try mode. Only the minimal health response is public. Wrapping the whole mux
// makes new routes private by default, including HTML and downloadable files.
//
// No configured token means management is disabled, not anonymous. The proxy
// and control-plane approvals can still run without a local management token.
func managementHandler(next http.Handler) http.Handler {
	token := os.Getenv("FAULTWALL_API_TOKEN")
	configured := strings.TrimSpace(token) != ""
	if !configured {
		log.Println("FAULTWALL_API_TOKEN not set: local management disabled; only GET /api/health is public")
	} else {
		log.Println("Local management requires FAULTWALL_API_TOKEN (Bearer header, or browser username faultwall and token as password)")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		if r.URL.Path == "/api/health" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			// Do not call the dashboard's richer health handler: it includes
			// tenant and workload data.
			writeJSON(w, map[string]string{"status": "ok"})
			return
		}
		if !configured {
			http.Error(w, "Local management disabled: set FAULTWALL_API_TOKEN and restart", http.StatusServiceUnavailable)
			return
		}

		// Bearer remains the API contract. Basic lets browsers authenticate the
		// existing UI (and its same-origin fetches) without putting the token
		// in URLs, HTML, JS storage, or a newly introduced session cookie.
		auth := r.Header.Get("Authorization")
		bearer, isBearer := strings.CutPrefix(auth, "Bearer ")
		user, password, isBasic := r.BasicAuth()
		validBearer := isBearer && subtle.ConstantTimeCompare([]byte(bearer), []byte(token)) == 1
		validBasic := isBasic && user == "faultwall" && subtle.ConstantTimeCompare([]byte(password), []byte(token)) == 1
		if len(r.Header.Values("Authorization")) != 1 || (!validBearer && !validBasic) {
			w.Header().Set("WWW-Authenticate", `Basic realm="FaultWall management", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Browsers send cached Basic credentials automatically. Require an
		// explicit same-origin Origin for mutations, so a form on an agent's
		// page cannot approve holds using the reviewer's cached credentials.
		// Scripts should use Bearer; they do not need an Origin header.
		if validBasic && r.Method != http.MethodGet && r.Method != http.MethodHead {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			origin, err := url.Parse(r.Header.Get("Origin"))
			if len(r.Header.Values("Origin")) != 1 || err != nil || origin.User != nil ||
				origin.Scheme != scheme ||
				origin.Host != r.Host || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
				http.Error(w, "Same-origin Origin required for browser mutations; API clients must use Bearer auth", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Management never inherits the SQL listener's host, even inside containers.
// Remote management is an explicit operator choice and still requires a token.
func managementBindAddr() string {
	if bind := os.Getenv("BIND_ADDR"); bind != "" {
		return bind
	}
	return "127.0.0.1"
}
