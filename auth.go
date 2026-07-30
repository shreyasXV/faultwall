package main

import (
	"log"
	"net/http"
	"os"
	"strings"
)

// bearerAuthMiddleware checks the Authorization: Bearer <token> header against
// the FAULTWALL_API_TOKEN env var. If no token is configured, it logs a
// warning once and allows unauthenticated access.
func bearerAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	token := os.Getenv("FAULTWALL_API_TOKEN")
	if token == "" {
		log.Println("WARN: FAULTWALL_API_TOKEN not set — sensitive API endpoints are unauthenticated")
		return next // no auth required
	}

	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
