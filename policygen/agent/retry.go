package agent

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"
)

// httpRetryConfig controls the retry/backoff for transient provider failures.
type httpRetryConfig struct {
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
}

// defaultRetryConfig is what openai.go and anthropic.go use unless overridden.
// 3 attempts at 1s/2s/4s with up to 250ms jitter. Capped at 10s per backoff.
var defaultRetryConfig = httpRetryConfig{
	maxAttempts: 3,
	baseDelay:   time.Second,
	maxDelay:    10 * time.Second,
}

// isRetryableStatus returns true for HTTP statuses we should back off on.
// 408 (request timeout), 429 (rate limit), 5xx (server-side faults).
func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout,
		http.StatusTooManyRequests:
		return true
	}
	return code >= 500 && code < 600
}

// doWithRetry executes req via client, retrying on transient errors and
// retryable HTTP statuses. Returns the final response or the last error.
//
// Caller is responsible for: setting headers/body on req, reading resp.Body
// only once, and closing resp.Body. doWithRetry closes intermediate response
// bodies for failed attempts so callers don't leak file descriptors.
func doWithRetry(client *http.Client, req *http.Request, cfg httpRetryConfig) (*http.Response, error) {
	if cfg.maxAttempts < 1 {
		cfg.maxAttempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= cfg.maxAttempts; attempt++ {
		resp, err := client.Do(req)
		if err == nil && !isRetryableStatus(resp.StatusCode) {
			return resp, nil
		}
		// Capture an error message for surfacing if all retries fail.
		if err != nil {
			lastErr = err
		} else {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
		}
		if attempt == cfg.maxAttempts {
			break
		}
		// Exponential backoff with jitter.
		backoff := cfg.baseDelay * (1 << (attempt - 1))
		if backoff > cfg.maxDelay {
			backoff = cfg.maxDelay
		}
		jitter := time.Duration(rand.Int63n(int64(250 * time.Millisecond)))
		select {
		case <-time.After(backoff + jitter):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	return nil, fmt.Errorf("after %d attempts: %w", cfg.maxAttempts, lastErr)
}
