package agent

import (
	"bytes"
	"net/http"
	"time"
)

// slackClient has an explicit timeout so a hung Slack webhook can't stall the cron loop.
var slackClient = &http.Client{Timeout: 5 * time.Second}

// postJSON sends a JSON payload to url.
// Used only for optional Slack notifications — callers should treat errors as non-fatal.
func postJSON(url string, payload []byte) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := slackClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
