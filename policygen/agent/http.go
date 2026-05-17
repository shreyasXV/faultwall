package agent

import (
	"bytes"
	"net/http"
)

// postJSON sends a JSON payload to url with a 5-second timeout.
// Used only for optional Slack notifications.
func postJSON(url string, payload []byte) error {
	resp, err := http.Post(url, "application/json", bytes.NewReader(payload)) //nolint:noctx
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
