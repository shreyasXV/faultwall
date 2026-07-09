package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	anthropicEndpoint = "https://api.anthropic.com/v1/messages"
	anthropicVersion  = "2023-06-01"

	// defaultAnthropicModel is the messages-api model APA uses when the operator
	// hasn't pinned one. Updated 2026-05-17. Bump when a newer claude-* model with
	// equivalent or better structured-output reliability ships.
	defaultAnthropicModel = "claude-opus-4-5"
)

type anthropicProvider struct {
	model  string
	apiKey string
	client *http.Client
}

func newAnthropicProvider(cfg APAConfig) (Provider, error) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY is not set")
	}
	model := cfg.Model
	if model == "" {
		model = defaultAnthropicModel
	}
	return &anthropicProvider{
		model:  model,
		apiKey: key,
		client: &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (p *anthropicProvider) Name() string {
	return "anthropic:" + p.model
}

func (p *anthropicProvider) Reason(ctx context.Context, prompt Prompt) (Response, error) {
	body := map[string]any{
		"model":      p.model,
		"system":     prompt.System,
		"max_tokens": prompt.MaxTokens,
		"messages": []map[string]string{
			{"role": "user", "content": prompt.User},
		},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Response{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicEndpoint, bytes.NewReader(payload))
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)

	start := time.Now()
	resp, err := doWithRetry(p.client, req, defaultRetryConfig)
	if err != nil {
		return Response{}, fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()
	latency := int(time.Since(start).Milliseconds())

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Response{}, fmt.Errorf("anthropic read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("anthropic status %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return Response{}, fmt.Errorf("anthropic parse response: %w", err)
	}
	if len(result.Content) == 0 {
		return Response{}, fmt.Errorf("anthropic returned no content blocks")
	}

	// Concatenate every text block. Claude may emit a leading prose/thinking
	// block before the JSON block; reading only Content[0].Text then handed the
	// parser prose (often starting with "*" or a bullet), yielding
	// "invalid character '*' looking for beginning of value". Joining all text
	// blocks lets extractJSONObject find the real JSON regardless of position.
	var sb strings.Builder
	for _, c := range result.Content {
		if c.Text == "" {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(c.Text)
	}

	return Response{
		Text:         sb.String(),
		InputTokens:  result.Usage.InputTokens,
		OutputTokens: result.Usage.OutputTokens,
		LatencyMs:    latency,
		ProviderID:   p.Name(),
	}, nil
}
