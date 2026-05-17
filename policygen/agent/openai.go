package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const openAIEndpoint = "https://api.openai.com/v1/chat/completions"

type openAIProvider struct {
	model  string
	apiKey string
	client *http.Client
}

func newOpenAIProvider(cfg APAConfig) (Provider, error) {
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("OPENAI_API_KEY is not set")
	}
	model := cfg.Model
	if model == "" {
		model = "gpt-4o-2024-08-06"
	}
	return &openAIProvider{
		model:  model,
		apiKey: key,
		client: &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (p *openAIProvider) Name() string {
	return "openai:" + p.model
}

func (p *openAIProvider) Reason(ctx context.Context, prompt Prompt) (Response, error) {
	body := map[string]any{
		"model": p.model,
		"messages": []map[string]string{
			{"role": "system", "content": prompt.System},
			{"role": "user", "content": prompt.User},
		},
		"response_format": map[string]string{"type": "json_object"},
		"max_tokens":      prompt.MaxTokens,
		"temperature":     prompt.Temperature,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Response{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openAIEndpoint, bytes.NewReader(payload))
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	start := time.Now()
	resp, err := p.client.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("openai request: %w", err)
	}
	defer resp.Body.Close()
	latency := int(time.Since(start).Milliseconds())

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Response{}, fmt.Errorf("openai read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("openai status %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return Response{}, fmt.Errorf("openai parse response: %w", err)
	}
	if len(result.Choices) == 0 {
		return Response{}, fmt.Errorf("openai returned no choices")
	}

	return Response{
		Text:         result.Choices[0].Message.Content,
		InputTokens:  result.Usage.PromptTokens,
		OutputTokens: result.Usage.CompletionTokens,
		LatencyMs:    latency,
		ProviderID:   p.Name(),
	}, nil
}
