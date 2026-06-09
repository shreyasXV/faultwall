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

const (
	openAIEndpoint = "https://api.openai.com/v1/chat/completions"

	// defaultOpenAIModel is the chat-completions model APA uses when the operator
	// hasn't pinned one. Updated 2026-05-17. Bump when a newer gpt-* model with
	// equivalent or better JSON-mode reliability ships.
	defaultOpenAIModel = "gpt-4o-2024-08-06"

	// defaultLiteLLMEndpoint is the local LiteLLM proxy's OpenAI-compatible
	// chat-completions route. Used by the "litellm" provider so APA can reason
	// over whatever model the proxy fronts (e.g. Bedrock Opus) with no direct
	// provider key. Override with OPENAI_BASE_URL.
	defaultLiteLLMEndpoint = "http://localhost:4000/v1/chat/completions"

	// defaultLiteLLMModel is the model_name to request from the LiteLLM proxy
	// when the operator hasn't pinned one. Matches the proxy's primary brain.
	defaultLiteLLMModel = "bedrock-opus"
)

type openAIProvider struct {
	name     string
	model    string
	apiKey   string
	endpoint string
	// omitTemperature drops the temperature param from the request. Some
	// Bedrock-fronted models (e.g. Claude Opus 4.x via LiteLLM) reject
	// temperature outright, so the litellm provider sets this.
	omitTemperature bool
	client          *http.Client
}

func newOpenAIProvider(cfg APAConfig) (Provider, error) {
	// Endpoint is overridable so APA can target any OpenAI-compatible gateway
	// (LiteLLM, vLLM, an Azure deployment, etc.) instead of api.openai.com.
	endpoint := os.Getenv("OPENAI_BASE_URL")
	if endpoint == "" {
		endpoint = openAIEndpoint
	}
	key := os.Getenv("OPENAI_API_KEY")
	// A bearer key is only mandatory when talking to the real OpenAI API.
	// Self-hosted gateways (LiteLLM with no master_key) accept unauthenticated
	// requests, so a key is optional when OPENAI_BASE_URL points elsewhere.
	if key == "" && endpoint == openAIEndpoint {
		return nil, fmt.Errorf("OPENAI_API_KEY is not set")
	}
	model := cfg.Model
	if model == "" {
		model = defaultOpenAIModel
	}
	return &openAIProvider{
		name:     "openai",
		model:    model,
		apiKey:   key,
		endpoint: endpoint,
		client:   &http.Client{Timeout: 120 * time.Second},
	}, nil
}

// newLiteLLMProvider targets a local/remote LiteLLM proxy via its
// OpenAI-compatible endpoint. Defaults to the Bedrock-fronted proxy on :4000
// so APA gets real LLM reasoning over Bedrock Opus with zero direct keys.
// Override endpoint with OPENAI_BASE_URL and auth (if the proxy sets a
// master_key) with OPENAI_API_KEY.
func newLiteLLMProvider(cfg APAConfig) (Provider, error) {
	endpoint := os.Getenv("OPENAI_BASE_URL")
	if endpoint == "" {
		endpoint = defaultLiteLLMEndpoint
	}
	model := cfg.Model
	if model == "" {
		model = defaultLiteLLMModel
	}
	return &openAIProvider{
		name:     "litellm",
		model:    model,
		apiKey:   os.Getenv("OPENAI_API_KEY"), // optional
		endpoint: endpoint,
		// Bedrock Claude Opus 4.x rejects the temperature param; LiteLLM
		// surfaces that as a 400, so omit it for this provider.
		omitTemperature: true,
		client:          &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (p *openAIProvider) Name() string {
	return p.name + ":" + p.model
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
	}
	if !p.omitTemperature {
		body["temperature"] = prompt.Temperature
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Response{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(payload))
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	start := time.Now()
	resp, err := doWithRetry(p.client, req, defaultRetryConfig)
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
