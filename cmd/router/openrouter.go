package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// ChatMessage is a single message in a chat completion request.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ResponseFormat controls the output format of the completion.
type ResponseFormat struct {
	Type string `json:"type"` // "json_object" | "text"
}

// ChatRequest is the OpenAI-compatible chat completion request body.
// Only known fields are parsed; unknown fields are dropped (the router does not
// need to forward arbitrary fields — it re-constructs the body for OpenRouter).
type ChatRequest struct {
	Model          string          `json:"model"`
	Messages       []ChatMessage   `json:"messages"`
	MaxTokens      int             `json:"max_tokens,omitempty"`
	Temperature    *float64        `json:"temperature,omitempty"`
	ResponseFormat *ResponseFormat `json:"response_format,omitempty"`
	Stream         bool            `json:"stream,omitempty"`
}

// ChatChoice is one element of the choices array in a chat completion response.
type ChatChoice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

// ChatUsage holds the token-usage fields from the response.
// The Cost field is OpenRouter-specific; it may be absent or zero.
type ChatUsage struct {
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	TotalTokens      int     `json:"total_tokens"`
	Cost             float64 `json:"cost,omitempty"` // OpenRouter-specific USD cost; may be 0
}

// ChatResponse is the typed parse of a chat completion response.
// Raw holds the original response bytes so they can be forwarded to the client
// byte-for-byte (preserving fields the router doesn't know about).
type ChatResponse struct {
	ID      string       `json:"id"`
	Model   string       `json:"model"`
	Choices []ChatChoice `json:"choices"`
	Usage   *ChatUsage   `json:"usage,omitempty"`
	Raw     []byte       `json:"-"` // not marshaled; used for passthrough
}

// OpenRouterClient is a typed HTTP client for the OpenRouter API.
// The API key is stored in memory and NEVER logged or echoed.
type OpenRouterClient struct {
	baseURL    string
	apiKey     string // never logged; masked in debug output
	httpClient *http.Client
	referer    string
	xTitle     string
}

// NewOpenRouterClient creates a client. key is read at construction time from
// the env var named by keyEnvVar. It is stored only in the struct; no logging.
func NewOpenRouterClient(baseURL, apiKey, referer, xTitle string) *OpenRouterClient {
	return &OpenRouterClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		referer: referer,
		xTitle:  xTitle,
	}
}

// maskedKey returns the last 4 characters of the key prefixed with "sk-or-...".
// Used only in debug log messages. NEVER log the full key.
func (c *OpenRouterClient) maskedKey() string {
	if len(c.apiKey) <= 4 {
		return "sk-or-...[too short]"
	}
	return "sk-or-..." + c.apiKey[len(c.apiKey)-4:]
}

// Complete sends a chat completion request to OpenRouter and returns the parsed
// response plus the raw response bytes for passthrough to the client.
// The ctx deadline controls the per-call timeout.
func (c *OpenRouterClient) Complete(ctx context.Context, req *ChatRequest) (*ChatResponse, []byte, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("openrouter: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("openrouter: build request: %w", err)
	}
	c.setHeaders(httpReq)

	slog.Info("openrouter call", "model", req.Model, "key_last4", c.maskedKey())

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("openrouter: HTTP error: %w", err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("openrouter: read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, rawBody, &OpenRouterError{StatusCode: resp.StatusCode, Body: rawBody}
	}

	var parsed ChatResponse
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, rawBody, fmt.Errorf("openrouter: parse response: %w", err)
	}
	parsed.Raw = rawBody
	return &parsed, rawBody, nil
}

// GetModels is a passthrough for GET /v1/models.
// Returns the raw response bytes to be forwarded to the client.
func (c *OpenRouterClient) GetModels(ctx context.Context) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/models", nil)
	if err != nil {
		return nil, fmt.Errorf("openrouter: build models request: %w", err)
	}
	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openrouter: models HTTP error: %w", err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("openrouter: read models body: %w", err)
	}
	return rawBody, nil
}

// setHeaders applies the required OpenRouter headers to a request.
// The Authorization header value is the API key and is NEVER logged.
func (c *OpenRouterClient) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "flint-router/0.1")
	if c.referer != "" {
		req.Header.Set("HTTP-Referer", c.referer)
	}
	if c.xTitle != "" {
		req.Header.Set("X-Title", c.xTitle)
	}
}

// OpenRouterError is returned when the upstream API responds with a non-200 status.
type OpenRouterError struct {
	StatusCode int
	Body       []byte
}

func (e *OpenRouterError) Error() string {
	return fmt.Sprintf("openrouter: upstream returned %d", e.StatusCode)
}
