package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// GatewayClient is an HTTP client for talking to the gateway sidecar.
// The interface makes it mockable in tests.
type GatewayClient interface {
	Reload(ctx context.Context) error
	Healthz(ctx context.Context) (gatewayHealthz, error)
}

// gatewayHealthz mirrors the gateway sidecar's /healthz response body.
type gatewayHealthz struct {
	Status       string `json:"status"`
	PolicyLoaded bool   `json:"policy_loaded"`
	AuditPath    string `json:"audit_path"`
}

// httpGatewayClient is the production GatewayClient backed by net/http.
type httpGatewayClient struct {
	baseURL string
	http    *http.Client
}

// NewGatewayClient returns an httpGatewayClient with a 2-second timeout.
func NewGatewayClient(baseURL string) GatewayClient {
	return &httpGatewayClient{
		baseURL: baseURL,
		http: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
}

// Reload calls POST /reload on the gateway sidecar.
func (c *httpGatewayClient) Reload(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/reload", nil)
	if err != nil {
		return fmt.Errorf("building reload request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST /reload: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /reload: gateway returned %d", resp.StatusCode)
	}
	return nil
}

// Healthz calls GET /healthz on the gateway sidecar.
func (c *httpGatewayClient) Healthz(ctx context.Context) (gatewayHealthz, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return gatewayHealthz{}, fmt.Errorf("building healthz request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return gatewayHealthz{}, fmt.Errorf("GET /healthz: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return gatewayHealthz{}, fmt.Errorf("GET /healthz: gateway returned %d", resp.StatusCode)
	}
	var h gatewayHealthz
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return gatewayHealthz{}, fmt.Errorf("decoding /healthz response: %w", err)
	}
	return h, nil
}
