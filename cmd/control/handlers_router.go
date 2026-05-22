package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"flint/engine/routing"
	"flint/pkg/api"
)

// ---------------------------------------------------------------------------
// RouterClient — HTTP client for the router sidecar (:7479)
// ---------------------------------------------------------------------------

// RouterClient is an HTTP client for talking to the router sidecar.
// The interface makes it mockable in tests.
type RouterClient interface {
	Reload(ctx context.Context) error
	Healthz(ctx context.Context) (routerHealthz, error)
}

// routerHealthz mirrors the router sidecar's /healthz response body.
type routerHealthz struct {
	Status       string `json:"status"`
	PolicyLoaded bool   `json:"policy_loaded"`
	AuditPath    string `json:"audit_path"`
	RouterUp     bool   `json:"router_up"`
}

// httpRouterClient is the production RouterClient backed by net/http.
type httpRouterClient struct {
	baseURL string
	http    *http.Client
}

// NewRouterClient returns an httpRouterClient with a 2-second timeout.
func NewRouterClient(baseURL string) RouterClient {
	return &httpRouterClient{
		baseURL: baseURL,
		http: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
}

// Reload calls POST /reload on the router sidecar.
func (c *httpRouterClient) Reload(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/reload", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &httpError{code: resp.StatusCode, msg: "POST /reload"}
	}
	return nil
}

// Healthz calls GET /healthz on the router sidecar.
func (c *httpRouterClient) Healthz(ctx context.Context) (routerHealthz, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return routerHealthz{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return routerHealthz{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return routerHealthz{}, &httpError{code: resp.StatusCode, msg: "GET /healthz"}
	}
	var h routerHealthz
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return routerHealthz{}, err
	}
	return h, nil
}

// httpError is a simple error type carrying an HTTP status code.
type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string {
	return e.msg + ": HTTP " + strconv.Itoa(e.code)
}

// ---------------------------------------------------------------------------
// Policy conversion helpers
// ---------------------------------------------------------------------------

// policyToRouterPolicy converts an engine/routing.Policy to api.RouterPolicy.
func policyToRouterPolicy(p *routing.Policy) api.RouterPolicy {
	rp := api.RouterPolicy{
		SchemaVersion: p.SchemaVersion,
		Classifier: api.RouterClassifier{
			Model:     p.Classifier.Model,
			TimeoutMs: p.Classifier.TimeoutMs,
			MaxTokens: p.Classifier.MaxTokens,
		},
		Default: routeRuleToRouterRoute(p.Default),
		Baseline: api.RouterBaseline{
			Model: p.Baseline.Model,
		},
	}
	for _, r := range p.Routes {
		rp.Routes = append(rp.Routes, routeRuleToRouterRoute(r))
	}
	return rp
}

func routeRuleToRouterRoute(r routing.Rule) api.RouterRoute {
	return api.RouterRoute{
		Name:     r.Name,
		If:       matchCondToRouterMatchCond(r.If),
		Target:   r.Target,
		Fallback: r.Fallback,
		Reason:   r.Reason,
	}
}

func matchCondToRouterMatchCond(m routing.MatchCondition) api.RouterMatchCond {
	return api.RouterMatchCond{
		Task:                  m.Task,
		Complexity:            m.Complexity,
		CapabilitiesInclude:   m.CapabilitiesInclude,
		MessagesMinLength:     m.MessagesMinLength,
		MessagesTotalTokensGT: m.MessagesTotalTokGT,
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/router/policy
// ---------------------------------------------------------------------------

// handleRouterPolicyGet handles GET /api/v1/router/policy.
// Reads router-policy.yaml from disk, parses it for validation, and returns
// the structured JSON view as api.RouterPolicy.
func handleRouterPolicyGet(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		policyPath := state.routerPolicyPath
		state.mu.RUnlock()

		p, err := routing.LoadPolicy(policyPath)
		if err != nil {
			slog.Error("router policy get: load failed", "path", policyPath, "err", err)
			writeJSONStatus(w, http.StatusInternalServerError, api.RouterPolicyPutResponse{
				OK:     false,
				Errors: []string{"failed to load policy: " + err.Error()},
			})
			return
		}

		writeJSON200(w, policyToRouterPolicy(p))
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/router/policy/raw
// ---------------------------------------------------------------------------

// handleRouterPolicyRaw handles GET /api/v1/router/policy/raw.
// Returns the raw YAML file contents as text/plain, preserving comments
// for the UI's textarea editor.
func handleRouterPolicyRaw(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		policyPath := state.routerPolicyPath
		state.mu.RUnlock()

		data, err := os.ReadFile(policyPath)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "router policy file not found", http.StatusNotFound)
				return
			}
			slog.Error("router policy raw: read failed", "path", policyPath, "err", err)
			http.Error(w, "failed to read policy file", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
}

// ---------------------------------------------------------------------------
// PUT /api/v1/router/policy
// ---------------------------------------------------------------------------

// handleRouterPolicyPut handles PUT /api/v1/router/policy.
// Body is YAML bytes. Validates via routing.LoadPolicyBytes, writes to a temp
// file, renames atomically, then POSTs to the router sidecar /reload.
// Supports ?dry_run=true for validation-only (used by the UI routes editor).
func handleRouterPolicyPut(state *State, rc RouterClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dryRun := r.URL.Query().Get("dry_run") == "true"

		state.mu.RLock()
		policyPath := state.routerPolicyPath
		state.mu.RUnlock()

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB limit
		if err != nil {
			writeJSONStatus(w, http.StatusBadRequest, api.RouterPolicyPutResponse{
				OK:     false,
				Errors: []string{"failed to read request body: " + err.Error()},
			})
			return
		}

		// Validate via LoadPolicyBytes before touching the file.
		if _, err := routing.LoadPolicyBytes(body); err != nil {
			var errMsgs []string
			for _, line := range strings.Split(err.Error(), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					errMsgs = append(errMsgs, line)
				}
			}
			writeJSONStatus(w, http.StatusBadRequest, api.RouterPolicyPutResponse{
				OK:     false,
				Errors: errMsgs,
			})
			return
		}

		// Dry run stops here — validation passed, no write.
		if dryRun {
			writeJSON200(w, api.RouterPolicyPutResponse{OK: true, Message: "validation passed"})
			return
		}

		// Ensure the policy directory exists.
		dir := filepath.Dir(policyPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			slog.Error("router policy put: mkdir failed", "dir", dir, "err", err)
			http.Error(w, "failed to create policy directory", http.StatusInternalServerError)
			return
		}

		// Write to a unique temp file in the same directory as policyPath so
		// os.Rename stays on the same filesystem (avoids EXDEV) and concurrent
		// PUTs don't collide on a fixed name.
		tmpFile, err := os.CreateTemp(dir, ".router-policy-*.tmp")
		if err != nil {
			slog.Error("router policy put: create tmp failed", "err", err)
			http.Error(w, "failed to create temp file", http.StatusInternalServerError)
			return
		}
		tmpPath := tmpFile.Name()

		if _, err := tmpFile.Write(body); err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			slog.Error("router policy put: write tmp failed", "err", err)
			http.Error(w, "failed to write temp file", http.StatusInternalServerError)
			return
		}
		if err := tmpFile.Close(); err != nil {
			os.Remove(tmpPath)
			slog.Error("router policy put: close tmp failed", "err", err)
			http.Error(w, "failed to close temp file", http.StatusInternalServerError)
			return
		}

		// Atomic rename.
		if err := os.Rename(tmpPath, policyPath); err != nil {
			slog.Error("router policy put: rename failed", "err", err)
			os.Remove(tmpPath)
			http.Error(w, "failed to commit policy file", http.StatusInternalServerError)
			return
		}

		// Notify router sidecar (best effort).
		ctx, cancel := context.WithTimeout(r.Context(), reloadTimeout)
		defer cancel()
		if err := rc.Reload(ctx); err != nil {
			slog.Warn("router policy put: sidecar reload failed (file is written; router will reload on next SIGHUP)", "err", err)
			// Still return 200 — the file is written.
		}

		writeJSON200(w, api.RouterPolicyPutResponse{OK: true})
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/router/decisions
// ---------------------------------------------------------------------------

// handleRouterDecisions handles GET /api/v1/router/decisions?limit=&since=.
// Returns paginated routing decisions from the in-memory ring buffer.
func handleRouterDecisions(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		limit := defaultDecisionLimit
		if raw := q.Get("limit"); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 {
				limit = v
			}
		}
		if limit > maxDecisionLimit {
			limit = maxDecisionLimit
		}

		since := q.Get("since")

		items, hasMore := state.RoutingDecisionsSince(since, limit)
		if items == nil {
			items = []api.RoutingDecision{}
		}

		var nextSince string
		if len(items) > 0 {
			nextSince = items[len(items)-1].TS
		}

		resp := api.RouterDecisionsResponse{
			Items:     items,
			NextSince: nextSince,
			HasMore:   hasMore,
		}
		writeJSON200(w, resp)
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/router/stats
// ---------------------------------------------------------------------------

// handleRouterStats handles GET /api/v1/router/stats?window=.
// Aggregates routing decisions over a time window.
// window accepts: "session"/"all" (default), "1m", "5m", "1h", "24h".
func handleRouterStats(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		window := r.URL.Query().Get("window")
		if window == "" {
			window = "session"
		}
		stats := state.ComputeRouterStats(window)
		writeJSON200(w, stats)
	}
}

// ---------------------------------------------------------------------------
// WS /api/v1/router/stream
// ---------------------------------------------------------------------------

// handleRouterStream upgrades the HTTP connection to WebSocket and streams
// live routing decisions on the router-specific bus. Uses the same envelope
// and ping/pong pattern as handleWS, but emits frames of type
// "routing_decision" (not "decision") from a dedicated bus instance.
func handleRouterStream(state *State, routerBus *Bus) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			slog.Warn("router ws: upgrade failed", "err", err)
			return
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(wsPongDeadline))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(wsPongDeadline))
			return nil
		})

		sub := routerBus.Subscribe()
		defer routerBus.Unsubscribe(sub)

		// Send hello frame with router schema version and backlog count.
		backlog := state.RecentRoutingDecisions(wsBacklogMax)
		helloFrame := api.WSFrame{
			Type: "hello",
			Data: api.WSHello{
				SchemaVersion: api.RouterAuditSchemaVersion,
				BacklogCount:  len(backlog),
			},
		}
		if err := writeJSON(conn, helloFrame); err != nil {
			slog.Debug("router ws: hello write failed", "err", err)
			return
		}

		// Send backlog.
		for _, row := range backlog {
			frame := api.WSFrame{Type: "routing_decision", Data: row}
			if err := writeJSON(conn, frame); err != nil {
				slog.Debug("router ws: backlog write failed", "err", err)
				return
			}
		}

		ticker := time.NewTicker(wsPingInterval)
		defer ticker.Stop()

		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				_, _, err := conn.ReadMessage()
				if err != nil {
					return
				}
			}
		}()

		for {
			select {
			case <-done:
				return

			case frame, ok := <-sub.Chan():
				if !ok {
					return
				}
				conn.SetWriteDeadline(time.Now().Add(wsWriteDeadline))
				if err := conn.WriteMessage(websocket.TextMessage, frame); err != nil {
					slog.Debug("router ws: write failed", "err", err)
					return
				}

			case <-ticker.C:
				conn.SetWriteDeadline(time.Now().Add(wsWriteDeadline))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					slog.Debug("router ws: ping failed", "err", err)
					return
				}
			}
		}
	}
}

