package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// newRouter builds the main HTTP mux for the router server.
func newRouter(p *Pipeline) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", handleChatCompletions(p))
	mux.HandleFunc("/v1/models", handleModelsPassthrough(p))
	mux.HandleFunc("/healthz", handleRouterHealthz(p))
	return loggingMiddleware(recoveryMiddleware(mux))
}

// handleChatCompletions is the main routing endpoint.
// POST /v1/chat/completions — classify → policy eval → forward → audit → return.
func handleChatCompletions(p *Pipeline) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is allowed")
			return
		}

		// Parse request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad_request", "failed to read request body")
			return
		}

		var req ChatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
			return
		}

		requestID := newRequestID()

		resp, rawBody, row, err := p.Process(r.Context(), &req, requestID)
		if err != nil {
			// Stream not supported
			var streamErr *StreamNotSupportedError
			if errors.As(err, &streamErr) {
				writeJSONError(w, http.StatusNotImplemented, "unsupported", "streaming not supported in v1")
				return
			}

			// Upstream 4xx/5xx — forward the raw body to the client unchanged
			var orErr *OpenRouterError
			if errors.As(err, &orErr) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(orErr.StatusCode)
				w.Write(rawBody)
				return
			}

			// Don't leak the upstream URL in the body — log it server-side instead.
			slog.Warn("upstream error", "err", err.Error())
			writeJSONError(w, http.StatusBadGateway, "upstream_error", "upstream call failed; see server log")
			return
		}

		// Attach routing decision headers
		w.Header().Set("Content-Type", "application/json")
		if row != nil {
			w.Header().Set("X-Flint-Routing-Rule", row.MatchedRuleName)
			w.Header().Set("X-Flint-Routing-Target", row.TargetModel)
			w.Header().Set("X-Flint-Routing-Total-Ms", strconv.FormatFloat(row.TotalLatencyMs, 'f', 2, 64))
			w.Header().Set("X-Flint-Routing-Cost-USD", strconv.FormatFloat(row.TotalCostUSD, 'g', -1, 64))
		}
		w.WriteHeader(http.StatusOK)
		w.Write(resp.Raw)
	}
}

// handleModelsPassthrough proxies GET /v1/models to OpenRouter.
func handleModelsPassthrough(p *Pipeline) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is allowed")
			return
		}
		rawBody, err := p.openrouter.GetModels(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusBadGateway, "upstream_error", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(rawBody)
	}
}

// handleRouterHealthz returns a simple health check response.
func handleRouterHealthz(p *Pipeline) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		policy := p.policy.Get()
		type healthzResp struct {
			Status       string `json:"status"`
			PolicyLoaded bool   `json:"policy_loaded"`
			Routes       int    `json:"routes"`
			AuditPath    string `json:"audit_path"`
			RouterUp     bool   `json:"router_up"`
		}
		hz := healthzResp{
			Status:       "ok",
			PolicyLoaded: policy != nil,
			AuditPath:    p.audit.Path(),
			RouterUp:     true,
		}
		if policy != nil {
			hz.Routes = len(policy.Routes)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(hz)
	}
}

// writeJSONError writes a standard JSON error response body.
func writeJSONError(w http.ResponseWriter, status int, errType, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"type":    errType,
			"message": message,
		},
	})
}

// newRequestID returns a random hex string for request tracing.
// This avoids an external uuid dependency while providing sufficient uniqueness.
func newRequestID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// loggingResponseWriter wraps http.ResponseWriter to capture the status code.
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lw *loggingResponseWriter) WriteHeader(code int) {
	lw.statusCode = code
	lw.ResponseWriter.WriteHeader(code)
}

// loggingMiddleware logs each request with method, path, status, and latency.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		t0 := time.Now()
		next.ServeHTTP(lw, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", lw.statusCode,
			"latency_ms", float64(time.Since(t0).Milliseconds()),
		)
	})
}

// recoveryMiddleware catches panics and returns 500 without crashing the server.
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic in handler", "recover", rec)
				writeJSONError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
