package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

const reloadTimeout = 2 * time.Second

// newRouter builds the HTTP router with all handlers mounted.
// It returns a *http.ServeMux configured with middleware.
func newRouter(state *State, bus *Bus, gw GatewayClient, routerBus *Bus, rc RouterClient) http.Handler {
	mux := http.NewServeMux()

	// --- API routes ---
	// We register both exact (/api/v1/foo) and prefix (/api/v1/foo/) patterns.
	// The exact pattern prevents Go's ServeMux from issuing a 301 redirect when
	// the trailing slash is absent. The prefix pattern handles sub-paths.

	agentsHandler := func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSuffix(r.URL.Path, "/")
		if path == "/api/v1/agents" {
			handleAgentsList(state)(w, r)
		} else {
			handleAgentDetail(state)(w, r)
		}
	}
	mux.HandleFunc("/api/v1/agents", agentsHandler)
	mux.HandleFunc("/api/v1/agents/", agentsHandler)

	connectionsHandler := func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSuffix(r.URL.Path, "/")
		if path == "/api/v1/connections" {
			handleConnectionsList(state, gw)(w, r)
		} else {
			handleConnectionDetail(state, gw)(w, r)
		}
	}
	mux.HandleFunc("/api/v1/connections", connectionsHandler)
	mux.HandleFunc("/api/v1/connections/", connectionsHandler)

	rolesHandler := func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSuffix(r.URL.Path, "/")
		if path == "/api/v1/roles" {
			switch r.Method {
			case http.MethodGet:
				handleRolesList(state)(w, r)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		} else {
			switch r.Method {
			case http.MethodGet:
				handleRolesList(state)(w, r)
			case http.MethodPut:
				handleRolesPut(state, gw)(w, r)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		}
	}
	mux.HandleFunc("/api/v1/roles", rolesHandler)
	mux.HandleFunc("/api/v1/roles/", rolesHandler)

	mux.HandleFunc("/api/v1/bindings", handleBindingsList(state))

	sessionsHandler := func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSuffix(r.URL.Path, "/")
		if path == "/api/v1/sessions" {
			handleSessionsList(state)(w, r)
		} else if strings.HasSuffix(path, "/events") {
			handleSessionEvents(state)(w, r)
		} else {
			handleSessionDetail(state)(w, r)
		}
	}
	mux.HandleFunc("/api/v1/sessions", sessionsHandler)
	mux.HandleFunc("/api/v1/sessions/", sessionsHandler)

	mux.HandleFunc("/api/v1/decisions", handleDecisions(state))

	mux.HandleFunc("/api/v1/stream", handleWS(state, bus))

	mux.HandleFunc("/healthz", handleHealthz(state, gw))

	// --- Router API routes ---

	// Router policy: /api/v1/router/policy and /api/v1/router/policy/raw
	routerPolicyHandler := func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSuffix(r.URL.Path, "/")
		if strings.HasSuffix(path, "/raw") {
			handleRouterPolicyRaw(state)(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			handleRouterPolicyGet(state)(w, r)
		case http.MethodPut:
			handleRouterPolicyPut(state, rc)(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
	mux.HandleFunc("/api/v1/router/policy", routerPolicyHandler)
	mux.HandleFunc("/api/v1/router/policy/", routerPolicyHandler)

	mux.HandleFunc("/api/v1/router/decisions", handleRouterDecisions(state))
	mux.HandleFunc("/api/v1/router/stats", handleRouterStats(state))
	mux.HandleFunc("/api/v1/router/stream", handleRouterStream(state, routerBus))

	// Apply middleware: recovery, logging, CORS.
	return corsMiddleware(loggingMiddleware(recoveryMiddleware(mux)))
}

// --- Middleware -----------------------------------------------------------------

// corsMiddleware adds CORS headers for the Vite dev origin and same-origin.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "http://127.0.0.1:5173" || origin == "http://localhost:5173" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs every request with method, path, status, and duration.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(lrw, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", lrw.code,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// recoveryMiddleware catches panics and returns 500.
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered",
					"path", r.URL.Path,
					"panic", rec,
					"stack", string(debug.Stack()),
				)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// loggingResponseWriter captures the status code for logging.
type loggingResponseWriter struct {
	http.ResponseWriter
	code int
}

func (l *loggingResponseWriter) WriteHeader(code int) {
	l.code = code
	l.ResponseWriter.WriteHeader(code)
}

// Hijack forwards to the underlying writer so WebSocket upgrades work behind
// the logging middleware.
func (l *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := l.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("logging wrapper: underlying writer is not a Hijacker")
	}
	return h.Hijack()
}

// --- JSON helpers ---------------------------------------------------------------

// writeJSONStatus marshals v and writes it with the given status code.
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		slog.Error("json marshal failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}
