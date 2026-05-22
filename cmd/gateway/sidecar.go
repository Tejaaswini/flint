package main

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"time"

	"flint/engine/authz"
	"flint/pkg/api"
)

// SidecarOpts configures the sidecar HTTP server.
type SidecarOpts struct {
	// Reload is called when POST /reload is received. A non-nil error causes
	// the endpoint to respond 500 with the error message.
	Reload func() error

	// PolicyHolder is used by GET /healthz to report policy state.
	PolicyHolder *authz.PolicyHolder

	// AuditPath is included in the /healthz response body.
	AuditPath string
}

// StartSidecar starts a non-blocking HTTP server on addr and returns it so the
// caller can shut it down gracefully (srv.Shutdown). Returns an error if the
// listener cannot be bound.
func StartSidecar(addr string, opts SidecarOpts) (*http.Server, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		policy := opts.PolicyHolder.Get()
		policyLoaded := policy != nil

		agentsKnown := 0
		if policy != nil {
			agentsKnown = len(policy.Bindings)
		}

		hz := api.Healthz{
			Status:       "ok",
			PolicyLoaded: policyLoaded,
			AgentsKnown:  agentsKnown,
			AuditPath:    opts.AuditPath,
			GatewayUp:    true,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(hz)
	})

	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if opts.Reload == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"ok":true}` + "\n"))
			return
		}

		if err := opts.Reload(); err != nil {
			slog.Error("sidecar reload failed", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}` + "\n"))
	})

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("sidecar server error", "error", err)
		}
	}()

	slog.Info("sidecar listening", "addr", addr)

	return srv, nil
}
