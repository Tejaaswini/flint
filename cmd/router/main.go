// flint-router — OpenRouter task-aware LLM router.
//
// Usage:
//
//	flint-router [flags]
//
// Flags:
//
//	--addr              127.0.0.1:7478         main HTTP server (OpenAI-compat endpoint)
//	--http-addr         127.0.0.1:7479         sidecar HTTP server (healthz + reload)
//	--policy            config/router-policy.yaml
//	--audit             router-audit.jsonl
//	--openrouter-base   https://openrouter.ai/api/v1
//	--openrouter-key-env OPENROUTER_API_KEY    name of the env var holding the API key
//	--pricing           config/pricing.json
//	--http-referer      https://github.com/flint-stack/flint
//	--x-title           Flint Router
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"flint/engine/routing"
)

func main() {
	// --- flags ---
	addr             := flag.String("addr", "127.0.0.1:7478", "main HTTP server address (OpenAI-compat endpoint)")
	httpAddr         := flag.String("http-addr", "127.0.0.1:7479", "sidecar HTTP server address (healthz + reload)")
	policyPath       := flag.String("policy", "config/router-policy.yaml", "path to router-policy.yaml")
	auditPath        := flag.String("audit", "router-audit.jsonl", "path to JSONL audit log (append mode)")
	openrouterBase   := flag.String("openrouter-base", "https://openrouter.ai/api/v1", "base URL for OpenRouter API")
	openrouterKeyEnv := flag.String("openrouter-key-env", "OPENROUTER_API_KEY", "env var name for the OpenRouter API key")
	pricingPath      := flag.String("pricing", "config/pricing.json", "path to pricing fallback JSON")
	httpReferer      := flag.String("http-referer", "https://github.com/flint-stack/flint", "HTTP-Referer header sent to OpenRouter")
	xTitle           := flag.String("x-title", "Flint Router", "X-Title header sent to OpenRouter")
	flag.Parse()

	// --- structured logger ---
	initLogger()

	// --- resolve API key ---
	apiKey := os.Getenv(*openrouterKeyEnv)
	if apiKey == "" {
		slog.Error("API key not found in environment", "env_var", *openrouterKeyEnv)
		os.Exit(1)
	}
	// Log only the masked form — NEVER log the full key
	maskedKey := "sk-or-..." + apiKey[max(0, len(apiKey)-4):]
	slog.Info("API key loaded", "masked", maskedKey)

	// --- load pricing table ---
	pricing, err := LoadPricingTable(*pricingPath)
	if err != nil {
		slog.Warn("could not load pricing file; using built-in defaults", "path", *pricingPath, "error", err)
		pricing = NewDefaultPricingTable()
	} else {
		slog.Info("pricing table loaded", "path", *pricingPath)
	}

	// --- load routing policy ---
	policy, err := routing.LoadPolicy(*policyPath)
	if err != nil {
		slog.Error("failed to load routing policy", "path", *policyPath, "error", err)
		os.Exit(1)
	}
	for _, w := range policy.Warnings {
		slog.Warn("policy warning", "message", w)
	}
	slog.Info("routing policy loaded", "routes", len(policy.Routes), "path", *policyPath)

	// --- wrap policy in holder for hot-reload ---
	holder := routing.NewPolicyHolder(policy)

	// --- open audit writer ---
	auditWriter, err := NewAuditWriter(*auditPath)
	if err != nil {
		slog.Error("failed to open router audit log", "path", *auditPath, "error", err)
		os.Exit(1)
	}
	slog.Info("router audit log opened", "path", *auditPath)

	// --- build OpenRouter client ---
	orClient := NewOpenRouterClient(*openrouterBase, apiKey, *httpReferer, *xTitle)

	// --- build classifier ---
	clf := NewClassifier(holder, orClient, pricing)

	// --- build pipeline ---
	pipeline := NewPipeline(holder, clf, orClient, auditWriter, pricing)

	// --- reload function (shared by SIGHUP and sidecar /reload) ---
	reloadFn := func() error {
		newPolicy, loadErr := routing.LoadPolicy(*policyPath)
		if loadErr != nil {
			slog.Error("policy reload failed; keeping current policy", "error", loadErr)
			return loadErr
		}
		for _, w := range newPolicy.Warnings {
			slog.Warn("policy warning", "message", w)
		}
		holder.Set(newPolicy)
		slog.Info("routing policy reloaded", "routes", len(newPolicy.Routes))
		return nil
	}

	// --- sidecar HTTP server ---
	sidecar, err := StartSidecar(*httpAddr, SidecarOpts{
		Reload:       reloadFn,
		PolicyHolder: holder,
		AuditPath:    *auditPath,
	})
	if err != nil {
		slog.Error("failed to start sidecar", "addr", *httpAddr, "error", err)
		os.Exit(1)
	}

	// --- signal handlers ---
	reloadSig := func() {
		_ = reloadFn()
	}
	drainFn := func() {
		pipeline.Drain()
	}
	done := InstallSignals(reloadSig, drainFn)

	// --- start main HTTP server ---
	mainHandler := newRouter(pipeline)
	srv := &http.Server{
		Addr:         *addr,
		Handler:      mainHandler,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("failed to bind main server", "addr", *addr, "error", err)
		os.Exit(1)
	}

	go func() {
		slog.Info("router server listening", "addr", *addr)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("router server error", "error", err)
		}
	}()

	slog.Info("flint-router started", "addr", *addr, "sidecar", *httpAddr, "policy", *policyPath)

	// --- wait for shutdown signal ---
	<-done

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Warn("main server shutdown error", "error", err)
	}
	if err := sidecar.Shutdown(ctx); err != nil {
		slog.Warn("sidecar shutdown error", "error", err)
	}
	if err := auditWriter.Close(); err != nil {
		slog.Warn("audit writer close error", "error", err)
	}

	slog.Info("flint-router stopped")
}

