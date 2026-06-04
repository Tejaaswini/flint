// Flint gateway — inline MCP proxy with RBAC enforcement and behavioral analysis.
//
// Usage:
//
//	flint-gateway --agent <id> [--roles config/roles.yaml] [--bindings config/bindings.yaml] \
//	              [--tools tools.yaml] [--audit flint-audit.jsonl] [--http-addr 127.0.0.1:7476] \
//	              -- <upstream> [args...]
//
// Example:
//
//	flint-gateway --agent support-bot -- npx -y @modelcontextprotocol/server-everything
//
// The --agent flag may also be set via the FLINT_AGENT_ID environment variable
// (flag takes precedence if both are provided).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"flint/engine"
	"flint/engine/authz"
	"flint/engine/session"
)

func main() {
	// --- flag parsing ---
	agentFlag := flag.String("agent", "", "agent identity for RBAC (required; fallback: FLINT_AGENT_ID env var)")
	rolesPath := flag.String("roles", "config/roles.yaml", "path to roles.yaml")
	bindingsPath := flag.String("bindings", "config/bindings.yaml", "path to bindings.yaml")
	toolsPath := flag.String("tools", "tools.yaml", "path to tools.yaml registry")
	auditPath := flag.String("audit", "flint-audit.jsonl", "path to JSONL audit log (append mode)")
	httpAddr := flag.String("http-addr", "127.0.0.1:7476", "address for the gateway HTTP sidecar (healthz + reload)")
	enforceMode := flag.String("enforce-mode", "block", "enforcement mode: block (default) or observe. block actively refuses forwarding when disposition is pause/terminate; observe logs only")
	flag.Parse()

	upstream := flag.Args()

	// --- structured logger ---
	initLogger()

	// --- resolve agent ID ---
	agentID := *agentFlag
	if agentID == "" {
		agentID = os.Getenv("FLINT_AGENT_ID")
	}

	if agentID == "" || len(upstream) == 0 {
		fmt.Fprintln(os.Stderr, "usage: flint-gateway --agent <id> [flags] -- <upstream> [args...]")
		os.Exit(1)
	}

	if *enforceMode != "block" && *enforceMode != "observe" {
		fmt.Fprintf(os.Stderr, "error: --enforce-mode must be 'block' or 'observe', got %q\n", *enforceMode)
		os.Exit(1)
	}

	// --- load tool registry ---
	registry, err := session.LoadRegistry(*toolsPath)
	if err != nil {
		slog.Warn("tools registry not loaded; falling back to built-in defaults", "path", *toolsPath, "error", err)
		registry = nil
	} else {
		slog.Info("tools registry loaded", "path", *toolsPath, "count", len(registry))
	}

	// --- load policy ---
	policy, err := authz.LoadPolicy(*rolesPath, *bindingsPath, registry)
	if err != nil {
		slog.Warn("policy not loaded; running in passthrough mode", "error", err)
		policy = nil
	} else {
		slog.Info("policy loaded", "roles", len(policy.Roles), "bindings", len(policy.Bindings))
	}

	// --- wrap policy in holder for hot-reload ---
	holder := authz.NewPolicyHolder(policy)

	// --- open audit writer ---
	auditWriter, err := NewWriter(*auditPath)
	if err != nil {
		slog.Error("failed to open audit log", "path", *auditPath, "error", err)
		os.Exit(1)
	}
	slog.Info("audit log opened", "path", *auditPath)

	// --- build engine ---
	sessionID := fmt.Sprintf("gw-%d", time.Now().UnixNano())
	eng := engine.New(sessionID, registry, holder)

	// --- build proxy ---
	p := NewProxy(agentID, upstream, eng, holder, auditWriter, *enforceMode)

	// --- reload function (shared by SIGHUP and sidecar /reload) ---
	reloadFn := func() error {
		newPolicy, loadErr := authz.LoadPolicy(*rolesPath, *bindingsPath, registry)
		if loadErr != nil {
			slog.Error("policy reload failed; keeping current policy", "error", loadErr)
			return loadErr
		}
		holder.Set(newPolicy)
		eng.Reload(newPolicy)
		slog.Info("policy reloaded", "roles", len(newPolicy.Roles), "bindings", len(newPolicy.Bindings))
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
		// Error is already logged inside reloadFn; ignore return here.
		_ = reloadFn()
	}
	drainFn := func() {
		p.Drain()
	}
	done, signaled := InstallSignals(reloadSig, drainFn)

	slog.Info("gateway started", "agent", agentID, "upstream", upstream[0], "sidecar", *httpAddr)

	// --- run proxy (blocks until stdin/upstream EOF or stop) ---
	if err := p.Run(); err != nil {
		slog.Error("gateway exited with error", "error", err)
	}

	// Wait for signal-handler drain to complete (if a stop signal fired).
	// If the proxy exited naturally (stdin EOF), signaled is false and we skip
	// the wait entirely — there is nothing to drain. The 7s timeout ensures a
	// stuck drain goroutine can never hang main beyond drain's own 5s deadline.
	if signaled.Load() {
		select {
		case <-done:
		case <-time.After(7 * time.Second):
			slog.Warn("shutdown: timed out waiting for drain goroutine to complete")
		}
	}

	// --- graceful shutdown ---
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sidecar.Shutdown(ctx); err != nil {
		slog.Warn("sidecar shutdown error", "error", err)
	}

	if err := auditWriter.Close(); err != nil {
		slog.Warn("audit writer close error", "error", err)
	}

	slog.Info("gateway stopped")
}
