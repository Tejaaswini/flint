// flint-control — control plane HTTP + WebSocket server.
//
// Usage:
//
//	flint-control --addr 127.0.0.1:7475 \
//	              --roles config/roles.yaml \
//	              --bindings config/bindings.yaml \
//	              --tools tools.yaml \
//	              --audit flint-audit.jsonl \
//	              --gateway-url http://127.0.0.1:7476
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"flint/engine/authz"
	"flint/engine/session"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7475", "listen address")
	rolesPath := flag.String("roles", "config/roles.yaml", "path to roles.yaml")
	bindingsPath := flag.String("bindings", "config/bindings.yaml", "path to bindings.yaml")
	toolsPath := flag.String("tools", "tools.yaml", "path to tools.yaml")
	auditPath := flag.String("audit", "flint-audit.jsonl", "path to audit JSONL file")
	gatewayURL := flag.String("gateway-url", "http://127.0.0.1:7476", "gateway sidecar base URL")
	routerPolicyPath := flag.String("router-policy", "config/router-policy.yaml", "path to router-policy.yaml")
	routerAuditPath := flag.String("router-audit", "router-audit.jsonl", "path to router audit JSONL file")
	routerURL := flag.String("router-url", "http://127.0.0.1:7479", "router sidecar base URL")
	flag.Parse()

	// Structured JSON logger to stderr.
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	slog.Info("flint-control starting",
		"addr", *addr,
		"roles", *rolesPath,
		"bindings", *bindingsPath,
		"tools", *toolsPath,
		"audit", *auditPath,
		"gateway_url", *gatewayURL,
		"router_policy", *routerPolicyPath,
		"router_audit", *routerAuditPath,
		"router_url", *routerURL,
	)

	// Load tool registry.
	registry, err := session.LoadRegistry(*toolsPath)
	if err != nil {
		slog.Warn("tools registry not loaded; running without tool metadata", "err", err)
		registry = nil
	} else {
		slog.Info("registry loaded", "tools", len(registry))
	}

	// Load policy.
	policy, err := authz.LoadPolicy(*rolesPath, *bindingsPath, registry)
	if err != nil {
		slog.Warn("policy not loaded; running in passthrough mode", "err", err)
		policy = nil
	} else {
		slog.Info("policy loaded", "roles", len(policy.Roles), "bindings", len(policy.Bindings))
	}

	// Build state.
	state := NewState(*rolesPath, *bindingsPath, *toolsPath, *auditPath, *gatewayURL)
	state.SetPolicy(policy)
	state.SetRegistry(registry)
	state.SetRouterPaths(*routerPolicyPath, *routerAuditPath, *routerURL)

	// Build gateway event bus and router event bus (separate instances so
	// router WS subscribers don't see gateway events and vice-versa).
	bus := NewBus()
	routerBus := NewBus()

	// Build gateway client.
	gw := NewGatewayClient(*gatewayURL)

	// Build router client.
	rc := NewRouterClient(*routerURL)

	// Bootstrap and start gateway audit tail.
	tail := NewAuditTail(*auditPath, state, bus)
	tail.Bootstrap()

	// Bootstrap and start router audit tail.
	routerTail := NewRouterAuditTail(*routerAuditPath, state, routerBus)
	routerTail.Bootstrap()

	// Start audit tail goroutines.
	stopTail := make(chan struct{})
	go tail.Start(stopTail)
	go routerTail.Start(stopTail)

	// Periodic gateway health probe (every 15s).
	stopHealthProbe := make(chan struct{})
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		// Initial ping.
		probeGateway(state, gw)
		for {
			select {
			case <-stopHealthProbe:
				return
			case <-ticker.C:
				probeGateway(state, gw)
			}
		}
	}()

	// Periodic router health probe (every 15s).
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		probeRouter(state, rc)
		for {
			select {
			case <-stopHealthProbe:
				return
			case <-ticker.C:
				probeRouter(state, rc)
			}
		}
	}()

	// Build HTTP server.
	handler := newRouter(state, bus, gw, routerBus, rc)
	srv := &http.Server{
		Addr:         *addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Listen before blocking so we can report "ready" before signal.
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("listen failed", "addr", *addr, "err", err)
		fmt.Fprintf(os.Stderr, "flint-control: listen failed: %v\n", err)
		os.Exit(1)
	}
	slog.Info("flint-control ready", "addr", *addr)

	// Signal handling.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Serve in background.
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- srv.Serve(ln)
	}()

	// Block until signal or server error.
	select {
	case sig := <-sigCh:
		slog.Info("shutting down", "signal", sig.String())
	case err := <-srvErr:
		if err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
		}
	}

	// Graceful shutdown: stop background workers, then drain HTTP.
	close(stopTail)
	close(stopHealthProbe)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Warn("graceful shutdown did not complete cleanly", "err", err)
	}

	slog.Info("flint-control stopped")
}

// probeGateway pings the gateway sidecar and updates state.
func probeGateway(state *State, gw GatewayClient) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := gw.Healthz(ctx); err == nil {
		state.MarkGatewayOK()
	}
}

// probeRouter pings the router sidecar and updates state.
func probeRouter(state *State, rc RouterClient) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := rc.Healthz(ctx); err == nil {
		state.MarkRouterOK()
	}
}
