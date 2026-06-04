package main

import (
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

// InstallSignals registers OS signal handlers for the gateway lifecycle:
//
//   - SIGHUP  → calls reload() synchronously on a dedicated goroutine.
//     If reload returns an error it is logged; the gateway continues on the
//     current policy.
//   - SIGTERM / SIGINT → calls drain() (which should block until in-flight
//     requests complete or a timeout fires) then closes the returned done
//     channel so main() can proceed to shutdown cleanup.
//
// The returned channel is closed once drain() has returned, signaling to the
// caller that it is safe to close the audit writer and exit.
// The returned signaled pointer is set to 1 before drain() is called, so that
// main() can distinguish a signal-driven exit from a natural stdin-EOF exit.
func InstallSignals(reload func(), drain func()) (<-chan struct{}, *atomic.Bool) {
	done := make(chan struct{})
	var signaled atomic.Bool

	sigReload := make(chan os.Signal, 1)
	signal.Notify(sigReload, syscall.SIGHUP)

	sigStop := make(chan os.Signal, 1)
	signal.Notify(sigStop, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		for {
			select {
			case <-sigReload:
				slog.Info("received SIGHUP, reloading policy")
				reload()

			case sig := <-sigStop:
				slog.Info("received signal, draining in-flight requests", "signal", sig.String())
				signaled.Store(true)
				drain()
				close(done)
				return
			}
		}
	}()

	return done, &signaled
}
