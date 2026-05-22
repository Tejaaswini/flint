package main

import (
	"log/slog"
	"os"
)

// initLogger sets the global slog default to a structured JSON handler writing
// to stderr at Info level. All router code uses slog.Info/Warn/Error so that
// every log line is machine-parseable by the control plane or external tooling.
func initLogger() {
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(handler))
}
