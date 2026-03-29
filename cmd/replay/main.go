// Flint — session firewall for MCP-connected agents
// Build: go build -o flint-replay ./cmd/replay
// Run:   ./flint-replay              (embedded traces)
//        ./flint-replay trace.json   (external trace)
package main

import (
	"fmt"
	"os"
	"sort"

	"flint/engine"
	"flint/engine/session"
	"flint/pkg/trace"
)

func loadRegistry() map[string]session.ToolMeta {
	registry, err := session.LoadRegistry("tools.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not load tools.yaml (%v), using built-in defaults\n", err)
		return nil
	}
	fmt.Fprintf(os.Stderr, "loaded %d tools from tools.yaml\n", len(registry))
	return registry
}

func main() {
	registry := loadRegistry()

	var traces []trace.TraceFile

	if len(os.Args) > 1 {
		arg := os.Args[1]
		info, err := os.Stat(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if info.IsDir() {
			traces, err = trace.LoadDir(arg)
		} else {
			var tf trace.TraceFile
			tf, err = trace.Load(arg)
			traces = append(traces, tf)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	} else {
		traces = append(traces, supabaseTrace(), benignTrace())
	}

	exitCode := 0
	for _, t := range traces {
		eng := engine.New(t.SessionID, registry)

		sort.Slice(t.Events, func(i, j int) bool {
			return t.Events[i].EventSeq < t.Events[j].EventSeq
		})

		for _, evt := range t.Events {
			eng.ProcessEvent(evt)
		}

		printReport(eng, t)

		if eng.Session.Disposition == "terminate" || eng.Session.Disposition == "pause" {
			exitCode = 1
		}
	}

	os.Exit(exitCode)
}

func printReport(eng *engine.Engine, t trace.TraceFile) {
	s := eng.Session
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("  FLINT SESSION REPORT: %s\n", t.Name)
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("  Session:     %s\n", s.SessionID)
	fmt.Printf("  Events:      %d\n", len(s.Events))
	fmt.Printf("  Edges:       %d\n", len(s.Edges))
	fmt.Printf("  Findings:    %d\n", len(s.Findings))
	fmt.Printf("  Risk Score:  %.0f\n", s.RiskScore)
	fmt.Printf("  Disposition: %s\n", s.Disposition)
	fmt.Println("───────────────────────────────────────────────────────────")

	fmt.Println("\n  EVENT TIMELINE")
	fmt.Println("  ─────────────")
	for _, e := range s.Events {
		d := "→"
		if e.Direction == "response" {
			d = "←"
		}
		fmt.Printf("  [%d] %s %s %-30s class=%-10s tags=%v\n",
			e.EventSeq, d, e.Direction, e.ToolName, e.PayloadClass, e.ToolTags)
	}

	if len(s.Edges) > 0 {
		fmt.Println("\n  DATA LINEAGE EDGES")
		fmt.Println("  ──────────────────")
		for _, e := range s.Edges {
			fmt.Printf("  event %d → event %d  [%s]  confidence=%.2f  keys=%v\n",
				e.SrcEventSeq, e.DstEventSeq, e.EdgeType, e.Confidence, e.MatchedKeys)
		}
	}

	if len(s.Findings) > 0 {
		fmt.Println("\n  ⚠ FINDINGS")
		fmt.Println("  ──────────")
		for _, f := range s.Findings {
			icon := "⚠"
			if f.Severity == "critical" {
				icon = "🚨"
			}
			fmt.Printf("  %s [%s] severity=%s confidence=%.2f action=%s score=+%.0f\n",
				icon, f.RuleID, f.Severity, f.Confidence, f.Action, f.Score)
			fmt.Printf("     %s\n", f.Message)
			if f.SrcEventSeq > 0 {
				fmt.Printf("     chain: event %d → event %d\n", f.SrcEventSeq, f.TriggerEventSeq)
			}
		}
	} else {
		fmt.Println("\n  ✓ No findings. Session looks clean.")
	}

	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────")
	switch s.Disposition {
	case "terminate":
		fmt.Println("  🛑 SESSION TERMINATED — behavioral chain detected")
	case "pause":
		fmt.Println("  ⏸  SESSION PAUSED — awaiting operator review")
	case "warn":
		fmt.Println("  ⚠  SESSION WARNING — suspicious patterns detected")
	default:
		fmt.Println("  ✅ SESSION ALLOWED — no actionable findings")
	}
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()
}
