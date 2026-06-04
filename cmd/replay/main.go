// Flint — session firewall for MCP-connected agents
// Build: go build -o flint-replay ./cmd/replay
// Run:   ./flint-replay                                   (embedded traces)
//
//	./flint-replay trace.json                          (single external trace)
//	./flint-replay traces/                             (directory of traces)
//	./flint-replay --corpus corpus/                    (scored corpus mode)
//	./flint-replay --corpus corpus/ --min-precision 0.95 --min-recall 0.80
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"flint/engine"
	"flint/engine/authz"
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

func loadPolicy(registry map[string]session.ToolMeta) *authz.Policy {
	return loadPolicyFrom("config/roles.yaml", "config/bindings.yaml", registry)
}

func loadCorpusPolicy(registry map[string]session.ToolMeta, rolesOverride, bindingsOverride string) *authz.Policy {
	roles := "config/roles.corpus.yaml"
	bindings := "config/bindings.corpus.yaml"
	if rolesOverride != "" {
		roles = rolesOverride
	}
	if bindingsOverride != "" {
		bindings = bindingsOverride
	}
	return loadPolicyFrom(roles, bindings, registry)
}

func loadPolicyFrom(rolesPath, bindingsPath string, registry map[string]session.ToolMeta) *authz.Policy {
	policy, err := authz.LoadPolicy(rolesPath, bindingsPath, registry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not load RBAC policy from %s + %s (%v), running in passthrough mode\n", rolesPath, bindingsPath, err)
		return nil
	}
	fmt.Fprintf(os.Stderr, "loaded RBAC policy: %d roles, %d bindings (from %s + %s)\n", len(policy.Roles), len(policy.Bindings), rolesPath, bindingsPath)
	return policy
}

func main() {
	// ── Corpus flags ────────────────────────────────────────────────────────
	corpusDir := flag.String("corpus", "", "path to a corpus directory with *.json + *.labels.json pairs")
	minPrecision := flag.Float64("min-precision", 0.95, "minimum per-rule precision threshold (corpus mode only)")
	minRecall := flag.Float64("min-recall", 0.80, "minimum per-rule recall threshold (corpus mode only)")
	perRule := flag.Bool("per-rule", false, "print per-rule precision/recall table (corpus mode only)")
	jsonReportPath := flag.String("json-report", "", "write machine-readable JSON report to this path (corpus mode only)")
	// Policy override flags (corpus mode defaults to config/roles.corpus.yaml + config/bindings.corpus.yaml)
	rolesPath := flag.String("roles", "", "override roles YAML path (corpus mode: defaults to config/roles.corpus.yaml)")
	bindingsPath := flag.String("bindings", "", "override bindings YAML path (corpus mode: defaults to config/bindings.corpus.yaml)")

	flag.Parse()
	args := flag.Args()

	registry := loadRegistry()

	// ── Corpus mode ─────────────────────────────────────────────────────────
	if *corpusDir != "" {
		policy := loadCorpusPolicy(registry, *rolesPath, *bindingsPath)
		runCorpusMode(registry, policy, *corpusDir, *minPrecision, *minRecall, *perRule, *jsonReportPath)
		return
	}

	policy := loadPolicy(registry)

	// ── Legacy mode (unchanged) ──────────────────────────────────────────────
	var traces []trace.TraceFile

	if len(args) > 0 {
		arg := args[0]
		info, err := os.Stat(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		var loadErr error
		if info.IsDir() {
			traces, loadErr = trace.LoadDir(arg)
		} else {
			var tf trace.TraceFile
			tf, loadErr = trace.Load(arg)
			traces = append(traces, tf)
		}
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", loadErr)
			os.Exit(1)
		}
	} else {
		traces = append(traces, supabaseTrace(), benignTrace())
	}

	exitCode := 0
	for _, t := range traces {
		eng := engine.NewWithPolicy(t.SessionID, registry, policy)

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

// corpusReport is the machine-readable JSON report written by --json-report.
type corpusReport struct {
	TotalSessions     int             `json:"total_sessions"`
	SessionsMatched   int             `json:"sessions_matched"`
	GlobalTP          int             `json:"global_tp"`
	GlobalFP          int             `json:"global_fp"`
	GlobalFN          int             `json:"global_fn"`
	GlobalPrecision   float64         `json:"global_precision"`
	GlobalRecall      float64         `json:"global_recall"`
	PerRule           []RuleMetrics   `json:"per_rule,omitempty"`
	SessionResults    []sessionResult `json:"session_results"`
}

type sessionResult struct {
	TraceName      string        `json:"trace_name"`
	LabeledClass   string        `json:"labeled_class"`
	PredictedClass string        `json:"predicted_class"`
	Disposition    string        `json:"disposition"`
	Expected       string        `json:"expected_disposition"`
	Matched        bool          `json:"session_matched"`
	PerRule        []RuleMetrics `json:"per_rule,omitempty"`
}

func runCorpusMode(
	registry map[string]session.ToolMeta,
	policy *authz.Policy,
	dir string,
	minPrec, minRec float64,
	showPerRule bool,
	reportPath string,
) {
	corpus, _, err := trace.LoadCorpus(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading corpus: %v\n", err)
		os.Exit(1)
	}

	if len(corpus) == 0 {
		fmt.Fprintf(os.Stderr, "error: no corpus entries found in %s\n", dir)
		os.Exit(1)
	}

	// Global accumulators keyed by ruleID
	globalTP := make(map[string]int)
	globalFP := make(map[string]int)
	globalFN := make(map[string]int)
	sessionsMatched := 0

	report := corpusReport{}
	report.TotalSessions = len(corpus)

	for _, entry := range corpus {
		eng := engine.NewWithPolicy(entry.Trace.SessionID, registry, policy)

		events := entry.Trace.Events
		sort.Slice(events, func(i, j int) bool {
			return events[i].EventSeq < events[j].EventSeq
		})
		for _, evt := range events {
			eng.ProcessEvent(evt)
		}

		scoreOut := Score(ScoreInput{
			Trace:   entry.Trace,
			Labels:  entry.Labels,
			Actual:  eng.Session.Findings,
			Session: eng.Session,
		})

		if scoreOut.SessionMatched {
			sessionsMatched++
		}

		for _, m := range scoreOut.PerRule {
			globalTP[m.RuleID] += m.TP
			globalFP[m.RuleID] += m.FP
			globalFN[m.RuleID] += m.FN
		}

		sr := sessionResult{
			TraceName:      entry.Trace.Name,
			LabeledClass:   scoreOut.LabeledClass,
			PredictedClass: scoreOut.PredictedClass,
			Disposition:    eng.Session.Disposition,
			Expected:       entry.Labels.Session.ExpectedDisposition,
			Matched:        scoreOut.SessionMatched,
		}
		if showPerRule {
			sr.PerRule = scoreOut.PerRule
		}
		report.SessionResults = append(report.SessionResults, sr)
	}

	report.SessionsMatched = sessionsMatched

	// Aggregate per-rule metrics across all sessions
	var aggregatePerRule []RuleMetrics
	failedRules := []string{}
	for ruleID := range globalTP {
		tp, fp, fn := globalTP[ruleID], globalFP[ruleID], globalFN[ruleID]
		prec, rec := 1.0, 1.0
		if tp+fp > 0 {
			prec = float64(tp) / float64(tp+fp)
		}
		if tp+fn > 0 {
			rec = float64(tp) / float64(tp+fn)
		}
		f1 := 0.0
		if prec+rec > 0 {
			f1 = 2 * prec * rec / (prec + rec)
		}
		m := RuleMetrics{RuleID: ruleID, TP: tp, FP: fp, FN: fn, Precision: prec, Recall: rec, F1: f1}
		aggregatePerRule = append(aggregatePerRule, m)
		report.GlobalTP += tp
		report.GlobalFP += fp
		report.GlobalFN += fn
		if prec < minPrec || rec < minRec {
			failedRules = append(failedRules, ruleID)
		}
	}
	// Also collect rules that only appeared in FP entries
	for ruleID := range globalFP {
		if _, ok := globalTP[ruleID]; !ok {
			fp := globalFP[ruleID]
			m := RuleMetrics{RuleID: ruleID, FP: fp, Precision: 0.0, Recall: 1.0}
			aggregatePerRule = append(aggregatePerRule, m)
			report.GlobalFP += fp
			if 0.0 < minPrec {
				failedRules = append(failedRules, ruleID)
			}
		}
	}

	if report.GlobalTP+report.GlobalFP > 0 {
		report.GlobalPrecision = float64(report.GlobalTP) / float64(report.GlobalTP+report.GlobalFP)
	} else {
		report.GlobalPrecision = 1.0
	}
	if report.GlobalTP+report.GlobalFN > 0 {
		report.GlobalRecall = float64(report.GlobalTP) / float64(report.GlobalTP+report.GlobalFN)
	} else {
		report.GlobalRecall = 1.0
	}
	if showPerRule {
		report.PerRule = aggregatePerRule
	}

	// Print summary
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("  FLINT CORPUS SCORE REPORT")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("  Corpus:          %s\n", dir)
	fmt.Printf("  Sessions:        %d total, %d matched expected disposition\n",
		report.TotalSessions, report.SessionsMatched)
	fmt.Printf("  Global TP/FP/FN: %d / %d / %d\n", report.GlobalTP, report.GlobalFP, report.GlobalFN)
	fmt.Printf("  Global precision: %.3f   recall: %.3f\n", report.GlobalPrecision, report.GlobalRecall)
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Println("  SESSION RESULTS")
	for _, sr := range report.SessionResults {
		icon := "✓"
		if !sr.Matched {
			icon = "✗"
		}
		fmt.Printf("  %s %-40s class=%-20s disp=%s\n",
			icon, sr.TraceName, sr.LabeledClass, sr.Disposition)
	}
	if showPerRule && len(aggregatePerRule) > 0 {
		fmt.Println("───────────────────────────────────────────────────────────")
		fmt.Println("  PER-RULE METRICS")
		fmt.Printf("  %-35s  %5s  %5s  %5s  %8s  %8s  %6s\n",
			"Rule", "TP", "FP", "FN", "Precision", "Recall", "F1")
		for _, m := range aggregatePerRule {
			fmt.Printf("  %-35s  %5d  %5d  %5d  %8.3f  %8.3f  %6.3f\n",
				m.RuleID, m.TP, m.FP, m.FN, m.Precision, m.Recall, m.F1)
		}
	}
	if len(failedRules) > 0 {
		fmt.Println("───────────────────────────────────────────────────────────")
		fmt.Printf("  THRESHOLD FAILURES (min_precision=%.2f, min_recall=%.2f)\n", minPrec, minRec)
		for _, r := range failedRules {
			fmt.Printf("  ✗ %s\n", r)
		}
	}
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()

	// JSON report
	if reportPath != "" {
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error marshaling JSON report: %v\n", err)
		} else {
			if err := os.WriteFile(reportPath, b, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "error writing JSON report to %s: %v\n", reportPath, err)
			} else {
				fmt.Fprintf(os.Stderr, "JSON report written to %s\n", reportPath)
			}
		}
	}

	// Exit with non-zero if thresholds fail
	if len(failedRules) > 0 || sessionsMatched != report.TotalSessions {
		os.Exit(1)
	}
}

func printReport(eng *engine.Engine, t trace.TraceFile) {
	s := eng.Session

	allowed, denied := 0, 0
	for _, d := range s.PolicyDecisions {
		if d.Allowed {
			allowed++
		} else {
			denied++
		}
	}

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

	if len(s.PolicyDecisions) > 0 {
		fmt.Println("\n  RBAC DECISIONS")
		fmt.Println("  ──────────────")
		fmt.Printf("  allowed: %d   denied: %d\n\n", allowed, denied)
		for _, d := range s.PolicyDecisions {
			icon := "✓"
			detail := fmt.Sprintf("role=%s verb=%s", d.MatchedRole, d.GrantedVerb)
			if !d.Allowed {
				icon = "✗"
				detail = fmt.Sprintf("reason=%s", d.Reason)
				if d.Constraint != "" {
					detail += fmt.Sprintf(" constraint=%s", d.Constraint)
				}
			}
			fmt.Printf("  %s  agent=%-14s  tool=%-28s  %s\n",
				icon, d.AgentID, d.ToolName, detail)
		}
		fmt.Println()
	}

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
