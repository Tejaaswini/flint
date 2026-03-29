package rules

import (
	"fmt"
	"regexp"
	"strings"

	"flint/engine/session"
)

// ─── Rule: secret_relay ─────────────────────────────────────────────────────

func EvalSecretRelay(s *session.SessionState, evt *session.SessionEvent) []session.Finding {
	var out []session.Finding
	if evt.Direction != "request" || !hasTag(evt.ToolTags, "external_write", "network_egress") {
		return out
	}
	for _, edge := range s.Edges {
		if edge.DstEventSeq != evt.EventSeq || edge.EdgeType != "exact_token_match" {
			continue
		}
		src := findEvt(s, edge.SrcEventSeq)
		if src == nil || src.Direction != "response" {
			continue
		}
		if src.PayloadClass != "restricted" && !hasTag(src.ToolTags, "restricted") {
			continue
		}
		out = append(out, session.Finding{
			RuleID:     "secret_relay",
			Severity:   "critical",
			Confidence: edge.Confidence,
			Message: fmt.Sprintf(
				"Secret relay: token from restricted response (event %d, tool %s) relayed to egress tool %s",
				edge.SrcEventSeq, src.ToolName, evt.ToolName),
			TriggerEventSeq: evt.EventSeq,
			SrcEventSeq:     edge.SrcEventSeq,
			Action:          "terminate",
			Score:           90,
			MatchedEdges:    []session.SessionEdge{edge},
		})
	}
	return out
}

// ─── Rule: restricted_read_external_write ───────────────────────────────────

func EvalRestrictedWrite(s *session.SessionState, evt *session.SessionEvent) []session.Finding {
	var out []session.Finding
	if evt.Direction != "request" || !hasTag(evt.ToolTags, "external_write", "network_egress") {
		return out
	}
	for _, edge := range s.Edges {
		if edge.DstEventSeq != evt.EventSeq || edge.Confidence < 0.7 {
			continue
		}
		src := findEvt(s, edge.SrcEventSeq)
		if src == nil || src.Direction != "response" {
			continue
		}
		if src.PayloadClass != "restricted" && !hasTag(src.ToolTags, "restricted") {
			continue
		}
		if alreadyCaughtBy(s, evt.EventSeq, edge.SrcEventSeq, "secret_relay") {
			continue
		}
		out = append(out, session.Finding{
			RuleID:     "restricted_read_external_write",
			Severity:   "critical",
			Confidence: edge.Confidence,
			Message: fmt.Sprintf(
				"Restricted data (event %d, tool %s) flowing to external write %s via %s",
				edge.SrcEventSeq, src.ToolName, evt.ToolName, edge.EdgeType),
			TriggerEventSeq: evt.EventSeq,
			SrcEventSeq:     edge.SrcEventSeq,
			Action:          "pause",
			Score:           80,
			MatchedEdges:    []session.SessionEdge{edge},
		})
	}
	return out
}

// ─── Rule: pagination_exfiltration ──────────────────────────────────────────

func EvalPagination(s *session.SessionState, evt *session.SessionEvent) []session.Finding {
	var out []session.Finding
	if evt.Direction != "request" || !hasTag(evt.ToolTags, "data_source") {
		return out
	}

	var same []session.SessionEvent
	for _, e := range s.Events {
		if e.Direction == "request" && e.ToolName == evt.ToolName {
			same = append(same, e)
		}
	}
	if len(same) < 3 {
		return out
	}

	for _, field := range []string{"offset", "page", "skip", "cursor", "start", "from"} {
		var vals []float64
		for _, r := range same {
			if r.Payload != nil {
				if v, ok := r.Payload[field]; ok {
					if n, ok := v.(float64); ok {
						vals = append(vals, n)
					}
				}
			}
		}
		if len(vals) >= 3 && isMono(vals) {
			out = append(out, session.Finding{
				RuleID:     "pagination_exfiltration",
				Severity:   "high",
				Confidence: 0.85,
				Message: fmt.Sprintf(
					"Pagination exfiltration: %d calls to %s with increasing %s (%v)",
					len(vals), evt.ToolName, field, vals),
				TriggerEventSeq: evt.EventSeq,
				Action:          "warn",
				Score:           50,
			})
		}
	}
	return out
}

// ─── Rule: tool_poisoning_indicator ─────────────────────────────────────────
//
// Fires when a response from an external_data tool contains text patterns
// that look like instruction injection — content trying to hijack the agent.

var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context|rules?)`),
	regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|context)`),
	regexp.MustCompile(`(?i)you\s+(are\s+now|must\s+now|should\s+now|will\s+now)\s+in`),
	regexp.MustCompile(`(?i)(new\s+)?system\s*(prompt|instructions?)\s*:`),
	regexp.MustCompile(`(?i)<\s*/?(system|s)\s*>|\[system\]|\[inst\]`),
	regexp.MustCompile(`(?i)(please\s+)?(run|execute|call|invoke)\s+(this|the\s+following|these)\s+(query|command|code|script|sql|tool)`),
	regexp.MustCompile(`(?i)(send|post|forward|exfiltrate|transmit)\s+(it|them|the\s+(results?|data|contents?|output))\s+(to|via|through|using)`),
	regexp.MustCompile(`(?i)as\s+your\s+(new\s+)?(instructions?|task|objective|goal)`),
	regexp.MustCompile(`(?i)from\s+now\s+on\s+(you\s+)?(must|will|should)`),
}

func EvalToolPoisoning(s *session.SessionState, evt *session.SessionEvent) []session.Finding {
	if evt.Direction != "response" || !hasTag(evt.ToolTags, "external_data") {
		return nil
	}
	for _, text := range collectStrings(evt.Payload) {
		for _, pat := range injectionPatterns {
			if m := pat.FindString(text); m != "" {
				snippet := m
				if len(snippet) > 60 {
					snippet = snippet[:60]
				}
				return []session.Finding{{
					RuleID:          "tool_poisoning_indicator",
					Severity:        "high",
					Confidence:      0.85,
					Message:         fmt.Sprintf("Instruction injection in %s response (event %d): %q", evt.ToolName, evt.EventSeq, snippet),
					TriggerEventSeq: evt.EventSeq,
					Action:          "warn",
					Score:           60,
				}}
			}
		}
	}
	return nil
}

// ─── Rule: filesystem_traversal_sequence ────────────────────────────────────
//
// Sync: fires immediately on sensitive path access or ../ traversal in a request.
// Async: fires when 3+ filesystem reads show strictly decreasing path depth.

var sensitivePathRE = regexp.MustCompile(
	`(?i)(` +
		`\.ssh/|` +
		`\.gnupg/|` +
		`\.aws/credentials|` +
		`\.netrc|` +
		`\.npmrc|` +
		`/etc/passwd|/etc/shadow|/etc/sudoers|` +
		`id_rsa|id_ed25519|id_ecdsa|` +
		`\.pem$|\.p12$|\.pfx$|` +
		`/\.env$|/\.env\.|` +
		`\.git/config|` +
		`credentials\.json|service_account\.json` +
		`)`)

var traversalRE = regexp.MustCompile(`\.\.[/\\]`)

func EvalFilesystemTraversal(s *session.SessionState, evt *session.SessionEvent) []session.Finding {
	if evt.Direction != "request" || !hasTag(evt.ToolTags, "filesystem") {
		return nil
	}

	path := extractPath(evt)
	if path == "" {
		return nil
	}

	// Sync: direct sensitive path access — highest priority
	if sensitivePathRE.MatchString(path) {
		return []session.Finding{{
			RuleID:          "filesystem_traversal_sequence",
			Severity:        "high",
			Confidence:      0.95,
			Message:         fmt.Sprintf("Sensitive path access: %s at event %d", path, evt.EventSeq),
			TriggerEventSeq: evt.EventSeq,
			Action:          "pause",
			Score:           70,
		}}
	}

	// Sync: explicit traversal sequence in path
	if traversalRE.MatchString(path) {
		return []session.Finding{{
			RuleID:          "filesystem_traversal_sequence",
			Severity:        "high",
			Confidence:      0.80,
			Message:         fmt.Sprintf("Path traversal detected: %s at event %d", path, evt.EventSeq),
			TriggerEventSeq: evt.EventSeq,
			Action:          "warn",
			Score:           50,
		}}
	}

	// Async: 3+ filesystem requests with strictly decreasing path depth
	var depths []int
	for _, e := range s.Events {
		if e.Direction == "request" && hasTag(e.ToolTags, "filesystem") {
			if p := extractPath(&e); p != "" {
				depths = append(depths, strings.Count(p, "/"))
			}
		}
	}
	if len(depths) >= 3 && isDecreasing(depths) {
		return []session.Finding{{
			RuleID:          "filesystem_traversal_sequence",
			Severity:        "high",
			Confidence:      0.75,
			Message:         fmt.Sprintf("Filesystem traversal sequence: %d reads with decreasing path depth ending at %s", len(depths), path),
			TriggerEventSeq: evt.EventSeq,
			Action:          "warn",
			Score:           40,
		}}
	}

	return nil
}

// ─── Rule: cross_scope_data_movement ────────────────────────────────────────
//
// Fires when data from a restricted-tagged source appears in a request to any
// tool that is NOT an egress channel (egress is already covered by
// restricted_read_external_write). Catches lateral data movement that doesn't
// immediately leave the system — e.g. restricted CRM data used in a code search.

func EvalCrossScopeMovement(s *session.SessionState, evt *session.SessionEvent) []session.Finding {
	var out []session.Finding
	if evt.Direction != "request" {
		return out
	}
	// Egress flows are already handled by restricted_read_external_write
	if hasTag(evt.ToolTags, "external_write", "network_egress") {
		return out
	}
	for _, edge := range s.Edges {
		if edge.DstEventSeq != evt.EventSeq || edge.Confidence < 0.7 {
			continue
		}
		src := findEvt(s, edge.SrcEventSeq)
		if src == nil || src.Direction != "response" {
			continue
		}
		if !hasTag(src.ToolTags, "restricted") {
			continue
		}
		if alreadyCaughtBy(s, evt.EventSeq, edge.SrcEventSeq, "secret_relay", "restricted_read_external_write") {
			continue
		}
		out = append(out, session.Finding{
			RuleID:     "cross_scope_data_movement",
			Severity:   "high",
			Confidence: edge.Confidence,
			Message: fmt.Sprintf(
				"Cross-scope movement: restricted data from %s (event %d) used in %s request via %s",
				src.ToolName, src.EventSeq, evt.ToolName, edge.EdgeType),
			TriggerEventSeq: evt.EventSeq,
			SrcEventSeq:     edge.SrcEventSeq,
			Action:          "warn",
			Score:           40,
			MatchedEdges:    []session.SessionEdge{edge},
		})
	}
	return out
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func hasTag(tags []string, want ...string) bool {
	for _, w := range want {
		for _, t := range tags {
			if t == w {
				return true
			}
		}
	}
	return false
}

func findEvt(s *session.SessionState, seq int64) *session.SessionEvent {
	for i := range s.Events {
		if s.Events[i].EventSeq == seq {
			return &s.Events[i]
		}
	}
	return nil
}

func isMono(v []float64) bool {
	for i := 1; i < len(v); i++ {
		if v[i] <= v[i-1] {
			return false
		}
	}
	return true
}

func isDecreasing(v []int) bool {
	for i := 1; i < len(v); i++ {
		if v[i] >= v[i-1] {
			return false
		}
	}
	return true
}

// alreadyCaughtBy returns true if a finding with the given trigger+src pair
// already exists for any of the named rules. Used to suppress lower-priority
// rules when a more specific one already fired on the same event pair.
func alreadyCaughtBy(s *session.SessionState, triggerSeq, srcSeq int64, ruleIDs ...string) bool {
	for _, f := range s.Findings {
		if f.TriggerEventSeq != triggerSeq || f.SrcEventSeq != srcSeq {
			continue
		}
		for _, id := range ruleIDs {
			if f.RuleID == id {
				return true
			}
		}
	}
	return false
}

// collectStrings returns all leaf string values from a payload, used by
// tool_poisoning_indicator to scan for injection patterns across any field.
func collectStrings(obj any) []string {
	var out []string
	switch v := obj.(type) {
	case map[string]any:
		for _, val := range v {
			out = append(out, collectStrings(val)...)
		}
	case []any:
		for _, val := range v {
			out = append(out, collectStrings(val)...)
		}
	case string:
		out = append(out, v)
	}
	return out
}

// extractPath pulls the file path from a filesystem tool's request payload.
func extractPath(evt *session.SessionEvent) string {
	if evt.Payload == nil {
		return ""
	}
	for _, key := range []string{"path", "file", "filename", "filepath", "file_path"} {
		if v, ok := evt.Payload[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}
