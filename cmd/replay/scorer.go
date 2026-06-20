package main

import (
	"flint/engine/session"
	"flint/pkg/trace"
)

// RuleMetrics holds per-rule precision/recall/F1 numbers computed by Score.
type RuleMetrics struct {
	RuleID     string
	TP, FP, FN int
	Precision  float64
	Recall     float64
	F1         float64
}

// ScoreInput is the input to the Score function.
type ScoreInput struct {
	Trace   trace.TraceFile
	Labels  trace.LabelsFile
	Actual  []session.Finding // all findings emitted by the engine for this session
	Session *session.SessionState
}

// ScoreOutput is the output from the Score function.
type ScoreOutput struct {
	PerRule        []RuleMetrics
	SessionMatched bool   // expected_disposition == actual disposition
	PredictedClass string // mapped from highest-severity rule fired
	LabeledClass   string
}

// Score computes per-rule precision/recall/F1 for a single corpus entry.
//
// Matching logic:
//
//   - For each event in labels with expected_findings[*].must_fire=true for rule X:
//     that is an expected positive (P). If actual findings contain a finding with
//     rule_id=X and trigger_event_seq matching, that's a TP; otherwise FN.
//
//   - For each event in labels with must_fire=false for rule X:
//     that's a negative guard. If actual findings contain rule X for that event, that's FP.
//
//   - Actual findings for rule X on an event with NO label entry for rule X:
//     counted as FP only if session-level expected_rules_silent contains X.
//     Otherwise they are unscored ("unlabeled") — not penalised, just logged.
func Score(in ScoreInput) ScoreOutput {
	// Build lookup: eventSeq -> []ExpectedFinding
	eventExpected := make(map[int64][]trace.ExpectedFinding)
	for _, el := range in.Labels.Events {
		eventExpected[el.EventSeq] = append(eventExpected[el.EventSeq], el.ExpectedFindings...)
	}

	// Build silent rule set for session-level FP guards
	silentRules := make(map[string]bool)
	for _, r := range in.Labels.Session.ExpectedRulesSilent {
		silentRules[r] = true
	}

	// Collect all rule IDs mentioned in labels (for initialising metrics)
	ruleIDsInLabels := make(map[string]bool)
	for _, el := range in.Labels.Events {
		for _, ef := range el.ExpectedFindings {
			ruleIDsInLabels[ef.RuleID] = true
		}
	}
	for _, r := range in.Labels.Session.ExpectedRulesSilent {
		ruleIDsInLabels[r] = true
	}

	// TP/FP/FN counters
	tp := make(map[string]int)
	fp := make(map[string]int)
	fn := make(map[string]int)

	// Count TPs and FNs from expected positives
	for _, el := range in.Labels.Events {
		for _, ef := range el.ExpectedFindings {
			if ef.MustFire {
				// Expected positive: look for a matching actual finding
				found := false
				for _, af := range in.Actual {
					if af.RuleID == ef.RuleID && af.TriggerEventSeq == el.EventSeq {
						found = true
						break
					}
				}
				if found {
					tp[ef.RuleID]++
				} else {
					fn[ef.RuleID]++
				}
			}
		}
	}

	// Count FPs from expected negatives (must_fire: false) and from silent rules
	for _, af := range in.Actual {
		expectedList, hasLabel := eventExpected[af.TriggerEventSeq]

		// Check if there's a negative expectation for this rule+event
		negativeGuard := false
		hasPositiveGuard := false
		if hasLabel {
			for _, ef := range expectedList {
				if ef.RuleID == af.RuleID {
					if !ef.MustFire {
						negativeGuard = true
					} else {
						hasPositiveGuard = true
					}
				}
			}
		}

		if negativeGuard {
			fp[af.RuleID]++
		} else if !hasPositiveGuard && silentRules[af.RuleID] {
			// Session-level silent rule fired — treat as FP
			fp[af.RuleID]++
		}
		// Otherwise: no label for this event+rule — unscored, not penalised
	}

	// Build per-rule metrics
	metricsMap := make(map[string]*RuleMetrics)
	for ruleID := range ruleIDsInLabels {
		metricsMap[ruleID] = &RuleMetrics{RuleID: ruleID}
	}
	// Also create entries for any rule that got an FP
	for ruleID := range fp {
		if _, ok := metricsMap[ruleID]; !ok {
			metricsMap[ruleID] = &RuleMetrics{RuleID: ruleID}
		}
	}

	var perRule []RuleMetrics
	for ruleID, m := range metricsMap {
		m.TP = tp[ruleID]
		m.FP = fp[ruleID]
		m.FN = fn[ruleID]

		if m.TP+m.FP > 0 {
			m.Precision = float64(m.TP) / float64(m.TP+m.FP)
		} else {
			m.Precision = 1.0 // no predictions made — no FPs — precision undefined; treat as 1.0
		}
		if m.TP+m.FN > 0 {
			m.Recall = float64(m.TP) / float64(m.TP+m.FN)
		} else {
			m.Recall = 1.0 // no positives in labels — recall undefined; treat as 1.0
		}
		if m.Precision+m.Recall > 0 {
			m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
		}
		perRule = append(perRule, *m)
	}

	// Session match
	actualDisp := ""
	if in.Session != nil {
		actualDisp = in.Session.Disposition
	}
	sessionMatched := actualDisp == in.Labels.Session.ExpectedDisposition

	// Predicted class: map from highest-severity finding
	predictedClass := "benign"
	severityOrder := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	best := 0
	for _, f := range in.Actual {
		if ord := severityOrder[f.Severity]; ord > best {
			best = ord
			switch f.RuleID {
			case "credential_exposure", "secret_relay":
				predictedClass = "credential_exfil"
			case "tool_poisoning_indicator":
				predictedClass = "prompt_poisoning"
			case "filesystem_traversal_sequence":
				predictedClass = "filesystem_traversal"
			case "cross_scope_data_movement":
				predictedClass = "cross_scope_leak"
			case "pagination_exfiltration":
				predictedClass = "pagination_exfil"
			default:
				predictedClass = "unknown"
			}
		}
	}

	return ScoreOutput{
		PerRule:        perRule,
		SessionMatched: sessionMatched,
		PredictedClass: predictedClass,
		LabeledClass:   in.Labels.Session.AttackClass,
	}
}
