package main

import (
	"testing"

	"flint/engine/session"
	"flint/pkg/trace"
)

func makeLabels(attackClass, expectedDisp string, events []trace.EventLabels) trace.LabelsFile {
	return trace.LabelsFile{
		SchemaVersion: 1,
		TraceName:     "test_trace",
		SessionID:     "test_sess",
		Session: trace.SessionLabels{
			AttackClass:         attackClass,
			ExpectedDisposition: expectedDisp,
		},
		Events: events,
	}
}

func finding(ruleID string, evtSeq int64) session.Finding {
	return session.Finding{
		RuleID:          ruleID,
		TriggerEventSeq: evtSeq,
		Severity:        "high",
	}
}

// TestScore_AllTP verifies that when all expected-positive events have matching
// actual findings, precision=1.0, recall=1.0, F1=1.0.
func TestScore_AllTP(t *testing.T) {
	labels := makeLabels("credential_exfil", "terminate", []trace.EventLabels{
		{
			EventSeq: 4,
			ExpectedFindings: []trace.ExpectedFinding{
				{RuleID: "credential_exposure", MustFire: true},
			},
		},
		{
			EventSeq: 5,
			ExpectedFindings: []trace.ExpectedFinding{
				{RuleID: "secret_relay", MustFire: true},
			},
		},
	})

	actual := []session.Finding{
		finding("credential_exposure", 4),
		finding("secret_relay", 5),
	}

	sess := &session.SessionState{Disposition: "terminate"}
	out := Score(ScoreInput{Labels: labels, Actual: actual, Session: sess})

	for _, m := range out.PerRule {
		if m.Precision != 1.0 {
			t.Errorf("rule %s precision: want 1.0, got %f", m.RuleID, m.Precision)
		}
		if m.Recall != 1.0 {
			t.Errorf("rule %s recall: want 1.0, got %f", m.RuleID, m.Recall)
		}
	}
	if !out.SessionMatched {
		t.Error("session should match: expected terminate, got terminate")
	}
}

// TestScore_FN verifies that a missing expected finding produces FN and recall < 1.
func TestScore_FN(t *testing.T) {
	labels := makeLabels("credential_exfil", "terminate", []trace.EventLabels{
		{
			EventSeq: 4,
			ExpectedFindings: []trace.ExpectedFinding{
				{RuleID: "credential_exposure", MustFire: true},
			},
		},
	})

	// No actual finding for event 4 — FN
	actual := []session.Finding{}
	sess := &session.SessionState{Disposition: "warn"}
	out := Score(ScoreInput{Labels: labels, Actual: actual, Session: sess})

	found := false
	for _, m := range out.PerRule {
		if m.RuleID == "credential_exposure" {
			found = true
			if m.FN != 1 {
				t.Errorf("FN: want 1, got %d", m.FN)
			}
			if m.Recall != 0.0 {
				t.Errorf("recall: want 0.0, got %f", m.Recall)
			}
		}
	}
	if !found {
		t.Error("credential_exposure rule not found in PerRule output")
	}

	if out.SessionMatched {
		t.Error("session should NOT match: expected terminate, got warn")
	}
}

// TestScore_FP verifies that a must_fire:false guard with a firing rule counts as FP.
func TestScore_FP(t *testing.T) {
	labels := makeLabels("benign", "allow", []trace.EventLabels{
		{
			EventSeq: 2,
			ExpectedFindings: []trace.ExpectedFinding{
				{RuleID: "credential_exposure", MustFire: false},
			},
		},
	})

	// Actual has credential_exposure on event 2 — FP per the guard
	actual := []session.Finding{
		finding("credential_exposure", 2),
	}
	sess := &session.SessionState{Disposition: "warn"}
	out := Score(ScoreInput{Labels: labels, Actual: actual, Session: sess})

	found := false
	for _, m := range out.PerRule {
		if m.RuleID == "credential_exposure" {
			found = true
			if m.FP != 1 {
				t.Errorf("FP: want 1, got %d", m.FP)
			}
			if m.Precision != 0.0 {
				t.Errorf("precision: want 0.0, got %f", m.Precision)
			}
		}
	}
	if !found {
		t.Error("credential_exposure rule not found in PerRule output")
	}
}

// TestScore_SilentRuleViolation verifies that a session-level expected_rules_silent
// rule that fires is counted as FP.
func TestScore_SilentRuleViolation(t *testing.T) {
	lf := trace.LabelsFile{
		SchemaVersion: 1,
		TraceName:     "test",
		SessionID:     "test_sess",
		Session: trace.SessionLabels{
			AttackClass:         "benign",
			ExpectedDisposition: "allow",
			ExpectedRulesSilent: []string{"pagination_exfiltration"},
		},
	}

	actual := []session.Finding{
		{RuleID: "pagination_exfiltration", TriggerEventSeq: 3, Severity: "high"},
	}
	sess := &session.SessionState{Disposition: "warn"}
	out := Score(ScoreInput{Labels: lf, Actual: actual, Session: sess})

	found := false
	for _, m := range out.PerRule {
		if m.RuleID == "pagination_exfiltration" {
			found = true
			if m.FP != 1 {
				t.Errorf("FP: want 1, got %d", m.FP)
			}
		}
	}
	if !found {
		t.Error("pagination_exfiltration rule not in PerRule")
	}
}

// TestScore_PredictedClassMapping verifies that credential findings map to
// the correct predicted class.
func TestScore_PredictedClassMapping(t *testing.T) {
	labels := makeLabels("credential_exfil", "terminate", nil)
	actual := []session.Finding{
		{RuleID: "credential_exposure", TriggerEventSeq: 4, Severity: "high"},
	}
	sess := &session.SessionState{Disposition: "terminate"}
	out := Score(ScoreInput{Labels: labels, Actual: actual, Session: sess})

	if out.PredictedClass != "credential_exfil" {
		t.Errorf("PredictedClass: want credential_exfil, got %q", out.PredictedClass)
	}
	if out.LabeledClass != "credential_exfil" {
		t.Errorf("LabeledClass: want credential_exfil, got %q", out.LabeledClass)
	}
}

// TestScore_EmptySession verifies that an empty actual findings list on a benign
// trace produces perfect precision and recall.
func TestScore_EmptySession(t *testing.T) {
	labels := makeLabels("benign", "allow", []trace.EventLabels{
		{
			EventSeq: 2,
			ExpectedFindings: []trace.ExpectedFinding{
				{RuleID: "credential_exposure", MustFire: false},
			},
		},
	})
	actual := []session.Finding{}
	sess := &session.SessionState{Disposition: "allow"}
	out := Score(ScoreInput{Labels: labels, Actual: actual, Session: sess})

	for _, m := range out.PerRule {
		if m.FP != 0 {
			t.Errorf("rule %s: FP want 0, got %d", m.RuleID, m.FP)
		}
	}
	if !out.SessionMatched {
		t.Error("session should match: expected allow, got allow")
	}
}
