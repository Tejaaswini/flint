package trace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LabelsFile is the schema for a corpus labels sidecar file.
// Every <name>.json trace must have a paired <name>.labels.json at the same
// path. See docs/corpus-labels-schema.md for the full specification.
type LabelsFile struct {
	// SchemaVersion is the labels schema version. Current: 1.
	SchemaVersion int `json:"schema_version"`
	// TraceName must match the trace file's "name" field.
	TraceName string `json:"trace_name"`
	// SessionID must match the trace file's "session_id" field.
	SessionID string `json:"session_id"`
	// Session holds session-level labels and expectations.
	Session SessionLabels `json:"session"`
	// Events holds per-event labels. Only events requiring assertions need entries.
	Events []EventLabels `json:"events"`
}

// SessionLabels holds session-level classification and expected outcomes.
type SessionLabels struct {
	// AttackClass categorises the session. Recommended vocabulary:
	// credential_exfil | prompt_poisoning | cross_scope_leak |
	// filesystem_traversal | pagination_exfil | benign.
	// Open-vocab: any string is valid.
	AttackClass string `json:"attack_class"`
	// ExpectedDisposition is the expected session disposition after replay.
	// Values: allow | warn | pause | terminate.
	ExpectedDisposition string `json:"expected_disposition"`
	// ExpectedRulesFired lists rule IDs that MUST fire over the session.
	// Optional; per-event expected_findings takes precedence for scoring.
	ExpectedRulesFired []string `json:"expected_rules_fired,omitempty"`
	// ExpectedRulesSilent lists rule IDs that must NOT fire. Used for FP tests.
	ExpectedRulesSilent []string `json:"expected_rules_silent,omitempty"`
	// Notes is free-text annotation.
	Notes string `json:"notes,omitempty"`
	// Source describes provenance for publication (e.g., "synthetic", "reconstructed-from-cve-XXXX").
	Source string `json:"source,omitempty"`
}

// EventLabels holds per-event labels for a single event in the trace.
type EventLabels struct {
	// EventSeq is the join key into the paired trace file.
	EventSeq int64 `json:"event_seq"`
	// Labels is a categorical label list.
	Labels []string `json:"labels,omitempty"`
	// ContainsCredentials is true iff the event payload contains at least one
	// real credential-shaped token (even if synthetic for tests).
	ContainsCredentials bool `json:"contains_credentials,omitempty"`
	// CredentialKinds lists the kinds of credentials present.
	CredentialKinds []string `json:"credential_kinds,omitempty"`
	// ExpectedFindings lists per-event rule assertions.
	ExpectedFindings []ExpectedFinding `json:"expected_findings,omitempty"`
	// ExpectedPostState describes expected session state after processing this event.
	ExpectedPostState *PostState `json:"expected_post_state,omitempty"`
}

// ExpectedFinding represents an expectation that a rule fires (or does NOT fire)
// on a specific event.
type ExpectedFinding struct {
	// RuleID is the rule identifier (e.g., "credential_exposure", "secret_relay").
	RuleID string `json:"rule_id"`
	// MustFire: true means this rule must fire on this event (TP expectation).
	// false means this rule must NOT fire on this event (FP guard).
	MustFire bool `json:"must_fire"`
}

// PostState describes expected derived state assertions after processing an event.
type PostState struct {
	// Restricted corresponds to s.RestrictedEvents[event_seq].
	Restricted bool `json:"restricted,omitempty"`
}

// CorpusEntry pairs a trace with its labels file.
type CorpusEntry struct {
	Trace  TraceFile
	Labels LabelsFile
}

// ValidationWarning is a non-fatal diagnostic produced during corpus loading.
// It signals a cross-validation mismatch between a labels file and its paired
// trace (e.g., a label references an event_seq that does not exist in the trace).
type ValidationWarning struct {
	// TraceName is the name field from the trace file.
	TraceName string
	// EventSeq is the event_seq value that triggered the warning.
	EventSeq int64
	// Message is a human-readable description of the problem.
	Message string
}

// LoadLabels reads a .labels.json sidecar file and parses it into a LabelsFile.
func LoadLabels(path string) (LabelsFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return LabelsFile{}, err
	}
	var lf LabelsFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return LabelsFile{}, fmt.Errorf("parsing labels file %s: %w", path, err)
	}
	return lf, nil
}

// LoadCorpus loads all trace+labels pairs from a directory. For each
// <name>.json found, it looks for a paired <name>.labels.json. If labels are
// missing, the entry is still returned with an empty LabelsFile (attack_class
// "unlabeled") and a warning is printed to stderr. Files named *.labels.json
// are skipped during the primary scan.
//
// After loading each pair, LoadCorpus cross-validates that every event_seq
// referenced in the labels file exists in the trace. Any mismatch is returned
// as a ValidationWarning AND printed to stderr. The affected CorpusEntry is
// still included — callers receive both the loaded data and the warnings so they
// can surface diagnostics without silently masking data bugs.
func LoadCorpus(dir string) ([]CorpusEntry, []ValidationWarning, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("reading corpus directory %s: %w", dir, err)
	}

	var corpus []CorpusEntry
	var warnings []ValidationWarning

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		// Skip label files; we'll load them when we encounter the trace.
		if strings.HasSuffix(name, ".labels.json") {
			continue
		}

		tracePath := filepath.Join(dir, name)
		tf, err := Load(tracePath)
		if err != nil {
			return nil, nil, fmt.Errorf("loading trace %s: %w", name, err)
		}

		stem := strings.TrimSuffix(name, ".json")
		labelsPath := filepath.Join(dir, stem+".labels.json")
		var lf LabelsFile
		if _, err := os.Stat(labelsPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "warning: no labels file for %s — scoring skipped for this trace\n", name)
			lf = LabelsFile{
				TraceName: tf.Name,
				SessionID: tf.SessionID,
				Session:   SessionLabels{AttackClass: "unlabeled"},
			}
		} else {
			lf, err = LoadLabels(labelsPath)
			if err != nil {
				return nil, nil, fmt.Errorf("loading labels %s: %w", stem+".labels.json", err)
			}
		}

		// Cross-validate: build a set of event_seq values present in the trace,
		// then warn for any event_seq in the labels that doesn't exist in the trace.
		// Missing event_seqs produce silent FNs in the scorer that look like engine
		// regressions — surfacing them here catches data bugs early.
		traceSeqs := make(map[int64]bool, len(tf.Events))
		for _, ev := range tf.Events {
			traceSeqs[ev.EventSeq] = true
		}
		for _, el := range lf.Events {
			if !traceSeqs[el.EventSeq] {
				msg := fmt.Sprintf(
					"WARN: corpus/%s.labels.json references event_seq=%d not present in trace (will be counted as FN)",
					stem, el.EventSeq,
				)
				fmt.Fprintln(os.Stderr, msg)
				warnings = append(warnings, ValidationWarning{
					TraceName: tf.Name,
					EventSeq:  el.EventSeq,
					Message:   msg,
				})
			}
		}

		corpus = append(corpus, CorpusEntry{Trace: tf, Labels: lf})
	}

	return corpus, warnings, nil
}
