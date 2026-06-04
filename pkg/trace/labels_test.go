package trace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"flint/engine/session"
)

// writeJSON is a test helper that marshals v and writes it to path.
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// makeTrace creates a TraceFile with event_seqs 1, 2, 3 and writes it as
// <name>.json under dir.
func makeTrace(t *testing.T, dir, name string) {
	t.Helper()
	tf := TraceFile{
		Name:      name,
		SessionID: "sess-" + name,
		Events: []session.SessionEvent{
			{EventSeq: 1, Direction: "request"},
			{EventSeq: 2, Direction: "response"},
			{EventSeq: 3, Direction: "request"},
		},
	}
	writeJSON(t, filepath.Join(dir, name+".json"), tf)
}

// makeLabels writes a labels sidecar for name under dir, referencing the given
// event_seqs.
func makeLabels(t *testing.T, dir, name string, seqs []int64) {
	t.Helper()
	var evLabels []EventLabels
	for _, seq := range seqs {
		evLabels = append(evLabels, EventLabels{
			EventSeq: seq,
			Labels:   []string{"test_label"},
		})
	}
	lf := LabelsFile{
		SchemaVersion: 1,
		TraceName:     name,
		SessionID:     "sess-" + name,
		Session:       SessionLabels{AttackClass: "benign", ExpectedDisposition: "allow"},
		Events:        evLabels,
	}
	writeJSON(t, filepath.Join(dir, name+".labels.json"), lf)
}

// TestLoadCorpus_NoMismatch verifies that when all label event_seqs exist in
// the trace, LoadCorpus returns no warnings.
func TestLoadCorpus_NoMismatch(t *testing.T) {
	dir := t.TempDir()
	makeTrace(t, dir, "clean")
	// Labels reference event 1 only — a subset of {1,2,3} — this is valid
	// partial labeling and must produce no warnings.
	makeLabels(t, dir, "clean", []int64{1})

	_, warnings, err := LoadCorpus(dir)
	if err != nil {
		t.Fatalf("LoadCorpus returned error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings, got %d: %+v", len(warnings), warnings)
	}
}

// TestLoadCorpus_OrphanedEventSeq verifies that when a labels file references
// an event_seq not present in the trace (e.g., 99), LoadCorpus emits a
// ValidationWarning for that seq without returning an error.
func TestLoadCorpus_OrphanedEventSeq(t *testing.T) {
	dir := t.TempDir()
	makeTrace(t, dir, "orphan")
	// Labels reference event 99 which does not exist in the trace {1,2,3}.
	makeLabels(t, dir, "orphan", []int64{1, 99})

	entries, warnings, err := LoadCorpus(dir)
	if err != nil {
		t.Fatalf("LoadCorpus returned error: %v", err)
	}

	// The entry must still be returned (no fail-fast).
	if len(entries) != 1 {
		t.Fatalf("expected 1 corpus entry, got %d", len(entries))
	}

	// Exactly one warning for event_seq=99.
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %+v", len(warnings), warnings)
	}
	w := warnings[0]
	if w.EventSeq != 99 {
		t.Errorf("warning.EventSeq = %d, want 99", w.EventSeq)
	}
	if w.TraceName != "orphan" {
		t.Errorf("warning.TraceName = %q, want %q", w.TraceName, "orphan")
	}
}
