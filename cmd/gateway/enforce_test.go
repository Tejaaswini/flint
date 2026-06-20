package main

import (
	"testing"

	"flint/engine/session"
)

// makeFindings builds a []session.Finding from (ruleID, action) pairs.
func makeFindings(pairs ...string) []session.Finding {
	var out []session.Finding
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, session.Finding{RuleID: pairs[i], Action: pairs[i+1]})
	}
	return out
}

func TestDecideEnforcement(t *testing.T) {
	cases := []struct {
		name         string
		disposition  string
		findings     []session.Finding
		mode         string
		wantBlock    bool
		wantRuleID   string
		wantEnforced string
	}{
		// 1. Clean allow — no findings, mode=block
		{
			name:         "allow_no_findings_block",
			disposition:  "allow",
			findings:     nil,
			mode:         "block",
			wantBlock:    false,
			wantRuleID:   "",
			wantEnforced: "allow",
		},
		// 2. Warn with a warn-finding, mode=block — observe only (warn does not trigger block)
		{
			name:         "warn_with_finding_block",
			disposition:  "warn",
			findings:     makeFindings("pagination_exfiltration", "warn"),
			mode:         "block",
			wantBlock:    false,
			wantRuleID:   "",
			wantEnforced: "observed",
		},
		// 3. Terminate with findings, mode=block — must block
		{
			name:         "terminate_block",
			disposition:  "terminate",
			findings:     makeFindings("secret_relay", "terminate"),
			mode:         "block",
			wantBlock:    true,
			wantRuleID:   "secret_relay",
			wantEnforced: "blocked",
		},
		// 4. Terminate with findings, mode=observe — must NOT block
		{
			name:         "terminate_observe",
			disposition:  "terminate",
			findings:     makeFindings("secret_relay", "terminate"),
			mode:         "observe",
			wantBlock:    false,
			wantRuleID:   "",
			wantEnforced: "observed",
		},
		// 5. Pause with findings, mode=block — must block
		{
			name:         "pause_block",
			disposition:  "pause",
			findings:     makeFindings("filesystem_traversal_sequence", "pause"),
			mode:         "block",
			wantBlock:    true,
			wantRuleID:   "filesystem_traversal_sequence",
			wantEnforced: "blocked",
		},
		// 6. Pause with findings, mode=observe — pass through
		{
			name:         "pause_observe",
			disposition:  "pause",
			findings:     makeFindings("filesystem_traversal_sequence", "pause"),
			mode:         "observe",
			wantBlock:    false,
			wantRuleID:   "",
			wantEnforced: "observed",
		},
		// 7. Terminate with multiple findings — cite highest-severity (terminate > pause > warn)
		{
			name:        "terminate_multiple_findings_picks_highest",
			disposition: "terminate",
			findings: makeFindings(
				"tool_poisoning_indicator", "warn",
				"filesystem_traversal_sequence", "pause",
				"secret_relay", "terminate",
			),
			mode:         "block",
			wantBlock:    true,
			wantRuleID:   "secret_relay",
			wantEnforced: "blocked",
		},
		// 8. Terminate with findings in warn/pause order — first terminate wins over later warn
		{
			name:        "terminate_findings_first_terminate_cited",
			disposition: "terminate",
			findings: makeFindings(
				"credential_exposure", "warn",
				"secret_relay", "terminate",
				"tool_poisoning_indicator", "warn",
			),
			mode:         "block",
			wantBlock:    true,
			wantRuleID:   "secret_relay",
			wantEnforced: "blocked",
		},
		// 9. Allow with findings (warn finding but disposition still allow) — observed
		{
			name:         "allow_with_findings_observed",
			disposition:  "allow",
			findings:     makeFindings("credential_exposure", "warn"),
			mode:         "block",
			wantBlock:    false,
			wantRuleID:   "",
			wantEnforced: "observed",
		},
		// 10. Terminate with empty findings slice — block but no cited rule
		{
			name:         "terminate_no_findings_still_blocks",
			disposition:  "terminate",
			findings:     []session.Finding{},
			mode:         "block",
			wantBlock:    true,
			wantRuleID:   "",
			wantEnforced: "blocked",
		},
		// 11. Warn, mode=observe, no findings — allow
		{
			name:         "warn_observe_no_findings",
			disposition:  "warn",
			findings:     nil,
			mode:         "observe",
			wantBlock:    false,
			wantRuleID:   "",
			wantEnforced: "allow",
		},
		// 12. Pause with two equal-rank findings — first wins (tie-break)
		{
			name:        "pause_two_pause_findings_first_wins",
			disposition: "pause",
			findings: makeFindings(
				"filesystem_traversal_sequence", "pause",
				"restricted_read_external_write", "pause",
			),
			mode:         "block",
			wantBlock:    true,
			wantRuleID:   "filesystem_traversal_sequence",
			wantEnforced: "blocked",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DecideEnforcement(tc.disposition, tc.findings, tc.mode)
			if got.Block != tc.wantBlock {
				t.Errorf("Block: got %v, want %v", got.Block, tc.wantBlock)
			}
			if got.CitedRuleID != tc.wantRuleID {
				t.Errorf("CitedRuleID: got %q, want %q", got.CitedRuleID, tc.wantRuleID)
			}
			if got.EnforcedAction != tc.wantEnforced {
				t.Errorf("EnforcedAction: got %q, want %q", got.EnforcedAction, tc.wantEnforced)
			}
		})
	}
}

func TestPickCitedFinding_Empty(t *testing.T) {
	if f := pickCitedFinding(nil); f != nil {
		t.Errorf("expected nil for empty input, got %v", f)
	}
}

func TestPickCitedFinding_SingleFinding(t *testing.T) {
	findings := makeFindings("secret_relay", "terminate")
	f := pickCitedFinding(findings)
	if f == nil {
		t.Fatal("expected non-nil result")
	}
	if f.RuleID != "secret_relay" {
		t.Errorf("got RuleID %q, want %q", f.RuleID, "secret_relay")
	}
}

func TestActionRank(t *testing.T) {
	if actionRank("terminate") <= actionRank("pause") {
		t.Error("terminate should outrank pause")
	}
	if actionRank("pause") <= actionRank("warn") {
		t.Error("pause should outrank warn")
	}
	if actionRank("warn") <= actionRank("") {
		t.Error("warn should outrank empty/unknown")
	}
}
