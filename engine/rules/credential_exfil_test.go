package rules

import (
	"testing"

	"flint/engine/session"
)

// Synthetic credential fixtures. Split-string literals prevent secret scanners
// from pattern-matching the full token in source. Each value is structurally
// valid for the detector regex but is not a real credential.
const (
	fakeAWSKey     = "AKIA" + "IOSFODNN7EXAMPLE"
	fakeAWSKeyASIA = "ASIA" + "IOSFODNN7EXAMPLE"
	fakeAWSKeyAlt  = "AKIA" + "BBBBBBBBBBBBBBBBB"
	fakeOpenAIProj = "sk-proj-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
	fakeAnthropic  = "sk-ant-api03-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab"
	fakeGitHubPAT  = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	fakeSlackBot   = "xoxb-" + "1234567890ab-1234567890ab-abcdefghijklmn"
	fakeStripeLive = "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWX"
	fakeSupabaseSR = "sbp_" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
)

// credentialCase is the table-driven test row shape for EvalCredentialExfil.
type credentialCase struct {
	Name      string
	Payload   map[string]any
	Direction string // defaults to "response"
	ToolName  string
	ToolTags  []string
	Want      struct {
		MustFire    []string // rule_ids that MUST appear in findings
		MustNotFire []string // rule_ids that MUST NOT appear in findings
		Restricted  bool     // expected post: s.RestrictedEvents[seq] == true
		KindSubset  []string // at least these kinds must appear in finding messages
	}
}

func makeTestSession() *session.SessionState {
	return &session.SessionState{
		SessionID:        "test_sess",
		Disposition:      "allow",
		TokenIndex:       make(map[string][]session.TokenOccurrence),
		FieldHashIndex:   make(map[string][]session.FieldOccurrence),
		DeniedRequestIDs: make(map[string]bool),
		RestrictedEvents: make(map[int64]bool),
	}
}

func makeTestEvent(tc credentialCase, seq int64) session.SessionEvent {
	dir := tc.Direction
	if dir == "" {
		dir = "response"
	}
	tool := tc.ToolName
	if tool == "" {
		tool = "test.tool"
	}
	return session.SessionEvent{
		SessionID: "test_sess",
		EventSeq:  seq,
		Direction: dir,
		ToolName:  tool,
		ToolTags:  tc.ToolTags,
		Payload:   tc.Payload,
	}
}

func hasFindingWith(findings []session.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func findingMessages(findings []session.Finding) []string {
	var msgs []string
	for _, f := range findings {
		msgs = append(msgs, f.Message)
	}
	return msgs
}

func msgContains(msgs []string, sub string) bool {
	for _, m := range msgs {
		if len(m) >= len(sub) {
			for i := 0; i <= len(m)-len(sub); i++ {
				if m[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func runCredentialCase(t *testing.T, tc credentialCase) {
	t.Helper()
	s := makeTestSession()
	evt := makeTestEvent(tc, 42)

	findings := EvalCredentialExfil(s, &evt)

	for _, ruleID := range tc.Want.MustFire {
		if !hasFindingWith(findings, ruleID) {
			t.Errorf("expected finding %q but got %v", ruleID, findingMessages(findings))
		}
	}
	for _, ruleID := range tc.Want.MustNotFire {
		if hasFindingWith(findings, ruleID) {
			t.Errorf("did not expect finding %q but got one; messages: %v", ruleID, findingMessages(findings))
		}
	}
	if tc.Want.Restricted != s.RestrictedEvents[42] {
		t.Errorf("RestrictedEvents[42]: want %v got %v", tc.Want.Restricted, s.RestrictedEvents[42])
	}
	for _, kind := range tc.Want.KindSubset {
		msgs := findingMessages(findings)
		if !msgContains(msgs, kind) {
			t.Errorf("expected kind %q in finding messages, got %v", kind, msgs)
		}
	}
}

// ─── Benign (FP control) tests ───────────────────────────────────────────────

func TestCredentialExfil_Benign(t *testing.T) {
	cases := []credentialCase{
		{
			Name:    "bcrypt_hash_in_response",
			Payload: map[string]any{"hash": "$2b$12$ABCDEFGHIJKLMNOPQRSTUVwxyz0123456789ABCDEF0123456789abcdef"},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			Name:    "git_sha_40_hex",
			Payload: map[string]any{"commit": "e3a1b2c4d5e6f7890abcdef1234567890abcdef1"},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			Name:    "md5_hex_32",
			Payload: map[string]any{"checksum": "d41d8cd98f00b204e9800998ecf8427e"},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			Name:    "sha256_hex_64",
			Payload: map[string]any{"digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			Name:    "uuid_v4_standard",
			Payload: map[string]any{"id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			Name:    "uuid_v4_in_id_field",
			Payload: map[string]any{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			// base64 of small JSON — looks like a JWT prefix eyJ... but is too short
			// to match the three-segment JWT pattern (all segments must be >=10 chars)
			Name:    "base64_of_small_json",
			Payload: map[string]any{"token": "eyJhYmMiOjEyM30="},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			Name:    "base64_of_uuid",
			Payload: map[string]any{"encoded": "eyJ1dWlkIjoiZjQ3YWMxMGItNThjYy00MzcyLWE1NjctMGUwMmIyYzNkNDc5In0="},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			// RFC 7519 §3.1 public sample JWT — known FP, intentionally pinned.
			// This fires because generic_jwt matches it; documented as accepted FP.
			// See devlog 025 §7 item 4 and 026 for the accepted trade-off.
			Name: "jwt_rfc7519_sample_known_fp",
			Payload: map[string]any{
				"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustFire: []string{"credential_exposure"}, Restricted: true, KindSubset: []string{"generic_jwt"}},
		},
		{
			Name:    "package_lock_integrity_hash",
			Payload: map[string]any{"integrity": "sha512-abc123def456ghi789jkl0mno1pqr2stu3vwx4yz5ABC6DEF7GHI8JKL9MNO0PQR1STU2VWX3="},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			Name: "markdown_with_code_block",
			Payload: map[string]any{
				"content": "Here is an example:\n```go\nfunc main() { fmt.Println(\"hello\") }\n```",
			},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			Name:    "random_user_id_18_chars",
			Payload: map[string]any{"user_id": "usr_123456789012345"},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			Name:    "mongo_objectid_24_hex",
			Payload: map[string]any{"_id": "507f1f77bcf86cd799439011"},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			Name:    "cron_expression",
			Payload: map[string]any{"schedule": "0 */6 * * *"},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			Name:    "iso8601_timestamp",
			Payload: map[string]any{"ts": "2024-01-15T14:00:00Z"},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			runCredentialCase(t, tc)
		})
	}
}

// ─── Must-match (TP) tests ────────────────────────────────────────────────────

func TestCredentialExfil_TruePositive(t *testing.T) {
	cases := []credentialCase{
		{
			Name:    "aws_access_key_akia",
			Payload: map[string]any{"key": fakeAWSKey},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustFire: []string{"credential_exposure"}, Restricted: true, KindSubset: []string{"aws_access_key"}},
		},
		{
			Name:    "aws_access_key_asia",
			Payload: map[string]any{"key": fakeAWSKeyASIA},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustFire: []string{"credential_exposure"}, Restricted: true, KindSubset: []string{"aws_access_key"}},
		},
		{
			Name:    "openai_sk_proj",
			Payload: map[string]any{"api_key": fakeOpenAIProj},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustFire: []string{"credential_exposure"}, Restricted: true, KindSubset: []string{"openai_key"}},
		},
		{
			Name: "anthropic_sk_ant",
			Payload: map[string]any{
				"key": fakeAnthropic,
			},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustFire: []string{"credential_exposure"}, Restricted: true, KindSubset: []string{"anthropic_key"}},
		},
		{
			Name:    "github_ghp",
			Payload: map[string]any{"token": fakeGitHubPAT},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustFire: []string{"credential_exposure"}, Restricted: true, KindSubset: []string{"github_pat"}},
		},
		{
			Name:    "slack_xoxb",
			Payload: map[string]any{"token": fakeSlackBot},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustFire: []string{"credential_exposure"}, Restricted: true, KindSubset: []string{"slack_token"}},
		},
		{
			Name:    "stripe_sk_live",
			Payload: map[string]any{"secret": fakeStripeLive},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustFire: []string{"credential_exposure"}, Restricted: true, KindSubset: []string{"stripe_secret"}},
		},
		{
			Name:    "supabase_sbp",
			Payload: map[string]any{"service_role_key": fakeSupabaseSR},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustFire: []string{"credential_exposure"}, Restricted: true, KindSubset: []string{"supabase_service_role"}},
		},
		{
			// Multi-kind: one payload with three different credential kinds.
			Name: "multi_kind_three_creds",
			Payload: map[string]any{
				"aws_key":    fakeAWSKey,
				"github_tok": fakeGitHubPAT,
				"stripe_key": fakeStripeLive,
			},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustFire: []string{"credential_exposure"}, Restricted: true, KindSubset: []string{"aws_access_key", "github_pat", "stripe_secret"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			runCredentialCase(t, tc)
		})
	}
}

// ─── Edge cases ───────────────────────────────────────────────────────────────

func TestCredentialExfil_EdgeCases(t *testing.T) {
	cases := []credentialCase{
		{
			Name:    "token_inside_larger_string",
			Payload: map[string]any{"body": "The key is " + fakeGitHubPAT + " and it works fine."},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustFire: []string{"credential_exposure"}, Restricted: true, KindSubset: []string{"github_pat"}},
		},
		{
			Name: "token_in_nested_json",
			Payload: map[string]any{
				"a": map[string]any{
					"b": []any{
						map[string]any{"c": fakeGitHubPAT},
					},
				},
			},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustFire: []string{"credential_exposure"}, Restricted: true, KindSubset: []string{"github_pat"}},
		},
		{
			// Multiple tokens of different types in one response — assert deduplicated findings
			Name: "multiple_tokens_one_response",
			Payload: map[string]any{
				"key1": fakeAWSKey,
				"key2": fakeAWSKey,  // duplicate of same kind
				"key3": fakeStripeLive,
			},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustFire: []string{"credential_exposure"}, Restricted: true, KindSubset: []string{"aws_access_key", "stripe_secret"}},
		},
		{
			Name:    "empty_payload",
			Payload: nil,
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			Name:    "non_string_payload_only",
			Payload: map[string]any{"count": float64(42), "active": true},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
		{
			// Request direction — must not fire regardless of payload.
			Name:      "request_direction_ignored",
			Direction: "request",
			Payload:   map[string]any{"key": fakeAWSKey},
			Want: struct {
				MustFire    []string
				MustNotFire []string
				Restricted  bool
				KindSubset  []string
			}{MustNotFire: []string{"credential_exposure"}, Restricted: false},
		},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			runCredentialCase(t, tc)
		})
	}
}

// ─── Deduplication verification ───────────────────────────────────────────────

// TestCredentialExfil_Deduplication checks that the same kind appearing
// multiple times in the payload produces exactly one finding for that kind.
func TestCredentialExfil_Deduplication(t *testing.T) {
	s := makeTestSession()
	evt := session.SessionEvent{
		SessionID: "test_sess",
		EventSeq:  7,
		Direction: "response",
		ToolName:  "db.fetch",
		Payload: map[string]any{
			"k1": fakeAWSKey,
			"k2": fakeAWSKeyAlt, // another AKIA key — same kind
		},
	}
	findings := EvalCredentialExfil(s, &evt)

	awsCount := 0
	for _, f := range findings {
		for _, msg := range []string{f.Message} {
			if len(msg) >= len("aws_access_key") {
				for i := 0; i <= len(msg)-len("aws_access_key"); i++ {
					if msg[i:i+len("aws_access_key")] == "aws_access_key" {
						awsCount++
						break
					}
				}
			}
		}
	}

	if awsCount != 1 {
		t.Errorf("expected exactly 1 aws_access_key finding, got %d", awsCount)
	}
}

// TestCredentialExfil_FindingFields checks the mandatory fields on a finding.
func TestCredentialExfil_FindingFields(t *testing.T) {
	s := makeTestSession()
	evt := session.SessionEvent{
		SessionID: "test_sess",
		EventSeq:  99,
		Direction: "response",
		ToolName:  "vault.read",
		Payload:   map[string]any{"secret": fakeAWSKey},
	}
	findings := EvalCredentialExfil(s, &evt)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.RuleID != "credential_exposure" {
		t.Errorf("RuleID: want credential_exposure, got %q", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("Severity: want high, got %q", f.Severity)
	}
	if f.Action != "warn" {
		t.Errorf("Action: want warn, got %q", f.Action)
	}
	if f.Score != 60 {
		t.Errorf("Score: want 60, got %f", f.Score)
	}
	if f.Confidence != 0.95 {
		t.Errorf("Confidence: want 0.95 for regex hit, got %f", f.Confidence)
	}
	if f.TriggerEventSeq != 99 {
		t.Errorf("TriggerEventSeq: want 99, got %d", f.TriggerEventSeq)
	}
}
