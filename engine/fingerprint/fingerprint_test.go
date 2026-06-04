package fingerprint

import (
	"testing"

	"flint/engine/session"
)

// Synthetic key fixtures. Split-string literals prevent secret scanners from
// pattern-matching the full token in source. Each value satisfies the
// fingerprint regex but is not a real credential.
const (
	fakeSkProjKey = "sk-proj-" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9876"
	fakeSkKey     = "sk-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst"
)

// TestExtractTokens_SkProjKey verifies that sk-proj-* OpenAI keys (the format
// issued since 2024 that includes a "proj-" infix) are correctly indexed.
// Before the fix the pattern `sk[-_][A-Za-z0-9]{20,}` terminated at the first
// `-` in "proj-", yielding only "proj" (4 chars) before hitting the 20-char
// floor and returning no match.
func TestExtractTokens_SkProjKey(t *testing.T) {
	key := fakeSkProjKey
	evt := &session.SessionEvent{
		EventSeq:  1,
		Direction: "response",
		Payload: map[string]any{
			"value": key,
		},
	}

	tokens := ExtractTokens(evt)

	found := false
	for _, tok := range tokens {
		if tok.Value == key {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ExtractTokens did not index sk-proj- key %q; got tokens: %v", key, tokens)
	}
}

// TestExtractTokens_SkKeyNoProj verifies that the original sk-<body> form
// (without the proj- infix) still matches.
func TestExtractTokens_SkKeyNoProj(t *testing.T) {
	key := fakeSkKey
	evt := &session.SessionEvent{
		EventSeq:  1,
		Direction: "response",
		Payload: map[string]any{
			"value": key,
		},
	}

	tokens := ExtractTokens(evt)

	found := false
	for _, tok := range tokens {
		if tok.Value == key {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ExtractTokens did not index sk- key %q; got tokens: %v", key, tokens)
	}
}

// TestExtractTokens_ShortSlugNoMatch verifies that a short benign slug like
// "sk-help-me" does NOT match (falls below the 20-char body floor).
func TestExtractTokens_ShortSlugNoMatch(t *testing.T) {
	evt := &session.SessionEvent{
		EventSeq:  1,
		Direction: "response",
		Payload: map[string]any{
			"value": "sk-help-me",
		},
	}

	tokens := ExtractTokens(evt)

	for _, tok := range tokens {
		if tok.Pattern != "sensitive_field_name" {
			t.Errorf("short slug sk-help-me should not match secretPatterns; got tok=%+v", tok)
		}
	}
}
