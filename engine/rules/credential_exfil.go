package rules

import (
	"fmt"
	"os"
	"regexp"

	"flint/engine/session"
)

// credentialPattern associates a kind label with a compiled regex.
type credentialPattern struct {
	kind    string
	pattern *regexp.Regexp
}

// v1CredentialPatterns is the precision-tuned regex set for vendor-specific
// credential shapes. Deliberately high precision over high recall — entropy
// fallback handles the long tail when enabled.
//
// Synthetic test values used throughout: AKIAIOSFODNN7EXAMPLE (AWS doc example),
// sk-proj-AAAA… etc. Never commit real keys.
var v1CredentialPatterns = []credentialPattern{
	{
		kind:    "aws_access_key",
		pattern: regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`),
	},
	{
		kind:    "openai_key",
		pattern: regexp.MustCompile(`sk-(?:proj-)?[A-Za-z0-9_\-]{32,}`),
	},
	{
		kind:    "anthropic_key",
		pattern: regexp.MustCompile(`sk-ant-(?:api03-)?[A-Za-z0-9_\-]{80,}`),
	},
	{
		kind:    "github_pat",
		pattern: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
	},
	{
		kind:    "slack_token",
		pattern: regexp.MustCompile(`xox[abprs]-[A-Za-z0-9\-]{10,}-[A-Za-z0-9\-]{10,}`),
	},
	{
		kind:    "stripe_secret",
		pattern: regexp.MustCompile(`sk_(?:live|test)_[A-Za-z0-9]{24,}`),
	},
	{
		kind:    "supabase_service_role",
		pattern: regexp.MustCompile(`sbp_[a-f0-9]{40,}`),
	},
	{
		kind:    "generic_jwt",
		pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`),
	},
}

// entropyHeuristicEnabled returns true if the FLINT_DETECT_ENTROPY=1 env var
// is set. The entropy heuristic is disabled by default because it has a
// moderate FP rate (~1 FP per 100 KB of typical agent payload) on benign
// content such as git refs, package lockfile hashes, and base64-encoded
// protobuf blobs. Enable it only if you accept the trade-off.
func entropyHeuristicEnabled() bool {
	return os.Getenv("FLINT_DETECT_ENTROPY") == "1"
}

// uuidPattern is used to skip UUID strings in the entropy heuristic.
var uuidPattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
)

// gitSHAPattern is used to skip 40-char hex git SHAs in the entropy heuristic.
var gitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// detectCredentials scans a single string value for any v1 credential pattern.
// Returns a deduplicated list of matching kind labels. Order is stable.
func detectCredentials(s string) []string {
	seen := make(map[string]bool)
	var kinds []string
	for _, cp := range v1CredentialPatterns {
		if cp.pattern.FindString(s) != "" {
			if !seen[cp.kind] {
				seen[cp.kind] = true
				kinds = append(kinds, cp.kind)
			}
		}
	}
	return kinds
}

// detectCredentialsWithEntropy is like detectCredentials but also runs the
// entropy heuristic for strings that pass the candidate filter and are not
// already matched by a v1 regex.
func detectCredentialsWithEntropy(s string) []string {
	kinds := detectCredentials(s)
	if len(kinds) > 0 {
		// Already caught by a v1 regex — don't double-count.
		return kinds
	}

	// Entropy candidate filter:
	//   - Length 40–200 chars (shorter is likely a hash; longer is likely prose)
	//   - Not a UUID or git SHA
	//   - Shannon entropy >= 4.5 bits/char
	if len(s) < 40 || len(s) > 200 {
		return nil
	}
	if uuidPattern.MatchString(s) || gitSHAPattern.MatchString(s) {
		return nil
	}
	if isHighEntropy(s, 4.5) {
		return []string{"entropy_only"}
	}
	return nil
}

// EvalCredentialExfil scans response payloads for credential-shaped tokens.
// On detection it:
//  (a) emits a credential_exposure Finding (Action: warn, Severity: high,
//      Score: 60, Confidence: 0.95 for regex hits / 0.70 for entropy-only)
//  (b) flags the event in s.RestrictedEvents so a subsequent egress request
//      can be caught by EvalSecretRelay as a relay event.
//
// Runs only on response events. Recognises credentials by regex match against
// a precision-tuned set of vendor-specific patterns (v1CredentialPatterns);
// falls back to Shannon entropy when FLINT_DETECT_ENTROPY=1 is set.
//
// Placement note: this rule is inserted FIRST in the engine dispatch order
// for readability / documentation, not for correctness. The composition with
// EvalSecretRelay works because RestrictedEvents is set on the session-level
// pointer (s), and EvalSecretRelay runs on the NEXT event's ProcessEvent call,
// after this one has already written to s.RestrictedEvents.
func EvalCredentialExfil(s *session.SessionState, evt *session.SessionEvent) []session.Finding {
	if evt.Direction != "response" {
		return nil
	}

	entropy := entropyHeuristicEnabled()

	// Collect all credential kinds found across every string value in the payload.
	allKinds := make(map[string]bool)
	for _, str := range collectStrings(evt.Payload) {
		var kinds []string
		if entropy {
			kinds = detectCredentialsWithEntropy(str)
		} else {
			kinds = detectCredentials(str)
		}
		for _, k := range kinds {
			allKinds[k] = true
		}
	}

	if len(allKinds) == 0 {
		return nil
	}

	// Mark this event as restricted so EvalSecretRelay can pick it up.
	if s.RestrictedEvents == nil {
		s.RestrictedEvents = make(map[int64]bool)
	}
	s.RestrictedEvents[evt.EventSeq] = true

	// Emit one Finding per distinct credential kind.
	var findings []session.Finding
	for kind := range allKinds {
		confidence := 0.95
		if kind == "entropy_only" {
			confidence = 0.70
		}
		findings = append(findings, session.Finding{
			RuleID:          "credential_exposure",
			Severity:        "high",
			Confidence:      confidence,
			Message:         fmt.Sprintf("Credential-shaped token (%s) in %s response (event %d)", kind, evt.ToolName, evt.EventSeq),
			TriggerEventSeq: evt.EventSeq,
			Action:          "warn",
			Score:           60,
		})
	}
	return findings
}
