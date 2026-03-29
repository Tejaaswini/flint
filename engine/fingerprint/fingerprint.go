package fingerprint

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	"flint/engine/session"
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk[-_]live[-_][A-Za-z0-9]{20,}`),
	regexp.MustCompile(`sk[-_][A-Za-z0-9]{20,}`),
	regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	regexp.MustCompile(`xox[bpras]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`Bearer\s+[A-Za-z0-9._~+/=-]{20,}`),
	regexp.MustCompile(`sbp_[a-f0-9]{40,}`),
	regexp.MustCompile(`service_role_[A-Za-z0-9_-]{20,}`),
}

var sensitiveFieldNames = regexp.MustCompile(
	`(?i)(api[_-]?key|secret|token|password|credential|auth|bearer|private[_-]?key|access[_-]?key|service[_-]?role)`,
)

func ExtractTokens(evt *session.SessionEvent) []session.TokenOccurrence {
	var out []session.TokenOccurrence
	if evt.Payload == nil {
		return out
	}
	walkPayload(evt.Payload, "", func(field, value string) {
		isSensitive := sensitiveFieldNames.MatchString(field)

		for _, pat := range secretPatterns {
			for _, m := range pat.FindAllString(value, -1) {
				out = append(out, session.TokenOccurrence{
					EventSeq: evt.EventSeq,
					Field:    field,
					Value:    m,
					Pattern:  pat.String()[:min(40, len(pat.String()))],
				})
			}
		}

		if isSensitive && len(value) > 6 {
			found := false
			for _, t := range out {
				if t.Value == value {
					found = true
					break
				}
			}
			if !found {
				out = append(out, session.TokenOccurrence{
					EventSeq: evt.EventSeq,
					Field:    field,
					Value:    value,
					Pattern:  "sensitive_field_name",
				})
			}
		}
	})
	return out
}

func ExtractFieldHashes(evt *session.SessionEvent) map[string]session.FieldOccurrence {
	hashes := make(map[string]session.FieldOccurrence)
	if evt.Payload == nil {
		return hashes
	}
	walkPayload(evt.Payload, "", func(field, value string) {
		if len(value) < 8 || isMetadataField(field) {
			return
		}
		hashes[hashValue(value)] = session.FieldOccurrence{
			EventSeq: evt.EventSeq,
			Field:    field,
			RawValue: value,
		}
	})
	return hashes
}

func isMetadataField(f string) bool {
	lower := strings.ToLower(f)
	for _, s := range []string{
		"status", "page", "limit", "offset", "cursor", "sort",
		"order", "count", "total", "type", "version", "created_at",
		"updated_at", "timestamp", "id", "method",
	} {
		if lower == s {
			return true
		}
	}
	return false
}

func hashValue(v string) string {
	h := sha256.Sum256([]byte(v))
	return fmt.Sprintf("%x", h[:12])
}

func walkPayload(obj any, prefix string, fn func(string, string)) {
	switch v := obj.(type) {
	case map[string]any:
		for k, val := range v {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			walkPayload(val, p, fn)
		}
	case []any:
		for i, val := range v {
			walkPayload(val, fmt.Sprintf("%s[%d]", prefix, i), fn)
		}
	case string:
		fn(prefix, v)
	case float64:
		fn(prefix, fmt.Sprintf("%v", v))
	}
}
