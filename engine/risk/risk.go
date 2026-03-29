package risk

import "flint/engine/session"

// Apply accumulates a finding's score into the session and escalates
// the disposition. Disposition only moves forward: allow → warn → pause → terminate.
func Apply(s *session.SessionState, f session.Finding) {
	s.RiskScore += f.Score
	switch {
	case f.Action == "terminate":
		s.Disposition = "terminate"
	case f.Action == "pause" && s.Disposition != "terminate":
		s.Disposition = "pause"
	case f.Action == "warn" && s.Disposition == "allow":
		s.Disposition = "warn"
	}
}
