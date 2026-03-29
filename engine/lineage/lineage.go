package lineage

import (
	"flint/engine/fingerprint"
	"flint/engine/session"
)

func BuildLineage(s *session.SessionState, evt *session.SessionEvent) []session.SessionEdge {
	var edges []session.SessionEdge

	if evt.Direction == "response" {
		for _, tok := range fingerprint.ExtractTokens(evt) {
			s.TokenIndex[tok.Value] = append(s.TokenIndex[tok.Value], tok)
		}
		for h, occ := range fingerprint.ExtractFieldHashes(evt) {
			s.FieldHashIndex[h] = append(s.FieldHashIndex[h], occ)
		}
	}

	if evt.Direction == "request" {
		for _, rt := range fingerprint.ExtractTokens(evt) {
			if priors, ok := s.TokenIndex[rt.Value]; ok {
				for _, p := range priors {
					if p.EventSeq < evt.EventSeq {
						edges = append(edges, session.SessionEdge{
							SrcEventSeq: p.EventSeq,
							DstEventSeq: evt.EventSeq,
							EdgeType:    "exact_token_match",
							Confidence:  1.0,
							MatchedKeys: []string{rt.Value},
						})
					}
				}
			}
		}

		rh := fingerprint.ExtractFieldHashes(evt)
		for h := range rh {
			if priors, ok := s.FieldHashIndex[h]; ok {
				for _, p := range priors {
					if p.EventSeq < evt.EventSeq {
						edges = append(edges, session.SessionEdge{
							SrcEventSeq: p.EventSeq,
							DstEventSeq: evt.EventSeq,
							EdgeType:    "field_value_overlap",
							Confidence:  0.9,
							MatchedKeys: []string{p.Field + " -> " + rh[h].Field},
						})
					}
				}
			}
		}
	}

	return edges
}
