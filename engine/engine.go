package engine

import (
	"encoding/json"
	"time"

	"flint/engine/lineage"
	"flint/engine/risk"
	"flint/engine/rules"
	"flint/engine/session"
)

type Engine struct {
	Session  *session.SessionState
	registry map[string]session.ToolMeta
}

// New creates an Engine. If registry is nil it falls back to the built-in defaults.
func New(id string, registry map[string]session.ToolMeta) *Engine {
	if registry == nil {
		registry = session.DefaultRegistry
	}
	return &Engine{
		registry: registry,
		Session: &session.SessionState{
			SessionID:      id,
			StartedAt:      time.Now(),
			Disposition:    "allow",
			TokenIndex:     make(map[string][]session.TokenOccurrence),
			FieldHashIndex: make(map[string][]session.FieldOccurrence),
		},
	}
}

func (e *Engine) ProcessEvent(evt session.SessionEvent) []session.Finding {
	session.ResolveToolWith(e.registry, &evt)
	evt.PayloadSize = estSize(evt.Payload)
	e.Session.Events = append(e.Session.Events, evt)
	e.Session.LastEventSeq = evt.EventSeq

	e.Session.Edges = append(e.Session.Edges, lineage.BuildLineage(e.Session, &evt)...)

	var findings []session.Finding
	findings = append(findings, rules.EvalSecretRelay(e.Session, &evt)...)
	findings = append(findings, rules.EvalRestrictedWrite(e.Session, &evt)...)
	findings = append(findings, rules.EvalPagination(e.Session, &evt)...)
	findings = append(findings, rules.EvalToolPoisoning(e.Session, &evt)...)
	findings = append(findings, rules.EvalFilesystemTraversal(e.Session, &evt)...)
	findings = append(findings, rules.EvalCrossScopeMovement(e.Session, &evt)...)

	for _, f := range findings {
		e.Session.Findings = append(e.Session.Findings, f)
		risk.Apply(e.Session, f)
	}

	return findings
}

func estSize(p any) int {
	b, _ := json.Marshal(p)
	return len(b)
}
