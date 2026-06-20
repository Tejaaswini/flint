package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"flint/engine"
	"flint/engine/authz"
	"flint/engine/session"
	"flint/pkg/api"
)

// -- MCP JSON-RPC types -------------------------------------------------------

// message covers both requests and responses. Method is set on requests;
// Result or Error is set on responses. ID uses RawMessage to preserve
// integer vs string IDs exactly as received.
type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolsCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// -- Proxy --------------------------------------------------------------------

// pendingReq tracks an in-flight request so we can correlate its response.
type pendingReq struct {
	method   string
	toolName string    // only populated for tools/call
	start    time.Time // when the request was forwarded upstream
}

// Proxy is the stateful MCP proxy. One instance per gateway process.
type Proxy struct {
	agentID  string
	upstream []string
	eng      *engine.Engine
	holder   *authz.PolicyHolder
	audit    *Writer

	// enforceMode controls whether the gateway blocks on pause/terminate
	// disposition ("block") or only logs ("observe").
	enforceMode string

	seqCounter int64

	mu      sync.Mutex
	pending map[string]pendingReq

	// inFlight tracks in-flight tools/call requests for drain-on-SIGTERM.
	inFlight sync.WaitGroup

	// stopOnce ensures Stop() is idempotent.
	stopOnce sync.Once
	// stopCh is closed by Stop() to signal fromAgent to stop reading.
	stopCh chan struct{}

	// cmd is the upstream subprocess; stored so Drain can terminate it.
	cmd *exec.Cmd
}

// NewProxy constructs a Proxy. holder and audit may be nil for test use.
// enforceMode must be "block" (default — actively refuse forwarding on
// pause/terminate) or "observe" (log only, preserves old pass-through behavior).
func NewProxy(agentID string, upstream []string, eng *engine.Engine, holder *authz.PolicyHolder, audit *Writer, enforceMode string) *Proxy {
	if enforceMode == "" {
		enforceMode = "block"
	}
	return &Proxy{
		agentID:     agentID,
		upstream:    upstream,
		eng:         eng,
		holder:      holder,
		audit:       audit,
		enforceMode: enforceMode,
		pending:     make(map[string]pendingReq),
		stopCh:      make(chan struct{}),
	}
}

// Run spawns the upstream MCP server and starts proxying.
func (p *Proxy) Run() error {
	cmd := exec.Command(p.upstream[0], p.upstream[1:]...)
	cmd.Stderr = os.Stderr
	p.cmd = cmd

	upstreamIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("upstream stdin pipe: %w", err)
	}
	upstreamOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("upstream stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting upstream %q: %w", p.upstream[0], err)
	}

	slog.Info("gateway started", "agent", p.agentID, "upstream", p.upstream[0])

	var wg sync.WaitGroup
	wg.Add(2)

	// Agent → upstream
	go func() {
		defer wg.Done()
		defer upstreamIn.Close()
		p.fromAgent(os.Stdin, upstreamIn)
	}()

	// Upstream → agent
	go func() {
		defer wg.Done()
		p.fromUpstream(upstreamOut, os.Stdout)
	}()

	wg.Wait()
	return cmd.Wait()
}

// Stop signals the proxy to stop accepting new agent input. It is safe to
// call concurrently and from signal handlers. The caller should also call
// Drain to wait for in-flight requests to complete.
func (p *Proxy) Stop() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
	})
}

// Drain waits up to 5 seconds for all in-flight tools/call requests to
// complete, then sends SIGTERM to the upstream subprocess.
func (p *Proxy) Drain() {
	p.Stop()

	// Wait for in-flight requests with a 5-second deadline.
	drained := make(chan struct{})
	go func() {
		p.inFlight.Wait()
		close(drained)
	}()

	select {
	case <-drained:
		slog.Info("all in-flight requests drained")
	case <-time.After(5 * time.Second):
		slog.Warn("drain timeout: some in-flight requests may not have completed")
	}

	// Signal upstream to terminate.
	if p.cmd != nil && p.cmd.Process != nil {
		if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			slog.Warn("failed to signal upstream process", "error", err)
		}
	}
}

func (p *Proxy) nextSeq() int64 {
	return atomic.AddInt64(&p.seqCounter, 1)
}

// fromAgent reads messages from the agent, applies RBAC, and forwards to upstream.
func (p *Proxy) fromAgent(in io.Reader, out io.Writer) {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	enc := json.NewEncoder(out)

	for scanner.Scan() {
		// Check if we should stop accepting new input.
		select {
		case <-p.stopCh:
			slog.Info("fromAgent: stop signal received, halting agent input")
			return
		default:
		}

		var msg message
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			slog.Warn("agent parse error", "error", err)
			continue
		}

		// Notifications have no ID — pass through untouched.
		if len(msg.ID) == 0 || string(msg.ID) == "null" {
			enc.Encode(msg)
			continue
		}

		idKey := string(msg.ID)

		switch msg.Method {
		case "tools/call":
			p.handleToolsCall(msg, idKey, enc)

		case "tools/list":
			// No RBAC on list itself — just track it so we can filter the response.
			p.mu.Lock()
			p.pending[idKey] = pendingReq{method: "tools/list", start: time.Now()}
			p.mu.Unlock()
			enc.Encode(msg)

		default:
			enc.Encode(msg)
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		slog.Error("agent read error", "error", err)
	}
}

// handleToolsCall runs RBAC on a tools/call request.
// Denied calls get a JSON-RPC error response; allowed calls are forwarded.
func (p *Proxy) handleToolsCall(msg message, idKey string, enc *json.Encoder) {
	// Track in-flight from the very top — guarantees Drain sees this request
	// in the WaitGroup even if it's denied or errors out before forwarding.
	p.inFlight.Add(1)
	allowed := false
	defer func() {
		if !allowed {
			p.inFlight.Done()
		}
	}()

	var params toolsCallParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		slog.Warn("tools/call params parse error", "error", err)
		enc.Encode(msg) // forward anyway — upstream will validate
		return
	}

	seq := p.nextSeq()
	evt := session.SessionEvent{
		SessionID: p.eng.Session.SessionID,
		AgentID:   p.agentID,
		EventSeq:  seq,
		Timestamp: time.Now(),
		Direction: "request",
		Method:    "tools/call",
		ToolName:  params.Name,
		RequestID: idKey,
		Payload:   params.Arguments,
	}

	dec, findings, disposition := p.eng.ProcessEvent(evt)

	// Behavioral enforcement hook (P1.9): consult the session disposition and
	// decide whether to block this request before forwarding upstream.
	// Use the disposition returned by ProcessEvent (captured under the mutex)
	// rather than reading p.eng.Session.Disposition directly, to avoid a race
	// with the concurrent fromUpstream goroutine.
	enfDec := DecideEnforcement(disposition, findings, p.enforceMode)

	// Write request-side audit row (with enforcement outcome).
	p.writeRequestAuditWithEnforcement(evt, dec, params.Arguments, enfDec, findings)

	if dec != nil && !dec.Allowed {
		reason := dec.Reason
		slog.Warn("DENIED", "agent", p.agentID, "tool", params.Name, "reason", reason)

		enc.Encode(message{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Error: &rpcError{
				Code:    -32001,
				Message: "flint: " + reason,
			},
		})
		return
	}

	if enfDec.Block {
		slog.Warn("BLOCKED", "agent", p.agentID, "tool", params.Name, "rule", enfDec.CitedRuleID, "disposition", disposition)
		enc.Encode(buildBlockedRequestResponse(msg.ID, enfDec.CitedRuleID, findings))
		return
	}

	slog.Info("ALLOWED", "agent", p.agentID, "tool", params.Name)

	// Mark allowed so the deferred Done() doesn't fire — fromUpstream owns
	// the Done() once the response arrives (or the connection closes).
	allowed = true
	p.mu.Lock()
	p.pending[idKey] = pendingReq{method: "tools/call", toolName: params.Name, start: time.Now()}
	p.mu.Unlock()

	enc.Encode(msg)
}

// fromUpstream reads responses from the upstream server and forwards to the agent,
// feeding allowed tool responses into the behavioral engine.
func (p *Proxy) fromUpstream(in io.Reader, out io.Writer) {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	enc := json.NewEncoder(out)

	for scanner.Scan() {
		var msg message
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			slog.Warn("upstream parse error", "error", err)
			out.Write(scanner.Bytes())
			out.Write([]byte("\n"))
			continue
		}

		// Server notifications — pass through.
		if len(msg.ID) == 0 || string(msg.ID) == "null" {
			enc.Encode(msg)
			continue
		}

		idKey := string(msg.ID)

		p.mu.Lock()
		req, ok := p.pending[idKey]
		if ok {
			delete(p.pending, idKey)
		}
		p.mu.Unlock()

		if !ok {
			enc.Encode(msg)
			continue
		}

		switch req.method {
		case "tools/call":
			p.handleToolsCallResponse(&msg, idKey, req.toolName, req.start)
			p.inFlight.Done()

		case "tools/list":
			if msg.Result != nil && msg.Error == nil {
				msg.Result = p.filterToolsList(msg.Result)
			}
		}

		enc.Encode(msg)
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		slog.Error("upstream read error", "error", err)
	}
}

// handleToolsCallResponse feeds the response into the behavioral engine,
// applies the enforcement hook, and writes a response-side audit row.
// msg is a pointer: when the response is blocked, msg.Result is overwritten in
// place with the blocked-response shape so the caller's enc.Encode(msg) forwards
// the replacement instead of the original upstream payload. Returns true when
// the response was blocked.
func (p *Proxy) handleToolsCallResponse(msg *message, idKey, toolName string, start time.Time) (blocked bool) {
	if msg.Result == nil || msg.Error != nil {
		return false
	}

	var payload map[string]any
	if err := json.Unmarshal(msg.Result, &payload); err != nil {
		return false
	}

	latencyMs := time.Since(start).Seconds() * 1000

	evt := session.SessionEvent{
		SessionID: p.eng.Session.SessionID,
		AgentID:   p.agentID,
		EventSeq:  p.nextSeq(),
		Timestamp: time.Now(),
		Direction: "response",
		Method:    "tools/call",
		ToolName:  toolName,
		RequestID: idKey,
		Payload:   payload,
	}

	_, findings, disposition := p.eng.ProcessEvent(evt)

	for _, f := range findings {
		slog.Info("FINDING",
			"rule", f.RuleID,
			"severity", f.Severity,
			"score", f.Score,
		)
	}

	// Behavioral enforcement hook (P1.9): block the response if the session
	// disposition is pause or terminate.
	// Use the disposition returned by ProcessEvent (captured under the mutex)
	// rather than reading p.eng.Session.Disposition directly, to avoid a race
	// with the concurrent fromAgent goroutine.
	enfDec := DecideEnforcement(disposition, findings, p.enforceMode)

	// Write response-side audit row (with enforcement outcome).
	p.writeResponseAuditWithEnforcement(evt, latencyMs, findings, enfDec)

	if enfDec.Block {
		slog.Warn("BLOCKED_RESPONSE", "agent", p.agentID, "tool", toolName, "rule", enfDec.CitedRuleID, "disposition", disposition)
		// Replace msg.Result in-place so that the caller's enc.Encode sends the
		// blocked payload instead of the original result.
		replacement := buildBlockedResponseResult(enfDec.CitedRuleID)
		replacementBytes, err := json.Marshal(replacement)
		if err == nil {
			msg.Result = replacementBytes
		}
		return true
	}
	return false
}

// writeRequestAuditWithEnforcement emits a "request" direction audit row.
// enfDec carries the enforcement outcome for behavioral findings. RBAC denials
// override the enforced_action to "blocked_rbac" to distinguish them.
func (p *Proxy) writeRequestAuditWithEnforcement(
	evt session.SessionEvent,
	dec *session.PolicyDecision,
	args map[string]any,
	enfDec EnforcementDecision,
	findings []session.Finding,
) {
	if p.audit == nil {
		return
	}

	findingRows := make([]api.FindingRow, 0, len(findings))
	for _, f := range findings {
		findingRows = append(findingRows, api.FindingRow{
			RuleID:   f.RuleID,
			Severity: f.Severity,
			Score:    f.Score,
			Message:  f.Message,
			Action:   f.Action,
		})
	}

	row := api.DecisionRow{
		TS:             evt.Timestamp.UTC().Format(time.RFC3339Nano),
		SessionID:      evt.SessionID,
		AgentID:        evt.AgentID,
		ToolName:       evt.ToolName,
		Direction:      "request",
		RequestID:      evt.RequestID,
		EventSeq:       evt.EventSeq,
		Findings:       findingRows,
		SchemaVersion:  api.AuditSchemaVersion,
		EnforcedAction: enfDec.EnforcedAction,
	}

	if dec != nil {
		row.Allowed = dec.Allowed
		row.Reason = dec.Reason
		row.Constraint = dec.Constraint
		row.MatchedRole = dec.MatchedRole
		row.MatchedRule = dec.MatchedRule
		row.MatchedRuleName = dec.MatchedRuleName
		row.RequiredVerb = dec.RequiredVerb
		row.GrantedVerb = dec.GrantedVerb
		row.EvaluatedScopes = dec.EvaluatedScopes

		// Fallback for matched rule name per spec §3.
		if row.MatchedRuleName == "" && dec.MatchedRole != "" {
			row.MatchedRuleName = fmt.Sprintf("%s#%d", dec.MatchedRole, dec.MatchedRule)
		}

		// RBAC-denied requests are hard-blocked; override with distinct value.
		if !dec.Allowed {
			row.EnforcedAction = "blocked_rbac"
		}
	}

	// Payload excerpt — best effort, truncated to 256 bytes.
	row.PayloadExcerpt = buildExcerpt(args)

	if err := p.audit.Write(row); err != nil {
		slog.Warn("audit write error (request)", "error", err)
	}
}

// writeResponseAuditWithEnforcement emits a "response" direction audit row
// with latency, findings, and enforcement outcome.
func (p *Proxy) writeResponseAuditWithEnforcement(
	evt session.SessionEvent,
	latencyMs float64,
	findings []session.Finding,
	enfDec EnforcementDecision,
) {
	if p.audit == nil {
		return
	}

	findingRows := make([]api.FindingRow, 0, len(findings))
	for _, f := range findings {
		findingRows = append(findingRows, api.FindingRow{
			RuleID:   f.RuleID,
			Severity: f.Severity,
			Score:    f.Score,
			Message:  f.Message,
			Action:   f.Action,
		})
	}

	row := api.DecisionRow{
		TS:             evt.Timestamp.UTC().Format(time.RFC3339Nano),
		SessionID:      evt.SessionID,
		AgentID:        evt.AgentID,
		ToolName:       evt.ToolName,
		Direction:      "response",
		Allowed:        true,
		RequestID:      evt.RequestID,
		EventSeq:       evt.EventSeq,
		LatencyMs:      &latencyMs,
		Findings:       findingRows,
		SchemaVersion:  api.AuditSchemaVersion,
		EnforcedAction: enfDec.EnforcedAction,
	}

	if err := p.audit.Write(row); err != nil {
		slog.Warn("audit write error (response)", "error", err)
	}
}

// buildBlockedRequestResponse constructs a JSON-RPC error response to send
// back to the agent when a request is blocked by the behavioral engine.
// The JSON-RPC spec requires the response ID to echo the request ID.
// Code -32001 is a custom application error (not reserved by JSON-RPC 2.0).
func buildBlockedRequestResponse(id json.RawMessage, ruleID string, findings []session.Finding) message {
	type findingSummary struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
	}
	var fSummaries []findingSummary
	for _, f := range findings {
		fSummaries = append(fSummaries, findingSummary{RuleID: f.RuleID, Severity: f.Severity})
	}
	// fSummaries reserved for a future rpcError.Data field (not in rpcError struct today).
	_ = fSummaries

	rpcMsg := "blocked by flint"
	if ruleID != "" {
		rpcMsg = "blocked by flint: " + ruleID
	}
	return message{
		JSONRPC: "2.0",
		ID:      id,
		Error: &rpcError{
			Code:    -32001,
			Message: rpcMsg,
		},
	}
}

// buildBlockedResponseResult constructs the MCP tool-call error shape used to
// replace a blocked upstream response before forwarding to the agent.
// Shape: {"content": [{"type": "text", "text": "blocked by flint: <rule>"}], "isError": true}
func buildBlockedResponseResult(ruleID string) map[string]any {
	msg := "blocked by flint"
	if ruleID != "" {
		msg = "blocked by flint: " + ruleID
	}
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": msg},
		},
		"isError": true,
	}
}

// buildExcerpt marshals args to JSON and returns up to 256 bytes, truncated
// on a UTF-8 rune boundary so multi-byte characters never split.
// Returns empty string when args is nil or marshaling fails.
func buildExcerpt(args map[string]any) string {
	if args == nil {
		return ""
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	const maxExcerpt = 256
	if len(raw) <= maxExcerpt {
		return string(raw)
	}
	// Walk back from maxExcerpt to the nearest valid UTF-8 boundary.
	cut := maxExcerpt
	for cut > 0 && !utf8.RuneStart(raw[cut]) {
		cut--
	}
	return string(raw[:cut])
}

// filterToolsList removes tools the agent has no binding for.
func (p *Proxy) filterToolsList(result json.RawMessage) json.RawMessage {
	policy := p.holder.Get()
	if policy == nil {
		return result
	}

	var res struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(result, &res); err != nil {
		return result
	}

	filtered := make([]json.RawMessage, 0, len(res.Tools))
	for _, raw := range res.Tools {
		var info struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &info); err != nil {
			continue
		}
		if authz.CanDiscover(policy, p.agentID, info.Name) {
			filtered = append(filtered, raw)
		}
	}

	out, err := json.Marshal(map[string]any{"tools": filtered})
	if err != nil {
		return result
	}
	return out
}

// lastDecisionFor returns the most recent PolicyDecision for the given tool name,
// or nil if none is found.
func lastDecisionFor(decisions []session.PolicyDecision, toolName string) *session.PolicyDecision {
	for i := len(decisions) - 1; i >= 0; i-- {
		d := decisions[i]
		if d.ToolName == toolName {
			return &decisions[i]
		}
	}
	return nil
}

// denialReason extracts the denial reason from the most recent matching PolicyDecision.
func denialReason(decisions []session.PolicyDecision, toolName string) string {
	for i := len(decisions) - 1; i >= 0; i-- {
		d := decisions[i]
		if !d.Allowed && d.ToolName == toolName {
			return d.Reason
		}
	}
	return "access denied"
}
