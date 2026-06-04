package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
	"unicode/utf8"

	"flint/engine/routing"
	"flint/pkg/api"
)

const (
	// forwardTimeoutSecs is the default timeout for the upstream forward call.
	forwardTimeoutSecs = 60
	// promptExcerptMaxBytes is the maximum byte length of the prompt excerpt stored in the audit row.
	promptExcerptMaxBytes = 256
)

// Pipeline orchestrates classify → policy eval → forward → audit for each
// incoming /v1/chat/completions request.
type Pipeline struct {
	policy     *routing.PolicyHolder
	classifier *Classifier
	openrouter *OpenRouterClient
	audit      *AuditWriter
	pricing    *PricingTable
	inFlight   sync.WaitGroup
}

// NewPipeline creates a Pipeline.
func NewPipeline(
	policy *routing.PolicyHolder,
	classifier *Classifier,
	or *OpenRouterClient,
	audit *AuditWriter,
	pricing *PricingTable,
) *Pipeline {
	return &Pipeline{
		policy:     policy,
		classifier: classifier,
		openrouter: or,
		audit:      audit,
		pricing:    pricing,
	}
}

// Drain waits for all in-flight forward calls to complete, up to 5 seconds.
func (p *Pipeline) Drain() {
	done := make(chan struct{})
	go func() {
		p.inFlight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		slog.Warn("drain timeout: some in-flight requests may not have completed")
	}
}

// Process is the main entry point. It classifies, evaluates, forwards, audits,
// and returns the upstream ChatResponse plus the assembled RoutingDecision.
//
// Errors returned here are fatal HTTP errors (bad request, etc.). For upstream
// errors, the response body + status code are encoded in OpenRouterError; the
// caller must handle that separately.
func (p *Pipeline) Process(ctx context.Context, req *ChatRequest, requestID string) (*ChatResponse, []byte, *api.RoutingDecision, error) {
	t0 := time.Now()

	row := &api.RoutingDecision{
		TS:        t0.UTC().Format(time.RFC3339Nano),
		RequestID: requestID,
	}

	// Stream check — reject before any I/O
	if req.Stream {
		row.Error = "unsupported_stream"
		writeAudit(p.audit, *row)
		return nil, nil, row, &StreamNotSupportedError{}
	}

	// Extract prompt context for classifier and evaluator
	classifierPrompt, messagesCtx := buildMessagesContext(req.Messages)
	row.PromptExcerpt = promptExcerpt(classifierPrompt)

	// 1. Classify (latency is captured inside ClassifierMetrics)
	classOutput, classMetrics := p.classifier.Classify(ctx, classifierPrompt)

	row.ClassifierModel = classMetrics.Model
	row.ClassifierLatencyMs = classMetrics.LatencyMs
	row.ClassifierCostUSD = classMetrics.CostUSD
	row.ClassifierOutput = api.ClassifierOutput{
		Task:         classOutput.Task,
		Complexity:   classOutput.Complexity,
		Capabilities: classOutput.Capabilities,
		Reasoning:    classOutput.Reasoning,
	}
	if classMetrics.Failed {
		row.ClassifierFailed = true
		row.ClassifierFailReason = classMetrics.FailReason
	}

	// 2. Policy evaluation
	policy := p.policy.Get()
	decision := routing.Evaluate(policy, classOutput, messagesCtx)
	row.MatchedRuleName = decision.MatchedRuleName
	row.TargetModel = decision.TargetModel

	// Baseline cost reference
	var baselineModel string
	if policy != nil {
		baselineModel = policy.Baseline.Model
	}
	row.BaselineCostUSD = 0 // will be set after we know token counts

	// 3. Forward
	p.inFlight.Add(1)
	defer p.inFlight.Done()

	forwardReq := *req           // shallow copy
	forwardReq.Model = decision.TargetModel
	forwardReq.Stream = false    // always off

	var (
		resp    *ChatResponse
		rawBody []byte
		fwdErr  error
	)

	fwdTargets := append([]string{decision.TargetModel}, decision.FallbackModels...)
	var fallbacksTried []string

	t2 := time.Now()
	for i, target := range fwdTargets {
		if i > 0 {
			fallbacksTried = append(fallbacksTried, target)
		}
		forwardReq.Model = target

		fwdCtx, cancel := context.WithTimeout(ctx, forwardTimeoutSecs*time.Second)
		resp, rawBody, fwdErr = p.openrouter.Complete(fwdCtx, &forwardReq)
		cancel()

		if fwdErr == nil {
			// Success
			if i > 0 {
				row.TargetModel = target // update to the actual target used
			}
			break
		}

		// Check if 4xx — not retryable
		var orErr *OpenRouterError
		if errors.As(fwdErr, &orErr) && orErr.StatusCode >= 400 && orErr.StatusCode < 500 {
			slog.Warn("forward: 4xx from upstream, not retrying",
				"target", target, "status", orErr.StatusCode)
			row.Error = "upstream_4xx"
			break
		}

		// 5xx or network — try next fallback
		slog.Warn("forward: upstream error, trying fallback",
			"target", target, "error", fwdErr, "fallback_idx", i)
		if i == len(fwdTargets)-1 {
			row.Error = "upstream_5xx_after_fallbacks"
		}
	}

	row.FallbacksTried = fallbacksTried
	forwardLatencyMs := float64(time.Since(t2).Milliseconds())
	row.ForwardLatencyMs = forwardLatencyMs

	if fwdErr != nil {
		row.TotalLatencyMs = float64(time.Since(t0).Milliseconds())
		row.TotalCostUSD = row.ClassifierCostUSD
		writeAudit(p.audit, *row)
		return nil, rawBody, row, fwdErr
	}

	// 4. Extract cost + token counts
	if resp.Usage != nil {
		row.PromptTokens = resp.Usage.PromptTokens
		row.CompletionTokens = resp.Usage.CompletionTokens

		if resp.Usage.Cost > 0 {
			row.ForwardCostUSD = resp.Usage.Cost
		} else {
			cost, found := p.pricing.Cost(forwardReq.Model, resp.Usage.PromptTokens, resp.Usage.CompletionTokens)
			if !found {
				slog.Warn("model not in pricing table; recording cost=0", "model", forwardReq.Model)
			}
			row.ForwardCostUSD = cost
		}
	}

	// 5. Baseline cost (counterfactual)
	row.BaselineCostUSD = EstimateBaselineCost(p.pricing, row.PromptTokens, row.CompletionTokens, baselineModel)

	// 6. Totals
	row.TotalCostUSD = row.ClassifierCostUSD + row.ForwardCostUSD
	// Classifier-failed requests fell through to default rule; the routing was blind, so credit nothing as savings (see concerns.md C-002).
	if row.ClassifierFailed {
		row.SavingsUSD = 0
	} else {
		row.SavingsUSD = row.BaselineCostUSD - row.TotalCostUSD
	}
	row.TotalLatencyMs = float64(time.Since(t0).Milliseconds())

	// 7. Audit
	writeAudit(p.audit, *row)

	return resp, rawBody, row, nil
}

// buildMessagesContext extracts the combined prompt string and MessagesContext
// from a ChatRequest's messages list.
func buildMessagesContext(messages []ChatMessage) (string, routing.MessagesContext) {
	totalChars := 0
	var combined []byte
	for _, m := range messages {
		totalChars += len(m.Content)
		if len(combined) > 0 {
			combined = append(combined, '\n')
		}
		combined = append(combined, m.Content...)
	}
	prompt := string(combined)
	return prompt, routing.MessagesContext{
		TotalChars: totalChars,
		EstTokens:  totalChars / 4,
	}
}

// promptExcerpt returns the first 256 bytes of the prompt at a UTF-8 boundary.
func promptExcerpt(prompt string) string {
	if len(prompt) <= promptExcerptMaxBytes {
		return prompt
	}
	for i := promptExcerptMaxBytes; i > 0; i-- {
		if utf8.RuneStart(prompt[i]) {
			return prompt[:i]
		}
	}
	return prompt[:promptExcerptMaxBytes]
}

// writeAudit logs audit write errors but does not return them to the caller.
// The request pipeline should not fail because the audit writer had an issue.
func writeAudit(w *AuditWriter, row api.RoutingDecision) {
	if err := w.Write(row); err != nil {
		slog.Error("audit write failed", "error", err)
	}
}

// StreamNotSupportedError is returned when a client sends stream:true.
type StreamNotSupportedError struct{}

func (e *StreamNotSupportedError) Error() string {
	return "streaming not supported in v1"
}
