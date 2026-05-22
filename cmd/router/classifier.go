package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
	"unicode/utf8"

	"flint/engine/routing"
)

// classifierSystemPrompt is the verbatim system message for the classifier.
// DO NOT change this without re-validating classifier accuracy.
const classifierSystemPrompt = `You are a classifier for an LLM routing system. You receive the user's conversation and you output a JSON object describing the task, so a router can pick the cheapest capable model.

You MUST output ONLY a JSON object with this exact shape, no prose, no markdown:

{
  "task": "code" | "classification" | "rag" | "summarization" | "conversation" | "vision" | "other",
  "complexity": "low" | "medium" | "high",
  "capabilities": [],
  "reasoning": "one short sentence"
}

The "capabilities" array MAY contain zero or more of: "vision", "tool_use", "long_context", "reasoning".

Guidelines:
- "code" = the user is asking to write, debug, refactor, or explain code.
- "classification" = label/categorize/score/judge a piece of text (spam, sentiment, intent, etc.). Usually short outputs.
- "rag" = answer a question grounded in a provided passage/context block.
- "summarization" = condense a longer input into a shorter output.
- "conversation" = open-ended chat without a clear task above.
- "vision" = the request includes image content or asks to describe/analyze an image.
- "other" = does not fit any category cleanly.

Complexity heuristic:
- low = trivial single-step task, short expected output.
- medium = multi-step but bounded (single file, single function, single paragraph).
- high = open-ended, multi-file, multi-paragraph, ambiguous, or requires planning.

If you are uncertain, prefer "other" + "medium" rather than guessing.`

// classifierUserTemplate is the user message template. {{prompt}} is replaced
// with the conversation content.
const classifierUserTemplate = `Classify the following conversation. Output JSON only.

---
%s
---`

// maxClassifierPromptChars is the maximum character count fed to the classifier.
// Long prompts are truncated at a UTF-8 boundary at this limit.
const maxClassifierPromptChars = 8000

// ClassifierMetrics carries the cost/latency metadata from a single classify call.
type ClassifierMetrics struct {
	LatencyMs  float64
	CostUSD    float64
	Model      string
	Failed     bool
	FailReason string
}

// Classifier wraps the OpenRouter client to perform task classification calls.
type Classifier struct {
	holder  *routing.PolicyHolder
	or      *OpenRouterClient
	pricing *PricingTable
}

// NewClassifier creates a Classifier that reads its config from the live policy holder.
func NewClassifier(holder *routing.PolicyHolder, or *OpenRouterClient, pricing *PricingTable) *Classifier {
	return &Classifier{holder: holder, or: or, pricing: pricing}
}

// Classify sends ONE OpenRouter call to classify the given prompt.
// It never returns an error to the caller — failures are encoded in
// metrics.Failed and the returned ClassifierOutput uses sentinel values
// (task="other", complexity="medium", capabilities=[], reasoning="<classifier_failed:reason>").
func (c *Classifier) Classify(ctx context.Context, prompt string) (routing.ClassifierOutput, ClassifierMetrics) {
	policy := c.holder.Get()
	if policy == nil {
		return classifierFailed("no_policy"), ClassifierMetrics{Failed: true, FailReason: "no_policy"}
	}

	cfg := policy.Classifier
	model := cfg.Model
	if model == "" {
		model = "openai/gpt-4o-mini"
	}
	timeoutMs := cfg.TimeoutMs
	if timeoutMs == 0 {
		timeoutMs = 1500
	}
	maxTokens := cfg.MaxTokens
	if maxTokens == 0 {
		maxTokens = 150
	}

	// Apply classifier-specific deadline
	classCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	truncatedPrompt := truncateUTF8(prompt, maxClassifierPromptChars)
	userMsg := fmt.Sprintf(classifierUserTemplate, truncatedPrompt)

	temp := 0.0
	req := &ChatRequest{
		Model: model,
		Messages: []ChatMessage{
			{Role: "system", Content: classifierSystemPrompt},
			{Role: "user", Content: userMsg},
		},
		MaxTokens:   maxTokens,
		Temperature: &temp,
		ResponseFormat: &ResponseFormat{
			Type: "json_object",
		},
	}

	t0 := time.Now()
	resp, _, err := c.or.Complete(classCtx, req)
	latencyMs := float64(time.Since(t0).Milliseconds())

	metrics := ClassifierMetrics{
		LatencyMs: latencyMs,
		Model:     model,
	}

	if err != nil {
		reason := classifyErrorReason(err, classCtx)
		slog.Warn("classifier call failed", "reason", reason, "latency_ms", latencyMs, "error", err)
		metrics.Failed = true
		metrics.FailReason = reason
		return classifierFailed(reason), metrics
	}

	// Extract cost from usage
	if resp.Usage != nil {
		if resp.Usage.Cost > 0 {
			metrics.CostUSD = resp.Usage.Cost
		} else {
			// Fall back to pricing table
			cost, found := c.pricing.Cost(model, resp.Usage.PromptTokens, resp.Usage.CompletionTokens)
			if !found {
				slog.Warn("classifier model not in pricing table", "model", model)
			}
			metrics.CostUSD = cost
		}
	}

	// Parse classifier JSON from the response content
	if len(resp.Choices) == 0 {
		reason := "empty_choices"
		metrics.Failed = true
		metrics.FailReason = reason
		return classifierFailed(reason), metrics
	}

	content := resp.Choices[0].Message.Content
	var output routing.ClassifierOutput
	if err := json.Unmarshal([]byte(content), &output); err != nil {
		reason := "parse"
		slog.Warn("classifier JSON parse error", "content", content, "error", err)
		metrics.Failed = true
		metrics.FailReason = reason
		return classifierFailed(reason), metrics
	}

	return output, metrics
}

// classifierFailed returns a sentinel ClassifierOutput for failure cases.
func classifierFailed(reason string) routing.ClassifierOutput {
	return routing.ClassifierOutput{
		Task:       "other",
		Complexity: "medium",
		Capabilities: []string{},
		Reasoning:  fmt.Sprintf("<classifier_failed:%s>", reason),
	}
}

// classifyErrorReason maps a classifier call error to a short reason string
// suitable for the audit row.
func classifyErrorReason(err error, ctx context.Context) string {
	if ctx.Err() != nil {
		return "timeout"
	}
	if orErr, ok := err.(*OpenRouterError); ok {
		switch orErr.StatusCode {
		case 401, 403:
			return "unauthorized"
		case 429:
			return "rate_limited"
		}
	}
	return "network"
}

// truncateUTF8 truncates s to at most maxChars bytes at a valid UTF-8 boundary.
func truncateUTF8(s string, maxChars int) string {
	if len(s) <= maxChars {
		return s
	}
	// Walk backwards from maxChars to find a valid rune boundary
	for i := maxChars; i > 0; i-- {
		if utf8.RuneStart(s[i]) {
			return s[:i]
		}
	}
	return s[:maxChars]
}
