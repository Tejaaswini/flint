package routing

// ClassifierOutput is the parsed result from the classifier model call.
// This type lives here (not in pkg/api) to keep engine/routing free of HTTP
// wire-type dependencies. cmd/router/classifier.go maps between the two.
type ClassifierOutput struct {
	Task         string
	Complexity   string
	Capabilities []string
	Reasoning    string
}

// MessagesContext carries the subset of incoming request data that the
// evaluator needs for length/token conditions. This avoids importing any
// OpenAI client type into the engine package.
type MessagesContext struct {
	// TotalChars is the total character count of all messages[*].content.
	TotalChars int

	// EstTokens is the estimated total token count. By convention: TotalChars/4.
	EstTokens int
}

// RouteDecision is the result of evaluating a Policy against a classifier output.
type RouteDecision struct {
	// MatchedRuleName is the Name of the rule that matched, or "<default>" if no
	// named rule matched and the default was used, or "" if the policy was nil.
	MatchedRuleName string

	// TargetModel is the model to send the request to.
	TargetModel string

	// FallbackModels is the ordered list of fallback models to try on upstream failure.
	FallbackModels []string

	// Reason is the human-readable reason from the matched rule.
	Reason string
}

// Evaluate is a pure function: walks policy.Routes in order and returns a
// RouteDecision for the first rule whose if-block matches the given classifier
// output and messages context. Falls back to policy.Default if no rule matches.
//
// It never returns an error. If policy is nil it returns a zero RouteDecision
// (empty TargetModel) — the caller is responsible for guarding against this.
func Evaluate(policy *Policy, c ClassifierOutput, ctx MessagesContext) RouteDecision {
	if policy == nil {
		return RouteDecision{}
	}

	for _, rule := range policy.Routes {
		if matchesRule(rule.If, c, ctx) {
			return RouteDecision{
				MatchedRuleName: rule.Name,
				TargetModel:     rule.Target,
				FallbackModels:  rule.Fallback,
				Reason:          rule.Reason,
			}
		}
	}

	// No named rule matched — use default.
	return RouteDecision{
		MatchedRuleName: policy.Default.Name,
		TargetModel:     policy.Default.Target,
		FallbackModels:  policy.Default.Fallback,
		Reason:          policy.Default.Reason,
	}
}

// matchesRule returns true iff all non-empty conditions in mc match the given
// classifier output and message context. Empty conditions are not constraining.
func matchesRule(mc MatchCondition, c ClassifierOutput, ctx MessagesContext) bool {
	// task
	if len(mc.Task) > 0 && !containsString(mc.Task, c.Task) {
		return false
	}

	// complexity
	if len(mc.Complexity) > 0 && !containsString(mc.Complexity, c.Complexity) {
		return false
	}

	// capabilities_include: every required capability must be present
	if len(mc.CapabilitiesInclude) > 0 {
		for _, required := range mc.CapabilitiesInclude {
			if !containsString(c.Capabilities, required) {
				return false
			}
		}
	}

	// messages_min_length
	if mc.MessagesMinLength > 0 && ctx.TotalChars < mc.MessagesMinLength {
		return false
	}

	// messages_total_tokens_gt
	if mc.MessagesTotalTokGT > 0 && ctx.EstTokens <= mc.MessagesTotalTokGT {
		return false
	}

	return true
}

// containsString reports whether s appears in the slice haystack.
func containsString(haystack []string, s string) bool {
	for _, h := range haystack {
		if h == s {
			return true
		}
	}
	return false
}
