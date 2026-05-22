package routing

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// modelIDRegex is the syntactic check for OpenRouter model IDs.
// Form: <provider>/<model-name> where both parts may contain letters, digits,
// dots, underscores, hyphens, and colons (for variant tags like ":free").
var modelIDRegex = regexp.MustCompile(`^[a-z0-9._-]+/[a-z0-9._:-]+$`)

// validTasks is the canonical set of task labels the classifier can return.
var validTasks = map[string]bool{
	"code":           true,
	"classification": true,
	"rag":            true,
	"summarization":  true,
	"conversation":   true,
	"vision":         true,
	"other":          true,
}

// validComplexities is the canonical set of complexity labels.
var validComplexities = map[string]bool{
	"low":    true,
	"medium": true,
	"high":   true,
}

// validCapabilities is the canonical set of capability labels.
var validCapabilities = map[string]bool{
	"vision":       true,
	"tool_use":     true,
	"long_context": true,
	"reasoning":    true,
}

// validIfKeys is the set of keys allowed inside an `if:` block.
var validIfKeys = map[string]bool{
	"task":                    true,
	"complexity":              true,
	"capabilities_include":    true,
	"capabilities_all":        true, // alias, accepted but treated as capabilities_include
	"messages_min_length":     true,
	"messages_total_tokens_gt": true,
}

// ---------------------------------------------------------------------------
// YAML input types
// ---------------------------------------------------------------------------

// yamlPolicyFile is the raw YAML shape before compilation.
type yamlPolicyFile struct {
	SchemaVersion int              `yaml:"schema_version"`
	Classifier    yamlClassifier   `yaml:"classifier"`
	Routes        []yamlRule       `yaml:"routes"`
	Default       yamlDefaultRoute `yaml:"default"`
	Baseline      yamlBaseline     `yaml:"baseline"`
}

type yamlClassifier struct {
	Model     string `yaml:"model"`
	TimeoutMs int    `yaml:"timeout_ms"`
	MaxTokens int    `yaml:"max_tokens"`
}

// yamlRule uses yaml.Node for the If block so we can detect unknown keys.
type yamlRule struct {
	Name     string    `yaml:"name"`
	If       yaml.Node `yaml:"if"`
	Target   string    `yaml:"target"`
	Fallback []string  `yaml:"fallback"`
	Reason   string    `yaml:"reason"`
}

// yamlIfBlock is the typed representation of a rule's if-block.
type yamlIfBlock struct {
	Task                  interface{} `yaml:"task"`
	Complexity            interface{} `yaml:"complexity"`
	CapabilitiesInclude   interface{} `yaml:"capabilities_include"`
	CapabilitiesAll       interface{} `yaml:"capabilities_all"`
	MessagesMinLength     int         `yaml:"messages_min_length"`
	MessagesTotalTokensGT int         `yaml:"messages_total_tokens_gt"`
}

type yamlDefaultRoute struct {
	Target   string   `yaml:"target"`
	Fallback []string `yaml:"fallback"`
	Reason   string   `yaml:"reason"`
}

type yamlBaseline struct {
	Model string `yaml:"model"`
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// LoadPolicy reads router-policy.yaml from disk and returns a compiled Policy.
// All validation errors are collected and joined; structural errors (file
// missing, YAML parse failure) return immediately.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("routing: reading %s: %w", path, err)
	}
	return LoadPolicyBytes(data)
}

// LoadPolicyBytes is the same as LoadPolicy but operates on bytes. Used by the
// control plane's PUT validation flow before the temp file is committed.
func LoadPolicyBytes(data []byte) (*Policy, error) {
	var raw yamlPolicyFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("routing: YAML parse error: %w", err)
	}
	return compile(raw)
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

// compile validates the parsed YAML and returns a compiled Policy.
// All validation errors are collected before returning.
func compile(raw yamlPolicyFile) (*Policy, error) {
	var errs []error
	var warnings []string

	// 1. Schema version
	if raw.SchemaVersion == 0 {
		errs = append(errs, fmt.Errorf("routing: schema_version is required"))
	} else if raw.SchemaVersion != SchemaVersion {
		errs = append(errs, fmt.Errorf("routing: schema_version %d not supported (want %d)", raw.SchemaVersion, SchemaVersion))
	}

	// 2. Classifier
	classifier := ClassifierConfig{
		Model:     raw.Classifier.Model,
		TimeoutMs: raw.Classifier.TimeoutMs,
		MaxTokens: raw.Classifier.MaxTokens,
	}
	if classifier.Model == "" {
		errs = append(errs, fmt.Errorf("routing: classifier.model is required"))
	}
	if classifier.TimeoutMs != 0 && (classifier.TimeoutMs < 100 || classifier.TimeoutMs > 30000) {
		errs = append(errs, fmt.Errorf("routing: classifier.timeout_ms must be in [100, 30000], got %d", classifier.TimeoutMs))
	}
	if classifier.TimeoutMs == 0 {
		classifier.TimeoutMs = 1500 // default
	}
	if classifier.MaxTokens == 0 {
		classifier.MaxTokens = 150 // default
	}

	// 3. Default
	if raw.Default.Target == "" {
		errs = append(errs, fmt.Errorf("routing: default.target is required"))
	}
	if raw.Default.Target != "" && !modelIDRegex.MatchString(raw.Default.Target) {
		errs = append(errs, fmt.Errorf("routing: default.target %q is not a valid model id", raw.Default.Target))
	}
	defaultRule := Rule{
		Name:     "<default>",
		Target:   raw.Default.Target,
		Fallback: raw.Default.Fallback,
		Reason:   raw.Default.Reason,
	}
	for i, fb := range defaultRule.Fallback {
		if !modelIDRegex.MatchString(fb) {
			errs = append(errs, fmt.Errorf("routing: default.fallback[%d] %q is not a valid model id", i, fb))
		}
	}

	// 4. Baseline
	baseline := Baseline{Model: raw.Baseline.Model}
	if baseline.Model == "" {
		errs = append(errs, fmt.Errorf("routing: baseline.model is required"))
	}

	// 5. Routes
	ruleNames := make(map[string]int) // name -> first index
	routes := make([]Rule, 0, len(raw.Routes))

	for i, yr := range raw.Routes {
		if yr.Name == "" {
			errs = append(errs, fmt.Errorf("routing: routes[%d].name is required", i))
		}
		if yr.Target == "" {
			errs = append(errs, fmt.Errorf("routing: routes[%d] (%q): target is required", i, yr.Name))
		}
		if yr.Target != "" && !modelIDRegex.MatchString(yr.Target) {
			errs = append(errs, fmt.Errorf("routing: routes[%d] (%q): target %q is not a valid model id", i, yr.Name, yr.Target))
		}

		// Check duplicate names
		if yr.Name != "" {
			if prev, dup := ruleNames[yr.Name]; dup {
				warnings = append(warnings, fmt.Sprintf("routing: routes[%d] and routes[%d] have the same name %q", prev, i, yr.Name))
			} else {
				ruleNames[yr.Name] = i
			}
		}

		// Validate fallback model ids
		for j, fb := range yr.Fallback {
			if !modelIDRegex.MatchString(fb) {
				errs = append(errs, fmt.Errorf("routing: routes[%d] (%q): fallback[%d] %q is not a valid model id", i, yr.Name, j, fb))
			}
		}

		// Parse if-block
		matchCond, condErrs := parseIfBlock(yr.If, i, yr.Name)
		errs = append(errs, condErrs...)

		if matchCond.IsEmpty() && yr.Name != "" {
			warnings = append(warnings, fmt.Sprintf("routing: routes[%d] (%q): if-block is empty — this rule matches everything", i, yr.Name))
		}

		routes = append(routes, Rule{
			Name:     yr.Name,
			If:       matchCond,
			Target:   yr.Target,
			Fallback: yr.Fallback,
			Reason:   yr.Reason,
		})
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return &Policy{
		SchemaVersion: raw.SchemaVersion,
		Classifier:    classifier,
		Routes:        routes,
		Default:       defaultRule,
		Baseline:      baseline,
		Warnings:      warnings,
	}, nil
}

// parseIfBlock converts a yaml.Node representing the if-block into a MatchCondition.
// It validates all keys and values, collecting errors.
func parseIfBlock(node yaml.Node, ruleIdx int, ruleName string) (MatchCondition, []error) {
	var errs []error
	var mc MatchCondition

	if node.Kind == 0 {
		// Empty/missing if-block — fine, means match-all
		return mc, nil
	}

	// Check for unknown keys by inspecting the raw YAML mapping node
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			if !validIfKeys[key] {
				errs = append(errs, fmt.Errorf("routing: routes[%d] (%q): unknown if-key %q", ruleIdx, ruleName, key))
			}
		}
	}

	// Decode into typed struct
	var ifBlock yamlIfBlock
	if err := node.Decode(&ifBlock); err != nil {
		errs = append(errs, fmt.Errorf("routing: routes[%d] (%q): if-block decode error: %w", ruleIdx, ruleName, err))
		return mc, errs
	}

	// task
	tasks, taskErrs := toStringList(ifBlock.Task, fmt.Sprintf("routes[%d] (%q) if.task", ruleIdx, ruleName))
	errs = append(errs, taskErrs...)
	for _, t := range tasks {
		if !validTasks[t] {
			errs = append(errs, fmt.Errorf("routing: routes[%d] (%q): invalid task value %q", ruleIdx, ruleName, t))
		}
	}
	mc.Task = tasks

	// complexity
	complexities, compErrs := toStringList(ifBlock.Complexity, fmt.Sprintf("routes[%d] (%q) if.complexity", ruleIdx, ruleName))
	errs = append(errs, compErrs...)
	for _, c := range complexities {
		if !validComplexities[c] {
			errs = append(errs, fmt.Errorf("routing: routes[%d] (%q): invalid complexity value %q", ruleIdx, ruleName, c))
		}
	}
	mc.Complexity = complexities

	// capabilities_include (and alias capabilities_all)
	capsRaw := ifBlock.CapabilitiesInclude
	if capsRaw == nil {
		capsRaw = ifBlock.CapabilitiesAll
	}
	caps, capErrs := toStringList(capsRaw, fmt.Sprintf("routes[%d] (%q) if.capabilities_include", ruleIdx, ruleName))
	errs = append(errs, capErrs...)
	for _, cap := range caps {
		if !validCapabilities[cap] {
			errs = append(errs, fmt.Errorf("routing: routes[%d] (%q): invalid capability value %q", ruleIdx, ruleName, cap))
		}
	}
	mc.CapabilitiesInclude = caps

	// messages_min_length
	if ifBlock.MessagesMinLength < 0 {
		errs = append(errs, fmt.Errorf("routing: routes[%d] (%q): messages_min_length must be non-negative", ruleIdx, ruleName))
	} else {
		mc.MessagesMinLength = ifBlock.MessagesMinLength
	}

	// messages_total_tokens_gt
	if ifBlock.MessagesTotalTokensGT < 0 {
		errs = append(errs, fmt.Errorf("routing: routes[%d] (%q): messages_total_tokens_gt must be non-negative", ruleIdx, ruleName))
	} else {
		mc.MessagesTotalTokGT = ifBlock.MessagesTotalTokensGT
	}

	return mc, errs
}

// toStringList converts an interface{} that may be a string or []interface{} to []string.
// fieldName is used in error messages.
func toStringList(v interface{}, fieldName string) ([]string, []error) {
	if v == nil {
		return nil, nil
	}
	switch val := v.(type) {
	case string:
		return []string{val}, nil
	case []interface{}:
		out := make([]string, 0, len(val))
		var errs []error
		for i, item := range val {
			s, ok := item.(string)
			if !ok {
				errs = append(errs, fmt.Errorf("routing: %s[%d] must be a string, got %T", fieldName, i, item))
				continue
			}
			out = append(out, s)
		}
		return out, errs
	default:
		return nil, []error{fmt.Errorf("routing: %s must be a string or list of strings, got %T", fieldName, v)}
	}
}
