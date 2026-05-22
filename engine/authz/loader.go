package authz

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"flint/engine/session"

	"gopkg.in/yaml.v3"
)

// knownConstraints is the set of constraint type names recognized by the evaluator.
// Any constraint name not in this set is a load-time error.
var knownConstraints = map[string]bool{
	"sql_intent":  true,
	"path_prefix": true,
}

// ConstraintMode controls behavior when a payload field is missing.
type ConstraintMode string

const (
	ConstraintStrict     ConstraintMode = "strict"
	ConstraintPermissive ConstraintMode = "permissive"
)

// Constraint is a compiled single constraint on a rule.
type Constraint struct {
	Type    string
	Allowed []string
	Mode    ConstraintMode
}

// EffectAllow and EffectDeny are the two valid rule effects.
const (
	EffectAllow = "allow"
	EffectDeny  = "deny"
)

// Rule is a compiled rule within a role.
type Rule struct {
	Resources   map[string]bool
	MaxVerb     string
	Constraints []Constraint
	Effect      string // "allow" | "deny"; default "allow"
	Name        string // optional human label; may be empty string
}

// Role is a compiled collection of rules.
type Role struct {
	Name  string
	Rules []Rule
}

// Binding is the compiled entry for a single agent — merged from all binding entries.
type Binding struct {
	AgentID string
	Roles   []string
	Scopes  map[string]bool // normalized lowercase; nil means unscoped (wildcard)
}

// Policy is the compiled, immutable result of loading roles and bindings.
type Policy struct {
	Roles    map[string]Role
	Bindings map[string]Binding
}

// -- YAML input types ---------------------------------------------------------

type yamlConstraint struct {
	Mode string `yaml:"mode"`
}

type yamlRule struct {
	Name        string              `yaml:"name"`
	Effect      string              `yaml:"effect"`
	Resources   []string            `yaml:"resources"`
	Verbs       []string            `yaml:"verbs"`
	Constraints map[string][]string `yaml:"constraints"`
	Mode        map[string]string   `yaml:"constraint_modes"` // optional: per-constraint mode override
}

type yamlRole struct {
	Name  string     `yaml:"name"`
	Rules []yamlRule `yaml:"rules"`
}

type yamlRolesFile struct {
	Roles []yamlRole `yaml:"roles"`
}

type yamlBinding struct {
	Agent  string   `yaml:"agent"`
	Roles  []string `yaml:"roles"`
	Scopes []string `yaml:"scopes"`
}

type yamlBindingsFile struct {
	Bindings []yamlBinding `yaml:"bindings"`
}

// -- LoadPolicy ---------------------------------------------------------------

// LoadPolicy reads roles and bindings YAML files and returns a compiled Policy.
// The registry parameter is used to expand server selectors (e.g. "server:github").
// Pass nil only in tests that do not use server selectors; production callers
// always pass the gateway's loaded registry.
// All validation errors are collected and returned together.
// Structural failures (missing file, malformed YAML) return immediately.
func LoadPolicy(rolesPath, bindingsPath string, registry map[string]session.ToolMeta) (*Policy, error) {
	rolesData, err := os.ReadFile(rolesPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", rolesPath, err)
	}
	bindingsData, err := os.ReadFile(bindingsPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", bindingsPath, err)
	}

	var rf yamlRolesFile
	if err := yaml.Unmarshal(rolesData, &rf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", rolesPath, err)
	}
	var bf yamlBindingsFile
	if err := yaml.Unmarshal(bindingsData, &bf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", bindingsPath, err)
	}

	return compile(rf, bf, registry)
}

// compile validates and compiles the parsed YAML into a Policy.
// All validation errors are collected; the first structural error does not abort others.
func compile(rf yamlRolesFile, bf yamlBindingsFile, registry map[string]session.ToolMeta) (*Policy, error) {
	var errs []error

	// -- Compile roles --------------------------------------------------------
	roles := make(map[string]Role, len(rf.Roles))
	roleNames := make(map[string]bool)

	for _, yr := range rf.Roles {
		if yr.Name == "" {
			errs = append(errs, fmt.Errorf("role has empty name"))
			continue
		}
		if roleNames[yr.Name] {
			errs = append(errs, fmt.Errorf("duplicate role name: %q", yr.Name))
			continue
		}
		roleNames[yr.Name] = true

		compiled, ruleErrs := compileRole(yr, registry)
		errs = append(errs, ruleErrs...)
		roles[yr.Name] = compiled
	}

	// -- Compile bindings (merge duplicates) ----------------------------------
	type partialBinding struct {
		roles  []string
		scopes []string // nil means unscoped
	}
	partials := make(map[string]*partialBinding)
	order := []string{} // preserve first-seen order for determinism

	for _, yb := range bf.Bindings {
		if yb.Agent == "" {
			errs = append(errs, fmt.Errorf("binding has empty agent name"))
			continue
		}
		if _, seen := partials[yb.Agent]; !seen {
			partials[yb.Agent] = &partialBinding{}
			order = append(order, yb.Agent)
		}
		p := partials[yb.Agent]
		p.roles = append(p.roles, yb.Roles...)
		p.scopes = append(p.scopes, yb.Scopes...)
	}

	// Validate role references and build final bindings
	bindings := make(map[string]Binding, len(partials))
	for _, agentID := range order {
		p := partials[agentID]

		for _, roleName := range p.roles {
			if !roleNames[roleName] {
				errs = append(errs, fmt.Errorf("binding for agent %q references unknown role %q", agentID, roleName))
			}
		}

		var scopeMap map[string]bool // nil = unscoped (wildcard)
		if len(p.scopes) > 0 {
			scopeMap = make(map[string]bool, len(p.scopes))
			for _, s := range p.scopes {
				normalized := normalizeScope(s)
				scopeMap[normalized] = true
			}
		}

		bindings[agentID] = Binding{
			AgentID: agentID,
			Roles:   dedup(p.roles),
			Scopes:  scopeMap,
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return &Policy{Roles: roles, Bindings: bindings}, nil
}

// compileRole compiles a single yamlRole into a Role, collecting errors.
func compileRole(role yamlRole, registry map[string]session.ToolMeta) (Role, []error) {
	var errs []error
	rules := make([]Rule, 0, len(role.Rules))

	for i, rule := range role.Rules {
		if len(rule.Resources) == 0 {
			errs = append(errs, fmt.Errorf("role %q rule %d: empty resources list", role.Name, i))
			continue
		}
		if len(rule.Verbs) == 0 {
			errs = append(errs, fmt.Errorf("role %q rule %d: empty verbs list", role.Name, i))
			continue
		}

		maxVerb, verbErr := highestVerb(rule.Verbs)
		if verbErr != nil {
			errs = append(errs, fmt.Errorf("role %q rule %d: %w", role.Name, i, verbErr))
			continue
		}

		// Resolve resources (may include server selectors and wildcards).
		resources := make(map[string]bool)
		for _, r := range rule.Resources {
			expanded, selErr := resolveSelector(r, registry)
			if selErr != nil {
				errs = append(errs, fmt.Errorf("role %q rule %d resource %q: %w", role.Name, i, r, selErr))
				continue
			}
			for _, name := range expanded {
				resources[name] = true
			}
		}

		constraints, cErrs := compileConstraints(rule.Constraints, rule.Mode)
		errs = append(errs, cErrs...)

		// Parse effect; default to "allow" for backward compatibility.
		effect := rule.Effect
		if effect == "" {
			effect = EffectAllow
		}
		if effect != EffectAllow && effect != EffectDeny {
			errs = append(errs, fmt.Errorf("role %q rule %d: unknown effect %q (must be allow or deny)", role.Name, i, effect))
			continue
		}

		rules = append(rules, Rule{
			Resources:   resources,
			MaxVerb:     maxVerb,
			Constraints: constraints,
			Effect:      effect,
			Name:        rule.Name, // may be empty string — that is valid
		})
	}

	return Role{Name: role.Name, Rules: rules}, errs
}

// resolveSelector expands a resource selector to the list of concrete tool names.
//
// Selector forms:
//   - bare tool name (e.g. "github.search_code")   → returned as-is
//   - "server:<name>"                               → all tools whose name starts with "<name>."
//   - "server:*" or "*"                             → every tool in the registry
//
// If the registry is nil, bare names and wildcards are returned unchanged; but
// server:<name> selectors (other than server:*) require the registry to validate
// the prefix and will return a load-time error when the registry is nil.
//
// Returns a load-time error if the server:<name> prefix matches no tools in the
// registry (unknown server).
func resolveSelector(resource string, registry map[string]session.ToolMeta) ([]string, error) {
	// Wildcard — all tools
	if resource == "*" || resource == "server:*" {
		if registry == nil {
			// No registry: return the wildcard verbatim so the hot path's
			// rule.Resources["*"] check still works.
			return []string{"*"}, nil
		}
		out := make([]string, 0, len(registry))
		for name := range registry {
			out = append(out, name)
		}
		return out, nil
	}

	// Server-prefix selector
	if strings.HasPrefix(resource, "server:") {
		serverName := strings.TrimPrefix(resource, "server:")
		if registry == nil {
			// Cannot validate without registry; treat as load-time error.
			return nil, fmt.Errorf("server selector %q requires a registry (registry is nil)", resource)
		}
		prefix := serverName + "."
		var out []string
		for name := range registry {
			if strings.HasPrefix(name, prefix) {
				out = append(out, name)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("server selector %q matches no tools in registry (unknown server)", resource)
		}
		return out, nil
	}

	// Bare tool name — returned as-is regardless of registry.
	return []string{resource}, nil
}

// compileConstraints validates and compiles the constraints map from a rule.
func compileConstraints(raw map[string][]string, modes map[string]string) ([]Constraint, []error) {
	var errs []error
	var out []Constraint

	for name, allowed := range raw {
		if !knownConstraints[name] {
			errs = append(errs, fmt.Errorf("unknown constraint type %q", name))
			continue
		}
		mode := ConstraintStrict
		if m, ok := modes[name]; ok {
			switch ConstraintMode(m) {
			case ConstraintStrict, ConstraintPermissive:
				mode = ConstraintMode(m)
			default:
				errs = append(errs, fmt.Errorf("constraint %q: unknown mode %q (must be strict or permissive)", name, m))
				continue
			}
		}
		out = append(out, Constraint{Type: name, Allowed: allowed, Mode: mode})
	}

	return out, errs
}

// highestVerb returns the verb with the highest ordinal from a list.
func highestVerb(verbs []string) (string, error) {
	best := -1
	bestVerb := ""
	for _, v := range verbs {
		ord := session.VerbOrdinal(v)
		if ord < 0 {
			return "", fmt.Errorf("unknown verb %q", v)
		}
		if ord > best {
			best = ord
			bestVerb = v
		}
	}
	return bestVerb, nil
}

// normalizeScope lowercases and trims a scope string.
func normalizeScope(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// dedup returns a slice with duplicate strings removed, preserving order.
func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
