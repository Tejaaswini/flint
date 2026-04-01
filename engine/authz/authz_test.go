package authz

import (
	"testing"

	"flint/engine/session"
	"gopkg.in/yaml.v3"
)

// -- helpers ------------------------------------------------------------------

func makePolicy(t *testing.T, rolesYAML, bindingsYAML string) *Policy {
	t.Helper()
	rf, bf := parseYAML(t, rolesYAML, bindingsYAML)
	p, err := compile(rf, bf)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

func parseYAML(t *testing.T, rolesYAML, bindingsYAML string) (yamlRolesFile, yamlBindingsFile) {
	t.Helper()
	import_yaml := func(src string, dst any) {
		t.Helper()
		if err := unmarshalString(src, dst); err != nil {
			t.Fatalf("yaml parse: %v", err)
		}
	}
	var rf yamlRolesFile
	var bf yamlBindingsFile
	import_yaml(rolesYAML, &rf)
	import_yaml(bindingsYAML, &bf)
	return rf, bf
}

func evt(tool, agent, scope string, payload map[string]any) session.SessionEvent {
	if payload == nil {
		payload = map[string]any{}
	}
	return session.SessionEvent{
		EventSeq:  1,
		ToolName:  tool,
		AgentID:   agent,
		Scope:     scope,
		RequestID: "req-1",
		Payload:   payload,
	}
}

// unmarshalString is a thin wrapper so test helpers can parse inline YAML.
func unmarshalString(src string, dst any) error {
	return yaml.Unmarshal([]byte(src), dst)
}

// -- fixtures -----------------------------------------------------------------

const rolesFixture = `
roles:
  - name: sql-readonly
    rules:
      - resources: ["db.query"]
        verbs: [invoke]
        constraints:
          sql_intent: [select]

  - name: support-agent
    rules:
      - resources: ["support.read_ticket"]
        verbs: [invoke]

  - name: code-reader
    rules:
      - resources: ["fs.read_file"]
        verbs: [invoke]
        constraints:
          path_prefix: ["/workspace/", "/repo/"]

  - name: discover-only
    rules:
      - resources: ["db.query"]
        verbs: [discover]

  - name: admin-role
    rules:
      - resources: ["*"]
        verbs: [admin]
        scopes: ["*"]
`

const bindingsFixture = `
bindings:
  - agent: support-bot
    roles: [sql-readonly, support-agent]
    scopes: [customer_data, support]

  - agent: code-agent
    roles: [code-reader]
    scopes: [local]

  - agent: discover-agent
    roles: [discover-only]
    scopes: [customer_data]

  - agent: wildcard-agent
    roles: [admin-role]
    scopes: ["*"]
`

// -- TestEvaluate -------------------------------------------------------------

func TestEvaluate(t *testing.T) {
	p := makePolicy(t, rolesFixture, bindingsFixture)

	tests := []struct {
		name       string
		policy     *Policy
		tool       string
		agent      string
		scope      string
		payload    map[string]any
		wantAllow  bool
		wantReason string
	}{
		// ---- passthrough and principal checks --------------------------------
		{
			name:       "no_policy_passthrough",
			policy:     nil,
			tool:       "db.query",
			agent:      "support-bot",
			scope:      "customer_data",
			wantAllow:  true,
			wantReason: session.ReasonNoPolicy,
		},
		{
			name:       "empty_principal_denied",
			policy:     p,
			tool:       "db.query",
			agent:      "",
			scope:      "customer_data",
			wantAllow:  false,
			wantReason: session.ReasonNoPrincipal,
		},

		// ---- binding checks --------------------------------------------------
		{
			name:       "no_binding",
			policy:     p,
			tool:       "db.query",
			agent:      "unknown-agent",
			scope:      "customer_data",
			wantAllow:  false,
			wantReason: session.ReasonNoBinding,
		},
		{
			name:       "scope_mismatch",
			policy:     p,
			tool:       "support.read_ticket",
			agent:      "support-bot",
			scope:      "finance", // not in support-bot's scopes
			wantAllow:  false,
			wantReason: session.ReasonScopeMismatch,
		},

		// ---- allow cases -----------------------------------------------------
		{
			name:       "allow_sql_select",
			policy:     p,
			tool:       "db.query",
			agent:      "support-bot",
			scope:      "customer_data",
			payload:    map[string]any{"query": "SELECT * FROM users"},
			wantAllow:  true,
			wantReason: session.ReasonAllowed,
		},
		{
			name:       "allow_support_read_ticket",
			policy:     p,
			tool:       "support.read_ticket",
			agent:      "support-bot",
			scope:      "support",
			wantAllow:  true,
			wantReason: session.ReasonAllowed,
		},
		{
			name:       "allow_path_prefix_workspace",
			policy:     p,
			tool:       "fs.read_file",
			agent:      "code-agent",
			scope:      "local",
			payload:    map[string]any{"path": "/workspace/main.go"},
			wantAllow:  true,
			wantReason: session.ReasonAllowed,
		},
		{
			name:       "allow_path_prefix_second_entry",
			policy:     p,
			tool:       "fs.read_file",
			agent:      "code-agent",
			scope:      "local",
			payload:    map[string]any{"path": "/repo/pkg/foo.go"},
			wantAllow:  true,
			wantReason: session.ReasonAllowed,
		},
		{
			name:       "allow_wildcard_scope_binding",
			policy:     p,
			tool:       "db.query",
			agent:      "wildcard-agent",
			scope:      "any_scope_at_all",
			wantAllow:  true,
			wantReason: session.ReasonAllowed,
		},
		{
			name:       "allow_empty_scope_event_wildcard_binding",
			policy:     p,
			tool:       "db.query",
			agent:      "wildcard-agent",
			scope:      "", // no scope on event, binding has *
			wantAllow:  true,
			wantReason: session.ReasonAllowed,
		},
		{
			name:       "allow_path_prefix_file_path_alias",
			policy:     p,
			tool:       "fs.read_file",
			agent:      "code-agent",
			scope:      "local",
			payload:    map[string]any{"file_path": "/workspace/config.go"}, // file_path alias, not path
			wantAllow:  true,
			wantReason: session.ReasonAllowed,
		},

		// ---- denial cases ----------------------------------------------------
		{
			name:       "no_matching_rule",
			policy:     p,
			tool:       "slack.send_message", // not in any support-bot role
			agent:      "support-bot",
			scope:      "customer_data",
			wantAllow:  false,
			wantReason: session.ReasonNoMatchingRule,
		},
		{
			name:       "verb_insufficient_discover_only",
			policy:     p,
			tool:       "db.query",
			agent:      "discover-agent",
			scope:      "customer_data",
			payload:    map[string]any{"query": "SELECT 1"},
			wantAllow:  false,
			wantReason: session.ReasonVerbInsufficient,
		},
		{
			name:       "constraint_violation_sql_delete",
			policy:     p,
			tool:       "db.query",
			agent:      "support-bot",
			scope:      "customer_data",
			payload:    map[string]any{"query": "DELETE FROM users"},
			wantAllow:  false,
			wantReason: session.ReasonConstraintViolation,
		},
		{
			name:       "constraint_violation_path_outside_prefix",
			policy:     p,
			tool:       "fs.read_file",
			agent:      "code-agent",
			scope:      "local",
			payload:    map[string]any{"path": "/etc/passwd"},
			wantAllow:  false,
			wantReason: session.ReasonConstraintViolation,
		},
		{
			name:       "constraint_unverifiable_strict_no_field",
			policy:     p,
			tool:       "db.query",
			agent:      "support-bot",
			scope:      "customer_data",
			payload:    map[string]any{"unrecognized_field": "SELECT 1"}, // no alias match
			wantAllow:  false,
			wantReason: session.ReasonConstraintUnverifiable,
		},
		{
			name:       "empty_scope_event_explicit_scope_binding",
			policy:     p,
			tool:       "db.query",
			agent:      "support-bot",
			scope:      "", // no scope on event, but support-bot has explicit scopes
			wantAllow:  false,
			wantReason: session.ReasonScopeMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := evt(tc.tool, tc.agent, tc.scope, tc.payload)
			got := Evaluate(tc.policy, tc.agent, &e)

			if got.Allowed != tc.wantAllow {
				t.Errorf("Allowed = %v, want %v", got.Allowed, tc.wantAllow)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tc.wantReason)
			}
		})
	}
}

// -- TestAdditiveRoles --------------------------------------------------------

// TestAdditiveRoles proves the engine never stops at the first denial —
// if role A fails but role B allows, the result must be allowed.
func TestAdditiveRoles(t *testing.T) {
	const roles = `
roles:
  - name: low-verb
    rules:
      - resources: ["db.query"]
        verbs: [discover]

  - name: full-access
    rules:
      - resources: ["db.query"]
        verbs: [invoke]
`
	const bindings = `
bindings:
  - agent: multi-role-agent
    roles: [low-verb, full-access]
    scopes: [database]
`
	p := makePolicy(t, roles, bindings)
	e := evt("db.query", "multi-role-agent", "database", nil)
	got := Evaluate(p, "multi-role-agent", &e)

	if !got.Allowed {
		t.Errorf("expected allowed, got denied with reason %q", got.Reason)
	}
}

// TestAdditiveRoles_ConstraintFailThenAllow: role A has constraint that fails,
// role B covers same tool without constraint — must allow.
func TestAdditiveRoles_ConstraintFailThenAllow(t *testing.T) {
	const roles = `
roles:
  - name: strict-sql
    rules:
      - resources: ["db.query"]
        verbs: [invoke]
        constraints:
          sql_intent: [select]

  - name: unrestricted-sql
    rules:
      - resources: ["db.query"]
        verbs: [invoke]
`
	const bindings = `
bindings:
  - agent: dual-agent
    roles: [strict-sql, unrestricted-sql]
    scopes: [database]
`
	p := makePolicy(t, roles, bindings)
	e := evt("db.query", "dual-agent", "database", map[string]any{"query": "DELETE FROM users"})
	got := Evaluate(p, "dual-agent", &e)

	if !got.Allowed {
		t.Errorf("expected allowed (unrestricted-sql covers it), got %q", got.Reason)
	}
}

// -- TestDenialPrecedence -----------------------------------------------------

// TestDenialPrecedence: when multiple candidates exist, constraint_violation
// should beat verb_insufficient.
func TestDenialPrecedence(t *testing.T) {
	const roles = `
roles:
  - name: low-verb-role
    rules:
      - resources: ["db.query"]
        verbs: [discover]

  - name: constrained-role
    rules:
      - resources: ["db.query"]
        verbs: [invoke]
        constraints:
          sql_intent: [select]
`
	const bindings = `
bindings:
  - agent: precedence-agent
    roles: [low-verb-role, constrained-role]
    scopes: [database]
`
	p := makePolicy(t, roles, bindings)
	// DELETE fails the constraint on constrained-role; low-verb-role produces verb_insufficient.
	// constraint_violation has higher precedence — should be the reported reason.
	e := evt("db.query", "precedence-agent", "database", map[string]any{"query": "DELETE FROM users"})
	got := Evaluate(p, "precedence-agent", &e)

	if got.Allowed {
		t.Fatal("expected denied")
	}
	if got.Reason != session.ReasonConstraintViolation {
		t.Errorf("Reason = %q, want %q", got.Reason, session.ReasonConstraintViolation)
	}
}

// -- TestDuplicateBindingsMerge -----------------------------------------------

func TestDuplicateBindingsMerge(t *testing.T) {
	const roles = `
roles:
  - name: role-a
    rules:
      - resources: ["tool.a"]
        verbs: [invoke]
  - name: role-b
    rules:
      - resources: ["tool.b"]
        verbs: [invoke]
`
	const bindings = `
bindings:
  - agent: merged-agent
    roles: [role-a]
    scopes: [scope-a]
  - agent: merged-agent
    roles: [role-b]
    scopes: [scope-b]
`
	p := makePolicy(t, roles, bindings)

	// Both tools should be accessible from their respective scopes
	eA := evt("tool.a", "merged-agent", "scope-a", nil)
	if got := Evaluate(p, "merged-agent", &eA); !got.Allowed {
		t.Errorf("tool.a in scope-a: expected allowed, got %q", got.Reason)
	}

	eB := evt("tool.b", "merged-agent", "scope-b", nil)
	if got := Evaluate(p, "merged-agent", &eB); !got.Allowed {
		t.Errorf("tool.b in scope-b: expected allowed, got %q", got.Reason)
	}
}

// -- TestScopeNormalization ---------------------------------------------------

func TestScopeNormalization(t *testing.T) {
	const roles = `
roles:
  - name: basic
    rules:
      - resources: ["tool.x"]
        verbs: [invoke]
`
	const bindings = `
bindings:
  - agent: norm-agent
    roles: [basic]
    scopes: [Customer_Data]
`
	p := makePolicy(t, roles, bindings)

	// Event scope in different case should still match after normalization
	e := evt("tool.x", "norm-agent", "customer_data", nil)
	got := Evaluate(p, "norm-agent", &e)
	if !got.Allowed {
		t.Errorf("expected scope normalization to match, got %q", got.Reason)
	}
}

// -- TestPolicyDecisionProvenance ---------------------------------------------

func TestPolicyDecisionProvenance(t *testing.T) {
	const roles = `
roles:
  - name: provenance-role
    rules:
      - resources: ["tool.x"]
        verbs: [invoke]
`
	const bindings = `
bindings:
  - agent: prov-agent
    roles: [provenance-role]
    scopes: [test]
`
	p := makePolicy(t, roles, bindings)
	e := evt("tool.x", "prov-agent", "test", nil)
	got := Evaluate(p, "prov-agent", &e)

	if !got.Allowed {
		t.Fatalf("expected allowed")
	}
	if got.MatchedRole != "provenance-role" {
		t.Errorf("MatchedRole = %q, want %q", got.MatchedRole, "provenance-role")
	}
	if got.GrantedVerb != session.VerbInvoke {
		t.Errorf("GrantedVerb = %q, want %q", got.GrantedVerb, session.VerbInvoke)
	}
}

// -- TestGrantedVerbOnDenial --------------------------------------------------

// TestGrantedVerbOnDenial verifies that GrantedVerb is set to the best available
// grant even when the call is denied due to verb_insufficient.
func TestGrantedVerbOnDenial(t *testing.T) {
	p := makePolicy(t, rolesFixture, bindingsFixture)

	// discover-agent holds discover-only role on db.query — verb too low for invoke
	e := evt("db.query", "discover-agent", "customer_data", map[string]any{"query": "SELECT 1"})
	got := Evaluate(p, "discover-agent", &e)

	if got.Allowed {
		t.Fatal("expected denied")
	}
	if got.Reason != session.ReasonVerbInsufficient {
		t.Fatalf("Reason = %q, want verb_insufficient", got.Reason)
	}
	if got.GrantedVerb != session.VerbDiscover {
		t.Errorf("GrantedVerb = %q, want %q — should show best available grant even on denial", got.GrantedVerb, session.VerbDiscover)
	}
}

// -- TestConstraintFieldOnDenial ----------------------------------------------

// TestConstraintFieldOnDenial verifies that PolicyDecision.Constraint is
// populated with the failing constraint name on denial.
func TestConstraintFieldOnDenial(t *testing.T) {
	p := makePolicy(t, rolesFixture, bindingsFixture)

	e := evt("db.query", "support-bot", "customer_data", map[string]any{"query": "DELETE FROM users"})
	got := Evaluate(p, "support-bot", &e)

	if got.Allowed {
		t.Fatal("expected denied")
	}
	if got.Reason != session.ReasonConstraintViolation {
		t.Fatalf("Reason = %q, want constraint_violation", got.Reason)
	}
	if got.Constraint != "sql_intent" {
		t.Errorf("Constraint = %q, want %q", got.Constraint, "sql_intent")
	}
}

// -- TestPermissiveConstraint -------------------------------------------------

func TestPermissiveConstraint(t *testing.T) {
	const roles = `
roles:
  - name: permissive-sql
    rules:
      - resources: ["db.query"]
        verbs: [invoke]
        constraints:
          sql_intent: [select]
        constraint_modes:
          sql_intent: permissive
`
	const bindings = `
bindings:
  - agent: perm-agent
    roles: [permissive-sql]
    scopes: [database]
`
	p := makePolicy(t, roles, bindings)

	// Missing field in permissive mode should pass
	e := evt("db.query", "perm-agent", "database", map[string]any{"unrecognized": "value"})
	got := Evaluate(p, "perm-agent", &e)
	if !got.Allowed {
		t.Errorf("permissive mode with missing field: expected allowed, got %q", got.Reason)
	}
}

// -- TestLoaderErrors ---------------------------------------------------------

func TestLoaderErrors(t *testing.T) {
	t.Run("unknown_constraint_type", func(t *testing.T) {
		const roles = `
roles:
  - name: bad-role
    rules:
      - resources: ["tool.x"]
        verbs: [invoke]
        constraints:
          nonexistent_constraint: [value]
`
		const bindings = `
bindings:
  - agent: agent-x
    roles: [bad-role]
    scopes: [test]
`
		var rf yamlRolesFile
		var bf yamlBindingsFile
		_ = unmarshalString(roles, &rf)
		_ = unmarshalString(bindings, &bf)
		_, err := compile(rf, bf)
		if err == nil {
			t.Fatal("expected error for unknown constraint type, got nil")
		}
	})

	t.Run("dangling_role_reference", func(t *testing.T) {
		const roles = `roles: []`
		const bindings = `
bindings:
  - agent: agent-x
    roles: [nonexistent-role]
    scopes: [test]
`
		var rf yamlRolesFile
		var bf yamlBindingsFile
		_ = unmarshalString(roles, &rf)
		_ = unmarshalString(bindings, &bf)
		_, err := compile(rf, bf)
		if err == nil {
			t.Fatal("expected error for dangling role reference, got nil")
		}
	})

	t.Run("invalid_verb", func(t *testing.T) {
		const roles = `
roles:
  - name: bad-verb-role
    rules:
      - resources: ["tool.x"]
        verbs: [superpower]
`
		const bindings = `bindings: []`
		var rf yamlRolesFile
		var bf yamlBindingsFile
		_ = unmarshalString(roles, &rf)
		_ = unmarshalString(bindings, &bf)
		_, err := compile(rf, bf)
		if err == nil {
			t.Fatal("expected error for invalid verb, got nil")
		}
	})
}

// -- TestLoaderCompiledContents -----------------------------------------------

func TestLoaderCompiledContents(t *testing.T) {
	const roles = `
roles:
  - name: sql-readonly
    rules:
      - resources: ["db.query"]
        verbs: [discover, invoke]
        constraints:
          sql_intent: [select, with]
`
	const bindings = `
bindings:
  - agent: test-agent
    roles: [sql-readonly]
    scopes: [database]
`
	var rf yamlRolesFile
	var bf yamlBindingsFile
	_ = unmarshalString(roles, &rf)
	_ = unmarshalString(bindings, &bf)
	p, err := compile(rf, bf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	role, ok := p.Roles["sql-readonly"]
	if !ok {
		t.Fatal("role sql-readonly not found")
	}
	if len(role.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(role.Rules))
	}
	rule := role.Rules[0]

	// discover + invoke → MaxVerb should be invoke (higher ordinal)
	if rule.MaxVerb != session.VerbInvoke {
		t.Errorf("MaxVerb = %q, want %q", rule.MaxVerb, session.VerbInvoke)
	}
	if !rule.Resources["db.query"] {
		t.Error("resource db.query not in compiled rule")
	}
	if len(rule.Constraints) != 1 {
		t.Fatalf("expected 1 constraint, got %d", len(rule.Constraints))
	}
	c := rule.Constraints[0]
	if c.Type != "sql_intent" {
		t.Errorf("constraint type = %q, want sql_intent", c.Type)
	}
	if len(c.Allowed) != 2 {
		t.Errorf("constraint allowed list = %v, want [select with]", c.Allowed)
	}

	// Binding contents
	binding, ok := p.Bindings["test-agent"]
	if !ok {
		t.Fatal("binding for test-agent not found")
	}
	if len(binding.Roles) != 1 || binding.Roles[0] != "sql-readonly" {
		t.Errorf("binding roles = %v, want [sql-readonly]", binding.Roles)
	}
	if !binding.Scopes["database"] {
		t.Error("scope database not in compiled binding")
	}
}
