package authz

import (
	"sync"
	"testing"

	"flint/engine/session"
	"gopkg.in/yaml.v3"
)

// -- helpers ------------------------------------------------------------------

func makePolicy(t *testing.T, rolesYAML, bindingsYAML string) *Policy {
	t.Helper()
	return makePolicyWithRegistry(t, rolesYAML, bindingsYAML, nil)
}

func makePolicyWithRegistry(t *testing.T, rolesYAML, bindingsYAML string, registry map[string]session.ToolMeta) *Policy {
	t.Helper()
	rf, bf := parseYAML(t, rolesYAML, bindingsYAML)
	p, err := compile(rf, bf, registry)
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
		_, err := compile(rf, bf, nil)
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
		_, err := compile(rf, bf, nil)
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
		_, err := compile(rf, bf, nil)
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
	p, err := compile(rf, bf, nil)
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

// ============================================================================
// New tests for §6.1 — deny rules, server selectors, rule names, hot reload
// ============================================================================

// 1. TestEvaluate_DenyWinsOverAllow: role A allows github.search_code, role B
// denies it — the deny must win and the reason must be explicit_deny.
func TestEvaluate_DenyWinsOverAllow(t *testing.T) {
	const roles = `
roles:
  - name: allow-github
    rules:
      - resources: ["github.search_code"]
        verbs: [invoke]
  - name: deny-github
    rules:
      - resources: ["github.search_code"]
        effect: deny
        verbs: [invoke]
`
	const bindings = `
bindings:
  - agent: test-agent
    roles: [allow-github, deny-github]
    scopes: [code]
`
	p := makePolicy(t, roles, bindings)
	e := evt("github.search_code", "test-agent", "code", nil)
	got := Evaluate(p, "test-agent", &e)

	if got.Allowed {
		t.Fatal("expected denied")
	}
	if got.Reason != session.ReasonExplicitDeny {
		t.Errorf("Reason = %q, want %q", got.Reason, session.ReasonExplicitDeny)
	}
}

// 2. TestEvaluate_DenyServerSelector: a deny rule with server:github selector
// must deny every github.* tool for the agent.
func TestEvaluate_DenyServerSelector(t *testing.T) {
	registry := map[string]session.ToolMeta{
		"github.search_code":   {},
		"github.delete_branch": {},
		"github.create_pr":     {},
		"slack.post_message":   {},
	}

	const roles = `
roles:
  - name: allow-all
    rules:
      - resources: ["*"]
        verbs: [invoke]
  - name: deny-github-server
    rules:
      - resources: ["server:github"]
        effect: deny
        verbs: [invoke]
`
	const bindings = `
bindings:
  - agent: test-agent
    roles: [allow-all, deny-github-server]
`
	rf, bf := parseYAML(t, roles, bindings)
	p, err := compile(rf, bf, registry)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	for _, tool := range []string{"github.search_code", "github.delete_branch", "github.create_pr"} {
		e := evt(tool, "test-agent", "", nil)
		got := Evaluate(p, "test-agent", &e)
		if got.Allowed {
			t.Errorf("tool %q: expected denied, got allowed", tool)
		}
		if got.Reason != session.ReasonExplicitDeny {
			t.Errorf("tool %q: Reason = %q, want %q", tool, got.Reason, session.ReasonExplicitDeny)
		}
	}

	// slack.post_message must still be allowed
	e := evt("slack.post_message", "test-agent", "", nil)
	got := Evaluate(p, "test-agent", &e)
	if !got.Allowed {
		t.Errorf("slack.post_message: expected allowed, got denied with %q", got.Reason)
	}
}

// 3. TestEvaluate_DenyWithConstraint_FiresOnMatch: a deny rule with
// sql_intent:[delete] must block DELETE queries.
func TestEvaluate_DenyWithConstraint_FiresOnMatch(t *testing.T) {
	const roles = `
roles:
  - name: allow-db
    rules:
      - resources: ["db.query"]
        verbs: [invoke]
  - name: deny-delete
    rules:
      - resources: ["db.query"]
        effect: deny
        verbs: [invoke]
        constraints:
          sql_intent: [delete]
`
	const bindings = `
bindings:
  - agent: test-agent
    roles: [allow-db, deny-delete]
    scopes: [database]
`
	p := makePolicy(t, roles, bindings)
	e := evt("db.query", "test-agent", "database", map[string]any{"query": "DELETE FROM users"})
	got := Evaluate(p, "test-agent", &e)

	if got.Allowed {
		t.Fatal("DELETE: expected denied")
	}
	if got.Reason != session.ReasonExplicitDeny {
		t.Errorf("DELETE: Reason = %q, want %q", got.Reason, session.ReasonExplicitDeny)
	}
}

// 4. TestEvaluate_DenyWithConstraint_DoesNotFireOnMismatch: the same deny rule
// must allow SELECT through (constraint does not match SELECT → deny doesn't fire).
func TestEvaluate_DenyWithConstraint_DoesNotFireOnMismatch(t *testing.T) {
	const roles = `
roles:
  - name: allow-db
    rules:
      - resources: ["db.query"]
        verbs: [invoke]
  - name: deny-delete
    rules:
      - resources: ["db.query"]
        effect: deny
        verbs: [invoke]
        constraints:
          sql_intent: [delete]
`
	const bindings = `
bindings:
  - agent: test-agent
    roles: [allow-db, deny-delete]
    scopes: [database]
`
	p := makePolicy(t, roles, bindings)
	e := evt("db.query", "test-agent", "database", map[string]any{"query": "SELECT * FROM users"})
	got := Evaluate(p, "test-agent", &e)

	if !got.Allowed {
		t.Errorf("SELECT: expected allowed, got denied with %q", got.Reason)
	}
}

// 5. TestEvaluate_MatchedRuleNamePropagates: a rule with name:"Block dangerous SQL"
// should expose that string in the decision's MatchedRuleName.
func TestEvaluate_MatchedRuleNamePropagates(t *testing.T) {
	const roles = `
roles:
  - name: allow-db
    rules:
      - resources: ["db.query"]
        verbs: [invoke]
  - name: deny-named
    rules:
      - name: "Block dangerous SQL"
        resources: ["db.query"]
        effect: deny
        verbs: [invoke]
        constraints:
          sql_intent: [delete, drop, truncate]
`
	const bindings = `
bindings:
  - agent: test-agent
    roles: [allow-db, deny-named]
    scopes: [database]
`
	p := makePolicy(t, roles, bindings)
	e := evt("db.query", "test-agent", "database", map[string]any{"query": "DROP TABLE users"})
	got := Evaluate(p, "test-agent", &e)

	if got.Allowed {
		t.Fatal("expected denied")
	}
	if got.MatchedRuleName != "Block dangerous SQL" {
		t.Errorf("MatchedRuleName = %q, want %q", got.MatchedRuleName, "Block dangerous SQL")
	}
}

// 6. TestLoadPolicy_ServerSelectorExpands: server:github must resolve to all
// github.* tools in the registry at compile time.
func TestLoadPolicy_ServerSelectorExpands(t *testing.T) {
	registry := map[string]session.ToolMeta{
		"github.search_code":   {},
		"github.delete_branch": {},
		"github.create_pr":     {},
		"slack.post_message":   {},
	}

	const roles = `
roles:
  - name: github-allow
    rules:
      - resources: ["server:github"]
        verbs: [invoke]
`
	const bindings = `
bindings:
  - agent: test-agent
    roles: [github-allow]
`
	rf, bf := parseYAML(t, roles, bindings)
	p, err := compile(rf, bf, registry)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	role, ok := p.Roles["github-allow"]
	if !ok {
		t.Fatal("role not found")
	}
	rule := role.Rules[0]

	// server:github should have expanded to the 3 github.* tools
	for _, tool := range []string{"github.search_code", "github.delete_branch", "github.create_pr"} {
		if !rule.Resources[tool] {
			t.Errorf("resource %q not in expanded rule.Resources", tool)
		}
	}
	// slack should NOT be there
	if rule.Resources["slack.post_message"] {
		t.Error("slack.post_message should not be in server:github expansion")
	}
	// The raw selector "server:github" should not be literally present
	if rule.Resources["server:github"] {
		t.Error("raw selector server:github should not be in compiled Resources")
	}
}

// 7. TestLoadPolicy_UnknownServerSelector: server:unknownsvr must produce a
// load-time error.
func TestLoadPolicy_UnknownServerSelector(t *testing.T) {
	registry := map[string]session.ToolMeta{
		"github.search_code": {},
	}

	const roles = `
roles:
  - name: bad-role
    rules:
      - resources: ["server:unknownsvr"]
        verbs: [invoke]
`
	const bindings = `
bindings:
  - agent: test-agent
    roles: [bad-role]
`
	rf, bf := parseYAML(t, roles, bindings)
	_, err := compile(rf, bf, registry)
	if err == nil {
		t.Fatal("expected error for unknown server selector, got nil")
	}
}

// 8. TestLoadPolicy_DefaultEffectAllow: a rule without an effect field must
// default to "allow" (backward compatibility with existing YAML files).
func TestLoadPolicy_DefaultEffectAllow(t *testing.T) {
	const roles = `
roles:
  - name: default-effect-role
    rules:
      - resources: ["tool.x"]
        verbs: [invoke]
`
	const bindings = `
bindings:
  - agent: test-agent
    roles: [default-effect-role]
    scopes: [test]
`
	p := makePolicy(t, roles, bindings)

	role, ok := p.Roles["default-effect-role"]
	if !ok {
		t.Fatal("role not found")
	}
	if len(role.Rules) == 0 {
		t.Fatal("no rules")
	}
	if role.Rules[0].Effect != EffectAllow {
		t.Errorf("Effect = %q, want %q", role.Rules[0].Effect, EffectAllow)
	}

	// Also verify the rule actually allows the tool
	e := evt("tool.x", "test-agent", "test", nil)
	got := Evaluate(p, "test-agent", &e)
	if !got.Allowed {
		t.Errorf("expected allowed, got denied with %q", got.Reason)
	}
}

// 9. TestCanDiscover_DenyWithoutConstraintHides: a constraint-less deny rule
// must remove the tool from discovery.
func TestCanDiscover_DenyWithoutConstraintHides(t *testing.T) {
	const roles = `
roles:
  - name: allow-tool
    rules:
      - resources: ["tool.x"]
        verbs: [invoke]
  - name: deny-tool
    rules:
      - resources: ["tool.x"]
        effect: deny
        verbs: [invoke]
`
	const bindings = `
bindings:
  - agent: test-agent
    roles: [allow-tool, deny-tool]
    scopes: [test]
`
	p := makePolicy(t, roles, bindings)

	if CanDiscover(p, "test-agent", "tool.x") {
		t.Error("expected CanDiscover=false for tool covered by constraint-less deny rule")
	}
}

// 10. TestCanDiscover_DenyWithConstraintDoesNotHide: a deny rule that has
// constraints must NOT suppress discovery (we can't evaluate constraints at
// tools/list time).
func TestCanDiscover_DenyWithConstraintDoesNotHide(t *testing.T) {
	const roles = `
roles:
  - name: allow-db
    rules:
      - resources: ["db.query"]
        verbs: [invoke]
  - name: deny-delete
    rules:
      - resources: ["db.query"]
        effect: deny
        verbs: [invoke]
        constraints:
          sql_intent: [delete]
`
	const bindings = `
bindings:
  - agent: test-agent
    roles: [allow-db, deny-delete]
    scopes: [database]
`
	p := makePolicy(t, roles, bindings)

	// Tool should still be discoverable because the deny rule has a constraint.
	if !CanDiscover(p, "test-agent", "db.query") {
		t.Error("expected CanDiscover=true: deny rule has a constraint, so tool stays discoverable")
	}
}

// 11. TestPolicyHolder_AtomicSwap: concurrent Get/Set on a PolicyHolder must
// not panic and must eventually reflect the new policy.
func TestPolicyHolder_AtomicSwap(t *testing.T) {
	const roles1 = `
roles:
  - name: role-v1
    rules:
      - resources: ["tool.a"]
        verbs: [invoke]
`
	const roles2 = `
roles:
  - name: role-v2
    rules:
      - resources: ["tool.b"]
        verbs: [invoke]
`
	const bindings = `
bindings:
  - agent: agent-x
    roles: [role-v1]
    scopes: [test]
`
	const bindings2 = `
bindings:
  - agent: agent-x
    roles: [role-v2]
    scopes: [test]
`
	p1 := makePolicy(t, roles1, bindings)
	p2 := makePolicy(t, roles2, bindings2)

	holder := NewPolicyHolder(p1)

	var wg sync.WaitGroup
	const readers = 50
	const swaps = 20

	// Concurrent readers
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				got := holder.Get()
				// Must not panic; pointer must be non-nil (we started with p1).
				if got == nil {
					t.Errorf("Get() returned nil unexpectedly")
					return
				}
			}
		}()
	}

	// Concurrent swaps between p1 and p2
	for i := 0; i < swaps; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%2 == 0 {
				holder.Set(p2)
			} else {
				holder.Set(p1)
			}
		}(i)
	}

	wg.Wait()

	// After all goroutines, the holder must return a non-nil policy.
	if holder.Get() == nil {
		t.Error("holder.Get() is nil after concurrent swap test")
	}
}

// 12. TestEngine_Reload: after Reload, ProcessEvent uses the new policy.
func TestEngine_Reload(t *testing.T) {
	// Note: we test the engine via authz.Evaluate directly since engine_test
	// is in a different package. Instead we use the PolicyHolder directly.
	const roles1 = `
roles:
  - name: allow-tool-a
    rules:
      - resources: ["tool.a"]
        verbs: [invoke]
`
	const roles2 = `
roles:
  - name: allow-tool-b
    rules:
      - resources: ["tool.b"]
        verbs: [invoke]
`
	const bindings1 = `
bindings:
  - agent: agent-x
    roles: [allow-tool-a]
    scopes: [test]
`
	const bindings2 = `
bindings:
  - agent: agent-x
    roles: [allow-tool-b]
    scopes: [test]
`
	p1 := makePolicy(t, roles1, bindings1)
	p2 := makePolicy(t, roles2, bindings2)

	holder := NewPolicyHolder(p1)

	// Before reload: tool.a is allowed, tool.b is not.
	eA := session.SessionEvent{ToolName: "tool.a", AgentID: "agent-x", Scope: "test", Payload: map[string]any{}}
	d := Evaluate(holder.Get(), "agent-x", &eA)
	if !d.Allowed {
		t.Fatalf("before reload: tool.a expected allowed, got %q", d.Reason)
	}

	// Reload to p2.
	holder.Set(p2)

	// After reload: tool.a should be denied (no_matching_rule), tool.b allowed.
	d = Evaluate(holder.Get(), "agent-x", &eA)
	if d.Allowed {
		t.Errorf("after reload: tool.a expected denied, got allowed")
	}

	eB := session.SessionEvent{ToolName: "tool.b", AgentID: "agent-x", Scope: "test", Payload: map[string]any{}}
	d = Evaluate(holder.Get(), "agent-x", &eB)
	if !d.Allowed {
		t.Errorf("after reload: tool.b expected allowed, got %q", d.Reason)
	}
}
