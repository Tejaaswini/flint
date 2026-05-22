package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"flint/pkg/api"
)

// nopGatewayClient is a GatewayClient test double that succeeds silently.
type nopGatewayClient struct{}

func (n *nopGatewayClient) Reload(_ context.Context) error {
	return nil
}
func (n *nopGatewayClient) Healthz(_ context.Context) (gatewayHealthz, error) {
	return gatewayHealthz{Status: "ok"}, nil
}

// TestRolesPut_RoundTrip verifies that PUT /api/v1/roles/:name writes the role
// and the response is ok=true.
func TestRolesPut_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	rolesPath := filepath.Join(dir, "roles.yaml")
	bindingsPath := filepath.Join(dir, "bindings.yaml")

	// Write minimal seed files.
	if err := os.WriteFile(rolesPath, []byte("roles:\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindingsPath, []byte(`bindings:
  - agent: test-agent
    roles: [test-role]
`), 0644); err != nil {
		t.Fatal(err)
	}

	state := NewState(rolesPath, bindingsPath, "", "", "")
	gw := &nopGatewayClient{}

	role := api.Role{
		Name: "test-role",
		Rules: []api.Rule{
			{
				Effect:    "allow",
				Resources: []string{"echo"},
				Verbs:     []string{"invoke"},
			},
		},
	}
	body, _ := json.Marshal(role)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/roles/test-role", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleRolesPut(state, gw)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp api.RolePutResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OK {
		t.Errorf("expected ok=true, got errors: %v", resp.Errors)
	}

	// Verify the YAML file was written with the role name.
	data, err := os.ReadFile(rolesPath)
	if err != nil {
		t.Fatalf("read roles: %v", err)
	}
	if !bytes.Contains(data, []byte("test-role")) {
		t.Errorf("roles file does not contain 'test-role':\n%s", data)
	}
}

// TestRolesPut_RejectsInvalidVerb verifies that a role with an unknown verb
// returns 400.
func TestRolesPut_RejectsInvalidVerb(t *testing.T) {
	dir := t.TempDir()
	rolesPath := filepath.Join(dir, "roles.yaml")
	bindingsPath := filepath.Join(dir, "bindings.yaml")

	if err := os.WriteFile(rolesPath, []byte("roles:\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindingsPath, []byte("bindings:\n"), 0644); err != nil {
		t.Fatal(err)
	}

	state := NewState(rolesPath, bindingsPath, "", "", "")
	gw := &nopGatewayClient{}

	role := api.Role{
		Name: "bad-role",
		Rules: []api.Rule{
			{
				Effect:    "allow",
				Resources: []string{"echo"},
				Verbs:     []string{"superadmin"}, // unknown verb
			},
		},
	}
	body, _ := json.Marshal(role)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/roles/bad-role", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleRolesPut(state, gw)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp api.RolePutResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.OK {
		t.Error("expected ok=false for invalid role")
	}
	if len(resp.Errors) == 0 {
		t.Error("expected at least one error message")
	}
}

// TestRolesList_ReadsFile verifies GET /api/v1/roles returns roles from YAML.
func TestRolesList_ReadsFile(t *testing.T) {
	dir := t.TempDir()
	rolesPath := filepath.Join(dir, "roles.yaml")

	yamlContent := `roles:
  - name: reader
    rules:
      - effect: allow
        resources: [echo]
        verbs: [invoke]
`
	if err := os.WriteFile(rolesPath, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	state := NewState(rolesPath, "", "", "", "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
	rec := httptest.NewRecorder()

	handleRolesList(state)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var roles []api.Role
	if err := json.NewDecoder(rec.Body).Decode(&roles); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(roles))
	}
	if roles[0].Name != "reader" {
		t.Errorf("expected role name 'reader', got %q", roles[0].Name)
	}
}
