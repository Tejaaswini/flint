package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"flint/engine/authz"
	"flint/pkg/api"
)

// handleRolesList handles GET /api/v1/roles.
// Returns the roles parsed directly from the YAML file so the response shows
// the raw selectors as written (not expanded).
func handleRolesList(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		roles, err := readRolesFile(state.rolesPath)
		if err != nil {
			slog.Error("roles list: read failed", "err", err)
			http.Error(w, "failed to read roles", http.StatusInternalServerError)
			return
		}
		writeJSON200(w, roles)
	}
}

// handleRolesPut handles PUT /api/v1/roles/:name.
func handleRolesPut(state *State, gw GatewayClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/roles/")
		name = strings.Trim(name, "/")
		if name == "" {
			writeJSONStatus(w, http.StatusBadRequest, api.RolePutResponse{
				OK:     false,
				Errors: []string{"role name required in path"},
			})
			return
		}

		// Parse incoming JSON body.
		var incoming api.Role
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, api.RolePutResponse{
				OK:     false,
				Errors: []string{"invalid JSON: " + err.Error()},
			})
			return
		}
		incoming.Name = name // ensure name matches path

		// Read the current roles.yaml as a Node tree to preserve ordering.
		originalData, err := os.ReadFile(state.rolesPath)
		if err != nil {
			slog.Error("roles put: read original failed", "err", err)
			http.Error(w, "failed to read roles file", http.StatusInternalServerError)
			return
		}

		newYAML, err := upsertRoleInYAML(originalData, incoming)
		if err != nil {
			slog.Error("roles put: YAML transform failed", "err", err)
			writeJSONStatus(w, http.StatusInternalServerError, api.RolePutResponse{
				OK:     false,
				Errors: []string{"YAML transform: " + err.Error()},
			})
			return
		}

		// Write to a unique temp file in the same directory as rolesPath so
		// os.Rename stays on the same filesystem (avoids EXDEV) and
		// concurrent PUTs don't collide on a fixed name.
		tmpFile, err := os.CreateTemp(filepath.Dir(state.rolesPath), ".roles-*.tmp")
		if err != nil {
			slog.Error("roles put: create tmp failed", "err", err)
			http.Error(w, "failed to create temp file", http.StatusInternalServerError)
			return
		}
		tmpPath := tmpFile.Name()
		if _, err := tmpFile.Write(newYAML); err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			slog.Error("roles put: write tmp failed", "err", err)
			http.Error(w, "failed to write temp file", http.StatusInternalServerError)
			return
		}
		if err := tmpFile.Close(); err != nil {
			os.Remove(tmpPath)
			slog.Error("roles put: close tmp failed", "err", err)
			http.Error(w, "failed to close temp file", http.StatusInternalServerError)
			return
		}

		// Validate: attempt to load the new policy.
		registry := state.GetRegistry()
		newPolicy, policyErr := authz.LoadPolicy(tmpPath, state.bindingsPath, registry)
		if policyErr != nil {
			// Roll back: remove tmp, return 400.
			os.Remove(tmpPath)
			var errMsgs []string
			for _, line := range strings.Split(policyErr.Error(), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					errMsgs = append(errMsgs, line)
				}
			}
			writeJSONStatus(w, http.StatusBadRequest, api.RolePutResponse{
				OK:     false,
				Errors: errMsgs,
			})
			return
		}

		// Atomic rename.
		if err := os.Rename(tmpPath, state.rolesPath); err != nil {
			slog.Error("roles put: rename failed", "err", err)
			os.Remove(tmpPath)
			http.Error(w, "failed to commit roles file", http.StatusInternalServerError)
			return
		}

		// Update in-memory policy.
		state.SetPolicy(newPolicy)

		// Notify gateway (best effort).
		ctx, cancel := context.WithTimeout(r.Context(), reloadTimeout)
		defer cancel()
		if err := gw.Reload(ctx); err != nil {
			slog.Warn("roles put: gateway reload failed (file is written; gateway will reload on next SIGHUP)", "err", err)
			// Still return 200 — the file is written and policy is updated.
		} else {
			state.MarkGatewayOK()
		}

		writeJSON200(w, api.RolePutResponse{OK: true})
	}
}

// upsertRoleInYAML updates or inserts a role in the YAML document, preserving
// top-level structure and ordering using the yaml.v3 Node API.
func upsertRoleInYAML(original []byte, role api.Role) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(original, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal YAML: %w", err)
	}

	if doc.Kind == 0 {
		// Empty file — build a fresh document.
		doc = yaml.Node{
			Kind: yaml.DocumentNode,
			Content: []*yaml.Node{
				{
					Kind:    yaml.MappingNode,
					Tag:     "!!map",
					Content: []*yaml.Node{},
				},
			},
		}
	}

	root := doc.Content[0] // the mapping node at the top level

	// Find the "roles" key in the top-level mapping.
	rolesIdx := -1
	for i := 0; i < len(root.Content)-1; i += 2 {
		if root.Content[i].Value == "roles" {
			rolesIdx = i + 1
			break
		}
	}

	// Build the new role YAML node.
	newRoleNode, err := roleToNode(role)
	if err != nil {
		return nil, fmt.Errorf("encoding role to YAML: %w", err)
	}

	if rolesIdx == -1 {
		// No "roles" key yet — append it.
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "roles"}
		listNode := &yaml.Node{
			Kind:    yaml.SequenceNode,
			Tag:     "!!seq",
			Content: []*yaml.Node{newRoleNode},
		}
		root.Content = append(root.Content, keyNode, listNode)
	} else {
		rolesSeq := root.Content[rolesIdx]
		// If the existing "roles:" key has a null/missing value (e.g. an empty
		// file `roles:\n`), replace the scalar node with a fresh sequence
		// node so the append produces well-formed YAML.
		if rolesSeq.Kind != yaml.SequenceNode {
			rolesSeq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{}}
			root.Content[rolesIdx] = rolesSeq
		}
		// Find and replace existing role by name.
		found := false
		for i, item := range rolesSeq.Content {
			roleName := mappingValue(item, "name")
			if roleName == role.Name {
				rolesSeq.Content[i] = newRoleNode
				found = true
				break
			}
		}
		if !found {
			rolesSeq.Content = append(rolesSeq.Content, newRoleNode)
		}
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("marshal YAML: %w", err)
	}
	return out, nil
}

// roleToNode encodes an api.Role into a yaml.Node for insertion.
func roleToNode(role api.Role) (*yaml.Node, error) {
	// Marshal through yaml to get proper node structure.
	// We use an intermediate struct that maps to the YAML schema.
	type yamlRule struct {
		Name        string              `yaml:"name,omitempty"`
		Effect      string              `yaml:"effect"`
		Resources   []string            `yaml:"resources"`
		Verbs       []string            `yaml:"verbs"`
		Constraints map[string][]string `yaml:"constraints,omitempty"`
	}
	type yamlRole struct {
		Name  string     `yaml:"name"`
		Rules []yamlRule `yaml:"rules"`
	}

	yr := yamlRole{Name: role.Name}
	for _, r := range role.Rules {
		yr.Rules = append(yr.Rules, yamlRule{
			Name:        r.Name,
			Effect:      r.Effect,
			Resources:   r.Resources,
			Verbs:       r.Verbs,
			Constraints: r.Constraints,
		})
	}

	var node yaml.Node
	if err := node.Encode(yr); err != nil {
		return nil, err
	}
	// node.Encode wraps in a document node; unwrap.
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return node.Content[0], nil
	}
	return &node, nil
}

// mappingValue returns the string value for a given key in a YAML mapping node.
func mappingValue(node *yaml.Node, key string) string {
	if node.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i < len(node.Content)-1; i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1].Value
		}
	}
	return ""
}

// readRolesFile parses the roles YAML and returns api.Role slice with raw selectors.
func readRolesFile(path string) ([]api.Role, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	type yamlRule struct {
		Name        string              `yaml:"name"`
		Effect      string              `yaml:"effect"`
		Resources   []string            `yaml:"resources"`
		Verbs       []string            `yaml:"verbs"`
		Constraints map[string][]string `yaml:"constraints,omitempty"`
	}
	type yamlRole struct {
		Name  string     `yaml:"name"`
		Rules []yamlRule `yaml:"rules"`
	}
	type yamlRolesFile struct {
		Roles []yamlRole `yaml:"roles"`
	}

	var rf yamlRolesFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, err
	}

	out := make([]api.Role, 0, len(rf.Roles))
	for _, yr := range rf.Roles {
		role := api.Role{Name: yr.Name}
		for _, r := range yr.Rules {
			effect := r.Effect
			if effect == "" {
				effect = "allow"
			}
			role.Rules = append(role.Rules, api.Rule{
				Name:        r.Name,
				Effect:      effect,
				Resources:   r.Resources,
				Verbs:       r.Verbs,
				Constraints: r.Constraints,
			})
		}
		out = append(out, role)
	}
	return out, nil
}
