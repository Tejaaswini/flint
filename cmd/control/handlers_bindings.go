package main

import (
	"log/slog"
	"net/http"
	"os"
	"sort"

	"gopkg.in/yaml.v3"

	"flint/pkg/api"
)

// handleBindingsList handles GET /api/v1/bindings.
// Returns the bindings parsed directly from the YAML file.
func handleBindingsList(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bindings, err := readBindingsFile(state.bindingsPath)
		if err != nil {
			slog.Error("bindings list: read failed", "err", err)
			http.Error(w, "failed to read bindings", http.StatusInternalServerError)
			return
		}
		writeJSON200(w, bindings)
	}
}

// readBindingsFile parses the bindings YAML and returns api.Binding slice.
func readBindingsFile(path string) ([]api.Binding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	type yamlBinding struct {
		Agent  string   `yaml:"agent"`
		Roles  []string `yaml:"roles"`
		Scopes []string `yaml:"scopes"`
	}
	type yamlBindingsFile struct {
		Bindings []yamlBinding `yaml:"bindings"`
	}

	var bf yamlBindingsFile
	if err := yaml.Unmarshal(data, &bf); err != nil {
		return nil, err
	}

	out := make([]api.Binding, 0, len(bf.Bindings))
	for _, yb := range bf.Bindings {
		scopes := yb.Scopes
		if scopes == nil {
			scopes = []string{}
		}
		sort.Strings(scopes)
		out = append(out, api.Binding{
			Agent:  yb.Agent,
			Roles:  yb.Roles,
			Scopes: scopes,
		})
	}
	return out, nil
}
