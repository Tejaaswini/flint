package session

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultRegistry is the built-in fallback used when no tools.yaml is present.
var DefaultRegistry = map[string]ToolMeta{
	"crm.lookup_customer":        {[]string{"data_source", "restricted"}, "customer_data", "restricted"},
	"crm.get_integration_tokens": {[]string{"data_source", "restricted"}, "customer_data", "restricted"},
	"db.execute_sql":             {[]string{"data_source", "sql", "restricted"}, "database", "restricted"},
	"slack.post_message":         {[]string{"external_write", "network_egress"}, "communications", "internal"},
	"github.search_code":         {[]string{"data_source"}, "code", "internal"},
	"support.read_ticket":        {[]string{"data_source", "external_data"}, "support", "internal"},
	"support.post_reply":         {[]string{"external_write", "network_egress"}, "support", "internal"},
	"fs.read_file":               {[]string{"data_source", "filesystem"}, "local", "internal"},
}

type toolEntry struct {
	Name         string   `yaml:"name"`
	Tags         []string `yaml:"tags"`
	Scope        string   `yaml:"scope"`
	PayloadClass string   `yaml:"payload_class"`
}

type toolsFile struct {
	Tools []toolEntry `yaml:"tools"`
}

// LoadRegistry parses a tools.yaml file and returns the registry map.
func LoadRegistry(path string) (map[string]ToolMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var tf toolsFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(tf.Tools) == 0 {
		return nil, fmt.Errorf("%s: no tools defined", path)
	}
	registry := make(map[string]ToolMeta, len(tf.Tools))
	for _, t := range tf.Tools {
		registry[t.Name] = ToolMeta{
			Tags:         t.Tags,
			Scope:        t.Scope,
			PayloadClass: t.PayloadClass,
		}
	}
	return registry, nil
}

// ResolveToolWith enriches an event using the provided registry.
func ResolveToolWith(registry map[string]ToolMeta, e *SessionEvent) {
	m, ok := registry[e.ToolName]
	if !ok {
		return
	}
	if len(e.ToolTags) == 0 {
		e.ToolTags = m.Tags
	}
	if e.Scope == "" {
		e.Scope = m.Scope
	}
	if e.PayloadClass == "" {
		e.PayloadClass = m.PayloadClass
	}
}
