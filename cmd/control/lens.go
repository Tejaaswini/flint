package main

import (
	"strings"

	"flint/engine/session"
)

// classifyTool returns the lens classification for a tool based on its metadata tags.
// Mapping (from architecture devlog §6.4):
//   - tag "admin"                              → "admin"
//   - tag "internal_write", "external_write", or "network_egress" → "write"
//   - everything else (including no tags)       → "read"
func classifyTool(meta session.ToolMeta) string {
	for _, tag := range meta.Tags {
		if tag == "admin" {
			return "admin"
		}
	}
	for _, tag := range meta.Tags {
		switch tag {
		case "internal_write", "external_write", "network_egress":
			return "write"
		}
	}
	return "read"
}

// lensFromVerb maps a granted verb to a UI lens, taking tool metadata into
// account for the "invoke" case (where the tool classification determines
// whether it's read or write-shaped).
//
//   - verb "admin"    → "admin"
//   - verb "discover" → "read"   (discover-only = read-shaped)
//   - verb "invoke"   → classifyTool(meta)
func lensFromVerb(verb string, meta session.ToolMeta) string {
	switch verb {
	case "admin":
		return "admin"
	case "discover":
		return "read"
	case "invoke":
		return classifyTool(meta)
	}
	return "read"
}

// serverFromTool extracts the server prefix from a tool name.
// For "github.search_code" → "github"; for a flat name like "echo" → "".
func serverFromTool(toolName string) string {
	if idx := strings.Index(toolName, "."); idx > 0 {
		return toolName[:idx]
	}
	return ""
}
