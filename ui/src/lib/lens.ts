import type { ToolEntry, EffectivePermission } from "@/api/types";

/**
 * Classify a tool into read | write | admin based on its tags.
 * This mirrors the server-side computation in the control plane.
 */
export function classifyTool(tool: ToolEntry): "read" | "write" | "admin" {
  if (tool.tags?.includes("admin")) return "admin";
  if (
    tool.tags?.includes("external_write") ||
    tool.tags?.includes("network_egress") ||
    tool.tags?.includes("internal_write")
  )
    return "write";
  return "read";
}

/**
 * Compute lens label from an effective permission + tool metadata.
 * Prefers the server-computed `perm.lens` field if present (non-empty).
 */
export function lensFromPermission(
  perm: EffectivePermission,
  tool?: ToolEntry
): "read" | "write" | "admin" {
  // Server computes this; if it's set, use it directly.
  if (perm.lens === "admin") return "admin";
  if (perm.lens === "write") return "write";
  if (perm.lens === "read") return "read";

  // Fallback client-side computation.
  if (perm.verb === "admin") return "admin";
  if (perm.verb === "discover") return "read";
  if (tool) return classifyTool(tool);
  return "read";
}

export type Lens = "read" | "write" | "admin";
