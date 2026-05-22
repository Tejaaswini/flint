/**
 * Status → color/style helpers for connection posture and decision outcomes.
 */

export type ConnectionStatus = "connected" | "degraded" | "offline";

export function statusVariant(
  status: ConnectionStatus
): "connected" | "degraded" | "offline" {
  return status;
}

export function statusColor(status: ConnectionStatus): string {
  switch (status) {
    case "connected":
      return "text-green-400";
    case "degraded":
      return "text-amber-400";
    case "offline":
      return "text-zinc-400";
  }
}

export function lensColor(lens: string): string {
  switch (lens) {
    case "admin":
      return "text-red-400";
    case "write":
      return "text-amber-400";
    case "read":
    default:
      return "text-blue-400";
  }
}
