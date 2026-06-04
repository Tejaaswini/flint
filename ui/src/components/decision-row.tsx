import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import type { DecisionRow } from "@/api/types";
import { formatTs } from "@/lib/ts";

interface Props {
  decision: DecisionRow;
  onClick?: () => void;
  compact?: boolean;
}

// Derive a single "tone" from the decision's allowed flag and enforced_action.
// Precedence (top wins):
//   1. RBAC denied (!allowed)                        → "deny"
//      (proxy.go also sets enforced_action="blocked_rbac" on these rows;
//       the !allowed check catches them before the string comparisons below)
//   2. enforced_action starts with "blocked"         → "blocked"
//      (covers both "blocked" behavioral blocks and "blocked_rbac" RBAC denials
//       in case allowed is ever accidentally true on such a row)
//   3. enforced_action === "observed"                → "observed"
//   4. everything else                               → "allow"
type Tone = "deny" | "blocked" | "observed" | "allow";

function deriveTone(decision: DecisionRow): Tone {
  if (!decision.allowed) return "deny";
  if (decision.enforced_action?.startsWith("blocked")) return "blocked";
  if (decision.enforced_action === "observed") return "observed";
  return "allow";
}

// Map a FindingRow's action to the badge variant we want.
// Missing/empty action falls back to "warn" (mirrors control-plane v1 normalization).
type FindingActionVariant = "warn" | "pause" | "terminate";

function findingVariant(action: string | undefined): FindingActionVariant {
  if (action === "terminate") return "terminate";
  if (action === "pause") return "pause";
  return "warn";
}

export function DecisionRowItem({ decision, onClick, compact = false }: Props) {
  const tone = deriveTone(decision);
  const findings = decision.findings ?? [];

  // Show at most 3 findings inline; remainder shown as "+N more".
  const MAX_CHIPS = 3;
  const visibleFindings = findings.slice(0, MAX_CHIPS);
  const overflowCount = findings.length - visibleFindings.length;

  return (
    <div
      className={cn(
        "flex items-start gap-3 px-3 py-2 rounded transition-colors cursor-pointer border-l-2",
        tone === "deny"
          ? "bg-red-950/30 border-l-red-600 hover:bg-red-950/50"
          : tone === "blocked"
          ? "bg-red-950/30 border-l-red-600 hover:bg-red-950/50"
          : tone === "observed"
          ? "bg-amber-950/20 border-l-amber-600 hover:bg-amber-950/30"
          : "bg-transparent border-l-green-700 hover:bg-muted/30",
        onClick && "cursor-pointer"
      )}
      onClick={onClick}
    >
      {/* Status badge — 3-state enforced_action or RBAC deny */}
      <Badge
        variant={tone}
        className="mt-0.5 shrink-0 text-xs"
      >
        {tone}
      </Badge>

      {/* Main content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-xs font-medium">{decision.tool_name}</span>
          {!compact && (
            <>
              <span className="text-muted-foreground text-xs">·</span>
              <span className="text-xs text-muted-foreground">{decision.agent_id}</span>
            </>
          )}
          {decision.matched_rule_name && (
            <>
              <span className="text-muted-foreground text-xs">·</span>
              <span className="text-xs text-muted-foreground italic truncate max-w-[200px]">
                {decision.matched_rule_name}
              </span>
            </>
          )}
          {/* Per-finding action chips */}
          {visibleFindings.map((f, i) => (
            <Badge
              key={i}
              variant={findingVariant(f.action)}
              className="text-xs truncate max-w-[160px]"
              title={f.message}
            >
              {f.rule_id} · {f.action ?? "warn"}
            </Badge>
          ))}
          {overflowCount > 0 && (
            <span className="text-xs text-muted-foreground">+{overflowCount} more</span>
          )}
        </div>
        {!compact && decision.payload_excerpt && (
          <p className="text-xs text-muted-foreground mt-0.5 truncate font-mono">
            {decision.payload_excerpt}
          </p>
        )}
        {!compact && (
          <p className="text-xs text-muted-foreground mt-0.5">
            reason: <span className="text-foreground">{decision.reason}</span>
            {decision.latency_ms != null && (
              <> · {decision.latency_ms.toFixed(1)}ms</>
            )}
          </p>
        )}
      </div>

      {/* Timestamp */}
      <span className="text-xs text-muted-foreground shrink-0">{formatTs(decision.ts)}</span>
    </div>
  );
}
