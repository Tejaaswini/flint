import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import type { DecisionRow } from "@/api/types";
import { formatTs } from "@/lib/ts";

interface Props {
  decision: DecisionRow;
  onClick?: () => void;
  compact?: boolean;
}

export function DecisionRowItem({ decision, onClick, compact = false }: Props) {
  const isDenied = !decision.allowed;
  const hasFinding = (decision.findings?.length ?? 0) > 0;

  return (
    <div
      className={cn(
        "flex items-start gap-3 px-3 py-2 rounded transition-colors cursor-pointer border-l-2",
        isDenied
          ? "bg-red-950/30 border-l-red-600 hover:bg-red-950/50"
          : hasFinding
          ? "bg-amber-950/20 border-l-amber-600 hover:bg-amber-950/30"
          : "bg-transparent border-l-green-700 hover:bg-muted/30",
        onClick && "cursor-pointer"
      )}
      onClick={onClick}
    >
      {/* Status badge */}
      <Badge
        variant={isDenied ? "deny" : "allow"}
        className="mt-0.5 shrink-0 text-xs"
      >
        {isDenied ? "deny" : "allow"}
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
          {hasFinding && (
            <Badge variant="finding" className="text-xs">
              finding
            </Badge>
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
