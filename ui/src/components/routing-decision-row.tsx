import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import type { RoutingDecision } from "@/api/types";
import { formatTs } from "@/lib/ts";

// ─── Task chip colors ─────────────────────────────────────────────────────────

const TASK_COLOR: Record<string, string> = {
  code: "bg-blue-900/60 text-blue-300 border-blue-800",
  classification: "bg-teal-900/60 text-teal-300 border-teal-800",
  rag: "bg-purple-900/60 text-purple-300 border-purple-800",
  summarization: "bg-amber-900/60 text-amber-300 border-amber-800",
  conversation: "bg-zinc-700/60 text-zinc-300 border-zinc-600",
  vision: "bg-pink-900/60 text-pink-300 border-pink-800",
  other: "bg-zinc-700/60 text-zinc-300 border-zinc-600",
};

const COMPLEXITY_COLOR: Record<string, string> = {
  low: "text-green-400",
  medium: "text-amber-400",
  high: "text-red-400",
};

function taskColor(task: string): string {
  return TASK_COLOR[task] ?? TASK_COLOR["other"];
}

function complexityColor(complexity: string): string {
  return COMPLEXITY_COLOR[complexity] ?? "text-zinc-400";
}

// ─── Formatting helpers ───────────────────────────────────────────────────────

function fmtCost(usd: number): string {
  if (usd < 0.00001) return "$0.00";
  if (usd < 0.001) return `$${(usd * 1000).toFixed(3)}m`;
  return `$${usd.toFixed(5)}`;
}

function fmtMs(ms: number): string {
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.round(ms)}ms`;
}

// ─── Component ────────────────────────────────────────────────────────────────

interface Props {
  decision: RoutingDecision;
  selected?: boolean;
  onClick?: () => void;
}

export function RoutingDecisionRow({ decision, selected, onClick }: Props) {
  const task = decision.classifier_output.task;
  const complexity = decision.classifier_output.complexity;
  const savingsPositive = decision.savings_usd >= 0;

  return (
    <div
      className={cn(
        "flex items-start gap-3 px-3 py-2 rounded transition-colors cursor-pointer border-l-2",
        selected
          ? "bg-accent/60 border-l-primary"
          : "bg-transparent border-l-transparent hover:bg-muted/30 hover:border-l-muted-foreground/30",
        onClick && "cursor-pointer"
      )}
      onClick={onClick}
    >
      {/* Task chip */}
      <span
        className={cn(
          "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold mt-0.5 shrink-0",
          taskColor(task)
        )}
      >
        {task}
      </span>

      {/* Main content */}
      <div className="flex-1 min-w-0 space-y-0.5">
        <div className="flex items-center gap-2 flex-wrap">
          {/* Complexity badge */}
          <span className={cn("text-xs font-medium", complexityColor(complexity))}>
            {complexity}
          </span>
          {/* Target model */}
          <span className="font-mono text-xs text-foreground truncate max-w-[220px]">
            {decision.target_model}
          </span>
          {/* Rule name */}
          {decision.matched_rule_name && (
            <>
              <span className="text-muted-foreground text-xs">·</span>
              <span className="text-xs text-muted-foreground italic truncate max-w-[160px]">
                {decision.matched_rule_name}
              </span>
            </>
          )}
        </div>
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          {/* Latency breakdown */}
          <span>
            {fmtMs(decision.classifier_latency_ms)}{" "}
            <span className="opacity-50">classify</span> +{" "}
            {fmtMs(decision.forward_latency_ms)}{" "}
            <span className="opacity-50">forward</span>{" "}
            <span className="text-foreground">=</span>{" "}
            <span className="text-foreground font-medium">
              {fmtMs(decision.total_latency_ms)}
            </span>
          </span>
          {/* Cost vs baseline */}
          <span>
            {fmtCost(decision.total_cost_usd)}{" "}
            <span className="line-through opacity-50">
              {fmtCost(decision.baseline_cost_usd)}
            </span>{" "}
            <span
              className={savingsPositive ? "text-green-400" : "text-red-400"}
              title={savingsPositive ? "saved vs baseline" : "cost more than baseline"}
            >
              {savingsPositive ? "+" : "−"}
              {fmtCost(Math.abs(decision.savings_usd))}
            </span>
          </span>
        </div>
      </div>

      {/* Timestamp */}
      <span className="text-xs text-muted-foreground shrink-0 mt-0.5">
        {formatTs(decision.ts)}
      </span>
    </div>
  );
}

// Re-export helpers for use in the detail panel
export { fmtCost, fmtMs, taskColor };
