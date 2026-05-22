import { useState } from "react";
import { Activity } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { RoutingDecisionRow, fmtCost, fmtMs } from "@/components/routing-decision-row";
import { useRoutingStream } from "@/api/ws";
import { useRouterStats, useRouterPolicy } from "@/api/client";
import { formatTs } from "@/lib/ts";
import type { RoutingDecision } from "@/api/types";
import { cn } from "@/lib/utils";

// ─── Stats strip ─────────────────────────────────────────────────────────────

function StatsStrip() {
  const { data: stats, isLoading } = useRouterStats("session");
  const { data: policy } = useRouterPolicy();

  if (isLoading) {
    return (
      <div className="grid grid-cols-5 gap-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-20 rounded-lg" />
        ))}
      </div>
    );
  }

  if (!stats) return null;

  const savingsPositive = stats.savings_usd >= 0;

  return (
    <div className="grid grid-cols-5 gap-3">
      <StatCard
        label="Total Calls"
        value={String(stats.total_calls)}
        sub="routing decisions"
      />
      <StatCard
        label="Total Cost"
        value={fmtCost(stats.total_cost_usd)}
        sub={`avg ${fmtMs(stats.avg_total_ms)} / call`}
      />
      <StatCard
        label="Baseline Cost"
        value={fmtCost(stats.baseline_cost_usd)}
        sub={policy?.baseline?.model ? `if all via ${policy.baseline.model}` : "counterfactual"}
      />
      <StatCard
        label="Savings"
        value={fmtCost(Math.abs(stats.savings_usd))}
        sub={`${Math.abs(stats.savings_pct).toFixed(1)}% ${savingsPositive ? "saved" : "lost"} vs baseline`}
        valueClass={savingsPositive ? "text-green-400" : "text-red-400"}
      />
      <StatCard
        label="Avg Latency"
        value={fmtMs(stats.avg_total_ms)}
        sub={`${fmtMs(stats.avg_classifier_ms)} classify + ${fmtMs(stats.avg_forward_ms)} forward`}
      />
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: string;
  sub: string;
  valueClass?: string;
}

function StatCard({ label, value, sub, valueClass }: StatCardProps) {
  return (
    <Card>
      <CardHeader className="pb-1 pt-4 px-4">
        <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent className="px-4 pb-4">
        <div className={cn("text-xl font-bold font-mono", valueClass ?? "text-foreground")}>
          {value}
        </div>
        <div className="text-xs text-muted-foreground mt-0.5 truncate">{sub}</div>
      </CardContent>
    </Card>
  );
}

// ─── Detail panel ─────────────────────────────────────────────────────────────

function DetailPanel({ decision }: { decision: RoutingDecision }) {
  return (
    <div className="space-y-4 p-4 overflow-auto h-full">
      <div>
        <h3 className="text-sm font-semibold mb-2">Decision summary</h3>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-sm">
          <dt className="text-muted-foreground text-xs">Request ID</dt>
          <dd className="font-mono text-xs truncate">{decision.request_id}</dd>
          <dt className="text-muted-foreground text-xs">Timestamp</dt>
          <dd className="text-xs">{formatTs(decision.ts)}</dd>
          <dt className="text-muted-foreground text-xs">Task</dt>
          <dd className="text-xs">{decision.classifier_output.task}</dd>
          <dt className="text-muted-foreground text-xs">Complexity</dt>
          <dd className="text-xs">{decision.classifier_output.complexity}</dd>
          <dt className="text-muted-foreground text-xs">Capabilities</dt>
          <dd className="text-xs">
            {decision.classifier_output.capabilities.length > 0
              ? decision.classifier_output.capabilities.join(", ")
              : "—"}
          </dd>
          <dt className="text-muted-foreground text-xs">Matched rule</dt>
          <dd className="text-xs">{decision.matched_rule_name || "—"}</dd>
          <dt className="text-muted-foreground text-xs">Target model</dt>
          <dd className="font-mono text-xs">{decision.target_model}</dd>
        </dl>
      </div>

      <div>
        <h3 className="text-sm font-semibold mb-2">Classifier reasoning</h3>
        <div className="text-xs bg-zinc-900 rounded p-3 text-zinc-300 leading-relaxed">
          {decision.classifier_output.reasoning}
        </div>
      </div>

      <div>
        <h3 className="text-sm font-semibold mb-2">Stage breakdown</h3>
        <div className="grid grid-cols-2 gap-3">
          <Card className="p-3">
            <div className="text-xs text-muted-foreground mb-1">Classifier</div>
            <div className="font-mono text-sm">{fmtMs(decision.classifier_latency_ms)}</div>
            <div className="text-xs text-muted-foreground mt-0.5">
              {fmtCost(decision.classifier_cost_usd)} cost
            </div>
            <div className="text-xs text-muted-foreground">
              {decision.classifier_model}
            </div>
          </Card>
          <Card className="p-3">
            <div className="text-xs text-muted-foreground mb-1">Forward</div>
            <div className="font-mono text-sm">{fmtMs(decision.forward_latency_ms)}</div>
            <div className="text-xs text-muted-foreground mt-0.5">
              {fmtCost(decision.forward_cost_usd)} cost
            </div>
            <div className="text-xs text-muted-foreground">
              {decision.prompt_tokens}p + {decision.completion_tokens}c tokens
            </div>
          </Card>
        </div>
        <div className="mt-2 text-xs text-muted-foreground space-y-0.5">
          <div>
            Total:{" "}
            <span className="text-foreground font-medium">
              {fmtMs(decision.total_latency_ms)}
            </span>{" "}
            ·{" "}
            <span className="text-foreground font-medium">
              {fmtCost(decision.total_cost_usd)}
            </span>
          </div>
          <div>
            Baseline cost (counterfactual):{" "}
            <span className="line-through text-muted-foreground/70">
              {fmtCost(decision.baseline_cost_usd)}
            </span>{" "}
            <span
              className={decision.savings_usd >= 0 ? "text-green-400" : "text-red-400"}
            >
              {decision.savings_usd >= 0 ? "saved " : "overspent "}
              {fmtCost(Math.abs(decision.savings_usd))}
            </span>
          </div>
        </div>
      </div>

      {decision.classifier_failed && (
        <div className="rounded-md border border-amber-600 bg-amber-950/40 px-3 py-2 text-xs text-amber-300">
          Classifier failed: {decision.classifier_fail_reason ?? "unknown reason"} — used default rule.
        </div>
      )}

      {decision.error && (
        <div className="rounded-md border border-red-700 bg-red-950/40 px-3 py-2 text-xs text-red-300">
          Error: {decision.error}
        </div>
      )}

      <div>
        <h3 className="text-sm font-semibold mb-2">Raw JSON</h3>
        <pre className="text-xs bg-zinc-900 rounded p-3 overflow-auto font-mono max-h-64 text-zinc-300">
          {JSON.stringify(decision, null, 2)}
        </pre>
      </div>
    </div>
  );
}

// ─── Main route ───────────────────────────────────────────────────────────────

export function RouterLiveRoute() {
  const { frames, isConnected, error } = useRoutingStream();
  const [selectedDecision, setSelectedDecision] = useState<RoutingDecision | null>(null);

  return (
    <div className="max-w-screen-xl mx-auto space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Router Live</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Real-time routing decisions with cost-vs-baseline savings.
        </p>
      </div>

      {/* Stats strip */}
      <StatsStrip />

      {/* Connection status */}
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <span
          className={cn(
            "inline-block h-2 w-2 rounded-full",
            isConnected ? "bg-green-500 animate-pulse" : "bg-zinc-600"
          )}
        />
        {isConnected ? "Connected" : error ?? "Disconnected — reconnecting..."}
        <span className="ml-auto">{frames.length} decisions buffered</span>
      </div>

      {/* Two-column layout */}
      {frames.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-20 text-muted-foreground">
            <Activity className="h-8 w-8 mb-2 opacity-30" />
            <p className="text-sm">Waiting for first routing decision</p>
            <p className="text-xs mt-1 text-muted-foreground/70">
              Run <code className="font-mono bg-muted px-1 py-0.5 rounded text-xs">make demo-router</code>{" "}
              to fire the synthetic workload.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="flex gap-4 min-h-0" style={{ height: "calc(100vh - 300px)" }}>
          {/* Left: live feed (60%) */}
          <div className="flex-[3] min-w-0 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                Live Feed
              </span>
              <div className="flex gap-1 flex-wrap justify-end">
                {["code", "classification", "rag", "summarization", "conversation", "vision", "other"].map((task) => {
                  const count = frames.filter((f) => f.classifier_output.task === task).length;
                  if (count === 0) return null;
                  return (
                    <Badge key={task} variant="secondary" className="text-xs px-1.5 py-0">
                      {task}: {count}
                    </Badge>
                  );
                })}
              </div>
            </div>
            <ScrollArea className="flex-1 rounded-lg border bg-card">
              <div className="space-y-0.5 p-2">
                {frames.map((frame, i) => (
                  <RoutingDecisionRow
                    key={`${frame.request_id}:${i}`}
                    decision={frame}
                    selected={selectedDecision?.request_id === frame.request_id}
                    onClick={() =>
                      setSelectedDecision(
                        selectedDecision?.request_id === frame.request_id ? null : frame
                      )
                    }
                  />
                ))}
              </div>
            </ScrollArea>
          </div>

          {/* Right: detail panel (40%) */}
          <div className="flex-[2] min-w-0 rounded-lg border bg-card overflow-hidden">
            {selectedDecision ? (
              <DetailPanel decision={selectedDecision} />
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-muted-foreground p-4">
                <Activity className="h-8 w-8 mb-2 opacity-20" />
                <p className="text-sm text-center">Select a decision to inspect</p>
                <p className="text-xs text-muted-foreground/70 mt-1 text-center">
                  Click any row on the left
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
