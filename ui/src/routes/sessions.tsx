import { useState } from "react";
import { AlertTriangle, Activity } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { DecisionRowItem } from "@/components/decision-row";
import { useDecisionStream } from "@/api/ws";
import { useSessions } from "@/api/client";
import { formatTs, formatTsRelative } from "@/lib/ts";
import type { DecisionRow, Session } from "@/api/types";
import { cn } from "@/lib/utils";

export function SessionsRoute() {
  return (
    <div className="max-w-6xl mx-auto space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Sessions</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Live decision stream and session history.
        </p>
      </div>

      <Tabs defaultValue="live">
        <TabsList>
          <TabsTrigger value="live">Live</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>

        <TabsContent value="live" className="mt-2">
          <LiveFeed />
        </TabsContent>

        <TabsContent value="history" className="mt-2">
          <SessionHistory />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─── Live Feed ────────────────────────────────────────────────────────────────

function LiveFeed() {
  const { frames, latestFinding, isConnected, clearFinding } = useDecisionStream();
  const [selectedDecision, setSelectedDecision] = useState<DecisionRow | null>(null);

  return (
    <div className="space-y-2">
      {/* Connection status */}
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <span
          className={cn(
            "inline-block h-2 w-2 rounded-full",
            isConnected ? "bg-green-500 animate-pulse" : "bg-zinc-600"
          )}
        />
        {isConnected ? "Connected" : "Disconnected — reconnecting..."}
        <span className="ml-auto">{frames.length} frames buffered</span>
      </div>

      {/* Finding banner */}
      {latestFinding && (
        <div
          className="rounded-lg border border-amber-600 bg-amber-950/60 px-4 py-2 flex items-center gap-2 cursor-pointer animate-fade-in"
          onClick={clearFinding}
        >
          <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
          <span className="text-sm text-amber-300">
            Finding: <strong>{latestFinding.rule_id}</strong> — {latestFinding.message}{" "}
            <span className="text-amber-500/70">(click to dismiss)</span>
          </span>
          <Badge variant="finding" className="ml-auto shrink-0">
            {latestFinding.severity}
          </Badge>
        </div>
      )}

      {/* Feed */}
      {frames.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground border border-dashed rounded-lg">
          <Activity className="h-8 w-8 mb-2 opacity-30" />
          <p className="text-sm">No events yet</p>
          <p className="text-xs mt-1">Waiting for tool calls from the gateway...</p>
        </div>
      ) : (
        <ScrollArea className="h-[calc(100vh-320px)] rounded-lg border bg-card">
          <div className="space-y-0.5 p-2">
            {frames.map((frame, i) => (
              <DecisionRowItem
                key={`${frame.session_id}:${frame.event_seq}:${frame.direction}:${i}`}
                decision={frame}
                onClick={() => setSelectedDecision(frame)}
              />
            ))}
          </div>
        </ScrollArea>
      )}

      {/* Detail drawer */}
      <Dialog open={!!selectedDecision} onOpenChange={(o) => !o && setSelectedDecision(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              Decision detail
              {selectedDecision && (
                <Badge variant={selectedDecision.allowed ? "allow" : "deny"}>
                  {selectedDecision.allowed ? "allowed" : "denied"}
                </Badge>
              )}
            </DialogTitle>
          </DialogHeader>
          {selectedDecision && <DecisionDetail decision={selectedDecision} />}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── Decision detail ──────────────────────────────────────────────────────────

function DecisionDetail({ decision }: { decision: DecisionRow }) {
  return (
    <div className="space-y-3">
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
        <dt className="text-muted-foreground">Tool</dt>
        <dd className="font-mono text-xs">{decision.tool_name}</dd>
        <dt className="text-muted-foreground">Agent</dt>
        <dd>{decision.agent_id}</dd>
        <dt className="text-muted-foreground">Session</dt>
        <dd className="font-mono text-xs truncate">{decision.session_id}</dd>
        <dt className="text-muted-foreground">Direction</dt>
        <dd>{decision.direction}</dd>
        <dt className="text-muted-foreground">Reason</dt>
        <dd className="font-mono text-xs">{decision.reason}</dd>
        <dt className="text-muted-foreground">Matched role</dt>
        <dd>{decision.matched_role || "—"}</dd>
        <dt className="text-muted-foreground">Matched rule</dt>
        <dd>
          {decision.matched_rule_name || (decision.matched_rule >= 0 ? `#${decision.matched_rule}` : "—")}
        </dd>
        <dt className="text-muted-foreground">Required verb</dt>
        <dd className="font-mono text-xs">{decision.required_verb || "—"}</dd>
        <dt className="text-muted-foreground">Granted verb</dt>
        <dd className="font-mono text-xs">{decision.granted_verb || "—"}</dd>
        <dt className="text-muted-foreground">Latency</dt>
        <dd>{decision.latency_ms != null ? `${decision.latency_ms.toFixed(1)}ms` : "—"}</dd>
        <dt className="text-muted-foreground">Timestamp</dt>
        <dd className="text-xs">{formatTs(decision.ts)}</dd>
        <dt className="text-muted-foreground">Event seq</dt>
        <dd className="font-mono text-xs">{decision.event_seq}</dd>
      </dl>

      {decision.payload_excerpt && (
        <div>
          <p className="text-xs text-muted-foreground mb-1">Payload excerpt</p>
          <pre className="text-xs bg-zinc-900 rounded p-2 overflow-auto font-mono">
            {decision.payload_excerpt}
          </pre>
        </div>
      )}

      {(decision.findings?.length ?? 0) > 0 && (
        <div>
          <p className="text-xs text-muted-foreground mb-1">Findings</p>
          <pre className="text-xs bg-zinc-900 rounded p-2 overflow-auto font-mono">
            {JSON.stringify(decision.findings, null, 2)}
          </pre>
        </div>
      )}

      <div>
        <p className="text-xs text-muted-foreground mb-1">Raw JSON</p>
        <pre className="text-xs bg-zinc-900 rounded p-2 overflow-auto font-mono max-h-48">
          {JSON.stringify(decision, null, 2)}
        </pre>
      </div>
    </div>
  );
}

// ─── History ──────────────────────────────────────────────────────────────────

function SessionHistory() {
  const { data: sessions, isLoading } = useSessions();
  const [selectedSession, setSelectedSession] = useState<Session | null>(null);

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    );
  }

  if (!sessions || sessions.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-muted-foreground border border-dashed rounded-lg">
        <Activity className="h-8 w-8 mb-2 opacity-30" />
        <p className="text-sm">No sessions recorded yet.</p>
      </div>
    );
  }

  return (
    <>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Session ID</TableHead>
            <TableHead>Agent</TableHead>
            <TableHead>Started</TableHead>
            <TableHead>Events</TableHead>
            <TableHead>Denied</TableHead>
            <TableHead>Findings</TableHead>
            <TableHead>Risk</TableHead>
            <TableHead>Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sessions.map((s) => (
            <TableRow
              key={s.id}
              className="cursor-pointer"
              onClick={() => setSelectedSession(s)}
            >
              <TableCell className="font-mono text-xs truncate max-w-[140px]">
                {s.id}
              </TableCell>
              <TableCell className="text-sm">{s.agent_id}</TableCell>
              <TableCell className="text-xs text-muted-foreground">
                {formatTsRelative(s.started_at)}
              </TableCell>
              <TableCell>{s.event_count}</TableCell>
              <TableCell>
                {s.denied_count > 0 ? (
                  <span className="text-red-400">{s.denied_count}</span>
                ) : (
                  0
                )}
              </TableCell>
              <TableCell>
                {s.findings_count > 0 ? (
                  <span className="text-amber-400">{s.findings_count}</span>
                ) : (
                  0
                )}
              </TableCell>
              <TableCell>
                <RiskBadge score={s.risk_score} />
              </TableCell>
              <TableCell>
                <Badge
                  variant={s.disposition === "active" ? "allow" : "secondary"}
                >
                  {s.disposition}
                </Badge>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      {/* Session detail drawer */}
      <Dialog
        open={!!selectedSession}
        onOpenChange={(o) => !o && setSelectedSession(null)}
      >
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Session detail</DialogTitle>
          </DialogHeader>
          {selectedSession && (
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
              <dt className="text-muted-foreground">ID</dt>
              <dd className="font-mono text-xs truncate">{selectedSession.id}</dd>
              <dt className="text-muted-foreground">Agent</dt>
              <dd>{selectedSession.agent_id}</dd>
              <dt className="text-muted-foreground">Started</dt>
              <dd className="text-xs">{formatTs(selectedSession.started_at)}</dd>
              <dt className="text-muted-foreground">Events</dt>
              <dd>{selectedSession.event_count}</dd>
              <dt className="text-muted-foreground">Denied</dt>
              <dd className={selectedSession.denied_count > 0 ? "text-red-400" : ""}>
                {selectedSession.denied_count}
              </dd>
              <dt className="text-muted-foreground">Findings</dt>
              <dd className={selectedSession.findings_count > 0 ? "text-amber-400" : ""}>
                {selectedSession.findings_count}
              </dd>
              <dt className="text-muted-foreground">Risk score</dt>
              <dd>{selectedSession.risk_score.toFixed(2)}</dd>
              <dt className="text-muted-foreground">Disposition</dt>
              <dd>{selectedSession.disposition}</dd>
            </dl>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}

function RiskBadge({ score }: { score: number }) {
  if (score >= 0.7)
    return <Badge variant="deny">{score.toFixed(2)}</Badge>;
  if (score >= 0.3)
    return <Badge variant="finding">{score.toFixed(2)}</Badge>;
  return <Badge variant="secondary">{score.toFixed(2)}</Badge>;
}
