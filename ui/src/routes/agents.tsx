import { useState } from "react";
import { Bot, ShieldX } from "lucide-react";
import { AgentCard } from "@/components/agent-card";
import { DecisionRowItem } from "@/components/decision-row";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useAgents, useAgent } from "@/api/client";
import { formatTsRelative } from "@/lib/ts";
import type { BadgeProps } from "@/components/ui/badge";

function lensVariant(lens: string): BadgeProps["variant"] {
  if (lens === "admin") return "admin";
  if (lens === "write") return "write";
  return "read";
}

function verbBadgeClass(verb: string): string {
  switch (verb) {
    case "admin":
      return "text-red-400 bg-red-900/40";
    case "invoke":
      return "text-blue-400 bg-blue-900/40";
    case "discover":
      return "text-zinc-300 bg-zinc-800";
    default:
      return "text-zinc-300 bg-zinc-800";
  }
}

export function AgentsRoute() {
  const { data: agents, isLoading } = useAgents();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const effectiveId = selectedId ?? agents?.[0]?.id ?? null;
  const { data: agentDetail, isLoading: isDetailLoading } = useAgent(effectiveId ?? "");

  if (isLoading) {
    return (
      <div className="flex gap-4 h-full">
        <div className="w-56 shrink-0 space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-16 rounded-lg" />
          ))}
        </div>
        <Skeleton className="flex-1 rounded-lg" />
      </div>
    );
  }

  if (!agents || agents.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
        <Bot className="h-10 w-10 mb-3 opacity-30" />
        <p className="text-sm font-medium">No agents seen yet</p>
        <p className="text-xs mt-1">Agents appear after their first tool call.</p>
      </div>
    );
  }

  return (
    <div className="flex gap-4 h-full max-w-6xl mx-auto">
      {/* Agent list */}
      <div className="w-52 shrink-0">
        <h2 className="text-xs font-medium text-muted-foreground uppercase tracking-wide px-3 mb-2">
          Agents
        </h2>
        <ScrollArea className="h-[calc(100vh-160px)]">
          <div className="space-y-1 pr-1">
            {agents.map((agent) => (
              <AgentCard
                key={agent.id}
                agent={agent}
                selected={effectiveId === agent.id}
                onClick={() => setSelectedId(agent.id)}
              />
            ))}
          </div>
        </ScrollArea>
      </div>

      {/* Detail panel */}
      <div className="flex-1 min-w-0 overflow-auto">
        {isDetailLoading ? (
          <Skeleton className="h-full rounded-lg" />
        ) : !agentDetail ? (
          <div className="text-muted-foreground text-sm p-6">Select an agent.</div>
        ) : (
          <div className="space-y-6">
            {/* Identity card */}
            <div className="rounded-lg border bg-card p-4 space-y-3">
              <div className="flex items-start gap-3">
                <div className="rounded-full bg-zinc-800 p-2">
                  <Bot className="h-5 w-5 text-muted-foreground" />
                </div>
                <div className="flex-1 min-w-0">
                  <h2 className="font-semibold text-base">{agentDetail.id}</h2>
                  <p className="text-xs text-muted-foreground">
                    Last seen {formatTsRelative(agentDetail.last_seen_at)}
                  </p>
                </div>
                {agentDetail.recent_denied_count > 0 && (
                  <Badge variant="deny">
                    {agentDetail.recent_denied_count} denied (24h)
                  </Badge>
                )}
              </div>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <span className="text-muted-foreground">Roles</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {agentDetail.roles.map((r) => (
                      <span key={r} className="rounded bg-zinc-800 px-2 py-0.5 font-mono">
                        {r}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <span className="text-muted-foreground">Scopes</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {agentDetail.scopes.map((s) => (
                      <span key={s} className="rounded bg-zinc-800 px-2 py-0.5">
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
              <div className="flex gap-4 text-xs text-muted-foreground">
                <span>
                  Discoverable:{" "}
                  <strong className="text-foreground">{agentDetail.discoverable_tools}</strong>
                </span>
                <span>
                  Invokable:{" "}
                  <strong className="text-foreground">{agentDetail.invokable_tools}</strong>
                </span>
              </div>
            </div>

            {/* Effective permissions table */}
            <div>
              <h3 className="text-sm font-medium mb-2">Effective permissions</h3>
              {agentDetail.effective_permissions.length === 0 ? (
                <div className="text-sm text-muted-foreground">No permissions computed.</div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Tool</TableHead>
                      <TableHead>Server</TableHead>
                      <TableHead>Verb</TableHead>
                      <TableHead>Lens</TableHead>
                      <TableHead>Granted by</TableHead>
                      <TableHead>Denied by</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {agentDetail.effective_permissions.map((perm) => (
                      <TableRow key={`${perm.tool_name}-${perm.verb}`}>
                        <TableCell>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="font-mono text-xs max-w-[160px] block truncate">
                                {perm.tool_name}
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>{perm.tool_name}</TooltipContent>
                          </Tooltip>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {perm.server}
                        </TableCell>
                        <TableCell>
                          <span
                            className={`text-xs px-2 py-0.5 rounded font-mono ${verbBadgeClass(perm.verb)}`}
                          >
                            {perm.verb}
                          </span>
                        </TableCell>
                        <TableCell>
                          <Badge variant={lensVariant(perm.lens)}>
                            {perm.lens}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {perm.granted_by_roles.map((r) => (
                              <span
                                key={r}
                                className="text-xs rounded bg-zinc-800 px-1.5 py-0.5 font-mono"
                              >
                                {r}
                              </span>
                            ))}
                            {perm.granted_by_roles.length === 0 && (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          {perm.denied_by_role ? (
                            <span className="text-xs text-red-400 font-mono bg-red-900/30 px-1.5 py-0.5 rounded">
                              {perm.denied_by_role}
                            </span>
                          ) : (
                            <span className="text-muted-foreground text-xs">—</span>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>

            {/* Recent denials */}
            <div>
              <h3 className="text-sm font-medium mb-2 flex items-center gap-1.5">
                <ShieldX className="h-4 w-4 text-red-400" />
                Recent denials
              </h3>
              {agentDetail.recent_denials.length === 0 ? (
                <p className="text-sm text-muted-foreground">No recent denials.</p>
              ) : (
                <div className="space-y-1">
                  {agentDetail.recent_denials.slice(0, 20).map((d, i) => (
                    <DecisionRowItem key={`${d.event_seq}-${i}`} decision={d} compact />
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
