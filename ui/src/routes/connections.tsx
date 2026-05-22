import { Server } from "lucide-react";
import { ConnectionCard } from "@/components/connection-card";
import { Skeleton } from "@/components/ui/skeleton";
import { useConnections } from "@/api/client";
import { useDecisions } from "@/api/client";

export function ConnectionsRoute() {
  const { data: connections, isLoading } = useConnections();
  const { data: decisionsResp } = useDecisions({ limit: 500 });

  // Footer stats from recent decisions
  const decisions = decisionsResp?.items ?? [];
  const denied = decisions.filter((d) => !d.allowed).length;
  const findings = decisions.reduce((n, d) => n + (d.findings?.length ?? 0), 0);

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-semibold">Connections</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          MCP upstream servers registered with the gateway.
        </p>
      </div>

      {/* Grid */}
      {isLoading ? (
        <div className="grid grid-cols-2 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-36 rounded-lg" />
          ))}
        </div>
      ) : !connections || connections.length === 0 ? (
        <EmptyConnections />
      ) : (
        <div className="grid grid-cols-2 gap-4">
          {connections.map((conn) => (
            <ConnectionCard key={conn.name} connection={conn} />
          ))}
        </div>
      )}

      {/* Footer summary */}
      {decisions.length > 0 && (
        <div className="rounded-lg border bg-card px-4 py-3 text-sm text-muted-foreground">
          Last 24h:{" "}
          <span className="text-foreground font-medium">{decisions.length}</span> decisions
          {" · "}
          <span className="text-red-400 font-medium">{denied}</span> denials
          {" · "}
          <span className="text-amber-400 font-medium">{findings}</span> findings
        </div>
      )}
    </div>
  );
}

function EmptyConnections() {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
      <Server className="h-10 w-10 mb-3 opacity-30" />
      <p className="text-sm font-medium">No connections yet</p>
      <p className="text-xs mt-1">Start the gateway to register MCP servers.</p>
    </div>
  );
}
