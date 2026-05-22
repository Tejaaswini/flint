import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Terminal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { ToolTable } from "@/components/tool-table";
import { DecisionRowItem } from "@/components/decision-row";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useConnection, useDecisions } from "@/api/client";
import type { BadgeProps } from "@/components/ui/badge";

function statusVariant(status: string): BadgeProps["variant"] {
  if (status === "connected") return "connected";
  if (status === "degraded") return "degraded";
  return "offline";
}

export function ConnectionDetailRoute() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const { data: conn, isLoading } = useConnection(name ?? "");
  const { data: decisionsResp } = useDecisions({ limit: 200 });

  // Filter decisions for this connection's tools
  const allDecisions = decisionsResp?.items ?? [];
  const connToolNames = new Set((conn?.tools ?? []).map((t) => t.name));
  const activityDecisions = allDecisions.filter((d) =>
    connToolNames.has(d.tool_name)
  );

  if (isLoading) {
    return (
      <div className="max-w-5xl mx-auto space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (!conn) {
    return (
      <div className="text-center py-20 text-muted-foreground">
        Connection not found.
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto space-y-4">
      {/* Back nav */}
      <Button
        variant="ghost"
        size="sm"
        className="gap-1.5 text-muted-foreground"
        onClick={() => navigate("/")}
      >
        <ArrowLeft className="h-4 w-4" />
        Connections
      </Button>

      {/* Header */}
      <div className="space-y-2">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold">{conn.name}</h1>
          <Badge variant={statusVariant(conn.status)}>{conn.status}</Badge>
          <span className="text-sm text-muted-foreground ml-auto">
            {conn.tool_count} tools
          </span>
        </div>
        {/* Command */}
        <div className="flex items-center gap-2 rounded-lg bg-zinc-900 border border-zinc-700 px-3 py-2">
          <Terminal className="h-4 w-4 text-muted-foreground shrink-0" />
          <code className="text-xs font-mono text-zinc-300">{conn.command.join(" ")}</code>
        </div>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="tools">
        <TabsList>
          <TabsTrigger value="tools">Tools ({conn.tools?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="activity">Activity ({activityDecisions.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="tools">
          <ToolTable tools={conn.tools ?? []} />
        </TabsContent>

        <TabsContent value="activity">
          {activityDecisions.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground text-sm">
              No activity yet for this connection.
            </div>
          ) : (
            <ScrollArea className="h-[500px] pr-2">
              <div className="space-y-1">
                {activityDecisions.map((d, i) => (
                  <DecisionRowItem key={`${d.event_seq}-${i}`} decision={d} />
                ))}
              </div>
            </ScrollArea>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
