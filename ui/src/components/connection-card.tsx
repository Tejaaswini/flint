import { useNavigate } from "react-router-dom";
import { Wrench, Clock, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { Connection } from "@/api/types";
import { formatTsRelative } from "@/lib/ts";
import type { BadgeProps } from "@/components/ui/badge";

function statusVariant(status: string): BadgeProps["variant"] {
  if (status === "connected") return "connected";
  if (status === "degraded") return "degraded";
  return "offline";
}

interface Props {
  connection: Connection;
}

export function ConnectionCard({ connection }: Props) {
  const navigate = useNavigate();

  return (
    <Card
      className="cursor-pointer hover:border-zinc-600 transition-colors"
      onClick={() => navigate(`/connections/${connection.name}`)}
    >
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-base font-semibold truncate">
            {connection.name}
          </CardTitle>
          <Badge variant={statusVariant(connection.status)} className="shrink-0">
            {connection.status}
          </Badge>
        </div>
        <p className="text-xs text-muted-foreground font-mono truncate">
          {connection.command.join(" ")}
        </p>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="grid grid-cols-3 gap-3 text-xs">
          <div className="flex flex-col gap-0.5">
            <div className="flex items-center gap-1 text-muted-foreground">
              <Wrench className="h-3 w-3" />
              <span>Tools</span>
            </div>
            <span className="font-semibold text-sm">{connection.tool_count}</span>
          </div>
          <div className="flex flex-col gap-0.5">
            <div className="flex items-center gap-1 text-muted-foreground">
              <Clock className="h-3 w-3" />
              <span>Last call</span>
            </div>
            <span className="font-medium">{formatTsRelative(connection.last_call_at)}</span>
          </div>
          <div className="flex flex-col gap-0.5">
            <div className="flex items-center gap-1 text-muted-foreground">
              <Zap className="h-3 w-3" />
              <span>p50</span>
            </div>
            <span className="font-medium">{connection.p50_latency_ms.toFixed(1)}ms</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
