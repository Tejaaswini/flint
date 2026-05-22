import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { formatTsRelative } from "@/lib/ts";
import type { Agent } from "@/api/types";

interface Props {
  agent: Agent;
  selected?: boolean;
  onClick?: () => void;
}

export function AgentCard({ agent, selected, onClick }: Props) {
  return (
    <div
      className={cn(
        "px-3 py-3 rounded-lg cursor-pointer border transition-colors",
        selected
          ? "border-zinc-500 bg-accent"
          : "border-transparent hover:bg-accent/50"
      )}
      onClick={onClick}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="font-medium text-sm truncate">{agent.id}</span>
        {agent.recent_denied_count > 0 && (
          <Badge variant="deny" className="text-xs shrink-0">
            {agent.recent_denied_count} denied
          </Badge>
        )}
      </div>
      <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
        <span>{agent.roles.join(", ")}</span>
        <span>·</span>
        <span>seen {formatTsRelative(agent.last_seen_at)}</span>
      </div>
    </div>
  );
}
