import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { ToolEntry } from "@/api/types";
import type { BadgeProps } from "@/components/ui/badge";

function classificationVariant(cls: string): BadgeProps["variant"] {
  if (cls === "admin") return "admin";
  if (cls === "write") return "write";
  return "read";
}

interface Props {
  tools: ToolEntry[];
}

export function ToolTable({ tools }: Props) {
  if (tools.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground text-sm">
        No tools registered for this connection.
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead>Classification</TableHead>
          <TableHead>Tags</TableHead>
          <TableHead>Scope</TableHead>
          <TableHead>Payload class</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {tools.map((tool) => (
          <TableRow key={tool.name}>
            <TableCell>
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="font-mono text-xs max-w-[200px] block truncate">
                    {tool.name}
                  </span>
                </TooltipTrigger>
                <TooltipContent>{tool.name}</TooltipContent>
              </Tooltip>
            </TableCell>
            <TableCell>
              <Badge variant={classificationVariant(tool.classification)}>
                {tool.classification}
              </Badge>
            </TableCell>
            <TableCell>
              <div className="flex flex-wrap gap-1">
                {tool.tags.length === 0 ? (
                  <span className="text-muted-foreground text-xs">—</span>
                ) : (
                  tool.tags.map((tag) => (
                    <Tooltip key={tag}>
                      <TooltipTrigger asChild>
                        <span className="inline-flex items-center rounded-full bg-zinc-800 px-2 py-0.5 text-xs text-zinc-300">
                          {tag}
                        </span>
                      </TooltipTrigger>
                      <TooltipContent>{tag}</TooltipContent>
                    </Tooltip>
                  ))
                )}
              </div>
            </TableCell>
            <TableCell className="text-xs text-muted-foreground">{tool.scope}</TableCell>
            <TableCell className="text-xs text-muted-foreground">{tool.payload_class}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
