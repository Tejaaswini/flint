import { useState } from "react";
import { RefreshCw, Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAgents } from "@/api/client";

export function Topbar() {
  const [darkMode, setDarkMode] = useState(true);
  const [selectedAgent, setSelectedAgent] = useState<string>("all");
  const { data: agents, isRefetching, refetch } = useAgents();

  function toggleDark() {
    setDarkMode((d) => !d);
    document.documentElement.classList.toggle("dark");
  }

  return (
    <header className="flex items-center gap-3 px-6 py-3 border-b bg-card shrink-0">
      {/* Agent filter */}
      <div className="flex items-center gap-2">
        <span className="text-xs text-muted-foreground font-medium">Agent</span>
        <Select value={selectedAgent} onValueChange={setSelectedAgent}>
          <SelectTrigger className="h-8 w-44 text-xs">
            <SelectValue placeholder="All agents" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All agents</SelectItem>
            {(agents ?? []).map((a) => (
              <SelectItem key={a.id} value={a.id}>
                {a.id}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="ml-auto flex items-center gap-2">
        {/* Refresh indicator */}
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          onClick={() => refetch()}
          title="Refresh"
        >
          <RefreshCw
            className={`h-4 w-4 ${isRefetching ? "animate-spin" : ""}`}
          />
        </Button>

        {/* Dark mode toggle */}
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          onClick={toggleDark}
          title="Toggle dark mode"
        >
          {darkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>
      </div>
    </header>
  );
}
