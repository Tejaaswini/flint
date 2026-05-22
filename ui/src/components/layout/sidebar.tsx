import { NavLink } from "react-router-dom";
import {
  Server,
  Bot,
  Activity,
  ShieldCheck,
  Zap,
  Workflow,
  GitBranch,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { to: "/", label: "Connections", icon: Server, exact: true },
  { to: "/agents", label: "Agents", icon: Bot, exact: false },
  { to: "/sessions", label: "Sessions", icon: Activity, exact: false },
  { to: "/router/live", label: "Router Live", icon: Workflow, exact: false },
  { to: "/router/routes", label: "Router Routes", icon: GitBranch, exact: false },
  { to: "/roles", label: "Roles", icon: ShieldCheck, exact: false },
];

export function Sidebar() {
  return (
    <aside className="flex flex-col w-56 shrink-0 border-r bg-card h-screen">
      {/* Logo */}
      <div className="flex items-center gap-2 px-4 py-4 border-b">
        <Zap className="h-5 w-5 text-primary" />
        <span className="font-semibold text-sm tracking-tight">Flint</span>
        <span className="ml-auto text-xs text-muted-foreground font-mono">v0.1</span>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-3 px-2 space-y-0.5">
        {NAV_ITEMS.map(({ to, label, icon: Icon, exact }) => (
          <NavLink
            key={to}
            to={to}
            end={exact}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium transition-colors",
                isActive
                  ? "bg-accent text-accent-foreground"
                  : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
              )
            }
          >
            <Icon className="h-4 w-4 shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t">
        <div className="text-xs text-muted-foreground">Mock mode</div>
      </div>
    </aside>
  );
}
