import { useState } from "react";
import { Plus, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { RoleEditor } from "@/components/role-editor";
import { useRoles } from "@/api/client";
import { cn } from "@/lib/utils";
import type { Role } from "@/api/types";

function emptyRole(): Role {
  return { name: "new-role", rules: [] };
}

export function RolesRoute() {
  const { data: roles, isLoading, refetch } = useRoles();
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [newRole, setNewRole] = useState<Role | null>(null);

  const allRoles: Role[] = [...(roles ?? []), ...(newRole ? [newRole] : [])];
  const effectiveName = newRole ? newRole.name : (selectedName ?? roles?.[0]?.name ?? null);
  const selectedRole = allRoles.find((r) => r.name === effectiveName) ?? null;

  function handleNewRole() {
    const role = emptyRole();
    setNewRole(role);
    setSelectedName(null);
  }

  function handleSaved() {
    setNewRole(null);
    refetch();
  }

  if (isLoading) {
    return (
      <div className="flex gap-4 h-full max-w-6xl mx-auto">
        <div className="w-52 shrink-0 space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-10 rounded-lg" />
          ))}
        </div>
        <Skeleton className="flex-1 rounded-lg" />
      </div>
    );
  }

  return (
    <div className="flex gap-6 max-w-6xl mx-auto h-full">
      {/* Role list */}
      <div className="w-52 shrink-0 flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            Roles
          </h2>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-xs"
            onClick={handleNewRole}
          >
            <Plus className="h-3.5 w-3.5" />
            New
          </Button>
        </div>
        <ScrollArea className="flex-1">
          <div className="space-y-0.5 pr-1">
            {allRoles.length === 0 ? (
              <div className="text-xs text-muted-foreground px-3 py-4">
                No roles yet.
              </div>
            ) : (
              allRoles.map((role) => (
                <RoleListItem
                  key={role.name}
                  role={role}
                  selected={effectiveName === role.name}
                  isNew={newRole?.name === role.name}
                  onClick={() => {
                    setSelectedName(role.name);
                    setNewRole(null);
                  }}
                />
              ))
            )}
          </div>
        </ScrollArea>
      </div>

      <Separator orientation="vertical" className="h-auto" />

      {/* Role editor */}
      <div className="flex-1 min-w-0 overflow-auto">
        {!selectedRole ? (
          <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
            <ShieldCheck className="h-10 w-10 mb-3 opacity-30" />
            <p className="text-sm">Select a role to edit</p>
          </div>
        ) : (
          <div className="space-y-4 max-w-2xl">
            <div>
              <h2 className="text-base font-semibold">{selectedRole.name}</h2>
              <p className="text-xs text-muted-foreground mt-0.5">
                {selectedRole.rules.length} rule{selectedRole.rules.length !== 1 ? "s" : ""}
                {selectedRole.rules.some((r) => r.effect === "deny") && (
                  <> · includes deny rules</>
                )}
              </p>
            </div>
            <RoleEditor
              key={selectedRole.name}
              role={selectedRole}
              onSaved={handleSaved}
            />
          </div>
        )}
      </div>
    </div>
  );
}

interface RoleListItemProps {
  role: Role;
  selected: boolean;
  isNew?: boolean;
  onClick: () => void;
}

function RoleListItem({ role, selected, isNew, onClick }: RoleListItemProps) {
  const hasDeny = role.rules.some((r) => r.effect === "deny");

  return (
    <div
      className={cn(
        "flex items-center gap-2 px-3 py-2 rounded-md cursor-pointer transition-colors text-sm",
        selected
          ? "bg-accent text-accent-foreground"
          : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
      )}
      onClick={onClick}
    >
      <span className="flex-1 truncate font-mono text-xs">{role.name}</span>
      <div className="flex items-center gap-1 shrink-0">
        {isNew && (
          <Badge variant="secondary" className="text-xs px-1 py-0">
            new
          </Badge>
        )}
        {hasDeny && (
          <Badge variant="deny" className="text-xs px-1 py-0">
            deny
          </Badge>
        )}
      </div>
    </div>
  );
}
