import { useState, useEffect } from "react";
import { Plus, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RuleCard } from "./rule-card";
import { useToast } from "@/components/ui/use-toast";
import { usePutRole } from "@/api/client";
import type { Role, Rule } from "@/api/types";

interface Props {
  role: Role;
  onSaved?: () => void;
}

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function emptyRule(): Rule {
  return { effect: "allow", resources: [], verbs: ["invoke"] };
}

export function RoleEditor({ role, onSaved }: Props) {
  const [draft, setDraft] = useState<Role>({ ...role, rules: role.rules.map((r) => ({ ...r })) });
  const [dirty, setDirty] = useState(false);
  const [apiErrors, setApiErrors] = useState<string[]>([]);
  const { toast } = useToast();
  const mutation = usePutRole();

  // Sync when role prop changes (e.g. user clicks a different role)
  useEffect(() => {
    setDraft({ ...role, rules: role.rules.map((r) => ({ ...r })) });
    setDirty(false);
    setApiErrors([]);
  }, [role.name]);

  useEffect(() => {
    setDirty(!deepEqual(draft, role));
  }, [draft, role]);

  function updateRule(idx: number, updated: Rule) {
    setDraft((d) => ({
      ...d,
      rules: d.rules.map((r, i) => (i === idx ? updated : r)),
    }));
  }

  function removeRule(idx: number) {
    setDraft((d) => ({ ...d, rules: d.rules.filter((_, i) => i !== idx) }));
  }

  function addRule() {
    setDraft((d) => ({ ...d, rules: [...d.rules, emptyRule()] }));
  }

  async function handleSave() {
    setApiErrors([]);
    try {
      const result = await mutation.mutateAsync({ name: draft.name, role: draft });
      if (!result.ok) {
        setApiErrors(result.errors ?? ["Unknown error"]);
        return;
      }
      toast({ variant: "success", title: "Role saved", description: `"${draft.name}" updated successfully.` });
      onSaved?.();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setApiErrors([msg]);
    }
  }

  return (
    <div className="space-y-4">
      {/* Role name */}
      <div className="space-y-1">
        <Label className="text-xs text-muted-foreground">Role name</Label>
        <Input
          className="h-8 text-sm font-mono"
          value={draft.name}
          onChange={(e) =>
            setDraft((d) => ({ ...d, name: e.target.value }))
          }
        />
      </div>

      {/* Error alert */}
      {apiErrors.length > 0 && (
        <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-3 space-y-1">
          <div className="flex items-center gap-2 text-destructive text-sm font-medium">
            <AlertCircle className="h-4 w-4" />
            Validation errors
          </div>
          <ul className="pl-6 list-disc text-xs text-destructive/80 space-y-0.5">
            {apiErrors.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Rules */}
      <div className="space-y-3">
        {draft.rules.length === 0 && (
          <div className="text-sm text-muted-foreground text-center py-6 border border-dashed rounded-lg">
            No rules yet. Add a rule below.
          </div>
        )}
        {draft.rules.map((rule, idx) => (
          <RuleCard
            key={idx}
            rule={rule}
            index={idx}
            onChange={(updated) => updateRule(idx, updated)}
            onRemove={() => removeRule(idx)}
          />
        ))}
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 pt-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={addRule}
        >
          <Plus className="h-3.5 w-3.5" />
          Add rule
        </Button>
        <Button
          type="button"
          size="sm"
          disabled={!dirty || mutation.isPending}
          onClick={handleSave}
          className="ml-auto"
        >
          {mutation.isPending ? "Saving..." : "Save changes"}
        </Button>
      </div>
    </div>
  );
}
