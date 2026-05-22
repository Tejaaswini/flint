import { useState, useRef, KeyboardEvent } from "react";
import { Trash2, ChevronDown, ChevronRight, Plus, X } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { EffectToggle } from "./effect-toggle";
import type { Rule } from "@/api/types";

const VERB_OPTIONS = ["invoke", "discover", "admin"];
const CONSTRAINT_KEYS = ["sql_intent", "path_prefix"] as const;

interface Props {
  rule: Rule;
  index: number;
  onChange: (updated: Rule) => void;
  onRemove: () => void;
}

export function RuleCard({ rule, index, onChange, onRemove }: Props) {
  const [constraintsOpen, setConstraintsOpen] = useState(
    Object.keys(rule.constraints ?? {}).length > 0
  );
  const resourceInputRef = useRef<HTMLInputElement>(null);

  function setEffect(effect: "allow" | "deny") {
    onChange({ ...rule, effect });
  }

  function setName(name: string) {
    onChange({ ...rule, name });
  }

  // Resource chip management
  function addResource(value: string) {
    const trimmed = value.trim();
    if (!trimmed) return;
    const resources = rule.resources ?? [];
    if (!resources.includes(trimmed)) {
      onChange({ ...rule, resources: [...resources, trimmed] });
    }
  }

  function removeResource(res: string) {
    onChange({ ...rule, resources: (rule.resources ?? []).filter((r) => r !== res) });
  }

  function handleResourceKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      const input = resourceInputRef.current;
      if (input && input.value.trim()) {
        addResource(input.value);
        input.value = "";
      }
    }
  }

  // Verb toggle
  function toggleVerb(verb: string) {
    const verbs = rule.verbs ?? [];
    if (verbs.includes(verb)) {
      onChange({ ...rule, verbs: verbs.filter((v) => v !== verb) });
    } else {
      onChange({ ...rule, verbs: [...verbs, verb] });
    }
  }

  // Constraint value chips
  function addConstraintValue(key: string, value: string) {
    const trimmed = value.trim();
    if (!trimmed) return;
    const existing = rule.constraints?.[key] ?? [];
    if (!existing.includes(trimmed)) {
      onChange({
        ...rule,
        constraints: { ...(rule.constraints ?? {}), [key]: [...existing, trimmed] },
      });
    }
  }

  function removeConstraintValue(key: string, value: string) {
    const existing = rule.constraints?.[key] ?? [];
    const updated = existing.filter((v) => v !== value);
    const constraints = { ...(rule.constraints ?? {}) };
    if (updated.length === 0) {
      delete constraints[key];
    } else {
      constraints[key] = updated;
    }
    onChange({ ...rule, constraints });
  }

  return (
    <Card className="border-zinc-700">
      <CardContent className="pt-4 space-y-4">
        {/* Header row */}
        <div className="flex items-center gap-3">
          <span className="text-xs text-muted-foreground font-mono w-5 shrink-0">
            #{index + 1}
          </span>
          <EffectToggle
            effect={(rule.effect as "allow" | "deny") ?? "allow"}
            onChange={setEffect}
          />
          <Input
            className="h-8 text-xs flex-1"
            placeholder="Rule name (optional)"
            value={rule.name ?? ""}
            onChange={(e) => setName(e.target.value)}
          />
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-muted-foreground hover:text-destructive shrink-0"
            onClick={onRemove}
            title="Remove rule"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>

        {/* Resources */}
        <div className="space-y-1.5">
          <Label className="text-xs text-muted-foreground">Resources</Label>
          <div className="flex flex-wrap gap-1.5 min-h-[32px] rounded-md border border-input bg-background px-2 py-1.5">
            {(rule.resources ?? []).map((res) => (
              <span
                key={res}
                className="inline-flex items-center gap-1 rounded-full bg-zinc-700 px-2 py-0.5 text-xs"
              >
                {res.startsWith("server:") ? (
                  <span className="text-blue-400">{res}</span>
                ) : res === "*" ? (
                  <span className="text-amber-400">{res}</span>
                ) : (
                  <span className="font-mono">{res}</span>
                )}
                <button
                  type="button"
                  onClick={() => removeResource(res)}
                  className="text-muted-foreground hover:text-foreground"
                >
                  <X className="h-3 w-3" />
                </button>
              </span>
            ))}
            <input
              ref={resourceInputRef}
              className="flex-1 min-w-[80px] bg-transparent text-xs outline-none placeholder:text-muted-foreground"
              placeholder="Add resource (Enter)"
              onKeyDown={handleResourceKeyDown}
              onBlur={(e) => {
                if (e.target.value.trim()) {
                  addResource(e.target.value);
                  e.target.value = "";
                }
              }}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            Accepts: bare tool names, <code className="bg-zinc-800 px-1 rounded">server:github</code>, or <code className="bg-zinc-800 px-1 rounded">*</code>
          </p>
        </div>

        {/* Verbs */}
        <div className="space-y-1.5">
          <Label className="text-xs text-muted-foreground">Verbs</Label>
          <div className="flex gap-2">
            {VERB_OPTIONS.map((verb) => (
              <button
                key={verb}
                type="button"
                onClick={() => toggleVerb(verb)}
                className={`px-3 py-1 rounded-full text-xs font-medium border transition-colors ${
                  (rule.verbs ?? []).includes(verb)
                    ? "bg-primary text-primary-foreground border-primary"
                    : "bg-transparent text-muted-foreground border-input hover:border-zinc-500"
                }`}
              >
                {verb}
              </button>
            ))}
          </div>
        </div>

        {/* Constraints accordion */}
        <div>
          <button
            type="button"
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
            onClick={() => setConstraintsOpen((o) => !o)}
          >
            {constraintsOpen ? (
              <ChevronDown className="h-3.5 w-3.5" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5" />
            )}
            Constraints
            {Object.keys(rule.constraints ?? {}).length > 0 && (
              <Badge variant="secondary" className="text-xs">
                {Object.keys(rule.constraints ?? {}).length}
              </Badge>
            )}
          </button>
          {constraintsOpen && (
            <div className="mt-2 space-y-2 pl-5">
              {CONSTRAINT_KEYS.map((key) => {
                const values = rule.constraints?.[key] ?? [];
                const inputId = `constraint-${index}-${key}`;
                return (
                  <div key={key} className="space-y-1">
                    <Label htmlFor={inputId} className="text-xs text-muted-foreground capitalize">
                      {key.replace("_", " ")}
                    </Label>
                    <div className="flex flex-wrap gap-1.5 min-h-[28px] rounded-md border border-input bg-background px-2 py-1">
                      {values.map((v) => (
                        <span
                          key={v}
                          className="inline-flex items-center gap-1 rounded-full bg-zinc-700 px-2 py-0.5 text-xs font-mono"
                        >
                          {v}
                          <button
                            type="button"
                            onClick={() => removeConstraintValue(key, v)}
                            className="text-muted-foreground hover:text-foreground"
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </span>
                      ))}
                      <input
                        id={inputId}
                        className="flex-1 min-w-[60px] bg-transparent text-xs outline-none placeholder:text-muted-foreground font-mono"
                        placeholder="Add value (Enter)"
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            const inp = e.currentTarget;
                            addConstraintValue(key, inp.value);
                            inp.value = "";
                          }
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
