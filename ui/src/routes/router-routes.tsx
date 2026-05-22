import { useState, useEffect, useCallback } from "react";
import { GitBranch, Save, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useRouterPolicyRaw, putRouterPolicy, useRouterPolicy } from "@/api/client";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "@/components/ui/use-toast";
import type { RouterPolicyView } from "@/api/types";
import { cn } from "@/lib/utils";

// ─── Rules preview ─────────────────────────────────────────────────────────

function conditionSummary(
  ifCond: RouterPolicyView["routes"][number]["if"]
): string {
  if (!ifCond) return "always";
  const parts: string[] = [];
  if (ifCond.task) {
    const tasks = Array.isArray(ifCond.task) ? ifCond.task : [ifCond.task];
    parts.push(`task in [${tasks.join(", ")}]`);
  }
  if (ifCond.complexity) {
    const vals = Array.isArray(ifCond.complexity) ? ifCond.complexity : [ifCond.complexity];
    parts.push(`complexity in [${vals.join(", ")}]`);
  }
  if (ifCond.capabilities_include) {
    const caps = Array.isArray(ifCond.capabilities_include)
      ? ifCond.capabilities_include
      : [ifCond.capabilities_include];
    parts.push(`capabilities include [${caps.join(", ")}]`);
  }
  if (ifCond.capabilities_all) {
    parts.push(`capabilities all [${ifCond.capabilities_all.join(", ")}]`);
  }
  if (ifCond.messages_min_length) {
    parts.push(`messages >= ${ifCond.messages_min_length} chars`);
  }
  if (ifCond.messages_total_tokens_gt) {
    parts.push(`tokens > ${ifCond.messages_total_tokens_gt}`);
  }
  return parts.length > 0 ? parts.join(" AND ") : "always";
}

interface RulesPreviewProps {
  policy: RouterPolicyView | null;
}

function RulesPreview({ policy }: RulesPreviewProps) {
  if (!policy) return null;

  return (
    <div className="space-y-2">
      <h3 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
        Rules preview
      </h3>
      {policy.routes.map((route, i) => (
        <Card key={route.name || i} className="bg-card/60">
          <CardContent className="py-3 px-4">
            <div className="flex items-start justify-between gap-2">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-muted-foreground tabular-nums">
                    {i + 1}.
                  </span>
                  <span className="text-sm font-medium">
                    {route.name || "(unnamed)"}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mt-1 font-mono">
                  {conditionSummary(route.if)}
                </p>
                {route.reason && (
                  <p className="text-xs text-muted-foreground/70 mt-0.5 italic">
                    {route.reason}
                  </p>
                )}
              </div>
              <div className="shrink-0 text-right space-y-1">
                <div className="font-mono text-xs text-foreground">{route.target}</div>
                {route.fallback && route.fallback.length > 0 && (
                  <div className="text-xs text-muted-foreground/60">
                    fallback: {route.fallback.join(", ")}
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      ))}

      {/* Default rule */}
      <Card className="bg-zinc-900/50 border-dashed">
        <CardContent className="py-3 px-4">
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <Badge variant="secondary" className="text-xs px-1.5 py-0">
                  default
                </Badge>
                <span className="text-xs text-muted-foreground font-mono">always</span>
              </div>
              {policy.default.reason && (
                <p className="text-xs text-muted-foreground/70 mt-0.5 italic">
                  {policy.default.reason}
                </p>
              )}
            </div>
            <div className="shrink-0 text-right">
              <div className="font-mono text-xs text-foreground">{policy.default.target}</div>
              {policy.default.fallback && policy.default.fallback.length > 0 && (
                <div className="text-xs text-muted-foreground/60">
                  fallback: {policy.default.fallback.join(", ")}
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Classifier + baseline info */}
      <div className="pt-1 text-xs text-muted-foreground space-y-1">
        <div>
          Classifier:{" "}
          <span className="font-mono text-foreground">{policy.classifier.model}</span>
          {" · "}timeout {policy.classifier.timeout_ms}ms
          {" · "}max_tokens {policy.classifier.max_tokens}
        </div>
        <div>
          Baseline (counterfactual):{" "}
          <span className="font-mono text-foreground">{policy.baseline.model}</span>
        </div>
      </div>
    </div>
  );
}

// ─── Main route ───────────────────────────────────────────────────────────────

export function RouterRoutesRoute() {
  const { data: rawYaml, isLoading: rawLoading, error: rawError } = useRouterPolicyRaw();
  const { data: policy, isLoading: policyLoading } = useRouterPolicy();
  const queryClient = useQueryClient();

  const [yamlValue, setYamlValue] = useState<string>("");
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [saveErrors, setSaveErrors] = useState<string[]>([]);

  // Seed textarea when raw YAML arrives
  useEffect(() => {
    if (rawYaml !== undefined && !isDirty) {
      setYamlValue(rawYaml);
    }
  }, [rawYaml, isDirty]);

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLTextAreaElement>) => {
      setYamlValue(e.target.value);
      setIsDirty(e.target.value !== (rawYaml ?? ""));
      setSaveErrors([]);
    },
    [rawYaml]
  );

  async function handleSave() {
    setIsSaving(true);
    setSaveErrors([]);
    try {
      const result = await putRouterPolicy(yamlValue);
      if (result.ok) {
        setIsDirty(false);
        toast({ title: "Policy saved", description: "Router policy updated successfully." });
        queryClient.invalidateQueries({ queryKey: ["router", "policy"] });
        queryClient.invalidateQueries({ queryKey: ["router", "policy", "raw"] });
      } else {
        setSaveErrors(result.errors ?? ["Unknown validation error"]);
      }
    } catch (err) {
      setSaveErrors([err instanceof Error ? err.message : "Save failed"]);
    } finally {
      setIsSaving(false);
    }
  }

  const isLoading = rawLoading || policyLoading;

  if (isLoading) {
    return (
      <div className="max-w-screen-xl mx-auto space-y-4">
        <Skeleton className="h-8 w-48" />
        <div className="flex gap-6">
          <Skeleton className="flex-1 h-96" />
          <Skeleton className="w-96 h-96" />
        </div>
      </div>
    );
  }

  if (rawError && !rawYaml) {
    return (
      <div className="max-w-screen-xl mx-auto space-y-4">
        <div>
          <h1 className="text-xl font-semibold">Router Routes</h1>
        </div>
        <Card className="border-red-800 bg-red-950/30">
          <CardContent className="py-4 px-4 text-sm text-red-300">
            <div className="flex items-center gap-2 mb-2">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span className="font-medium">Failed to load policy</span>
            </div>
            <p className="text-xs opacity-80">
              {rawError instanceof Error ? rawError.message : String(rawError)}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="max-w-screen-xl mx-auto space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <GitBranch className="h-5 w-5 text-muted-foreground" />
            Router Routes
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Edit the routing policy YAML. Save to apply immediately.
          </p>
        </div>
        <Button
          onClick={handleSave}
          disabled={!isDirty || isSaving}
          size="sm"
          className="gap-2"
        >
          <Save className="h-4 w-4" />
          {isSaving ? "Saving..." : "Save"}
        </Button>
      </div>

      {/* Validation errors */}
      {saveErrors.length > 0 && (
        <div className="rounded-lg border border-red-700 bg-red-950/40 px-4 py-3 space-y-1">
          <div className="flex items-center gap-2 text-sm text-red-300 font-medium">
            <AlertCircle className="h-4 w-4 shrink-0" />
            Policy validation failed
          </div>
          <ul className="space-y-0.5 mt-1">
            {saveErrors.map((e, i) => (
              <li key={i} className="text-xs text-red-400 font-mono">
                {e}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex gap-6" style={{ minHeight: "calc(100vh - 260px)" }}>
        {/* Left: YAML editor */}
        <div className="flex-1 min-w-0 flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
              Policy YAML
            </span>
            <div className="flex items-center gap-2">
              {isDirty && (
                <Badge variant="secondary" className="text-xs px-1.5 py-0">
                  unsaved changes
                </Badge>
              )}
            </div>
          </div>
          <textarea
            value={yamlValue}
            onChange={handleChange}
            className={cn(
              "flex-1 w-full min-h-[500px] rounded-lg border bg-zinc-950 p-4",
              "font-mono text-xs text-zinc-200 leading-relaxed",
              "resize-none outline-none focus:ring-2 focus:ring-ring focus:ring-offset-0",
              "whitespace-pre placeholder:text-muted-foreground/50",
              isDirty && "border-amber-700/60"
            )}
            spellCheck={false}
            placeholder="schema_version: 1\n\nclassifier:\n  model: openai/gpt-4o-mini\n  ..."
          />
        </div>

        {/* Right: Rules preview */}
        <div className="w-96 shrink-0 overflow-auto">
          <RulesPreview policy={policy ?? null} />
        </div>
      </div>
    </div>
  );
}
