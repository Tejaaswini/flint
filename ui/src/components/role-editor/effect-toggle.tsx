import { cn } from "@/lib/utils";

interface Props {
  effect: "allow" | "deny";
  onChange: (effect: "allow" | "deny") => void;
  disabled?: boolean;
}

export function EffectToggle({ effect, onChange, disabled }: Props) {
  return (
    <div className={cn("flex rounded-md overflow-hidden border border-input text-xs font-medium", disabled && "opacity-50 pointer-events-none")}>
      <button
        type="button"
        onClick={() => onChange("allow")}
        className={cn(
          "px-3 py-1.5 transition-colors",
          effect === "allow"
            ? "bg-green-900/80 text-green-300 border-r border-input"
            : "bg-transparent text-muted-foreground hover:bg-muted border-r border-input"
        )}
      >
        Allow
      </button>
      <button
        type="button"
        onClick={() => onChange("deny")}
        className={cn(
          "px-3 py-1.5 transition-colors",
          effect === "deny"
            ? "bg-red-900/80 text-red-300"
            : "bg-transparent text-muted-foreground hover:bg-muted"
        )}
      >
        Deny
      </button>
    </div>
  );
}
