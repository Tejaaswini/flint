import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-primary text-primary-foreground hover:bg-primary/80",
        secondary:
          "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
        destructive:
          "border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/80",
        outline: "text-foreground",
        // Flint-specific
        allow:
          "border-transparent bg-green-900/60 text-green-300 hover:bg-green-900/80",
        deny: "border-transparent bg-red-900/60 text-red-300 hover:bg-red-900/80",
        finding:
          "border-transparent bg-amber-900/60 text-amber-300 hover:bg-amber-900/80",
        read: "border-transparent bg-blue-900/60 text-blue-300",
        write: "border-transparent bg-amber-900/60 text-amber-300",
        admin: "border-transparent bg-red-900/60 text-red-300",
        connected:
          "border-transparent bg-green-900/60 text-green-300",
        degraded:
          "border-transparent bg-amber-900/60 text-amber-300",
        offline:
          "border-transparent bg-zinc-700 text-zinc-300",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
