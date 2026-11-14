import { cn } from "@/lib/utils";
import type { HTMLAttributes } from "react";

export function Badge({ className, ...props }: HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border border-border bg-muted px-2.5 py-1 font-mono text-xs text-foreground transition-colors hover:border-accent hover:text-accent",
        className
      )}
      {...props}
    />
  );
}
