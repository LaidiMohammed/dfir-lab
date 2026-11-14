import Link from "next/link";
import { ArrowRight, Radar } from "lucide-react";

/**
 * Cross-link from a module (methodology) page to its interactive analyzer
 * in the Detection Workbench. `lab` must match a Workbench lab id.
 */
export function WorkbenchCta({ lab }: { lab: "linux" | "timeline" | "memory" | "network" }) {
  return (
    <Link
      href={`/workbench?lab=${lab}`}
      className="group mt-8 flex flex-col gap-3 rounded-xl border border-accent/40 bg-accent-muted p-5 transition-colors hover:border-accent sm:flex-row sm:items-center sm:justify-between sm:p-6"
    >
      <span className="flex items-start gap-4">
        <Radar className="mt-1 h-6 w-6 shrink-0 text-accent" aria-hidden />
        <span>
          <span className="block font-mono text-[11px] uppercase tracking-[0.25em] text-accent">
            Interactive — run it now
          </span>
          <span className="mt-1 block text-sm leading-relaxed text-foreground/90 sm:text-base">
            Analyze this lab&apos;s evidence in the built-in detection
            workbench — real rules, real parsing, zero upload.
          </span>
        </span>
      </span>
      <span className="inline-flex shrink-0 items-center gap-2 font-mono text-sm font-bold uppercase tracking-wider text-accent">
        Open workbench
        <ArrowRight
          className="h-4 w-4 transition-transform group-hover:translate-x-1"
          aria-hidden
        />
      </span>
    </Link>
  );
}
