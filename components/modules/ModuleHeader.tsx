import { getModuleIcon } from "@/lib/icons";
import type { Module } from "@/lib/types";

export function ModuleHeader({ module }: { module: Module }) {
  const Icon = getModuleIcon(module.icon);

  return (
    <header>
      <div className="flex flex-col gap-6 sm:flex-row sm:items-start">
        <div
          className="flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl border border-border bg-accent-muted"
          aria-hidden
        >
          <Icon className="h-8 w-8 text-accent" />
        </div>
        <div className="space-y-3">
          <p className="font-mono text-xs uppercase tracking-[0.25em] text-accent">
            Traceback — Investigation Lab
          </p>
          <h1 className="text-3xl font-bold leading-tight tracking-tight sm:text-4xl lg:text-5xl">
            {module.title}
          </h1>
          <p className="font-mono text-sm text-muted-foreground">
            {module.subtitle}
          </p>
        </div>
      </div>

      <p className="mt-8 max-w-3xl text-lg leading-relaxed text-foreground/90">
        {module.description}
      </p>

      <div className="mt-8 grid gap-4 md:grid-cols-2">
        <div className="rounded-xl border border-border bg-muted/40 p-5">
          <p className="font-mono text-xs uppercase tracking-[0.25em] text-accent">
            Objective
          </p>
          <p className="mt-2 text-sm leading-relaxed text-foreground/90">
            {module.objective}
          </p>
        </div>
        <div className="rounded-xl border border-border bg-muted/40 p-5">
          <p className="font-mono text-xs uppercase tracking-[0.25em] text-accent">
            Context
          </p>
          <p className="mt-2 text-sm leading-relaxed text-foreground/90">
            {module.context}
          </p>
        </div>
      </div>
    </header>
  );
}
