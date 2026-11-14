"use client";

import { motion } from "framer-motion";
import { ToolBadge } from "@/components/modules/ToolBadge";
import type { Step } from "@/lib/types";

export function StepList({ steps }: { steps: Step[] }) {
  return (
    <ol className="space-y-6">
      {steps.map((step, index) => (
        <motion.li
          key={step.order}
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-60px" }}
          transition={{ duration: 0.45, delay: index * 0.08, ease: "easeOut" }}
          className="flex flex-col gap-4 rounded-xl border border-border bg-muted/40 p-5 sm:flex-row sm:gap-6 sm:p-6"
        >
          <div className="flex shrink-0 items-start">
            <span
              className="flex h-11 w-11 items-center justify-center rounded-full border border-accent/40 bg-accent-muted font-mono text-base font-bold text-accent"
              aria-hidden
            >
              {String(step.order).padStart(2, "0")}
            </span>
          </div>
          <div className="space-y-3">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <h3 className="text-lg font-semibold tracking-tight">
                {step.title}
              </h3>
              <span className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
                Step {step.order}/{steps.length}
              </span>
            </div>
            <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground sm:text-[15px]">
              {step.body}
            </p>
            <ul className="flex flex-wrap gap-2 pt-1" aria-label="Tools used in this step">
              {step.tools.map((tool) => (
                <li key={tool}>
                  <ToolBadge name={tool} />
                </li>
              ))}
            </ul>
          </div>
        </motion.li>
      ))}
    </ol>
  );
}
