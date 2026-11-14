"use client";

import { useState, type ReactNode } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  TriangleAlert,
  ClipboardCopy,
  ClipboardCheck,
  ScanLine,
  Upload,
  FlaskConical,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type {
  DetectionReport,
  SampleMeta,
  Severity,
  Verdict,
} from "@/lib/detection/types";

const SEVERITY_STYLES: Record<Severity, string> = {
  high: "border-[#ff5c5c]/40 bg-[#ff5c5c]/10 text-[#ff8080]",
  medium: "border-[#ffb454]/40 bg-[#ffb454]/10 text-[#ffb454]",
  low: "border-[#8aa4ff]/40 bg-[#8aa4ff]/10 text-[#a8bcff]",
  info: "border-border bg-muted text-muted-fg",
};

export function SeverityChip({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex w-16 shrink-0 items-center justify-center rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider",
        SEVERITY_STYLES[severity]
      )}
    >
      {severity}
    </span>
  );
}

const VERDICT_STYLES: Record<
  Verdict,
  { label: string; box: string; text: string; icon: typeof ShieldCheck }
> = {
  clean: {
    label: "CLEAN",
    box: "border-accent/40 bg-accent-muted",
    text: "text-accent",
    icon: ShieldCheck,
  },
  suspicious: {
    label: "SUSPICIOUS",
    box: "border-[#ffb454]/40 bg-[#ffb454]/10",
    text: "text-[#ffb454]",
    icon: ShieldAlert,
  },
  malicious: {
    label: "MALICIOUS",
    box: "border-[#ff5c5c]/40 bg-[#ff5c5c]/10",
    text: "text-[#ff5c5c]",
    icon: TriangleAlert,
  },
};

export function VerdictBanner({
  verdict,
  summary,
}: {
  verdict: Verdict;
  summary: string;
}) {
  const config = VERDICT_STYLES[verdict];
  const Icon = config.icon;
  return (
    <div className={cn("rounded-xl border p-4", config.box)} role="status">
      <div className="flex items-center gap-3">
        <Icon size={22} className={config.text} aria-hidden="true" />
        <span className={cn("font-mono text-base font-bold tracking-[0.2em]", config.text)}>
          {config.label}
        </span>
      </div>
      <p className="mt-2 text-sm leading-relaxed text-foreground/85">{summary}</p>
    </div>
  );
}

export function StatStrip({ stats }: { stats: DetectionReport["stats"] }) {
  if (stats.length === 0) return null;
  return (
    <dl className="grid grid-cols-2 gap-2 sm:grid-cols-3">
      {stats.map((s) => (
        <div
          key={s.label}
          className="rounded-lg border border-border bg-muted/40 px-3 py-2"
        >
          <dt className="font-mono text-[9px] uppercase tracking-wider text-muted-fg">
            {s.label}
          </dt>
          <dd className="mt-0.5 truncate font-mono text-xs text-foreground" title={s.value}>
            {s.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function FindingsList({ findings }: { findings: DetectionReport["findings"] }) {
  if (findings.length === 0) {
    return (
      <p className="rounded-lg border border-border bg-muted/30 p-4 text-sm text-muted-fg">
        No findings — artifact analyzed clean. Widen the scope if suspicion remains.
      </p>
    );
  }
  return (
    <ul className="space-y-2">
      {findings.map((f, idx) => (
        <li
          key={`${f.rule}-${idx}`}
          className="flex gap-3 rounded-lg border border-border bg-background/40 p-3"
        >
          <SeverityChip severity={f.severity} />
          <div className="min-w-0">
            <p className="text-sm font-medium leading-snug text-foreground/90">
              {f.title}
            </p>
            <p className="mt-1 text-xs leading-relaxed text-muted-fg">{f.detail}</p>
            <p className="mt-1.5 font-mono text-[10px] uppercase tracking-wider text-muted-fg/70">
              rule: {f.rule}
            </p>
            {f.ioc ? (
              <code className="mt-1 block truncate rounded border border-border bg-muted/60 px-2 py-0.5 font-mono text-[11px] text-accent/90" title={f.ioc}>
                {f.ioc}
              </code>
            ) : null}
          </div>
        </li>
      ))}
    </ul>
  );
}

export function IocStrip({ iocs }: { iocs: string[] }) {
  const [copied, setCopied] = useState(false);
  if (iocs.length === 0) return null;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(iocs.join("\n"));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // clipboard unavailable — keep the UI usable
      setCopied(false);
    }
  };

  return (
    <div className="rounded-lg border border-accent/20 bg-accent-muted/40 p-3">
      <div className="flex items-center justify-between gap-3">
        <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-accent">
          IoC list — {iocs.length}
        </p>
        <button
          type="button"
          onClick={copy}
          className="inline-flex items-center gap-1.5 rounded-md border border-accent/30 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-accent transition-colors hover:border-accent/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70"
          aria-label="Copy all indicators to clipboard"
        >
          {copied ? (
            <>
              <ClipboardCheck size={12} aria-hidden="true" /> Copied
            </>
          ) : (
            <>
              <ClipboardCopy size={12} aria-hidden="true" /> Copy all
            </>
          )}
        </button>
      </div>
      <ul className="mt-2 flex flex-wrap gap-1.5">
        {iocs.map((ioc) => (
          <li
            key={ioc}
            className="max-w-full truncate rounded border border-border bg-background/60 px-2 py-0.5 font-mono text-[11px] text-foreground/85"
            title={ioc}
          >
            {ioc}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ReportView({
  report,
  onReset,
}: {
  report: DetectionReport;
  onReset: () => void;
}) {
  return (
    <div className="space-y-3">
      <VerdictBanner verdict={report.verdict} summary={report.summary} />
      <StatStrip stats={report.stats} />
      <FindingsList findings={report.findings} />
      <IocStrip iocs={report.iocs} />
      <p className="px-1 font-mono text-[10px] text-muted-fg/80">
        Verdict computed in your browser from embedded heuristics — verify before acting.
        {" "}
        <button
          type="button"
          onClick={onReset}
          className="text-accent underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70"
        >
          Analyze another artifact
        </button>
      </p>
    </div>
  );
}

export function Placeholder() {
  return (
    <div className="flex h-full min-h-56 flex-col items-center justify-center rounded-xl border border-dashed border-border bg-muted/20 p-8 text-center">
      <ScanLine size={36} className="text-muted-fg/60" aria-hidden="true" />
      <p className="mt-3 max-w-xs text-sm text-muted-fg">
        Drop an artifact on the left — or load a built-in attack scenario.
        Verdicts compute locally.
      </p>
    </div>
  );
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-[#ff5c5c]/40 bg-[#ff5c5c]/10 p-3 text-xs leading-relaxed text-[#ffb0b0]"
    >
      {message}
    </div>
  );
}

export function SampleBar({
  samples,
  activeId,
  onSelect,
  disabled,
}: {
  samples: SampleMeta[];
  activeId: string | null;
  onSelect: (id: string) => void;
  disabled?: boolean;
}) {
  return (
    <div className="space-y-2">
      <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-fg">
        Or load a synthetic sample
      </p>
      <ul className="space-y-2">
        {samples.map((sample) => (
          <li key={sample.id}>
            <button
              type="button"
              disabled={disabled}
              onClick={() => onSelect(sample.id)}
              className={cn(
                "w-full rounded-lg border border-border bg-muted/30 px-3 py-2 text-left transition-colors hover:border-accent/40 hover:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70 disabled:cursor-not-allowed disabled:opacity-60",
                activeId === sample.id && "border-accent/50 bg-accent-muted/50"
              )}
              aria-pressed={activeId === sample.id}
            >
              <span className="flex items-center gap-2 text-xs font-semibold text-foreground/90">
                <FlaskConical size={12} className="shrink-0 text-accent" aria-hidden="true" />
                {sample.label}
              </span>
              <span className="mt-1 block text-[11px] leading-snug text-muted-fg">
                {sample.blurb}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function DropZone({
  label,
  hint,
  accept,
  onFile,
  disabled,
}: {
  label: string;
  hint: string;
  accept: string;
  onFile: (file: File) => void;
  disabled?: boolean;
}) {
  const [dragging, setDragging] = useState(false);

  return (
    <label
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const file = e.dataTransfer.files?.[0];
        if (file && !disabled) onFile(file);
      }}
      className={cn(
        "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-border bg-muted/20 px-4 py-6 text-center transition-colors hover:border-accent/40 focus-within:ring-2 focus-within:ring-accent/60",
        dragging && "border-accent/60 bg-accent-muted/30",
        disabled && "cursor-not-allowed opacity-60"
      )}
    >
      <input
        type="file"
        accept={accept}
        className="sr-only"
        disabled={disabled}
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) onFile(file);
          e.target.value = "";
        }}
      />
      <Upload size={22} className="text-muted-fg" aria-hidden="true" />
      <span className="text-sm font-medium text-foreground/85">{label}</span>
      <span className="font-mono text-[10px] text-muted-fg">{hint}</span>
    </label>
  );
}

export function AnalyzingHint() {
  return (
    <div
      role="status"
      className="flex h-full min-h-56 items-center justify-center rounded-xl border border-border bg-muted/20 p-8"
    >
      <p className="animate-pulse font-mono text-xs uppercase tracking-[0.3em] text-accent">
        Analyzing…
      </p>
    </div>
  );
}

export function InputColumn({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4">
      <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-fg">
        {title}
      </p>
      <div className="mt-3 space-y-3">{children}</div>
    </div>
  );
}
