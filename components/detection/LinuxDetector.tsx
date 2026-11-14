"use client";

import { useState } from "react";
import {
  AnalyzingHint,
  ErrorBox,
  InputColumn,
  Placeholder,
  ReportView,
} from "@/components/detection/detection-ui";
import {
  analyzeLinuxLog,
  buildLinuxLogSample,
  parseLinuxLog,
} from "@/lib/detection/linux";
import type { DetectionReport } from "@/lib/detection/types";
import { FlaskConical } from "lucide-react";

export function LinuxDetector() {
  const [text, setText] = useState("");
  const [report, setReport] = useState<DetectionReport | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const analyze = () => {
    if (!text.trim()) {
      setError("Paste an auth.log/syslog slice first — or load the attack scenario.");
      return;
    }
    setAnalyzing(true);
    setError(null);
    window.setTimeout(() => {
      const entries = parseLinuxLog(text);
      if (entries.length === 0) {
        setAnalyzing(false);
        setError("No parseable lines found.");
        return;
      }
      setReport(analyzeLinuxLog(entries));
      setAnalyzing(false);
    }, 300);
  };

  return (
    <div className="grid gap-4 lg:grid-cols-5">
      <div className="space-y-3 lg:col-span-2">
        <InputColumn title="1 · Log input (auth.log / syslog)">
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            spellCheck={false}
            placeholder="Nov 14 08:08:47 srv01 sshd[471]: Accepted password for root from 185.220.14.9 port 61110 ssh2"
            className="h-44 w-full resize-y rounded-lg border border-border bg-background/60 p-3 font-mono text-[11px] leading-relaxed text-foreground/90 placeholder:text-muted-fg/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60"
            aria-label="Linux log input"
          />
          <p className="font-mono text-[10px] text-muted-fg">
            handles sshd / sudo / cron / auditd lines — paste any slice, it stays in your browser
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={analyze}
              disabled={analyzing}
              className="inline-flex h-9 items-center rounded-md bg-accent px-4 text-xs font-semibold text-primary-foreground transition-colors hover:bg-accent/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70 disabled:opacity-60"
            >
              Analyze log
            </button>
            <button
              type="button"
              onClick={() => {
                setText(buildLinuxLogSample());
                setError(null);
              }}
              className="inline-flex h-9 items-center gap-1.5 rounded-md border border-border px-3 text-xs text-muted-fg transition-colors hover:border-accent/40 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70"
            >
              <FlaskConical size={12} aria-hidden="true" />
              Load attack scenario
            </button>
            {text && (
              <button
                type="button"
                onClick={() => {
                  setText("");
                  setReport(null);
                  setError(null);
                }}
                className="inline-flex h-9 items-center rounded-md px-2 text-xs text-muted-fg/70 transition-colors hover:text-foreground"
              >
                Clear
              </button>
            )}
          </div>
        </InputColumn>
        {error ? <ErrorBox message={error} /> : null}
      </div>
      <div className="lg:col-span-3">
        {analyzing ? (
          <AnalyzingHint />
        ) : report ? (
          <ReportView
            report={report}
            onReset={() => {
              setReport(null);
              setError(null);
            }}
          />
        ) : (
          <Placeholder />
        )}
      </div>
    </div>
  );
}
