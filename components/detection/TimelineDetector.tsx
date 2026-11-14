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
  analyzeTimeline,
  buildTimelineSample,
  parseTimeline,
} from "@/lib/detection/timeline";
import type { DetectionReport } from "@/lib/detection/types";
import { FlaskConical } from "lucide-react";

export function TimelineDetector() {
  const [text, setText] = useState("");
  const [report, setReport] = useState<DetectionReport | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const analyze = () => {
    if (!text.trim()) {
      setError("Paste a timeline CSV first — or load the attack scenario.");
      return;
    }
    setAnalyzing(true);
    setError(null);
    window.setTimeout(() => {
      const entries = parseTimeline(text);
      if (entries.length === 0) {
        setAnalyzing(false);
        setError("No parseable entries found — expected CSV columns: timestamp,host,source,event_id,level,message.");
        return;
      }
      setReport(analyzeTimeline(entries));
      setAnalyzing(false);
    }, 300);
  };

  return (
    <div className="grid gap-4 lg:grid-cols-5">
      <div className="space-y-3 lg:col-span-2">
        <InputColumn title="1 · Timeline input (CSV)">
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            spellCheck={false}
            placeholder="2026-11-14T08:04:19,DC01,Microsoft-Windows-Security-Auditing,4625,Information,&quot;An account failed to log on...&quot;"
            className="h-44 w-full resize-y rounded-lg border border-border bg-background/60 p-3 font-mono text-[11px] leading-relaxed text-foreground/90 placeholder:text-muted-fg/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60"
            aria-label="Timeline CSV input"
          />
          <p className="font-mono text-[10px] text-muted-fg">
            timestamp,host,source,event_id,level,message — or any line containing a known event ID (4624/4625/4648/4688/4698/7045/1102)
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={analyze}
              disabled={analyzing}
              className="inline-flex h-9 items-center rounded-md bg-accent px-4 text-xs font-semibold text-primary-foreground transition-colors hover:bg-accent/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70 disabled:opacity-60"
            >
              Analyze timeline
            </button>
            <button
              type="button"
              onClick={() => {
                setText(buildTimelineSample());
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
