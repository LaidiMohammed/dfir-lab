"use client";

import { useState } from "react";
import {
  AnalyzingHint,
  DropZone,
  ErrorBox,
  InputColumn,
  Placeholder,
  ReportView,
  SampleBar,
} from "@/components/detection/detection-ui";
import {
  peSamples,
  buildSamplePe,
  parsePe,
  analyzePe,
  PeError,
  type PeSampleId,
} from "@/lib/detection/pe";
import type { DetectionReport, SampleMeta } from "@/lib/detection/types";

const peSampleMetas: SampleMeta[] = peSamples.map((s) => ({
  id: s.id,
  label: s.label,
  blurb: s.blurb,
}));

export function MemoryDetector() {
  const [report, setReport] = useState<DetectionReport | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeSample, setActiveSample] = useState<string | null>(null);

  const run = (buffer: ArrayBuffer) => {
    setAnalyzing(true);
    setError(null);
    window.setTimeout(() => {
      try {
        setReport(analyzePe(parsePe(buffer)));
      } catch (err) {
        setReport(null);
        setError(
          err instanceof PeError
            ? err.message
            : "Could not parse this binary. PE32/PE32+ (.exe, .dll, .sys, .scr) only."
        );
      } finally {
        setAnalyzing(false);
      }
    }, 350);
  };

  const onFile = (file: File) => {
    setActiveSample(null);
    file
      .arrayBuffer()
      .then(run)
      .catch(() => setError("Could not read the file."));
  };

  const onSample = (id: string) => {
    setActiveSample(id);
    run(buildSamplePe(id as PeSampleId));
  };

  return (
    <div className="grid gap-4 lg:grid-cols-5">
      <div className="space-y-3 lg:col-span-2">
        <InputColumn title="1 · Binary input">
          <DropZone
            label="Drop a suspicious .exe / .dll"
            hint="static PE triage · sections · entropy · W^X flags · local only"
            accept=".exe,.dll,.sys,.scr,.bin,application/octet-stream"
            onFile={onFile}
            disabled={analyzing}
          />
        </InputColumn>
        <InputColumn title="2 · Synthetic samples">
          <SampleBar
            samples={peSampleMetas}
            activeId={activeSample}
            onSelect={onSample}
            disabled={analyzing}
          />
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
              setActiveSample(null);
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
