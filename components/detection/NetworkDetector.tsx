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
  networkSamples,
  buildNetworkSample,
} from "@/lib/detection/samples-network";
import { parsePcap, PcapError } from "@/lib/detection/pcap";
import { analyzeNetwork } from "@/lib/detection/network";
import type { DetectionReport } from "@/lib/detection/types";

export function NetworkDetector() {
  const [report, setReport] = useState<DetectionReport | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeSample, setActiveSample] = useState<string | null>(null);

  const run = (buffer: ArrayBuffer) => {
    setAnalyzing(true);
    setError(null);
    window.setTimeout(() => {
      try {
        setReport(analyzeNetwork(parsePcap(buffer)));
      } catch (err) {
        setReport(null);
        setError(
          err instanceof PcapError
            ? err.message
            : "Could not parse this capture. Make sure it is a classic PCAP (Ethernet, IPv4)."
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
    run(buildNetworkSample(id));
  };

  return (
    <div className="grid gap-4 lg:grid-cols-5">
      <div className="space-y-3 lg:col-span-2">
        <InputColumn title="1 · Capture input">
          <DropZone
            label="Drop a .pcap capture here"
            hint="classic PCAP · Ethernet · IPv4 · parsed locally"
            accept=".pcap,.cap,application/vnd.tcpdump.pcap"
            onFile={onFile}
            disabled={analyzing}
          />
        </InputColumn>
        <InputColumn title="2 · Attack scenarios (synthetic)">
          <SampleBar
            samples={networkSamples}
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
