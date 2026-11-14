import type { Metadata } from "next";
import { Container } from "@/components/layout/Container";
import { WorkbenchClient } from "@/components/workbench/WorkbenchClient";

export const metadata: Metadata = {
  title: {
    absolute: "Detection Workbench — DFIR Lab",
  },
  description:
    "Hands-on, in-browser detection: analyze Linux auth.log, Windows event " +
    "CSV timelines, Volatility process lists and real PCAP captures. " +
    "Everything runs locally in your browser — no evidence ever leaves " +
    "your machine.",
};

export default function WorkbenchPage() {
  return (
    <Container className="py-16 md:py-24">
      <p className="font-mono text-xs uppercase tracking-[0.3em] text-accent">
        {"// Detection Workbench"}
      </p>
      <h1 className="mt-4 max-w-3xl text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl">
        Real detection,
        <br />
        <span className="text-accent">in your browser.</span>
      </h1>
      <p className="mt-6 max-w-2xl text-lg leading-relaxed text-muted-foreground">
        Four working analyzers — one per lab. Paste evidence or load a sample
        dataset, run the ruleset, export the findings as JSON/CSV. Analysis is
        100% client-side: your logs, memory dumps and packet captures never
        leave this page.
      </p>
      <div className="mt-12">
        <WorkbenchClient />
      </div>
    </Container>
  );
}
