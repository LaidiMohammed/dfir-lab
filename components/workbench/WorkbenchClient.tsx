"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  analyzeLinuxLog,
  analyzeTimelineCsv,
  analyzeProcesses,
  analyzePcap,
} from "@/lib/detection";
import type { AnalysisResult, Severity } from "@/lib/detection/types";
import { SEVERITY_ORDER } from "@/lib/detection/types";
import {
  Activity,
  Clock,
  Cpu,
  Download,
  FileText,
  FolderOpen,
  Network,
  Play,
  Radar,
  RotateCcw,
  Terminal,
  Upload,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";

type LabId = "linux" | "timeline" | "memory" | "network";

interface LabConfig {
  id: LabId;
  label: string;
  icon: LucideIcon;
  title: string;
  blurb: string;
  accepts: string;
  placeholder: string;
  samplePath: string;
  sampleName: string;
  inputKind: "text" | "pcap";
  analyze: (input: string | Uint8Array) => AnalysisResult;
  detects: { rule: string; what: string }[];
}

const LABS: LabConfig[] = [
  {
    id: "linux",
    label: "Linux Server",
    icon: Terminal,
    title: "Linux auth.log / history analyzer",
    blurb:
      "Paste or drop an auth.log / secure / syslog export. Detects SSH brute force, post-brute-force success, rogue accounts, SUID abuse, reverse shells, persistence and anti-forensics.",
    accepts: ".log,.txt,.csv",
    placeholder:
      "Nov 14 08:12:01 web01 sshd[2204]: Failed password for invalid user admin from 203.0.113.44 port 51124 ssh2\n…",
    samplePath: "/samples/sample-auth.log",
    sampleName: "sample-auth.log",
    inputKind: "text",
    analyze: (input) => analyzeLinuxLog(String(input)),
    detects: [
      { rule: "LDX-001", what: "SSH brute force (≥5 fails/IP)" },
      { rule: "LDX-002", what: "Success after brute force (critical)" },
      { rule: "LDX-003", what: "UID-0 / suspicious account creation" },
      { rule: "LDX-004", what: "SUID backdoor planting" },
      { rule: "LDX-005", what: "Reverse shell / curl|bash pipes" },
      { rule: "LDX-006", what: "LD_PRELOAD hijack" },
      { rule: "LDX-007", what: "authorized_keys tampering" },
      { rule: "LDX-008", what: "Log & history destruction" },
      { rule: "LDX-009", what: "Root login from external IP" },
      { rule: "LDX-010", what: "Malicious cron entry" },
    ],
  },
  {
    id: "timeline",
    label: "Windows Timeline",
    icon: Clock,
    title: "Windows event log (CSV) analyzer",
    blurb:
      "Paste or drop a CSV export of Windows events (EvtxECmd, plaso…). Detects brute force & password spray, log deletion, malicious services, obfuscated PowerShell and credential dumping.",
    accepts: ".csv,.txt",
    placeholder:
      "Time Created,Event ID,Channel,Computer,Description\n2026-11-10T03:10:01,4625,Security,DC01,\"Account failed to log on…\"\n…",
    samplePath: "/samples/sample-timeline.csv",
    sampleName: "sample-timeline.csv",
    inputKind: "text",
    analyze: (input) => analyzeTimelineCsv(String(input)),
    detects: [
      { rule: "TLX-001", what: "Mass failed logons (4625 ×8)" },
      { rule: "TLX-002", what: "Password spray (≥5 accounts)" },
      { rule: "TLX-003", what: "4624 success after failures (critical)" },
      { rule: "TLX-004", what: "Security log cleared (1102)" },
      { rule: "TLX-005", what: "Service from user-writable path (7045)" },
      { rule: "TLX-006", what: "Obfuscated/encoded PowerShell" },
      { rule: "TLX-007", what: "Credential dumping tooling" },
    ],
  },
  {
    id: "memory",
    label: "Memory",
    icon: Cpu,
    title: "Process list analyzer (Volatility pslist)",
    blurb:
      "Paste or drop a pslist/pstree export (CSV, TSV or whitespace-separated: PID PPID Name [CommandLine]). Detects masquerading, maldoc→shell chains, offensive tooling and encoded commands.",
    accepts: ".csv,.tsv,.txt,.log",
    placeholder:
      "PID,PPID,Name,CommandLine\n1100,4,System,\n3500,1100,winword.exe,\"WINWORD.EXE /n …\\invoice.docm\"\n…",
    samplePath: "/samples/sample-processes.csv",
    sampleName: "sample-processes.csv",
    inputKind: "text",
    analyze: (input) => analyzeProcesses(String(input)),
    detects: [
      { rule: "MEMX-001", what: "Mimikatz/Rubeus/etc. tooling artefacts" },
      { rule: "MEMX-002", what: "Masquerading (svch0st, scvhost…)" },
      { rule: "MEMX-003", what: "winword → powershell chains" },
      { rule: "MEMX-004", what: "Encoded command lines" },
      { rule: "MEMX-005", what: "Detached shell (PPID 0)" },
    ],
  },
  {
    id: "network",
    label: "Network / PCAP",
    icon: Network,
    title: "PCAP analyzer (in-browser pcap/pcapng)",
    blurb:
      "Drop or upload a .pcap / .pcapng capture. The built-in parser extracts flows, DNS and HTTP directly in your browser — no upload anywhere — then hunts beaconing, exfil and DGA activity.",
    accepts: ".pcap,.pcapng,.cap",
    placeholder: "",
    samplePath: "/samples/intrusion.pcap",
    sampleName: "intrusion.pcap",
    inputKind: "pcap",
    analyze: (input) => analyzePcap(input as Uint8Array),
    detects: [
      { rule: "NETX-001", what: "Cleartext credentials (HTTP)" },
      { rule: "NETX-002", what: "Beaconing (fixed interval, CV<0.3)" },
      { rule: "NETX-003", what: "Bulk transfer ≥ 250 KB / dst" },
      { rule: "NETX-004", what: "High-entropy DNS (DGA)" },
      { rule: "NETX-005", what: "Suspicious ports (4444, 6667…)" },
    ],
  },
];

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "border-red-500/50 bg-red-500/10 text-red-400",
  high: "border-orange-500/50 bg-orange-500/10 text-orange-400",
  medium: "border-yellow-500/50 bg-yellow-500/10 text-yellow-300",
  low: "border-sky-500/50 bg-sky-500/10 text-sky-400",
  info: "border-border bg-muted text-muted-foreground",
};

function csvEscape(value: string): string {
  const v = value.replace(/"/g, '""');
  return /[",\n]/.test(v) ? `"${v}"` : v;
}

function downloadBlob(name: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

const MAX_RENDERED_FINDINGS = 100;

export function WorkbenchClient() {
  const [active, setActive] = useState<LabId>("linux");
  const [textInput, setTextInput] = useState("");
  const [bytesInput, setBytesInput] = useState<Uint8Array | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const lab = LABS.find((l) => l.id === active)!;

  // Deep-link: /workbench?lab=network
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const labParam = params.get("lab") as LabId | null;
    if (labParam && LABS.some((l) => l.id === labParam)) {
      setActive(labParam);
    }
  }, []);

  const switchLab = useCallback((id: LabId) => {
    setActive(id);
    setTextInput("");
    setBytesInput(null);
    setFileName(null);
    setResult(null);
    setError(null);
  }, []);

  const analyzeNow = useCallback(() => {
    setError(null);
    setBusy(true);
    try {
      if (lab.inputKind === "pcap") {
        if (!bytesInput) {
          setError("Upload a .pcap capture first — or load the sample dataset.");
          setBusy(false);
          return;
        }
        setResult(lab.analyze(bytesInput));
      } else {
        const source = textInput.trim();
        if (!source) {
          setError("Paste evidence first — or load the sample dataset.");
          setBusy(false);
          return;
        }
        setResult(lab.analyze(source));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed on this input.");
    } finally {
      setBusy(false);
    }
  }, [lab, textInput, bytesInput]);

  const loadSample = useCallback(async () => {
    setError(null);
    setBusy(true);
    try {
      const res = await fetch(lab.samplePath);
      if (!res.ok) throw new Error(`Could not fetch sample (${res.status})`);
      if (lab.inputKind === "pcap") {
        const buf = new Uint8Array(await res.arrayBuffer());
        setBytesInput(buf);
        setTextInput("");
      } else {
        setTextInput(await res.text());
        setBytesInput(null);
      }
      setFileName(lab.sampleName);
      setResult(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load sample dataset.");
    } finally {
      setBusy(false);
    }
  }, [lab]);

  const onFilePicked = useCallback(
    async (file: File | undefined) => {
      if (!file) return;
      setError(null);
      setFileName(file.name);
      setResult(null);
      if (lab.inputKind === "pcap") {
        const buf = new Uint8Array(await file.arrayBuffer());
        setBytesInput(buf);
        setTextInput("");
      } else {
        const text = await file.text();
        setTextInput(text);
        setBytesInput(null);
      }
    },
    [lab.inputKind]
  );

  const exportJson = useCallback(() => {
    if (!result) return;
    const payload = {
      tool: "Traceback — Detection Workbench",
      lab: lab.id,
      file: fileName,
      generatedAt: new Date().toISOString(),
      stats: result.stats,
      findings: result.findings,
    };
    downloadBlob(
      `traceback-${lab.id}-findings.json`,
      JSON.stringify(payload, null, 2),
      "application/json"
    );
  }, [result, lab.id, fileName]);

  const exportCsv = useCallback(() => {
    if (!result) return;
    const header = [
      "ruleId",
      "severity",
      "title",
      "mitre",
      "summary",
      "evidence",
      "line",
      "remediation",
    ].join(",");
    const rows = result.findings.map((f) =>
      [
        csvEscape(f.ruleId),
        f.severity,
        csvEscape(f.title),
        csvEscape(f.mitre),
        csvEscape(f.summary),
        csvEscape(f.evidence),
        f.line ?? "",
        csvEscape(f.remediation),
      ].join(",")
    );
    downloadBlob(
      `traceback-${lab.id}-findings.csv`,
      [header, ...rows].join("\r\n"),
      "text/csv"
    );
  }, [result, lab.id]);

  const counts = useMemo(() => {
    if (!result) return null;
    return result.stats;
  }, [result]);

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
      {/* ── Input panel ─────────────────────────────────────────── */}
      <section className="flex flex-col gap-4 rounded-xl border border-border bg-muted/40 p-5 sm:p-6">
        {/* Tab bar */}
        <div
          className="grid grid-cols-2 gap-2 sm:grid-cols-4"
          role="tablist"
          aria-label="Detection labs"
        >
          {LABS.map((l) => {
            const Icon = l.icon;
            const selected = l.id === active;
            return (
              <button
                key={l.id}
                role="tab"
                aria-selected={selected}
                onClick={() => switchLab(l.id)}
                className={cn(
                  "flex flex-col items-center gap-1.5 rounded-lg border px-2 py-3 font-mono text-[11px] uppercase tracking-wider transition-all",
                  selected
                    ? "border-accent/60 bg-accent-muted text-accent"
                    : "border-border bg-muted text-muted-foreground hover:border-accent/40 hover:text-foreground"
                )}
              >
                <Icon className="h-5 w-5" aria-hidden />
                {l.label}
              </button>
            );
          })}
        </div>

        <div>
          <h2 className="text-lg font-semibold tracking-tight">{lab.title}</h2>
          <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
            {lab.blurb}
          </p>
        </div>

        {/* Evidence input */}
        {lab.inputKind === "text" ? (
          <textarea
            value={textInput}
            onChange={(e) => {
              setTextInput(e.target.value);
              setResult(null);
            }}
            spellCheck={false}
            aria-label="Evidence input"
            placeholder={lab.placeholder}
            className="h-48 w-full resize-y rounded-lg border border-border bg-background p-3 font-mono text-xs leading-relaxed text-foreground placeholder:text-muted-foreground/60 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent sm:h-56"
          />
        ) : (
          <div className="flex h-48 flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-border bg-background p-4 text-center sm:h-56">
            <Upload className="h-8 w-8 text-muted-foreground" aria-hidden />
            <p className="font-mono text-xs text-muted-foreground">
              {bytesInput
                ? `${fileName} — ${(bytesInput.byteLength / 1024).toFixed(1)} KB loaded`
                : "No capture loaded yet"}
            </p>
            <button
              onClick={() => fileRef.current?.click()}
              className="rounded-md border border-border bg-muted px-4 py-2 font-mono text-xs uppercase tracking-wider text-foreground transition-colors hover:border-accent hover:text-accent"
            >
              Choose .pcap file
            </button>
            <input
              ref={fileRef}
              type="file"
              accept={lab.accepts}
              className="sr-only"
              aria-label="Choose PCAP file"
              onChange={(e) => void onFilePicked(e.target.files?.[0])}
            />
          </div>
        )}
        {lab.inputKind === "text" && (
          <div className="flex items-center justify-between gap-3">
            <button
              onClick={() => fileRef.current?.click()}
              className="inline-flex items-center gap-2 font-mono text-xs text-muted-foreground transition-colors hover:text-accent"
            >
              <FolderOpen className="h-4 w-4" aria-hidden />
              or pick a file
            </button>
            <input
              ref={fileRef}
              type="file"
              accept={lab.accepts}
              className="sr-only"
              aria-label="Choose evidence file"
              onChange={(e) => void onFilePicked(e.target.files?.[0])}
            />
            <button
              onClick={() => void loadSample()}
              disabled={busy}
              className="inline-flex items-center gap-2 font-mono text-xs text-accent transition-opacity hover:opacity-80 disabled:opacity-50"
            >
              <FileText className="h-4 w-4" aria-hidden />
              Load sample dataset
            </button>
          </div>
        )}
        {lab.inputKind === "pcap" && (
          <button
            onClick={() => void loadSample()}
            disabled={busy}
            className="inline-flex items-center justify-center gap-2 self-center font-mono text-xs text-accent transition-opacity hover:opacity-80 disabled:opacity-50"
          >
            <FileText className="h-4 w-4" aria-hidden />
            Load sample capture (intrusion.pcap)
          </button>
        )}

        {/* Actions */}
        <div className="flex items-center gap-3">
          <button
            onClick={analyzeNow}
            disabled={busy}
            className="inline-flex flex-1 items-center justify-center gap-2 rounded-lg bg-accent px-4 py-3 font-mono text-xs font-bold uppercase tracking-wider text-background transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            <Play className="h-4 w-4" aria-hidden />
            {busy ? "Working…" : "Run detection"}
          </button>
          <button
            onClick={() => {
              setTextInput("");
              setBytesInput(null);
              setFileName(null);
              setResult(null);
              setError(null);
            }}
            aria-label="Clear input and results"
            className="rounded-lg border border-border p-3 text-muted-foreground transition-colors hover:border-accent hover:text-accent"
          >
            <RotateCcw className="h-4 w-4" aria-hidden />
          </button>
        </div>

        {error && (
          <p role="alert" className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 font-mono text-xs text-red-400">
            {error}
          </p>
        )}

        {/* Detections covered */}
        <details className="rounded-lg border border-border bg-background p-3">
          <summary className="cursor-pointer font-mono text-xs uppercase tracking-widest text-muted-foreground hover:text-foreground">
            {lab.detects.length} detection rules in this analyzer
          </summary>
          <ul className="mt-3 space-y-1.5">
            {lab.detects.map((d) => (
              <li key={d.rule} className="flex items-baseline gap-2 font-mono text-[11px]">
                <span className="w-14 shrink-0 text-accent">{d.rule}</span>
                <span className="text-muted-foreground">{d.what}</span>
              </li>
            ))}
          </ul>
        </details>
      </section>

      {/* ── Results panel ───────────────────────────────────────── */}
      <section aria-live="polite" className="flex flex-col gap-4">
        {!result ? (
          <div className="flex h-full min-h-64 flex-col items-center justify-center gap-4 rounded-xl border border-dashed border-border p-8 text-center">
            <Radar className="h-10 w-10 text-muted-foreground/60" aria-hidden />
            <div>
              <p className="font-semibold">No analysis yet</p>
              <p className="mt-1 max-w-sm text-sm text-muted-foreground">
                Load the sample dataset or paste your own evidence, then hit{" "}
                <span className="font-mono text-accent">Run detection</span>.
                Analysis runs locally in your browser — nothing is uploaded.
              </p>
            </div>
          </div>
        ) : (
          <>
            {/* Summary strip */}
            <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
              <div className="rounded-lg border border-border bg-muted/40 p-3 text-center sm:col-span-1">
                <p className="font-mono text-lg font-bold leading-none text-foreground">
                  {counts?.itemsScanned ?? 0}
                </p>
                <p className="mt-1 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                  scanned
                </p>
              </div>
              {SEVERITY_ORDER.map((sev) => (
                <div
                  key={sev}
                  className={cn(
                    "rounded-lg border p-3 text-center",
                    SEVERITY_STYLE[sev]
                  )}
                >
                  <p className="font-mono text-lg font-bold leading-none">
                    {counts?.bySeverity[sev] ?? 0}
                  </p>
                  <p className="mt-1 font-mono text-[10px] uppercase tracking-wider opacity-80">
                    {sev}
                  </p>
                </div>
              ))}
            </div>

            {/* Exports */}
            <div className="flex items-center justify-between gap-3 rounded-lg border border-border bg-muted/40 px-4 py-2.5">
              <p className="font-mono text-xs text-muted-foreground">
                <span className="text-accent">{result.stats.totalFindings}</span>{" "}
                finding(s) across{" "}
                <span className="text-foreground">{counts?.itemsScanned}</span>{" "}
                record(s)
              </p>
              <div className="flex items-center gap-2">
                <button
                  onClick={exportJson}
                  className="inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 font-mono text-[11px] text-muted-foreground transition-colors hover:border-accent hover:text-accent"
                >
                  <Download className="h-3.5 w-3.5" aria-hidden />
                  JSON
                </button>
                <button
                  onClick={exportCsv}
                  className="inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 font-mono text-[11px] text-muted-foreground transition-colors hover:border-accent hover:text-accent"
                >
                  <Download className="h-3.5 w-3.5" aria-hidden />
                  CSV
                </button>
              </div>
            </div>

            {/* Findings */}
            {result.findings.length === 0 ? (
              <div className="rounded-xl border border-border bg-muted/40 p-6 text-center text-sm text-muted-foreground">
                No rule fired. Either this evidence is clean — or the input
                format was not recognized. Check the expected columns/sample.
              </div>
            ) : (
              <ol className="space-y-3">
                {result.findings
                  .slice(0, MAX_RENDERED_FINDINGS)
                  .map((f, idx) => (
                    <li
                      key={`${f.ruleId}-${idx}`}
                      className="rounded-xl border border-border bg-muted/40 p-4"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={cn(
                            "rounded border px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider",
                            SEVERITY_STYLE[f.severity]
                          )}
                        >
                          {f.severity}
                        </span>
                        <span className="font-mono text-[11px] text-accent">
                          {f.ruleId}
                        </span>
                        <span className="font-mono text-[10px] text-muted-foreground">
                          {f.mitre}
                        </span>
                      </div>
                      <h3 className="mt-2 text-sm font-semibold leading-snug">
                        {f.title}
                      </h3>
                      <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                        {f.summary}
                      </p>
                      <pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-background p-2 font-mono text-[10px] leading-relaxed text-foreground/85">
                        {f.evidence}
                      </pre>
                      <p className="mt-2 flex items-start gap-1.5 text-[11px] leading-relaxed text-muted-foreground">
                        <Activity className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" aria-hidden />
                        {f.remediation}
                      </p>
                    </li>
                  ))}
                {result.findings.length > MAX_RENDERED_FINDINGS && (
                  <li className="rounded-lg border border-border p-3 text-center font-mono text-xs text-muted-foreground">
                    …and {result.findings.length - MAX_RENDERED_FINDINGS} more (see JSON export)
                  </li>
                )}
              </ol>
            )}
          </>
        )}
      </section>
    </div>
  );
}
