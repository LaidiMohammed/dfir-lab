/**
 * Memory/process detection engine — runs client-side on process lists
 * (Volatility `pslist` / `pstree` exports, CSV/TSV/whitespace separated).
 * Expected columns: PID  PPID  Name  [CommandLine]
 */
import {
  buildResult,
  type AnalysisResult,
  type Finding,
} from "./types.ts";
import { splitCsvLine } from "./timeline.ts";

export interface ProcRow {
  line: number;
  pid: number;
  ppid: number;
  name: string;
  commandLine: string;
}

const WS_RE = /\s+/;
const KNOWN_SYSTEM = new Set([
  "system",
  "registry",
  "smss.exe",
  "csrss.exe",
  "wininit.exe",
  "services.exe",
  "lsass.exe",
  "svchost.exe",
  "winlogon.exe",
  "fontdrvhost.exe",
  "explorer.exe",
  "spoolsv.exe",
  "taskhostw.exe",
]);

export function parseProcessList(input: string): ProcRow[] {
  const lines = input.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length === 0) return [];

  // Detect delimiter from the first line: comma, tab, pipe, or whitespace.
  const first = lines[0]!;
  let delim: "," | "\t" | "|" | "ws" = "ws";
  if (first.includes(",")) delim = ",";
  else if (first.includes("\t")) delim = "\t";
  else if (first.includes("|")) delim = "|";

  const rows: ProcRow[] = [];
  const startIdx = /pid/i.test(first) && /ppid/i.test(first) ? 1 : 0;

  for (let i = startIdx; i < lines.length; i++) {
    const raw = lines[i]!.trim();
    let parts: string[];
    if (delim === ",") parts = splitCsvLine(raw);
    else if (delim === "|") parts = raw.split("|").map((s) => s.trim());
    else if (delim === "\t") parts = raw.split("\t").map((s) => s.trim());
    else parts = raw.split(WS_RE);

    if (parts.length < 3) continue;
    const pid = Number.parseInt(parts[0]!, 10);
    const ppid = Number.parseInt(parts[1]!, 10);
    if (Number.isNaN(pid) || Number.isNaN(ppid)) continue;
    const name = parts[2]!.replace(/^"|"$/g, "");
    const commandLine = parts.slice(3).join(delim === "ws" ? " " : " ");
    rows.push({ line: i + 1, pid, ppid, name, commandLine });
  }
  return rows;
}

/** Levenshtein distance capped at 3 (cheap, allocation-free-ish). */
function editDistance(a: string, b: string, cap = 3): number {
  const m = a.length;
  const n = b.length;
  if (Math.abs(m - n) > cap) return cap + 1;
  const prev = new Array<number>(n + 1);
  const curr = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    const ai = a.charCodeAt(i - 1);
    for (let j = 1; j <= n; j++) {
      const cost = ai === b.charCodeAt(j - 1) ? 0 : 1;
      curr[j] = Math.min(
        curr[j - 1]! + 1,
        prev[j]! + 1,
        prev[j - 1]! + cost
      );
    }
    for (let j = 0; j <= n; j++) prev[j] = curr[j]!;
  }
  return prev[n]!;
}

const LOLBIN_SPAWNERS: Record<string, string[]> = {
  "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "rundll32.exe", "wmic.exe"],
  "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"],
  "powerpnt.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
  "outlook.exe": ["cmd.exe", "powershell.exe"],
  "acrobat.exe": ["cmd.exe", "powershell.exe"],
};

const EVIL_TOOLS_RE =
  /\b(mimikatz|wce|procdump|pwdump|gsecdump|lazagne|rubeus|sharphound|bloodhound|nanodump|pypykatz)\b/i;

const PS_EVIL_RE =
  /(?:-enc(?:odedcommand)?\b|frombase64string|invoke-expression|\biex\b|downloadstring|new-object\s+net\.webclient)/i;

export function analyzeProcesses(input: string): AnalysisResult {
  const rows = parseProcessList(input);
  const findings: Finding[] = [];

  // ── MEMX-001 — known credential-theft / offense tooling in image names ──
  for (const row of rows) {
    const hay = `${row.name} ${row.commandLine}`;
    if (EVIL_TOOLS_RE.test(hay)) {
      findings.push({
        ruleId: "MEMX-001",
        severity: "critical",
        title: `Known offensive-tool artefact in process memory: ${row.name}`,
        mitre: "T1003 — OS Credential Dumping",
        summary:
          "Process name or command line references a well-known credential-theft / AD-enumeration toolkit.",
        evidence: `line ${row.line} (pid ${row.pid}): ${row.name} ${row.commandLine}`.trim(),
        line: row.line,
        remediation:
          "Dump and hash the process region, isolate the host, reset all credentials valid on it.",
      });
    }
  }

  // ── MEMX-002 — masquerading: near-miss of a known system process ────────
  for (const row of rows) {
    const lower = row.name.toLowerCase();
    if (KNOWN_SYSTEM.has(lower)) continue;
    for (const sys of KNOWN_SYSTEM) {
      if (!sys.endsWith(".exe")) continue;
      if (Math.abs(lower.length - sys.length) > 3) continue;
      if (editDistance(lower, sys, 2) <= 2 && lower.length >= 5) {
        findings.push({
          ruleId: "MEMX-002",
          severity: "high",
          title: `Masquerading process "${row.name}" (≈ ${sys})`,
          mitre: "T1036.005 — Match Legitimate Name or Location",
          summary:
            "An image name within edit distance 2 of a core system binary is a classic trojan disguise (e.g. svch0st.exe, scvhost.exe).",
          evidence: `line ${row.line} (pid ${row.pid}): ${row.name} ${row.commandLine}`.trim(),
          line: row.line,
          remediation:
            "Verify digital signature & path of the binary, hash it, check its parent and loaded modules — system binaries must live in System32.",
        });
        break;
      }
    }
  }

  // ── MEMX-003 — Office/user apps spawning shell machinery ────────────────
  const byPid = new Map<number, ProcRow>();
  for (const row of rows) byPid.set(row.pid, row);
  for (const row of rows) {
    const parent = byPid.get(row.ppid);
    if (!parent) continue;
    const spawners = LOLBIN_SPAWNERS[parent.name.toLowerCase()];
    if (!spawners) continue;
    if (spawners.includes(row.name.toLowerCase())) {
      findings.push({
        ruleId: "MEMX-003",
        severity: "high",
        title: `${parent.name} → ${row.name} (maldoc-style execution chain)`,
        mitre: "T1204.002 / T1566.001 — Malicious File via Phishing",
        summary:
          "A document/reader application spawning a shell or script host is the canonical malicious-doc execution pattern.",
        evidence: `line ${row.line} (pid ${row.pid}) spawned by pid ${parent.ppid} → ${parent.name}; commandLine: ${row.commandLine || "(none)"}`,
        line: row.line,
        remediation:
          "Quarantine the document, decode/detonate it in a sandbox, review mail gateway logs for siblings.",
      });
    }
  }

  // ── MEMX-004 — encoded PowerShell in command lines ───────────────────────
  for (const row of rows) {
    if (!PS_EVIL_RE.test(row.commandLine)) continue;
    if (!/powershell|pwsh|wmic|mshta|cmd/i.test(row.commandLine)) continue;
    findings.push({
      ruleId: "MEMX-004",
      severity: "high",
      title: `Obfuscated command line in ${row.name}`,
      mitre: "T1059.001 / T1027 — PowerShell + Obfuscation",
      summary:
        "Command line carries encoding/obfuscation markers typical of staged payloads and C2 launchers.",
      evidence: `line ${row.line} (pid ${row.pid}): ${row.commandLine.slice(0, 220)}`,
      line: row.line,
      remediation:
        "Decode the payload, extract IOCs (URLs, hashes, mutexes), pivot to network captures.",
    });
  }

  // ── MEMX-005 — process with cmdline but zero network-ish parent missing ──
  const shellNames = /^(cmd|powershell|pwsh|wscript|cscript|mshta)\.exe$/i;
  for (const row of rows) {
    if (shellNames.test(row.name) && row.ppid === 0) {
      findings.push({
        ruleId: "MEMX-005",
        severity: "medium",
        title: `Shell process ${row.name} with PPID 0 (detached)`,
        mitre: "T1564 — Hide Artifacts",
        summary:
          "A detached shell with no parent in the snapshot suggests either a capture gap or a deliberately orphaned implant.",
        evidence: `line ${row.line} (pid ${row.pid}): ${row.name} ${row.commandLine}`.trim(),
        line: row.line,
        remediation:
          "Cross-check with psscan/cmdline plugins, confirm capture completeness, dump the process for analysis.",
      });
    }
  }

  return buildResult(findings, rows.length);
}
