/**
 * Windows event/timeline detection engine — runs client-side on CSV exports
 * (e.g. from EvtxECmd, plaso psort or Get-WinEvent | Export-Csv).
 * Header columns are matched case-insensitively with several known aliases.
 */
import {
  buildResult,
  type AnalysisResult,
  type Finding,
} from "./types.ts";

const HEADER_ALIASES: Record<string, string[]> = {
  time: [
    "time created",
    "timestamp",
    "time",
    "date",
    "datetime",
    "@timestamp",
    "utc time",
  ],
  eventId: [
    "event id",
    "eventid",
    "event_id",
    "id",
    "event",
    "eid",
  ],
  message: [
    "description",
    "message",
    "msg",
    "summary",
    "task category",
    "details",
    "payload",
  ],
  computer: ["computer", "host", "hostname", "machine", "system"],
};

function findColumn(headers: string[], aliases: string[]): number {
  const normalized = headers.map((h) => h.trim().toLowerCase());
  for (const alias of aliases) {
    const idx = normalized.indexOf(alias);
    if (idx !== -1) return idx;
  }
  return -1;
}

/** Minimal RFC-4180-ish CSV line splitter (quotes supported). */
export function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          cur += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        cur += ch;
      }
    } else {
      if (ch === ",") {
        out.push(cur);
        cur = "";
      } else if (ch === '"') {
        inQuotes = true;
      } else {
        cur += ch;
      }
    }
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

interface EventRow {
  line: number;
  timeRaw: string;
  timeMs?: number;
  eventId: string;
  message: string;
  computer: string;
}

const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

export function analyzeTimelineCsv(input: string): AnalysisResult {
  const lines = input.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const findings: Finding[] = [];

  if (lines.length === 0) {
    return buildResult(findings, 0);
  }

  const headers = splitCsvLine(lines[0]!);
  const timeCol = findColumn(headers, HEADER_ALIASES.time!);
  const eventCol = findColumn(headers, HEADER_ALIASES.eventId!);
  const msgCol = findColumn(headers, HEADER_ALIASES.message!);
  const compCol = findColumn(headers, HEADER_ALIASES.computer!);

  const rows: EventRow[] = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = splitCsvLine(lines[i]!);
    const timeRaw = timeCol >= 0 ? (cols[timeCol] ?? "") : "";
    const timeMs = Date.parse(timeRaw);
    rows.push({
      line: i + 1,
      timeRaw,
      timeMs: Number.isNaN(timeMs) ? undefined : timeMs,
      eventId: eventCol >= 0 ? (cols[eventCol] ?? "").trim() : "",
      message: msgCol >= 0 ? (cols[msgCol] ?? "") : "",
      computer: compCol >= 0 ? (cols[compCol] ?? "") : "",
    });
  }

  const ipIn = (s: string): string | undefined => IP_RE.exec(s)?.[0];

  // ── TLX-001 — brute force: ≥8 × 4625 within the capture window ──────────
  const failed = rows.filter((r) => r.eventId === "4625");
  if (failed.length >= 8) {
    const ips = new Map<string, number>();
    for (const r of failed) {
      const ip = ipIn(r.message) ?? ipIn(r.computer);
      if (ip) ips.set(ip, (ips.get(ip) ?? 0) + 1);
    }
    const top = [...ips.entries()].sort((a, b) => b[1] - a[1])[0];
    findings.push({
      ruleId: "TLX-001",
      severity: "high",
      title: `Mass failed logons (4625): ${failed.length} events${
        top ? `, mostly from ${top[0]}` : ""
      }`,
      mitre: "T1110 — Brute Force",
      summary:
        "High volume of failed authentication events indicates password guessing or password spraying against this host.",
      evidence: failed
        .slice(0, 4)
        .map((r) => `line ${r.line} [${r.timeRaw}]: ${r.message.slice(0, 160)}`)
        .join("\n"),
      line: failed[0]!.line,
      remediation:
        "Lock/disable targeted accounts, block offending sources, tighten lockout policy, review exposed services.",
    });
  }

  // ── TLX-002 — password spray: ≥5 × 4625 from one IP to many users ───────
  const byIp = new Map<string, Set<string>>();
  for (const r of failed) {
    const ip = ipIn(r.message);
    if (!ip) continue;
    const acct =
      /account\s*name[:=]\s*([\w.@$-]+)/i.exec(r.message)?.[1] ??
      /user\s*(?:name)?\s*[:=]\s*([\w.@-]+)/i.exec(r.message)?.[1] ??
      "unknown";
    const bucket = byIp.get(ip) ?? new Set<string>();
    bucket.add(acct.toLowerCase());
    byIp.set(ip, bucket);
  }
  for (const [ip, users] of byIp) {
    if (users.size >= 5) {
      findings.push({
        ruleId: "TLX-002",
        severity: "high",
        title: `Password spray: ${ip} tried ≥5 distinct accounts (4625)`,
        mitre: "T1110.003 — Password Spraying",
        summary:
          "One source attempting many different usernames is spraying, not targeted guessing — it often evades per-account lockout.",
        evidence: `line(s) ${failed
          .filter((r) => ipIn(r.message) === ip)
          .slice(0, 4)
          .map((r) => r.line)
          .join(", ")} → accounts: ${[...users].slice(0, 6).join(", ")}`,
        remediation:
          "Block the source, audit targeted accounts, enable stronger lockout thresholds and MFA.",
      });
    }
  }

  // ── TLX-003 — successful logon right after failures from same IP ────────
  for (const r of rows) {
    if (r.eventId !== "4624") continue;
    const ip = ipIn(r.message);
    if (!ip) continue;
    const prior = failed.filter(
      (f) => ipIn(f.message) === ip && priorBefore(f.timeMs, r.timeMs)
    );
    if (prior.length >= 3) {
      findings.push({
        ruleId: "TLX-003",
        severity: "critical",
        title: `4624 success from ${ip} after ${prior.length} failures — likely brute-force win`,
        mitre: "T1110 → T1078 — Brute Force → Valid Accounts",
        summary:
          "A successful logon following repeated failures from the same source is the strongest timeline signal of a completed breach.",
        evidence: `line ${r.line} [${r.timeRaw}]: ${r.message.slice(0, 160)}`,
        line: r.line,
        remediation:
          "Assume the account is owned: reset credentials, review session activity, hunt persistence before cleanup.",
      });
    }
  }

  // ── TLX-004 — Security log cleared (1102) ────────────────────────────────
  for (const r of rows) {
    if (r.eventId !== "1102") continue;
    findings.push({
      ruleId: "TLX-004",
      severity: "critical",
      title: "Security event log was cleared (1102)",
      mitre: "T1070.001 — Indicator Removal: Clear Windows Event Logs",
      summary:
        "The Security channel was wiped — a deliberate anti-forensics action, almost always correlated with an intrusion.",
      evidence: `line ${r.line} [${r.timeRaw}]: ${r.message.slice(0, 200)}`,
      line: r.line,
      remediation:
        "Recover logs from forwarded copies (SIEM/WEF), note both ends of the cleared window, treat host as compromised.",
    });
  }

  // ── TLX-005 — suspicious service installation (7045) ─────────────────────
  for (const r of rows) {
    if (r.eventId !== "7045") continue;
    const msg = r.message;
    const suspicious =
      /(\\temp\\|\\tmp\\|\\appdata\\|\\public\\|\\users\\public\\|\\programdata\\)[^\n"]*\.exe/i.test(
        msg
      );
    if (suspicious) {
      findings.push({
        ruleId: "TLX-005",
        severity: "high",
        title: "Service installed from a user-writable path (7045)",
        mitre: "T1543.003 — Create or Modify System Process: Windows Service",
        summary:
          "A new service whose binary lives in a user-writable directory is textbook attacker persistence.",
        evidence: `line ${r.line} [${r.timeRaw}]: ${msg.slice(0, 200)}`,
        line: r.line,
        remediation:
          "Inspect the service binary (hash + signature), check service account, remove malicious service, hunt its dropped files.",
      });
    }
  }

  // ── TLX-006 — obfuscated / encoded PowerShell ────────────────────────────
  const PS_EVIL_RE =
    /(?:-enc(?:odedcommand)?\b|frombase64string|invoke-expression|\biex\b|downloadstring|new-object\s+net\.webclient)/i;
  for (const r of rows) {
    if (!PS_EVIL_RE.test(r.message)) continue;
    if (r.eventId !== "4688" && !/powershell/i.test(r.message)) continue;
    findings.push({
      ruleId: "TLX-006",
      severity: "high",
      title: "Obfuscated or encoded PowerShell execution",
      mitre: "T1059.001 / T1027 — PowerShell + Obfuscation",
      summary:
        "Encoded command-line PowerShell is the default payload delivery/execution vector for Windows intrusions.",
      evidence: `line ${r.line} [${r.timeRaw}]: ${r.message.slice(0, 200)}`,
      line: r.line,
      remediation:
        "Decode the base64 payload in a sandbox, identify the dropper chain, block the delivery domain/hash.",
    });
  }

  // ── TLX-007 — credential-dump tooling strings in command lines ───────────
  const DUMP_RE = /(mimikatz|lsass\.dmp|sekurlsa|procdump[^\n]*lsass|wce\.exe|pwdump)/i;
  for (const r of rows) {
    if (DUMP_RE.test(r.message)) {
      findings.push({
        ruleId: "TLX-007",
        severity: "critical",
        title: "Credential theft tooling observed in event data",
        mitre: "T1003 — OS Credential Dumping",
        summary:
          "Command line references a known credential-dumping tool or an LSASS dump — full credential compromise is assumed.",
        evidence: `line ${r.line} [${r.timeRaw}]: ${r.message.slice(0, 200)}`,
        line: r.line,
        remediation:
          "Reset every credential valid on this host (and derived/krbtgt), isolate host, engage IR.",
      });
    }
  }

  return buildResult(findings, rows.length);
}

function priorBefore(a?: number, b?: number): boolean {
  if (a === undefined || b === undefined) return true; // unknown order — keep conservative
  return a <= b;
}
