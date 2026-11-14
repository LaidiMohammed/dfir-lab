/**
 * Linux host detection engine — runs fully client-side on raw text
 * (auth.log / secure / syslog / bash history exports, one record per line).
 */
import { buildResult, type AnalysisResult, type Finding } from "./types.ts";

const PRIVATE_RE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1$|localhost$)/;

export function isPrivateIp(ip: string): boolean {
  return PRIVATE_RE.test(ip);
}

interface SshAttempt {
  line: number;
  raw: string;
  user: string;
  ip: string;
  failed: boolean;
}

const FAILED_RE =
  /Failed password for (?:invalid user )?([\w.@-]+) from (\d{1,3}(?:\.\d{1,3}){3})/i;
const ACCEPTED_RE =
  /Accepted (?:password|publickey|none) for ([\w.@-]+) from (\d{1,3}(?:\.\d{1,3}){3})/i;

export function analyzeLinuxLog(input: string): AnalysisResult {
  const lines = input.split(/\r?\n/);
  const findings: Finding[] = [];

  // ── Parse SSH authentication lines ─────────────────────────────────────
  const attempts: SshAttempt[] = [];
  lines.forEach((raw, i) => {
    const lineNo = i + 1;
    const failed = FAILED_RE.exec(raw);
    if (failed) {
      attempts.push({ line: lineNo, raw: raw.trim(), user: failed[1]!, ip: failed[2]!, failed: true });
      return;
    }
    const accepted = ACCEPTED_RE.exec(raw);
    if (accepted) {
      attempts.push({ line: lineNo, raw: raw.trim(), user: accepted[1]!, ip: accepted[2]!, failed: false });
    }
  });

  // ── LDX-001 — SSH brute force (≥5 failed attempts, same source IP) ──────
  const failsByIp = new Map<string, SshAttempt[]>();
  for (const a of attempts) {
    if (!a.failed) continue;
    const bucket = failsByIp.get(a.ip) ?? [];
    bucket.push(a);
    failsByIp.set(a.ip, bucket);
  }
  for (const [ip, bucket] of failsByIp) {
    if (bucket.length >= 5) {
      findings.push({
        ruleId: "LDX-001",
        severity: bucket.length >= 10 ? "high" : "medium",
        title: `SSH brute force from ${ip} (${bucket.length} failed attempts)`,
        mitre: "T1110.001 — Password Guessing",
        summary:
          "Repeated failed SSH authentication attempts from a single source indicate password-guessing activity.",
        evidence: bucket
          .slice(0, 4)
          .map((b) => `lines ${b.line}: ${b.raw}`)
          .join("\n"),
        line: bucket[0]!.line,
        remediation:
          "Block the source at the firewall/fail2ban, rotate affected account passwords, enforce key-only SSH where possible.",
      });
    }
  }

  // ── LDX-002 — Successful login from an IP that brute-forced first ───────
  for (const a of attempts) {
    if (a.failed) continue;
    const prior = failsByIp.get(a.ip);
    if (prior && prior.length >= 3) {
      findings.push({
        ruleId: "LDX-002",
        severity: "critical",
        title: `Successful ${a.user} login after ${prior.length} failures from ${a.ip}`,
        mitre: "T1110 → T1078 — Brute Force → Valid Accounts",
        summary:
          "A successful authentication from an IP that previously failed repeatedly strongly indicates a successful brute-force intrusion.",
        evidence: `lines ${a.line}: ${a.raw}\npreceded by ${prior.length} failed attempt(s) from ${a.ip} (first at line ${prior[0]!.line})`,
        line: a.line,
        remediation:
          "Treat the account as compromised: reset credentials, audit authorized_keys & crontabs, hunt for persistence, review session activity.",
      });
    }
  }

  // ── LDX-003 — root / superuser-equivalent account creation ─────────────
  const USERADD_RE = /\b(?:useradd|adduser)\b.*(?:-o\b|-u\s*0\b|uid=0)/i;
  const SUSPICIOUS_NAME_RE =
    /\b(?:useradd|adduser)\b.*\b(backupd|svcadmin|sysadmin2|support2|test123|daemon2|sysmon2|backupuser)\b/i;
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (!line) return;
    if (USERADD_RE.test(line) || SUSPICIOUS_NAME_RE.test(line)) {
      findings.push({
        ruleId: "LDX-003",
        severity: "critical",
        title: "Superuser-equivalent or suspicious account created",
        mitre: "T1136.001 — Create Account: Local Account",
        summary:
          "A new account with UID 0 / -o (non-unique UID) or a masquerading name was created — a classic persistence backdoor.",
        evidence: `line ${i + 1}: ${line}`,
        line: i + 1,
        remediation:
          "Remove the rogue account, audit /etc/passwd and /etc/sudoers for other modifications, check group membership.",
      });
    }
  });

  // ── LDX-004 — SUID backdoor planting ────────────────────────────────────
  const SUID_RE = /\bchmod\b.*(?:u\+s|4755|u=rwxs|\+s\b.*\/(?:bin|tmp|var|dev))/i;
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (SUID_RE.test(line)) {
      findings.push({
        ruleId: "LDX-004",
        severity: "high",
        title: "SUID bit set on a binary",
        mitre: "T1548.001 — Setuid and Setgid",
        summary:
          "Setting a SUID/SGID bit on a binary grants it the owner's (often root) privileges regardless of the caller — common backdoor technique.",
        evidence: `line ${i + 1}: ${line}`,
        line: i + 1,
        remediation:
          "Audit all SUID binaries (find / -perm -4000 -type f), remove non-standard SUID bits, verify package integrity.",
      });
    }
  });

  // ── LDX-005 — Remote download piped to shell / reverse shells ───────────
  const PIPE_SHELL_RE =
    /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|da|z)?sh\b/i;
  const REV_SHELL_RE =
    /(?:bash\s+-i\s*>&?\s*\/dev\/tcp\/|nc(?:at)?(?:\.openbsd)?\s+-[a-z]*e\s+\S*sh\b|mkfifo[^\n]*nc[^\n]*-e|python[^\n]*socket[^\n]*connect|perl[^\n]*socket[^\n]*INET)/i;
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (!line) return;
    if (PIPE_SHELL_RE.test(line)) {
      findings.push({
        ruleId: "LDX-005",
        severity: "critical",
        title: "Remote script piped directly into a shell",
        mitre: "T1059.004 — Command and Scripting Interpreter: Unix Shell",
        summary:
          "Downloading and piping a remote script to a shell executes unreviewed attacker code with current user's privileges.",
        evidence: `line ${i + 1}: ${line}`,
        line: i + 1,
        remediation:
          "Kill the scheduled task/process, fetch the URL to a safe environment for analysis, rotate credentials used on this host.",
      });
    } else if (REV_SHELL_RE.test(line)) {
      findings.push({
        ruleId: "LDX-005",
        severity: "critical",
        title: "Reverse shell pattern detected",
        mitre: "T1059.004 — Unix Shell (Reverse Shell)",
        summary:
          "Command line matches a classic reverse-shell implant (/dev/tcp, nc -e, mkfifo, socket connect).",
        evidence: `line ${i + 1}: ${line}`,
        line: i + 1,
        remediation:
          "Isolate the host, identify the egress destination, sweep persistence locations (cron, systemd, shell rc files).",
      });
    }
  });

  // ── LDX-006 — LD_PRELOAD / ld.so.preload abuse ──────────────────────────
  const LD_PRELOAD_RE = /LD_PRELOAD\s*=|ld\.so\.preload/i;
  lines.forEach((raw, i) => {
    if (LD_PRELOAD_RE.test(raw)) {
      findings.push({
        ruleId: "LDX-006",
        severity: "high",
        title: "LD_PRELOAD / ld.so.preload abuse",
        mitre: "T1574.006 — LD_PRELOAD",
        summary:
          "LD_PRELOAD hijacks dynamic linking to inject code into every (or selected) process — stealthy rootkit persistence.",
        evidence: `line ${i + 1}: ${raw.trim()}`,
        line: i + 1,
        remediation:
          "Inspect /etc/ld.so.preload and env of suspicious processes, remove the rogue library, verify against package manifests (debsums/rpm -Va).",
      });
    }
  });

  // ── LDX-007 — authorized_keys tampering ─────────────────────────────────
  const AUTHKEYS_RE = /authorized_keys/i;
  lines.forEach((raw, i) => {
    if (AUTHKEYS_RE.test(raw)) {
      findings.push({
        ruleId: "LDX-007",
        severity: "high",
        title: "authorized_keys modified",
        mitre: "T1098.004 — Account Manipulation: SSH Authorized Keys",
        summary:
          "A reference to authorized_keys indicates an SSH key was added or checked — a common persistence path for Linux attackers.",
        evidence: `line ${i + 1}: ${raw.trim()}`,
        line: i + 1,
        remediation:
          "Diff ~/.ssh/authorized_keys against known-good copies for every login-capable user; remove unknown keys.",
      });
    }
  });

  // ── LDX-008 — anti-forensics: log deletion & history tampering ──────────
  const LOG_TAMPER_RE =
    /(?:rm\s+(?:-[a-z]*f[a-z]*\s+|--force\s+)?[^\n]*(?:\/var\/log|auth\.log|syslog|\.bash_history)|history\s+-c|unset\s+HISTFILE|>\s*\/var\/log\/)/i;
  lines.forEach((raw, i) => {
    if (LOG_TAMPER_RE.test(raw)) {
      findings.push({
        ruleId: "LDX-008",
        severity: "high",
        title: "Evidence destruction: log/history tampering",
        mitre: "T1070.002 — Indicator Removal: Clear Linux or Mac System Logs",
        summary:
          "The line deletes logs, wipes history, or neutralizes HISTFILE — deliberate anti-forensics to blind responders.",
        evidence: `line ${i + 1}: ${raw.trim()}`,
        line: i + 1,
        remediation:
          "Preserve remaining logs immediately, check log forwarding gap (SIEM ingestion), treat everything after this line as suspect.",
      });
    }
  });

  // ── LDX-009 — root login from external network ───────────────────────────
  const ROOT_EXTERNAL_RE =
    /Accepted \S+ for root from (\d{1,3}(?:\.\d{1,3}){3})/i;
  lines.forEach((raw, i) => {
    const m = ROOT_EXTERNAL_RE.exec(raw);
    if (m && !isPrivateIp(m[1]!)) {
      findings.push({
        ruleId: "LDX-009",
        severity: "critical",
        title: `Direct root login from external IP ${m[1]}`,
        mitre: "T1133 — External Remote Services",
        summary:
          "Direct root SSH authentication from a public address bypasses accountability and usually means the host is fully owned.",
        evidence: `line ${i + 1}: ${raw.trim()}`,
        line: i + 1,
        remediation:
          "Disable PasswordAuthentication/PermitRootLogin in sshd_config, rotate root credential/keys, engage incident response.",
      });
    }
  });

  // ── LDX-010 — crontab beacon / scheduled malicious job ───────────────────
  const CRON_EVIL_RE =
    /\*\s*\*\s*\*\s*\*\s*\*[^\n]*(?:curl|wget|bash|nc\b|python|\/dev\/tcp)/i;
  lines.forEach((raw, i) => {
    if (CRON_EVIL_RE.test(raw)) {
      findings.push({
        ruleId: "LDX-010",
        severity: "critical",
        title: "Malicious cron entry (download/shell execution)",
        mitre: "T1053.003 — Scheduled Task/Job: Cron",
        summary:
          "A cron line executes a shell, downloader, or /dev/tcp connector on a schedule — persistent attacker foothold.",
        evidence: `line ${i + 1}: ${raw.trim()}`,
        line: i + 1,
        remediation:
          "Remove the cron entry (crontab -e, /etc/cron.*, /etc/cron.d), capture the referenced payload URL for blocking.",
      });
    }
  });

  return buildResult(findings, lines.length);
}
