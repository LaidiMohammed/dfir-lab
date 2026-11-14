/**
 * Network traffic detectors — take a parsed PCAP and emit a report.
 * Rules: PORT_SCAN, DNS_TUNNEL_QNAME, DNS_TUNNEL_TXT, BEACONING,
 * EXFIL_VOLUME, CLEAR_PROTO, ICMP_VOLUME.
 */
import {
  type DetectionReport,
  type Finding,
  computeVerdict,
} from "@/lib/detection/types";
import {
  formatBytes,
  formatDuration,
  isPrivateIp,
  median,
  parentDomain,
  stddev,
} from "@/lib/detection/format";
import type { ParsedPcap } from "@/lib/detection/pcap";

const CLEARTEXT_PORTS = new Set([21, 23, 25, 80]);
const EXFIL_IGNORE_PORTS = new Set([53]); // DNS volume handled separately

export function analyzeNetwork(parsed: ParsedPcap): DetectionReport {
  const findings: Finding[] = [];
  const iocs = new Set<string>();

  // --- PORT_SCAN: SYN-only packets to many distinct ports ------------------
  const synByPair = new Map<string, { src: string; dst: string; ports: Set<number>; firstTs: number; lastTs: number }>();
  for (const f of parsed.flows) {
    if (f.proto !== "tcp" || f.synOnly === 0 || f.dstPort === null) continue;
    const key = `${f.srcIp}→${f.dstIp}`;
    let entry = synByPair.get(key);
    if (!entry) {
      entry = { src: f.srcIp, dst: f.dstIp, ports: new Set(), firstTs: f.firstTs, lastTs: f.lastTs };
      synByPair.set(key, entry);
    }
    entry.ports.add(f.dstPort);
    entry.firstTs = Math.min(entry.firstTs, f.firstTs);
    entry.lastTs = Math.max(entry.lastTs, f.lastTs);
  }
  for (const { src, dst, ports, firstTs, lastTs } of synByPair.values()) {
    const span = Math.max(lastTs - firstTs, 1);
    const count = ports.size;
    if (count >= 15) {
      findings.push({
        rule: "PORT_SCAN",
        severity: "high",
        title: `Port scan from ${src}`,
        detail: `${count} distinct SYN-only destination ports hit within ${span.toFixed(0)}s (threshold: 15). Classic horizontal/vertical scan pattern — correlate with follow-on connects.`,
        ioc: dst,
      });
      iocs.add(dst);
    } else if (count >= 5) {
      findings.push({
        rule: "PORT_SCAN",
        severity: "medium",
        title: `Possible port sweep from ${src}`,
        detail: `${count} distinct SYN-only ports toward ${dst} in ${span.toFixed(0)}s. Below the hard threshold — worth watching for escalation.`,
        ioc: dst,
      });
    }
  }

  // --- DNS detectors -------------------------------------------------------
  const byDomain = new Map<string, { qnames: string[]; txt: number; total: number; answersBytes: number; srcs: Set<string> }>();
  for (const q of parsed.dns) {
    if (q.isAnswer) continue;
    const domain = parentDomain(q.qname);
    if (!domain) continue;
    let d = byDomain.get(domain);
    if (!d) {
      d = { qnames: [], txt: 0, total: 0, answersBytes: 0, srcs: new Set() };
      byDomain.set(domain, d);
    }
    d.qnames.push(q.qname);
    d.total += 1;
    d.answersBytes += q.answersBytes;
    if (q.qtype === 16) d.txt += 1; // TXT
    d.srcs.add(q.srcIp);
  }
  for (const [domain, d] of byDomain) {
    const subLengths = d.qnames.map((q) => q.split(".")[0]?.length ?? 0);
    const avgLen =
      subLengths.reduce((a, b) => a + b, 0) / Math.max(subLengths.length, 1);
    if (d.total >= 20 && avgLen >= 24) {
      findings.push({
        rule: "DNS_TUNNEL_QNAME",
        severity: "high",
        title: `DNS tunneling signature on ${domain}`,
        detail: `${d.total} queries to ${domain} with average subdomain length ${avgLen.toFixed(0)} chars — consistent with encoded payload exfiltration (thresholds: ≥20 queries, ≥24 chars).`,
        ioc: domain,
      });
      iocs.add(domain);
    } else if (d.total >= 40) {
      findings.push({
        rule: "DNS_TUNNEL_VOLUME",
        severity: "medium",
        title: `High-volume DNS traffic to ${domain}`,
        detail: `${d.total} queries to a single domain — above the baseline for normal browsing. Inspect payloads for covert channeling.`,
        ioc: domain,
      });
      iocs.add(domain);
    }
    if (d.txt >= 8) {
      findings.push({
        rule: "DNS_TUNNEL_TXT",
        severity: "high",
        title: `Excessive TXT queries to ${domain}`,
        detail: `${d.txt} TXT queries observed. DNS-over-TXT is the canonical command-and-control / tunneling channel (threshold: 8).`,
        ioc: domain,
      });
      iocs.add(domain);
    } else if (d.txt >= 3) {
      findings.push({
        rule: "DNS_TUNNEL_TXT",
        severity: "medium",
        title: `Unusual TXT query volume to ${domain}`,
        detail: `${d.txt} TXT queries — monitor for covert-channel behavior.`,
        ioc: domain,
      });
    }
  }

  // --- BEACONING: periodic interval flows ----------------------------------
  for (const f of parsed.flows) {
    if (f.proto !== "tcp" || f.timestamps.length < 8) continue;
    const sorted = [...f.timestamps].sort((a, b) => a - b);
    const gaps: number[] = [];
    for (let i = 1; i < sorted.length; i++) {
      const cur = sorted[i];
      const prev = sorted[i - 1];
      if (cur !== undefined && prev !== undefined) gaps.push(cur - prev);
    }
    const med = median(gaps);
    if (med < 0.5 || med > 600) continue; // ignore microsecond RTTs & rare polls
    const sd = stddev(gaps);
    const cv = sd / med;
    if (cv < 0.25) {
      findings.push({
        rule: "BEACONING",
        severity: sorted.length >= 12 ? "high" : "medium",
        title: `Periodic beaconing to ${f.dstIp}:${f.dstPort ?? "?"}`,
        detail: `${sorted.length} TCP packets with median interval ${med.toFixed(1)}s (jitter ${(cv * 100).toFixed(0)}%). Heartbeat-style C2 beaconing; XOR-encode/time-jitter analysis recommended.`,
        ioc: `${f.dstIp}:${f.dstPort}`,
      });
      iocs.add(`${f.dstIp}:${f.dstPort}`);
    }
  }

  // --- EXFIL_VOLUME: large outbound transfers to public IPs ----------------
  const outbound = new Map<string, number>();
  for (const f of parsed.flows) {
    if (isPrivateIp(f.dstIp)) continue;
    if (EXFIL_IGNORE_PORTS.has(f.dstPort ?? -1)) continue;
    if (!isPrivateIp(f.srcIp)) continue;
    outbound.set(f.dstIp, (outbound.get(f.dstIp) ?? 0) + f.bytes);
  }
  for (const [dst, bytes] of outbound) {
    if (bytes >= 25 * 1024 * 1024) {
      findings.push({
        rule: "EXFIL_VOLUME",
        severity: "high",
        title: `Large outbound transfer to ${dst}`,
        detail: `${formatBytes(bytes)} sent to a public destination — exceeds the 25 MB alerting threshold. Confirm with the host owner; likely staging for exfiltration.`,
        ioc: dst,
      });
      iocs.add(dst);
    } else if (bytes >= 5 * 1024 * 1024) {
      findings.push({
        rule: "EXFIL_VOLUME",
        severity: "medium",
        title: `Elevated outbound volume to ${dst}`,
        detail: `${formatBytes(bytes)} to a public destination — above the 5 MB baseline. Verify business justification.`,
        ioc: dst,
      });
      iocs.add(dst);
    }
  }

  // --- CLEAR_PROTO: cleartext protocols in use ------------------------------
  const cleartext = parsed.flows.filter(
    (f) => f.dstPort !== null && CLEARTEXT_PORTS.has(f.dstPort) && f.bytes > 4096
  );
  if (cleartext.length > 0) {
    const services = [
      ...new Set(
        cleartext.map((f) =>
          f.dstPort === 21 ? "FTP" : f.dstPort === 23 ? "Telnet" : f.dstPort === 25 ? "SMTP" : "HTTP"
        )
      ),
    ];
    findings.push({
      rule: "CLEAR_PROTO",
      severity: "info",
      title: `Cleartext protocol(s) observed: ${services.join(", ")}`,
      detail:
        "Traffic is unencrypted — credentials and content visible on the wire. If expected for the VLAN, restrict it; otherwise investigate why it exists.",
    });
  }

  // --- ICMP_VOLUME: oversized ICMP traffic ----------------------------------
  const icmpBytes = new Map<string, number>();
  for (const f of parsed.flows) {
    if (f.proto !== "icmp") continue;
    icmpBytes.set(f.dstIp, (icmpBytes.get(f.dstIp) ?? 0) + f.bytes);
  }
  for (const [dst, bytes] of icmpBytes) {
    if (bytes >= 8192) {
      findings.push({
        rule: "ICMP_VOLUME",
        severity: "medium",
        title: `Abnormally large ICMP volume to ${dst}`,
        detail: `${formatBytes(bytes)} of ICMP — possible ICMP tunneling (icmptx/pingtunnel) or ping flooding.`,
        ioc: dst,
      });
      iocs.add(dst);
    }
  }

  const verdict = computeVerdict(findings);
  const summary = buildSummary(verdict, findings, parsed);

  return {
    verdict,
    summary,
    findings: sortFindings(findings),
    iocs: [...iocs],
    stats: [
      { label: "Packets", value: String(parsed.totalPackets) },
      { label: "Volume", value: formatBytes(parsed.totalBytes) },
      { label: "Duration", value: formatDuration(parsed.durationSeconds) },
      { label: "Flows", value: String(parsed.flows.length) },
      { label: "DNS queries", value: String(parsed.dns.filter((q) => !q.isAnswer).length) },
    ],
  };
}

function sortFindings(findings: Finding[]): Finding[] {
  const rank = { high: 3, medium: 2, low: 1, info: 0 } as const;
  return [...findings].sort((a, b) => rank[b.severity] - rank[a.severity]);
}

function buildSummary(
  verdict: "clean" | "suspicious" | "malicious",
  findings: Finding[],
  parsed: ParsedPcap
): string {
  const high = findings.filter((f) => f.severity === "high").length;
  const med = findings.filter((f) => f.severity === "medium").length;
  if (verdict === "clean") {
    return `No malicious indicators across ${parsed.totalPackets} packets. Traffic is within normal baselines — continue monitoring.`;
  }
  if (verdict === "suspicious") {
    return `${med} suspicious finding(s) — no confirmed compromise yet, but anomalies exceed baseline. Triage the hosts involved and watch for escalation.`;
  }
  return `${high} high-severity finding(s) and ${med} medium. Strong indicators of active compromise — isolate the source host(s), block the IoCs, and open an incident.`;
}
