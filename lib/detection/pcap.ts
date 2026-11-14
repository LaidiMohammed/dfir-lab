/**
 * Network detection engine — pure TypeScript, zero dependencies.
 * Parses classic .pcap (LE/BE) and basic .pcapng files entirely in the
 * browser, reconstructs flows, and applies beaconing/exfil/DGA/credential
 * heuristics.
 */
import {
  buildResult,
  type AnalysisResult,
  type Finding,
} from "./types.ts";

interface Packet {
  /** epoch milliseconds */
  timeMs: number;
  proto: "tcp" | "udp" | "other";
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  tcpSyn: boolean;
  /** L4 payload */
  payload: Uint8Array;
  /** Full IP packet length in bytes (approx. wire length) */
  ipBytes: number;
}

function readU32(view: DataView, off: number, le: boolean): number {
  return view.getUint32(off, le);
}

function ipv4ToString(view: DataView, off: number): string {
  return `${view.getUint8(off)}.${view.getUint8(off + 1)}.${view.getUint8(off + 2)}.${view.getUint8(off + 3)}`;
}

function ipv6ToString(view: DataView, off: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 8; i++) parts.push(view.getUint16(off + i * 2).toString(16));
  return parts.join(":");
}

function payloadAscii(payload: Uint8Array, maxLen = 400): string {
  let out = "";
  const n = Math.min(payload.length, maxLen);
  for (let i = 0; i < n; i++) {
    const c = payload[i]!;
    out += c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
  }
  return out;
}

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const EXFIL_BYTES = 250 * 1024; // 250 KB per destination
const BEACON_MIN_PACKETS = 5;
const BEACON_MAX_CV = 0.3; // coefficient of variation of inter-arrival times
const PORT_SCAN_MIN_PORTS = 15; // distinct SYN-only ports from one source
const DNS_TUNNEL_MIN_QUERIES = 20; // total queries to one parent domain
const DNS_TUNNEL_MIN_LABEL = 24; // avg subdomain label length (chars)
const DNS_TUNNEL_TXT_MIN = 8; // TXT queries to one parent domain
const SUSPICIOUS_PORTS = new Map<number, string>([
  [4444, "Metasploit default listener"],
  [4445, "Metasploit alternate listener"],
  [6666, "IRC / botnet C2"],
  [6667, "IRC / botnet C2"],
  [31337, "elite-speak backdoor"],
  [1337, "leetspeak backdoor"],
  [5555, "Android ADB / secondary C2"],
]);

/* ── pcap parsing ──────────────────────────────────────────────────────────── */

export function parsePcap(bytes: Uint8Array): Packet[] {
  if (bytes.length < 24) return [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const magicLE = readU32(view, 0, true);
  const isClassicLE = magicLE === 0xa1b2c3d4 || magicLE === 0xa1b23c4d;
  const magicBE = readU32(view, 0, false);
  const isClassicBE = magicBE === 0xa1b2c3d4 || magicBE === 0xa1b23c4d;

  if (bytes.length >= 12 && readU32(view, 0, true) === 0x0a0d0d0a) {
    return parsePcapng(view, bytes);
  }
  if (isClassicLE) return parseClassic(view, bytes, true);
  if (isClassicBE) return parseClassic(view, bytes, false);
  return [];
}

function parseClassic(
  view: DataView,
  bytes: Uint8Array,
  le: boolean
): Packet[] {
  // global header: 24 bytes
  const network = readU32(view, 20, le); // 1 = Ethernet
  if (network !== 1) {
    // Only Ethernet linktype is supported by this minimal parser.
    return [];
  }
  const packets: Packet[] = [];
  let off = 24;
  while (off + 16 <= bytes.length) {
    const tsSec = readU32(view, off, le);
    const tsUsec = readU32(view, off + 4, le);
    const inclLen = readU32(view, off + 8, le);
    off += 16;
    if (inclLen > bytes.length - off) break; // truncated
    const data = bytes.subarray(off, off + inclLen);
    off += inclLen;
    const pkt = parseFrame(data, (tsSec * 1000 + Math.floor(tsUsec / 1000)));
    if (pkt) packets.push(pkt);
  }
  return packets;
}

function parsePcapng(view: DataView, bytes: Uint8Array): Packet[] {
  // Determine endianness from the Byte-Order Magic at offset 8 of the SHB.
  const bomLE = readU32(view, 8, true) === 0x1a2b3c4d;
  const le = bomLE;
  let sectionLinkType = 1;
  let off = 0;
  const packets: Packet[] = [];

  while (off + 12 <= bytes.length) {
    const blockType = readU32(view, off, le);
    const blockTotalLen = readU32(view, off + 4, le);
    if (blockTotalLen < 12 || off + blockTotalLen > bytes.length) break;

    if (blockType === 0x00000001) {
      // IDB: linktype (2 bytes) + reserved (2) + snaplen (4)
      sectionLinkType = view.getUint16(off + 8, le);
    } else if (blockType === 0x00000006) {
      // EPB: iface_id(4) ts_high(4) ts_low(4) cap_len(4) orig_len(4) data...
      const tsHigh = readU32(view, off + 12, le);
      const tsLow = readU32(view, off + 16, le);
      const capLen = readU32(view, off + 20, le);
      const dataStart = off + 28;
      if (dataStart + capLen <= off + blockTotalLen) {
        const data = bytes.subarray(dataStart, dataStart + capLen);
        const tsUs = (tsHigh * 2 ** 32 + tsLow);
        const pkt = parseFrame(data, Math.floor(tsUs / 1000));
        if (pkt && sectionLinkType === 1) packets.push(pkt);
      }
    }
    off += blockTotalLen;
  }
  return packets;
}

const ETH_IP = 0x0800;
const ETH_IPV6 = 0x86dd;
const ETH_VLAN = 0x8100;

function parseFrame(data: Uint8Array, timeMs: number): Packet | null {
  if (data.length < 34) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  let ethType = view.getUint16(12);
  let l3Off = 14;
  if (ethType === ETH_VLAN) {
    ethType = view.getUint16(16);
    l3Off = 18;
  }

  if (ethType === ETH_IP) {
    const ihl = (view.getUint8(l3Off) & 0x0f) * 4;
    const totalLen = view.getUint16(l3Off + 2);
    const proto = view.getUint8(l3Off + 9);
    const srcIp = ipv4ToString(view, l3Off + 12);
    const dstIp = ipv4ToString(view, l3Off + 16);
    const l4Off = l3Off + ihl;
    return parseL4(view, data, l4Off, proto, srcIp, dstIp, totalLen, timeMs);
  }

  if (ethType === ETH_IPV6) {
    const payloadLen = view.getUint16(l3Off + 4);
    const nextHeader = view.getUint8(l3Off + 6);
    const srcIp = ipv6ToString(view, l3Off + 8);
    const dstIp = ipv6ToString(view, l3Off + 24);
    let l4Off = l3Off + 40;
    let proto = nextHeader;
    // walk a couple of extension headers (hop-by-hop / routing / dest-opts)
    for (let hop = 0; hop < 4; hop++) {
      if (proto === 0 || proto === 43 || proto === 60) {
        const nh = view.getUint8(l4Off);
        const len = (view.getUint8(l4Off + 1) + 1) * 8;
        proto = nh;
        l4Off += len;
      } else if (proto === 44) {
        proto = view.getUint8(l4Off);
        l4Off += 8;
      } else if (proto === 51) {
        const len = (view.getUint8(l4Off + 1) + 2) * 4;
        proto = view.getUint8(l4Off);
        l4Off += len;
      } else break;
    }
    return parseL4(view, data, l4Off, proto, srcIp, dstIp, payloadLen + 40, timeMs);
  }
  return null;
}

function parseL4(
  view: DataView,
  data: Uint8Array,
  l4Off: number,
  proto: number,
  srcIp: string,
  dstIp: string,
  ipBytes: number,
  timeMs: number
): Packet | null {
  if (l4Off + 8 > data.length) return null;

  if (proto === 6) {
    // TCP
    if (l4Off + 20 > data.length) return null;
    const srcPort = view.getUint16(l4Off);
    const dstPort = view.getUint16(l4Off + 2);
    const dataOffset = (view.getUint8(l4Off + 12) >> 4) * 4;
    if (dataOffset < 20 || l4Off + dataOffset > data.length) return null;
    const flags = view.getUint8(l4Off + 13);
    const payloadStart = l4Off + dataOffset;
    const payload =
      payloadStart <= data.length
        ? data.subarray(payloadStart, data.length)
        : new Uint8Array(0);
    return {
      timeMs,
      proto: "tcp",
      srcIp,
      dstIp,
      srcPort,
      dstPort,
      tcpSyn: (flags & 0x02) !== 0 && (flags & 0x10) === 0,
      payload,
      ipBytes,
    };
  }

  if (proto === 17) {
    // UDP
    const srcPort = view.getUint16(l4Off);
    const dstPort = view.getUint16(l4Off + 2);
    const payload = data.subarray(l4Off + 8, data.length);
    return {
      timeMs,
      proto: "udp",
      srcIp,
      dstIp,
      srcPort,
      dstPort,
      tcpSyn: false,
      payload,
      ipBytes,
    };
  }

  return {
    timeMs,
    proto: "other",
    srcIp,
    dstIp,
    srcPort: 0,
    dstPort: 0,
    tcpSyn: false,
    payload: new Uint8Array(0),
    ipBytes,
  };
}

/* ── detection ─────────────────────────────────────────────────────────────── */

function parseDnsQuestionFull(
  payload: Uint8Array
): { name: string; qtype: number } | null {
  // DNS header = 12 bytes; first question follows.
  if (payload.length < 17) return null;
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const qdCount = view.getUint16(4);
  if (qdCount < 1) return null;
  let off = 12;
  const labels: string[] = [];
  while (off < payload.length) {
    const len = payload[off]!;
    if (len === 0) {
      off += 1;
      break;
    }
    if (len >= 0x40) return null; // compressed pointer — not expected in questions
    off += 1;
    if (off + len > payload.length) return null;
    labels.push(String.fromCharCode(...payload.subarray(off, off + len)));
    off += len;
  }
  if (off + 2 > payload.length) return null;
  const qtype = view.getUint16(off);
  const name = labels.join(".").toLowerCase();
  return name.length > 0 && name.length < 255 ? { name, qtype } : null;
}

/** Parent domain approximation: last two labels. */
function parentDomain(qname: string): string {
  const labels = qname.split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  return labels.slice(-2).join(".");
}

export function analyzePcap(bytes: Uint8Array): AnalysisResult {
  const findings: Finding[] = [];
  const packets = parsePcap(bytes);

  const flowKey = (p: Packet) =>
    `${p.proto}|${p.srcIp}|${p.srcPort}>${p.dstIp}|${p.dstPort}`;

  // ── NETX-001 — cleartext credentials in HTTP / generic text payloads ──────
  const credSeen = new Set<string>();
  for (const p of packets) {
    if (p.payload.length === 0) continue;
    const text = payloadAscii(p.payload, 1200);
    const isHttp =
      /^(GET|POST|PUT|HEAD|OPTIONS)\s/.test(text) ||
      text.includes("\r\nHost:") ||
      p.dstPort === 80;
    const passMatch =
      /(?:password|passwd|pwd)\s*=\s*([^&\s.]{1,6})[^&\s.]*/i.exec(text);
    const basicAuth = /Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i.exec(text);
    if (isHttp && passMatch) {
      const key = `${p.srcIp}>${p.dstIp}:${passMatch[0].slice(0, 24)}`;
      if (credSeen.has(key)) continue;
      credSeen.add(key);
      findings.push({
        ruleId: "NETX-001",
        severity: "critical",
        title: `Cleartext credentials in HTTP payload (${p.srcIp} → ${p.dstIp})`,
        mitre: "T1552 — Unsecured Credentials",
        summary:
          "A password parameter travelled unencrypted in an HTTP request body/query — readable by anyone on the wire.",
        evidence: `${p.srcIp}:${p.srcPort} → ${p.dstIp}:${p.dstPort}\n${text.slice(0, 160).replace(passMatch[0], passMatch[0].slice(0, 12) + "…[redacted]")}`,
        remediation:
          "Force HTTPS, rotate the exposed credential, inspect the backend logs for the account's activity.",
      });
    } else if (isHttp && basicAuth) {
      const key = `${p.srcIp}>${p.dstIp}:basic`;
      if (credSeen.has(key)) continue;
      credSeen.add(key);
      findings.push({
        ruleId: "NETX-001",
        severity: "critical",
        title: `HTTP Basic auth in cleartext (${p.srcIp} → ${p.dstIp})`,
        mitre: "T1552 — Unsecured Credentials",
        summary:
          "Authorization: Basic is base64, not encryption — trivial to reverse for anyone capturing the traffic.",
        evidence: `${p.srcIp}:${p.srcPort} → ${p.dstIp}:${p.dstPort}\nAuthorization: Basic ${basicAuth[1]!.slice(0, 8)}…[redacted]`,
        remediation:
          "Move the service behind TLS, rotate the credential, prefer token-based auth.",
      });
    }
  }

  // ── DNS question extraction + entropy analysis ─────────────────────────────
  const dnsQueries: { qname: string; qtype: number; srcIp: string; timeMs: number }[] = [];
  for (const p of packets) {
    if (p.proto === "udp" && p.dstPort === 53) {
      const q = parseDnsQuestionFull(p.payload);
      if (q) dnsQueries.push({ qname: q.name, qtype: q.qtype, srcIp: p.srcIp, timeMs: p.timeMs });
    }
  }
  for (const { qname, srcIp } of dnsQueries) {
    const labels = qname.split(".");
    const longest = labels.slice(0, -2).reduce((a, b) => (b.length > a.length ? b : a), labels[0]!);
    const entropy = shannonEntropy(longest);
    if (longest.length >= 18 && entropy >= 4.0) {
      findings.push({
        ruleId: "NETX-004",
        severity: "medium",
        title: `High-entropy DNS label "${longest.slice(0, 32)}…" (possible DGA)`,
        mitre: "T1568.002 — Domain Generation Algorithms",
        summary:
          "Statistically random-looking subdomains are characteristic of DGA-based C2 rendezvous traffic.",
        evidence: `${srcIp} queried: ${qname} (entropy ${entropy.toFixed(2)} bits/char)`,
        remediation:
          "Sinkhole the domain at the resolver, hunt matching queries across the estate, block at proxy/EDR.",
      });
    }
  }

  // ── NETX-002 — beaconing (fixed-interval C2 callbacks) ────────────────────
  const flows = new Map<string, Packet[]>();
  for (const p of packets) {
    if (p.proto !== "tcp") continue;
    const bucket = flows.get(flowKey(p)) ?? [];
    bucket.push(p);
    flows.set(flowKey(p), bucket);
  }
  for (const [key, group] of flows) {
    if (group.length < BEACON_MIN_PACKETS) continue;
    const sorted = [...group].sort((a, b) => a.timeMs - b.timeMs);
    const intervals: number[] = [];
    for (let i = 1; i < sorted.length; i++) {
      intervals.push(sorted[i]!.timeMs - sorted[i - 1]!.timeMs);
    }
    const mean = intervals.reduce((s, v) => s + v, 0) / intervals.length;
    if (mean < 500) continue; // too fast — interactive, skip
    const variance =
      intervals.reduce((s, v) => s + (v - mean) ** 2, 0) / intervals.length;
    const cv = Math.sqrt(variance) / mean;
    if (cv <= BEACON_MAX_CV) {
      findings.push({
        ruleId: "NETX-002",
        severity: "high",
        title: `Beaconing: ${group.length} callbacks at ~${Math.round(mean / 1000)}s intervals`,
        mitre: "T1071 — Application Layer Protocol (C2)",
        summary:
          "Regular, low-variance inter-packet timing from one host to one endpoint is the signature of an automated C2 beacon.",
        evidence: `${key}\nintervals(ms): ${intervals.slice(0, 6).join(", ")}  cv=${cv.toFixed(2)}`,
        remediation:
          "Block the destination, capture and analyze the host that owns the source IP, hunt sibling beacons by interval.",
      });
    }
  }

  // ── NETX-003 — bulk transfer (possible exfiltration) ──────────────────────
  const bytesPerDst = new Map<string, number>();
  for (const p of packets) {
    bytesPerDst.set(p.dstIp, (bytesPerDst.get(p.dstIp) ?? 0) + p.payload.length);
  }
  for (const [dstIp, total] of bytesPerDst) {
    if (total >= EXFIL_BYTES) {
      findings.push({
        ruleId: "NETX-003",
        severity: "high",
        title: `Bulk transfer to ${dstIp}: ${(total / 1024).toFixed(0)} KB of payload`,
        mitre: "T1041 — Exfiltration Over C2 Channel",
        summary:
          "A single off-host destination received an unusually large volume of payload bytes — consistent with staged exfiltration.",
        evidence: `destination ${dstIp} — ${total} payload bytes across ${
          packets.filter((p) => p.dstIp === dstIp).length
        } packets`,
        remediation:
          "Identify what was staged (broker/file server logs), block the destination, scope data loss with the data owner.",
      });
    }
  }

  // ── NETX-007/008 — DNS tunneling (QNAME payload & TXT exfil) ─────────────
  const byDomain = new Map<
    string,
    { total: number; txt: number; subLenTotal: number; src: string }
  >();
  for (const { qname, qtype, srcIp } of dnsQueries) {
    const domain = parentDomain(qname);
    if (!domain || !domain.includes(".")) continue;
    const entry =
      byDomain.get(domain) ?? { total: 0, txt: 0, subLenTotal: 0, src: srcIp };
    entry.total += 1;
    if (qtype === 16) entry.txt += 1; // TXT
    entry.subLenTotal += qname.split(".")[0]?.length ?? 0;
    byDomain.set(domain, entry);
  }
  for (const [domain, d] of byDomain) {
    const avgLen = d.subLenTotal / Math.max(d.total, 1);
    if (d.total >= DNS_TUNNEL_MIN_QUERIES && avgLen >= DNS_TUNNEL_MIN_LABEL) {
      findings.push({
        ruleId: "NETX-007",
        severity: "high",
        title: `DNS tunneling — ${d.total} long subdomain queries to ${domain}`,
        mitre: "T1071.004 — DNS",
        summary:
          "Hundreds of encoded-looking subdomains against one parent domain at a steady rate is the classic DNS tunnel. Data crosses the boundary inside the query name itself.",
        evidence: `${d.src} → ${domain} (avg subdomain ${avgLen.toFixed(0)} chars over ${d.total} queries)`,
        remediation:
          "Sinkhole or rate-limit the domain at the resolver, capture full DNS logs, hunt for matching host traffic on port 53.",
      });
    }
    if (d.txt >= DNS_TUNNEL_TXT_MIN) {
      findings.push({
        ruleId: "NETX-008",
        severity: "high",
        title: `Excessive DNS TXT queries to ${domain} (${d.txt})`,
        mitre: "T1071.004 — DNS",
        summary:
          "TXT records are the go-to carrier for DNS-based C2 channels (tunneling, beacon responses, staged payloads).",
        evidence: `${d.src} queried ${d.txt} TXT records for ${domain}`,
        remediation:
          "Block or answer-sinkhole the domain, inspect the querying host for tunneling tooling, capture the full session.",
      });
    }
  }

  // ── NETX-006 — port scan (SYN-only to many distinct ports) ────────────────
  const synByPair = new Map<
    string,
    { src: string; dst: string; ports: Set<number> }
  >();
  for (const p of packets) {
    if (!p.tcpSyn) continue;
    const key = `${p.srcIp}>${p.dstIp}`;
    const entry =
      synByPair.get(key) ?? { src: p.srcIp, dst: p.dstIp, ports: new Set<number>() };
    entry.ports.add(p.dstPort);
    synByPair.set(key, entry);
  }
  for (const { src, dst, ports } of synByPair.values()) {
    if (ports.size < PORT_SCAN_MIN_PORTS) continue;
    const sorted = [...ports].sort((a, b) => a - b);
    const preview = sorted.slice(0, 15).join(", ");
    findings.push({
      ruleId: "NETX-006",
      severity: "high",
      title: `Port scan: ${ports.size} SYN-only ports from ${src} → ${dst}`,
      mitre: "T1595.001 — Active Scanning: Port Scan",
      summary:
        "One source fired SYN-only probes across many distinct destination ports toward one target — standard pre-exploitation service discovery.",
      evidence: `${src} → ${dst}\nSYN-only ports (${ports.size}): ${preview}${ports.size > 15 ? ", …" : ""}`,
      remediation:
        "Block the source, verify no scanned service was reachable, pivot the host into incident triage for follow-on exploitation.",
    });
  }

  // ── NETX-005 — suspicious destination ports ───────────────────────────────
  const portSeen = new Set<string>();
  for (const p of packets) {
    const reason = SUSPICIOUS_PORTS.get(p.dstPort);
    if (!reason) continue;
    const key = `${p.dstIp}:${p.dstPort}`;
    if (portSeen.has(key)) continue;
    portSeen.add(key);
    findings.push({
      ruleId: "NETX-005",
      severity: "medium",
      title: `Outbound traffic to suspicious port ${p.dstPort} (${reason})`,
      mitre: "T1571 — Non-Standard Port",
      summary:
        "The destination port is a well-known C2/listener favorite; coupled with any other finding it is strong evidence of compromise.",
      evidence: `${p.srcIp} → ${p.dstIp}:${p.dstPort} (${p.proto.toUpperCase()})`,
      remediation:
        "Block or alert on this destination:port, capture the full session payload, pivot on the source host.",
    });
  }

  return buildResult(findings, packets.length);
}
