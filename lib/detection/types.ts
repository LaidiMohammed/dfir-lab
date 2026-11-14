/** Shared detection framework types — used by all four module playgrounds. */

export type Severity = "high" | "medium" | "low" | "info";

export interface Finding {
  /** Stable rule identifier, e.g. PORT_SCAN, DNS_TUNNEL_QNAME. */
  rule: string;
  title: string;
  detail: string;
  severity: Severity;
  /** Optional indicator(s) this finding is responsible for. */
  ioc?: string;
}

export type Verdict = "clean" | "suspicious" | "malicious";

export interface DetectionReport {
  verdict: Verdict;
  /** One-paragraph analyst-grade summary. */
  summary: string;
  findings: Finding[];
  /** De-duplicated indicators to block (IPs, domains, decoded payloads, hashes). */
  iocs: string[];
  /** Small stat counters shown above the findings. */
  stats: { label: string; value: string }[];
}

export interface SampleMeta {
  id: string;
  label: string;
  /** Short description shown on the sample picker button. */
  blurb: string;
}

export const severityRank: Record<Severity, number> = {
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function computeVerdict(findings: Finding[]): Verdict {
  if (findings.some((f) => f.severity === "high")) return "malicious";
  if (findings.filter((f) => f.severity === "medium").length >= 2) return "suspicious";
  if (findings.some((f) => f.severity === "medium")) return "suspicious";
  return "clean";
}

/** Shared seeded PRNG (mulberry32) so generated samples are deterministic. */
export function mulberry32(seed: number) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Shannon entropy in bits per byte (0–8). */
export function shannonEntropy(data: Uint8Array): number {
  if (data.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < data.length; i++) {
    const byte = data[i];
    if (byte !== undefined) counts[byte] = (counts[byte] ?? 0) + 1;
  }
  let entropy = 0;
  const total = data.length;
  for (let i = 0; i < 256; i++) {
    const c = counts[i];
    if (c === undefined || c === 0) continue;
    const p = c / total;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
