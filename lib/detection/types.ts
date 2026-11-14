/**
 * Shared types for the client-side detection engine.
 * Everything runs in the browser — no evidence ever leaves the machine.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  /** Stable rule identifier, e.g. "LDX-001". */
  ruleId: string;
  severity: Severity;
  title: string;
  /** MITRE ATT&CK technique reference, e.g. "T1110 — Brute Force". */
  mitre: string;
  /** Short human-readable explanation of what was observed. */
  summary: string;
  /** Raw evidence: the offending line(s), counter or flow description. */
  evidence: string;
  /** 1-based source line number, when the input is line-based. */
  line?: number;
  /** What an analyst should do next. */
  remediation: string;
}

export interface AnalysisStats {
  /** Lines / records / packets examined. */
  itemsScanned: number;
  bySeverity: Record<Severity, number>;
  totalFindings: number;
}

export interface AnalysisResult {
  findings: Finding[];
  stats: AnalysisStats;
}

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export function emptySeverityCount(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function buildResult(
  findings: Finding[],
  itemsScanned: number
): AnalysisResult {
  const bySeverity = emptySeverityCount();
  for (const f of findings) {
    bySeverity[f.severity] += 1;
  }
  return {
    findings: sortFindings(findings),
    stats: {
      itemsScanned,
      bySeverity,
      totalFindings: findings.length,
    },
  };
}

export function sortFindings(findings: Finding[]): Finding[] {
  const rank: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  return [...findings].sort((a, b) => {
    const d = rank[a.severity] - rank[b.severity];
    if (d !== 0) return d;
    return (a.line ?? Number.MAX_SAFE_INTEGER) - (b.line ?? Number.MAX_SAFE_INTEGER);
  });
}
