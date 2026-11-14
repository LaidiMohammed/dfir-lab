/** Small shared math/format helpers for the detectors. */

export function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const midValue = sorted[mid];
  if (midValue === undefined) return 0;
  if (sorted.length % 2 === 0) {
    const prev = sorted[mid - 1];
    return prev === undefined ? midValue : (prev + midValue) / 2;
  }
  return midValue;
}

export function stddev(values: number[]): number {
  if (values.length < 2) return 0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance =
    values.reduce((acc, v) => acc + (v - mean) ** 2, 0) / (values.length - 1);
  return Math.sqrt(variance);
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

/** RFC1918-ish private/internal range check. */
export function isPrivateIp(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  const [a, b] = parts;
  if (a === undefined || b === undefined || parts.length !== 4) return true;
  if (parts.some(Number.isNaN)) return true;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  return false;
}

/** Parent domain approximation: last two labels. */
export function parentDomain(qname: string): string {
  const labels = qname.toLowerCase().split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  return labels.slice(-2).join(".");
}
