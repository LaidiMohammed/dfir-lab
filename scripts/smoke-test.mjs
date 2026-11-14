/**
 * Smoke test for the client-side detection engine. Run with:
 *   node scripts/smoke-test.mjs
 * Exits non-zero when a rule that should fire stays silent.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(resolve(root, p), "utf8");
const readBytes = (p) => new Uint8Array(readFileSync(resolve(root, p)));

const { analyzeLinuxLog } = await import("../lib/detection/linux.ts");
const { analyzeTimelineCsv } = await import("../lib/detection/timeline.ts");
const { analyzeProcesses } = await import("../lib/detection/memory.ts");
const { analyzePcap } = await import("../lib/detection/pcap.ts");

let failures = 0;

function expectRules(name, result, expectedRules) {
  const fired = new Set(result.findings.map((f) => f.ruleId));
  console.log(`\n== ${name} — scanned ${result.stats.itemsScanned}, ${result.stats.totalFindings} finding(s)`);
  for (const f of result.findings) {
    console.log(`   [${f.severity.toUpperCase()}] ${f.ruleId}  ${f.title.slice(0, 90)}`);
  }
  for (const rule of expectedRules) {
    const ok = fired.has(rule);
    console.log(`   ${ok ? "PASS" : "FAIL"}  expects ${rule}`);
    if (!ok) failures += 1;
  }
}

expectRules("Linux auth.log", analyzeLinuxLog(read("public/samples/sample-auth.log")), [
  "LDX-001", "LDX-002", "LDX-003", "LDX-005", "LDX-006", "LDX-007", "LDX-008", "LDX-009", "LDX-010",
]);

expectRules("Windows timeline CSV", analyzeTimelineCsv(read("public/samples/sample-timeline.csv")), [
  "TLX-001", "TLX-002", "TLX-003", "TLX-004", "TLX-005", "TLX-006", "TLX-007",
]);

expectRules("Process list", analyzeProcesses(read("public/samples/sample-processes.csv")), [
  "MEMX-001", "MEMX-002", "MEMX-003", "MEMX-004",
]);

expectRules("Sample PCAP", analyzePcap(readBytes("public/samples/intrusion.pcap")), [
  "NETX-001", "NETX-002", "NETX-003", "NETX-004", "NETX-005",
]);

console.log(failures === 0 ? "\nSMOKE TEST: ALL RULES FIRED ✓" : `\nSMOKE TEST: ${failures} rule(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
