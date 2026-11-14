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

// ── Synthetic in-memory captures: port scan & DNS tunneling ─────────────────
function synthPcap(packets) {
  const globalHeader = new Uint8Array(24);
  const gv = new DataView(globalHeader.buffer);
  gv.setUint32(0, 0xa1b2c3d4, true); // magic, little-endian
  gv.setUint16(4, 2, true);
  gv.setUint16(6, 4, true);
  gv.setUint32(16, 65535, true);
  gv.setUint32(20, 1, true); // network = Ethernet
  const parts = [globalHeader];
  for (const { tsSec, frame } of packets) {
    const rec = new Uint8Array(16);
    const rv = new DataView(rec.buffer);
    rv.setUint32(0, tsSec, true);
    rv.setUint32(4, 0, true);
    rv.setUint32(8, frame.length, true);
    rv.setUint32(12, frame.length, true);
    parts.push(rec, frame);
  }
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function ipHeader(totalLen, proto, srcIp, dstIp) {
  const ip = new Uint8Array(20);
  ip[0] = 0x45; // version + IHL
  ip[2] = (totalLen >> 8) & 0xff;
  ip[3] = totalLen & 0xff;
  ip[8] = 64; // TTL
  ip[9] = proto;
  const sip = srcIp.split(".").map(Number);
  const dip = dstIp.split(".").map(Number);
  for (let i = 0; i < 4; i++) {
    ip[12 + i] = sip[i];
    ip[16 + i] = dip[i];
  }
  return ip;
}

function ethFrame(l3) {
  const frame = new Uint8Array(14 + l3.length);
  frame.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x02], 0); // dst mac
  frame.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 6); // src mac
  frame[12] = 0x08;
  frame[13] = 0x00; // etherType IPv4
  frame.set(l3, 14);
  return frame;
}

function ethIpTcp(srcIp, dstIp, srcPort, dstPort, flags) {
  const tcp = new Uint8Array(20);
  tcp[0] = (srcPort >> 8) & 0xff;
  tcp[1] = srcPort & 0xff;
  tcp[2] = (dstPort >> 8) & 0xff;
  tcp[3] = dstPort & 0xff;
  tcp[12] = 0x50; // data offset = 5 words
  tcp[13] = flags; // SYN only
  const ip = ipHeader(20 + tcp.length, 6, srcIp, dstIp);
  const l3 = new Uint8Array(ip.length + tcp.length);
  l3.set(ip, 0);
  l3.set(tcp, ip.length);
  return ethFrame(l3);
}

function ethIpUdp(srcIp, dstIp, srcPort, dstPort, payload) {
  const udp = new Uint8Array(8);
  udp[0] = (srcPort >> 8) & 0xff;
  udp[1] = srcPort & 0xff;
  udp[2] = (dstPort >> 8) & 0xff;
  udp[3] = dstPort & 0xff;
  const udpLen = 8 + payload.length;
  udp[4] = (udpLen >> 8) & 0xff;
  udp[5] = udpLen & 0xff;
  const ip = ipHeader(20 + udpLen, 17, srcIp, dstIp);
  const l3 = new Uint8Array(ip.length + udpLen);
  l3.set(ip, 0);
  l3.set(udp, ip.length);
  l3.set(payload, ip.length + 8);
  return ethFrame(l3);
}

function dnsQueryPacket(qname, qtype) {
  const labels = qname.split(".");
  let size = 12;
  for (const l of labels) size += 1 + l.length;
  size += 1 + 4;
  const pkt = new Uint8Array(size);
  const dv = new DataView(pkt.buffer);
  dv.setUint16(0, 0x1234); // transaction id
  dv.setUint16(2, 0x0100); // recursion desired
  dv.setUint16(4, 1); // qdcount
  let off = 12;
  for (const l of labels) {
    pkt[off++] = l.length;
    for (let i = 0; i < l.length; i++) pkt[off++] = l.charCodeAt(i) & 0xff;
  }
  pkt[off++] = 0x00;
  dv.setUint16(off, qtype);
  off += 2;
  dv.setUint16(off, 1); // qclass IN
  return pkt;
}

const portScanPackets = [];
for (let i = 0; i < 30; i++) {
  portScanPackets.push({
    tsSec: 1700000000 + i,
    frame: ethIpTcp("10.0.0.9", "192.0.2.55", 40000 + i, 20 + i * 7, 0x02),
  });
}
expectRules("Synthetic port scan", analyzePcap(synthPcap(portScanPackets)), ["NETX-006"]);

const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
const dnsTunnelPackets = [];
for (let i = 0; i < 24; i++) {
  let label = "";
  let seed = (i + 1) * 2654435761;
  for (let j = 0; j < 38; j++) {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    label += alphabet[seed % alphabet.length];
  }
  dnsTunnelPackets.push({
    tsSec: 1700000100 + i,
    frame: ethIpUdp(
      "10.0.0.9",
      "1.1.1.1",
      50000 + i,
      53,
      dnsQueryPacket(label + ".tunnel.example", 16) // TXT
    ),
  });
}
expectRules("Synthetic DNS tunnel", analyzePcap(synthPcap(dnsTunnelPackets)), [
  "NETX-007",
  "NETX-008",
]);

console.log(failures === 0 ? "\nSMOKE TEST: ALL RULES FIRED ✓" : `\nSMOKE TEST: ${failures} rule(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
