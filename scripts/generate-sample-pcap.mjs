/**
 * Generates public/samples/intrusion.pcap — a synthetic, deterministic lab
 * capture used to demonstrate the NETX detection rules. Run with:
 *   node scripts/generate-sample-pcap.mjs
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const outPath = resolve(__dirname, "..", "public", "samples", "intrusion.pcap");

const records = [];
let seq = 1000;
const baseSec = 1_763_000_000; // fixed lab timestamp (2025-11-13)
let tick = 0; // seconds offset

function ipBytes(a, b, c, d) {
  return [a, b, c, d];
}
const HOST = ipBytes(10, 0, 8, 15);
const EXTERNAL_C2 = ipBytes(198, 51, 100, 99);
const EXTERNAL_WEB = ipBytes(203, 0, 113, 7);
const EXFIL_DST = ipBytes(198, 51, 100, 77);
const MSF_4434 = ipBytes(198, 51, 100, 200);

function ethFrame(srcMac, dstMac, etherType) {
  const f = Buffer.alloc(14);
  Buffer.from(dstMac.split(":").map((h) => parseInt(h, 16))).copy(f, 0);
  Buffer.from(srcMac.split(":").map((h) => parseInt(h, 16))).copy(f, 6);
  f.writeUInt16BE(etherType, 12);
  return f;
}

function ipv4Packet(src, dst, proto, payload, totalLenOverride) {
  const totalLen = 20 + payload.length;
  const p = Buffer.alloc(20);
  p.writeUInt8(0x45, 0);
  p.writeUInt8(0, 1);
  p.writeUInt16BE(totalLenOverride ?? totalLen, 2);
  p.writeUInt16BE(0x1234, 4);
  p.writeUInt16BE(0x4000, 6);
  p.writeUInt8(64, 8);
  p.writeUInt8(proto, 9);
  p.writeUInt16BE(0, 10); // checksum (not validated by our analyzer)
  Buffer.from(src).copy(p, 12);
  Buffer.from(dst).copy(p, 16);
  return Buffer.concat([p, payload]);
}

function tcpSegment(sport, dport, seqNo, ack, flags, payload) {
  const t = Buffer.alloc(20);
  t.writeUInt16BE(sport, 0);
  t.writeUInt16BE(dport, 2);
  t.writeUInt32BE(seqNo >>> 0, 4);
  t.writeUInt32BE(ack >>> 0, 8);
  t.writeUInt8(0x50, 12); // data offset = 5 (20 bytes)
  t.writeUInt8(flags, 13);
  t.writeUInt16BE(8192, 14);
  t.writeUInt16BE(0, 16); // checksum
  t.writeUInt16BE(0, 18);
  return Buffer.concat([t, payload]);
}

function udpDatagram(sport, dport, payload) {
  const u = Buffer.alloc(8);
  u.writeUInt16BE(sport, 0);
  u.writeUInt16BE(dport, 2);
  u.writeUInt16BE(8 + payload.length, 4);
  u.writeUInt16BE(0, 6);
  return Buffer.concat([u, payload]);
}

function dnsQuery(id, qname) {
  const q = Buffer.alloc(12);
  q.writeUInt16BE(id, 0);
  q.writeUInt16BE(0x0100, 2); // recursion desired
  q.writeUInt16BE(1, 4); // qd
  q.writeUInt16BE(0, 6);
  q.writeUInt16BE(0, 8);
  q.writeUInt16BE(0, 10);
  const labels = [];
  for (const part of qname.split(".")) {
    labels.push(Buffer.from([part.length]));
    labels.push(Buffer.from(part, "ascii"));
  }
  labels.push(Buffer.from([0]));
  const qtype = Buffer.alloc(4);
  qtype.writeUInt16BE(1, 0); // A
  qtype.writeUInt16BE(1, 2); // IN
  return Buffer.concat([q, ...labels, qtype]);
}

function pushEthIpTcp(tsSec, tsUsec, srcMac, dstMac, src, dst, sport, dport, flags, payload) {
  const tcp = tcpSegment(sport, dport, seq, 0, flags, payload);
  seq += Math.max(payload.length, 1);
  const ip = ipv4Packet(src, dst, 6, tcp);
  const frame = Buffer.concat([ethFrame(srcMac, dstMac, 0x0800), ip]);
  records.push({ tsSec, tsUsec, data: frame });
}

function pushEthIpUdp(tsSec, tsUsec, srcMac, dstMac, src, dst, sport, dport, payload) {
  const udp = udpDatagram(sport, dport, payload);
  const ip = ipv4Packet(src, dst, 17, udp);
  const frame = Buffer.concat([ethFrame(srcMac, dstMac, 0x0800), ip]);
  records.push({ tsSec, tsUsec, data: frame });
}

function ts(offsetSec, usec = 0) {
  return { tsSec: baseSec + offsetSec, tsUsec: usec };
}

/* 1) Benign traffic: one DNS query for a normal domain + HTTP GET */
{
  const t = ts(tick += 5);
  pushEthIpUdp(t.tsSec, t.tsUsec, "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:ff", HOST, ipBytes(8, 8, 8, 8), 53333, 53, dnsQuery(0x1111, "updates.microsoft.com"));
}
{
  const t = ts(tick += 5);
  pushEthIpTcp(t.tsSec, t.tsUsec, "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:ff", HOST, EXTERNAL_WEB, 49210, 80, 0x18, Buffer.from(
    "GET /about HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n", "ascii"));
}

/* 2) Beaconing: 6 SYNs to the C2 every 30s */
for (let i = 0; i < 6; i++) {
  const t = ts(tick += i === 0 ? 20 : 30);
  pushEthIpTcp(t.tsSec, t.tsUsec, "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:ff", HOST, EXTERNAL_C2, 49152, 443, 0x02, Buffer.alloc(0));
}

/* 3) Cleartext credentials in HTTP POST */
{
  const t = ts(tick += 15);
  pushEthIpTcp(t.tsSec, t.tsUsec, "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:ff", HOST, EXTERNAL_WEB, 49211, 80, 0x18, Buffer.from(
    "POST /login HTTP/1.1\r\nHost: app.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 33\r\n\r\nuser=admin&password=Sup3rSecret", "ascii"));
}

/* 4) High-entropy DGA-like DNS query */
{
  const t = ts(tick += 12);
  pushEthIpUdp(t.tsSec, t.tsUsec, "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:ff", HOST, ipBytes(8, 8, 8, 8), 53334, 53, dnsQuery(0x2222, "xj9k2m4n8b7v1z6q3w5e8r0t4y7u2i1.com"));
}

/* 5) Outbound to Metasploit-default port 4444 */
{
  const t = ts(tick += 9);
  pushEthIpTcp(t.tsSec, t.tsUsec, "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:ff", HOST, MSF_4434, 49300, 4444, 0x02, Buffer.alloc(0));
}

/* 6) Bulk transfer to an external host: 34 x 8 KB payloads (~272 KB) */
const exfilPayload = Buffer.alloc(8192, 0x41);
for (let i = 0; i < 34; i++) {
  const t = ts(tick += 1);
  pushEthIpTcp(t.tsSec, t.tsUsec, "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:ff", HOST, EXFIL_DST, 49400, 80, 0x18, exfilPayload);
}

/* Assemble classic little-endian pcap */
const globalHeader = Buffer.alloc(24);
globalHeader.writeUInt32LE(0xa1b2c3d4, 0);
globalHeader.writeUInt16LE(2, 4);
globalHeader.writeUInt16LE(4, 6);
globalHeader.writeInt32LE(0, 8);
globalHeader.writeUInt32LE(0, 12);
globalHeader.writeUInt32LE(65535, 16);
globalHeader.writeUInt32LE(1, 20); // Ethernet

const parts = [globalHeader];
for (const r of records) {
  const rec = Buffer.alloc(16);
  rec.writeUInt32LE(r.tsSec >>> 0, 0);
  rec.writeUInt32LE(r.tsUsec >>> 0, 4);
  rec.writeUInt32LE(r.data.length, 8);
  rec.writeUInt32LE(r.data.length, 12);
  parts.push(rec, r.data);
}
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, Buffer.concat(parts));
console.log(`Wrote ${outPath} — ${records.length} packets, ${parts.reduce((s, p) => s + p.length, 0)} bytes`);
