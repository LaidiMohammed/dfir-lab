/**
 * Deterministic synthetic-PCAP builders. Every sample is generated at runtime
 * into a classic PCAP ArrayBuffer, then analyzed through the same parser as a
 * user-dropped file — no fixtures, no mocks in the detection path.
 */
import { mulberry32 } from "@/lib/detection/types";
import type { SampleMeta } from "@/lib/detection/types";

export const networkSamples: SampleMeta[] = [
  {
    id: "clean",
    label: "Baseline — normal office traffic",
    blurb: "Three workstations browsing, DNS to public resolvers. Expected: clean.",
  },
  {
    id: "port-scan",
    label: "Attack — port scan",
    blurb: "One host SYN-scans 45 ports of an external server in seconds. Expected: port scan.",
  },
  {
    id: "dns-tunnel",
    label: "Attack — DNS tunneling",
    blurb: "Encoded subdomains + TXT queries to one domain. Expected: DNS tunneling.",
  },
  {
    id: "beacon",
    label: "Attack — C2 beacon",
    blurb: "A workstation phones home every 30 seconds, like clockwork. Expected: beaconing.",
  },
  {
    id: "exfil",
    label: "Attack — bulk exfiltration",
    blurb: "Sustained multi-MB upload to an unknown public host. Expected: exfil volume.",
  },
];

const byteAt = (u: ArrayLike<number>, i: number): number => u[i] ?? 0;

const MAC_A = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const MAC_B = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

const encoder = new TextEncoder();

// ---------------------------------------------------------------------------
// Packet primitives
// ---------------------------------------------------------------------------

function ipv4Checksum(header: Uint8Array): number {
  let sum = 0;
  for (let i = 0; i < header.length; i += 2) {
    sum += ((byteAt(header, i) << 8) | byteAt(header, i + 1)) >>> 0;
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
}

function ipFromString(ip: string): number[] {
  return ip.split(".").map((n) => Number(n) & 0xff);
}

function buildIpv4(srcIp: string, dstIp: string, proto: number, payloadLength: number, id: number): Uint8Array {
  const total = 20 + payloadLength;
  const h = new Uint8Array(20);
  h[0] = 0x45;
  h[1] = 0;
  h[2] = (total >> 8) & 0xff;
  h[3] = total & 0xff;
  h[4] = (id >> 8) & 0xff;
  h[5] = id & 0xff;
  h[6] = 0x40; // flags: don't fragment
  h[7] = 0;
  h[8] = 64; // TTL
  h[9] = proto;
  h[10] = 0;
  h[11] = 0; // checksum zeroed for calculation
  const s = ipFromString(srcIp);
  const d = ipFromString(dstIp);
  for (let i = 0; i < 4; i++) h[12 + i] = byteAt(s, i);
  for (let i = 0; i < 4; i++) h[16 + i] = byteAt(d, i);
  const csum = ipv4Checksum(h);
  h[10] = (csum >> 8) & 0xff;
  h[11] = csum & 0xff;
  return h;
}

function buildTcp(srcPort: number, dstPort: number, seq: number, ack: number, flags: number): Uint8Array {
  const t = new Uint8Array(20);
  t[0] = (srcPort >> 8) & 0xff;
  t[1] = srcPort & 0xff;
  t[2] = (dstPort >> 8) & 0xff;
  t[3] = dstPort & 0xff;
  t[4] = (seq >>> 24) & 0xff;
  t[5] = (seq >>> 16) & 0xff;
  t[6] = (seq >>> 8) & 0xff;
  t[7] = seq & 0xff;
  t[8] = (ack >>> 24) & 0xff;
  t[9] = (ack >>> 16) & 0xff;
  t[10] = (ack >>> 8) & 0xff;
  t[11] = ack & 0xff;
  t[12] = 0x50; // data offset = 5 words
  t[13] = flags;
  t[14] = 0xfa;
  t[15] = 0xf0; // window
  return t;
}

function buildUdp(srcPort: number, dstPort: number, payloadLength: number): Uint8Array {
  const u = new Uint8Array(8);
  const len = 8 + payloadLength;
  u[0] = (srcPort >> 8) & 0xff;
  u[1] = srcPort & 0xff;
  u[2] = (dstPort >> 8) & 0xff;
  u[3] = dstPort & 0xff;
  u[4] = (len >> 8) & 0xff;
  u[5] = len & 0xff;
  return u;
}

function buildEthernet(etherType: number, srcMac: number[], dstMac: number[], payload: Uint8Array): Uint8Array {
  const frame = new Uint8Array(14 + payload.length);
  for (let i = 0; i < 6; i++) frame[i] = byteAt(dstMac, i);
  for (let i = 0; i < 6; i++) frame[6 + i] = byteAt(srcMac, i);
  frame[12] = (etherType >> 8) & 0xff;
  frame[13] = etherType & 0xff;
  frame.set(payload, 14);
  return frame;
}

function buildDnsQuery(id: number, qname: string, qtype: number): Uint8Array {
  const labels = qname.split(".").filter(Boolean);
  let nameLen = 1;
  for (const l of labels) nameLen += 1 + l.length;
  const packet = new Uint8Array(12 + nameLen + 4);
  packet[0] = (id >> 8) & 0xff;
  packet[1] = id & 0xff;
  packet[2] = 0x01;
  packet[3] = 0x00; // RD
  packet[4] = 0x00;
  packet[5] = 0x01; // qdcount = 1
  let pos = 12;
  for (const label of labels) {
    packet[pos++] = label.length;
    for (let i = 0; i < label.length; i++) packet[pos++] = label.charCodeAt(i) & 0xff;
  }
  packet[pos++] = 0x00;
  packet[pos++] = (qtype >> 8) & 0xff;
  packet[pos++] = qtype & 0xff;
  packet[pos++] = 0x00;
  packet[pos++] = 0x01; // qclass IN
  return packet;
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

class PcapBuilder {
  private records: { ts: number; frame: Uint8Array }[] = [];
  add(ts: number, frame: Uint8Array) {
    this.records.push({ ts, frame });
  }
  tcpPacket(ts: number, srcIp: string, dstIp: string, sport: number, dport: number, flags: number, seq: number, payload?: Uint8Array, id = 0) {
    const tcp = buildTcp(sport, dport, seq, flags & 0x10 ? 1 : 0, flags);
    const payloadLen = payload?.length ?? 0;
    const ip = buildIpv4(srcIp, dstIp, 6, tcp.length + payloadLen, id);
    const segment = new Uint8Array(tcp.length + payloadLen);
    segment.set(tcp, 0);
    if (payload) segment.set(payload, tcp.length);
    const ipPacket = new Uint8Array(ip.length + segment.length);
    ipPacket.set(ip, 0);
    ipPacket.set(segment, ip.length);
    this.add(ts, buildEthernet(0x0800, MAC_A, MAC_B, ipPacket));
  }
  udpPacket(ts: number, srcIp: string, dstIp: string, sport: number, dport: number, payload: Uint8Array, id = 0) {
    const udp = buildUdp(sport, dport, payload.length);
    const ip = buildIpv4(srcIp, dstIp, 17, udp.length + payload.length, id);
    const datagram = new Uint8Array(udp.length + payload.length);
    datagram.set(udp, 0);
    datagram.set(payload, udp.length);
    const ipPacket = new Uint8Array(ip.length + datagram.length);
    ipPacket.set(ip, 0);
    ipPacket.set(datagram, ip.length);
    this.add(ts, buildEthernet(0x0800, MAC_A, MAC_B, ipPacket));
  }
  dnsQuery(ts: number, srcIp: string, resolver: string, qname: string, qtype: number, id: number) {
    const dns = buildDnsQuery(id, qname, qtype);
    this.udpPacket(ts, srcIp, resolver, 51000 + (id % 1000), 53, dns, id);
  }
  toArrayBuffer(): ArrayBuffer {
    this.records.sort((a, b) => a.ts - b.ts);
    const globalSize = 24;
    const recordHeaders = this.records.length * 16;
    const framesSize = this.records.reduce((acc, r) => acc + r.frame.length, 0);
    const buffer = new ArrayBuffer(globalSize + recordHeaders + framesSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    view.setUint32(0, 0xa1b2c3d4, true); // magic, little-endian
    view.setUint16(4, 2, true); // version major
    view.setUint16(6, 4, true); // version minor
    view.setInt32(8, 0, true); // thiszone
    view.setUint32(12, 0, true); // sigfigs
    view.setUint32(16, 65535, true); // snaplen
    view.setUint32(20, 1, true); // link type: Ethernet

    let offset = globalSize;
    for (const { ts, frame } of this.records) {
      const tsSec = Math.floor(ts);
      const tsUsec = Math.floor((ts - tsSec) * 1e6);
      view.setUint32(offset, tsSec, true);
      view.setUint32(offset + 4, tsUsec, true);
      view.setUint32(offset + 8, frame.length, true);
      view.setUint32(offset + 12, frame.length, true);
      offset += 16;
      bytes.set(frame, offset);
      offset += frame.length;
    }
    return buffer;
  }
}

// ---------------------------------------------------------------------------
// Samples
// ---------------------------------------------------------------------------

function addBaseline(b: PcapBuilder, rand: () => number, start: number) {
  // Three workstations doing ordinary browsing over ~10 minutes.
  const hosts = ["192.168.1.10", "192.168.1.11", "192.168.1.12"];
  const publicSites = ["142.250.185.14", "104.244.42.129", "151.101.1.69"];
  let t = start;
  for (const host of hosts) {
    for (const site of publicSites) {
      t += rand() * 120;
      // DNS lookup (short qname)
      b.dnsQuery(t, host, "8.8.8.8", `www.site-${Math.floor(rand() * 100)}.example`, 1, Math.floor(rand() * 65535));
      // TCP handshake + one payload packet
      b.tcpPacket(t + 0.002, host, site, 49000 + Math.floor(rand() * 2000), 443, 0x02, 1000, undefined, Math.floor(rand() * 65535));
      b.tcpPacket(t + 0.004, site, host, 443, 49000, 0x12, 5000, undefined, Math.floor(rand() * 65535));
      b.tcpPacket(t + 0.006, host, site, 49000 + Math.floor(rand() * 2000), 443, 0x18, 1001, undefined, Math.floor(rand() * 65535));
    }
  }
}

export function buildNetworkSample(id: string): ArrayBuffer {
  const b = new PcapBuilder();
  const base = Math.floor(Date.UTC(2026, 10, 14, 8, 0, 0) / 1000);

  if (id === "clean") {
    const rand = mulberry32(42);
    addBaseline(b, rand, base);
    return b.toArrayBuffer();
  }

  if (id === "port-scan") {
    const rand = mulberry32(43);
    addBaseline(b, rand, base);
    const t0 = base + 300;
    for (let i = 0; i < 45; i++) {
      const port = 20 + ((i * 137) % 1000) + (i % 3) * 10000;
      b.tcpPacket(t0 + i * 0.4, "192.168.1.50", "203.0.113.87", 40000 + i, port, 0x02, 7000 + i, undefined, i);
    }
    return b.toArrayBuffer();
  }

  if (id === "dns-tunnel") {
    const rand = mulberry32(44);
    addBaseline(b, rand, base);
    const charset = "abcdefghijklmnopqrstuvwxyz0123456789";
    const t0 = base + 300;
    for (let i = 0; i < 26; i++) {
      let label = "";
      for (let j = 0; j < 38; j++) label += charset[Math.floor(rand() * charset.length)];
      const qname = `${label}.tunnel-evil.example`;
      b.dnsQuery(t0 + i * 2.5, "192.168.1.60", "1.1.1.1", qname, 16, 1000 + i);
    }
    return b.toArrayBuffer();
  }

  if (id === "beacon") {
    const rand = mulberry32(45);
    addBaseline(b, rand, base);
    const t0 = base + 120;
    for (let i = 0; i < 13; i++) {
      const jitter = (rand() - 0.5) * 1.6;
      b.tcpPacket(t0 + i * 30 + jitter, "192.168.1.70", "198.51.100.23", 51000, 8443, 0x18, 9000 + i, undefined, i);
    }
    return b.toArrayBuffer();
  }

  if (id === "exfil") {
    const rand = mulberry32(46);
    addBaseline(b, rand, base);
    const t0 = base + 200;
    const payload = encoder.encode(
      "A".repeat(4800) // ~4.8 KB per frame — bulk transfer (~25 MB total)
    );
    for (let i = 0; i < 5600; i++) {
      b.tcpPacket(
        t0 + i * 0.08,
        "192.168.1.80",
        "203.0.113.99",
        52000,
        8080,
        0x18,
        20000 + i * 4800,
        payload,
        i & 0xffff
      );
    }
    return b.toArrayBuffer();
  }

  return buildNetworkSample("clean");
}
