/**
 * Minimal, dependency-free classic-PCAP parser (Ethernet/IPv4/TCP/UDP/DNS).
 * Runs entirely in the browser. PCAP-NG is rejected with a clear error.
 */

export interface DnsQuery {
  ts: number;
  srcIp: string;
  qname: string;
  qtype: number; // 1=A, 16=TXT, 28=AAAA, 255=ANY ...
  isAnswer: boolean;
  answersBytes: number;
}

export interface ParsedPacket {
  ts: number; // seconds (float)
  srcIp: string;
  dstIp: string;
  proto: "tcp" | "udp" | "icmp" | "other";
  srcPort: number | null;
  dstPort: number | null;
  bytes: number; // on-wire frame length
  tcpFlags: number | null; // null unless TCP
}

export interface Flow {
  key: string;
  srcIp: string;
  dstIp: string;
  proto: "tcp" | "udp" | "icmp" | "other";
  srcPort: number | null;
  dstPort: number | null;
  packets: number;
  bytes: number;
  synOnly: number;
  firstTs: number;
  lastTs: number;
  timestamps: number[];
}

export interface ParsedPcap {
  packets: ParsedPacket[];
  flows: Flow[];
  dns: DnsQuery[];
  totalPackets: number;
  totalBytes: number;
  firstTs: number;
  lastTs: number;
  durationSeconds: number;
  linkType: number;
}

export class PcapError extends Error {}

// On-disk magic bytes, read as big-endian:
//   A1 B2 C3 D4 → big-endian capture     (=> littleEndian = false)
//   D4 C3 B2 A1 → little-endian capture  (=> littleEndian = true)
const MAGIC_DISK_A1 = 0xa1b2c3d4;
const MAGIC_DISK_D4 = 0xd4c3b2a1;
const MAGIC_DISK_A1_NANO = 0xa1b23c4d;
const MAGIC_DISK_4D_NANO = 0x4d3cb2a1;
const MAGIC_NG = 0x0a0d0d0a;


const byteAt = (u: Uint8Array, i: number): number => u[i] ?? 0;
export function parsePcap(buffer: ArrayBuffer): ParsedPcap {
  const view = new DataView(buffer);
  if (buffer.byteLength < 24) {
    throw new PcapError("File too small â€” not a classic PCAP capture.");
  }

  const magic = view.getUint32(0, false);
  if (magic === MAGIC_NG || magic === 0x0a0d0d0a) {
    throw new PcapError(
      "PCAP-NG is not supported. Convert with: editcap -F pcap in.pcapng out.pcap"
    );
  }

  let littleEndian: boolean;
  let nanoseconds: boolean;
  if (magic === MAGIC_DISK_A1) {
    littleEndian = false;
    nanoseconds = false;
  } else if (magic === MAGIC_DISK_D4) {
    littleEndian = true;
    nanoseconds = false;
  } else if (magic === MAGIC_DISK_A1_NANO) {
    littleEndian = false;
    nanoseconds = true;
  } else if (magic === MAGIC_DISK_4D_NANO) {
    littleEndian = true;
    nanoseconds = true;
  } else {
    throw new PcapError(
      `Unrecognized capture magic 0x${magic.toString(16)} â€” expected classic PCAP ` +
        "(0xa1b2c3d4). Export with editcap -F pcap."
    );
  }

  const linkType = view.getUint32(20, littleEndian);
  if (linkType !== 1 && linkType !== 101 && linkType !== 0 && linkType !== 12) {
    throw new PcapError(
      `Unsupported link type ${linkType}. Expected Ethernet (1), raw IP (101), or NULL (0/12).`
    );
  }

  const packets: ParsedPacket[] = [];
  const dns: DnsQuery[] = [];
  let offset = 24;
  let firstTs = Infinity;
  let lastTs = -Infinity;
  let totalBytes = 0;

  while (offset + 16 <= buffer.byteLength) {
    const tsSec = view.getUint32(offset, littleEndian);
    const tsFrac = view.getUint32(offset + 4, littleEndian);
    const inclLen = view.getUint32(offset + 8, littleEndian);
    const origLen = view.getUint32(offset + 12, littleEndian);
    offset += 16;
    if (offset + inclLen > buffer.byteLength) break;

    const ts = tsSec + (nanoseconds ? tsFrac / 1e9 : tsFrac / 1e6);
    firstTs = Math.min(firstTs, ts);
    lastTs = Math.max(lastTs, ts);
    totalBytes += origLen;

    const frame = new Uint8Array(buffer, offset, inclLen);
    offset += inclLen;

    let ipOffset = 0;
    if (linkType === 1) {
      if (frame.length < 14) continue;
      ipOffset = 14;
      // 802.1Q VLAN tag: TPID 0x8100
      if (
        frame.length > 18 &&
        byteAt(frame, 12) === 0x81 &&
        byteAt(frame, 13) === 0x00
      ) {
        ipOffset = 18;
      }
      const etherType = (byteAt(frame, ipOffset - 2) << 8) | byteAt(frame, ipOffset - 1);
      if (etherType !== 0x0800) continue; // IPv4 only
    } else if (linkType === 0 || linkType === 12) {
      ipOffset = 4; // BSD loopback header
    } // linkType 101: raw IP at 0

    const parsed = parseIpv4(frame, ipOffset, ts, inclLen);
    if (parsed) {
      packets.push(parsed.packet);
      if (parsed.dns) dns.push(...parsed.dns);
    }
  }

  if (packets.length === 0) {
    throw new PcapError(
      "No IPv4 packets found. Supported: Ethernet/raw captures of TCP/UDP/ICMP traffic."
    );
  }

  return {
    packets,
    flows: buildFlows(packets),
    dns,
    totalPackets: packets.length,
    totalBytes,
    firstTs,
    lastTs,
    durationSeconds: lastTs - firstTs,
    linkType,
  };
}

function ipv4String(frame: Uint8Array, offset: number): string {
  return `${byteAt(frame, offset)}.${byteAt(frame, offset + 1)}.${byteAt(frame, offset + 2)}.${byteAt(frame, offset + 3)}`;
}

function parseIpv4(
  frame: Uint8Array,
  ipOffset: number,
  ts: number,
  frameLen: number
): { packet: ParsedPacket; dns?: DnsQuery[] } | null {
  if (frame.length < ipOffset + 20) return null;
  const version = byteAt(frame, ipOffset) >> 4;
  if (version !== 4) return null;
  const ihl = (byteAt(frame, ipOffset) & 0x0f) * 4;
  if (frame.length < ipOffset + ihl) return null;
  const totalLength = (byteAt(frame, ipOffset + 2) << 8) | byteAt(frame, ipOffset + 3);
  const srcIp = ipv4String(frame, ipOffset + 12);
  const dstIp = ipv4String(frame, ipOffset + 16);
  const protocol = byteAt(frame, ipOffset + 9);
  const transportOffset = ipOffset + ihl;
  const payloadLength = Math.max(0, totalLength - ihl);

  const base = {
    ts,
    srcIp,
    dstIp,
    bytes: frameLen,
  };

  if (protocol === 6) {
    if (frame.length < transportOffset + 20) return null;
    const srcPort = (byteAt(frame, transportOffset) << 8) | byteAt(frame, transportOffset + 1);
    const dstPort = (byteAt(frame, transportOffset + 2) << 8) | byteAt(frame, transportOffset + 3);
    const dataOffset = ((byteAt(frame, transportOffset + 12) >> 4) & 0x0f) * 4;
    const tcpFlags = byteAt(frame, transportOffset + 13);
    const payloadStart = transportOffset + dataOffset;
    const payloadLen = Math.max(
      0,
      transportOffset + payloadLength - payloadStart
    );
    const dnsQueries =
      (srcPort === 53 || dstPort === 53) && payloadLen > 0
        ? parseDns(frame, payloadStart, payloadLen, ts, srcIp)
        : undefined;
    return {
      packet: {
        ...base,
        proto: "tcp",
        srcPort,
        dstPort,
        tcpFlags,
      },
      dns: dnsQueries,
    };
  }

  if (protocol === 17) {
    if (frame.length < transportOffset + 8) return null;
    const srcPort = (byteAt(frame, transportOffset) << 8) | byteAt(frame, transportOffset + 1);
    const dstPort = (byteAt(frame, transportOffset + 2) << 8) | byteAt(frame, transportOffset + 3);
    const payloadStart = transportOffset + 8;
    const udpLen = (byteAt(frame, transportOffset + 4) << 8) | byteAt(frame, transportOffset + 5);
    const payloadLen = Math.max(0, udpLen - 8);
    const dnsQueries =
      (srcPort === 53 || dstPort === 53) && payloadLen > 0
        ? parseDns(frame, payloadStart, payloadLen, ts, srcIp)
        : undefined;
    return {
      packet: {
        ...base,
        proto: "udp",
        srcPort,
        dstPort,
        tcpFlags: null,
      },
      dns: dnsQueries,
    };
  }

  if (protocol === 1) {
    return {
      packet: { ...base, proto: "icmp", srcPort: null, dstPort: null, tcpFlags: null },
    };
  }

  return {
    packet: { ...base, proto: "other", srcPort: null, dstPort: null, tcpFlags: null },
  };
}

function readName(
  frame: Uint8Array,
  start: number,
  limit: number
): { name: string; next: number } | null {
  const labels: string[] = [];
  let pos = start;
  let jumped = false;
  let next = start;
  let guard = 0;
  while (guard++ < 64) {
    if (pos >= limit) return null;
    const len = byteAt(frame, pos);
    if (len === 0) {
      if (!jumped) next = pos + 1;
      return { name: labels.join("."), next };
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= limit) return null;
      const pointer = ((len & 0x3f) << 8) | byteAt(frame, pos + 1);
      if (!jumped) next = pos + 2;
      pos = pointer;
      jumped = true;
      continue;
    }
    if (pos + 1 + len > limit) return null;
    let label = "";
    for (let i = 0; i < len; i++) label += String.fromCharCode(byteAt(frame, pos + 1 + i));
    labels.push(label);
    pos += 1 + len;
  }
  return null;
}

function parseDns(
  frame: Uint8Array,
  start: number,
  length: number,
  ts: number,
  srcIp: string
): DnsQuery[] {
  const end = start + length;
  if (length < 12) return [];
  const view = new DataView(frame.buffer, frame.byteOffset + start, length);
  const flags = view.getUint16(2);
  const isAnswer = (flags & 0x8000) !== 0;
  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);

  const queries: DnsQuery[] = [];
  let pos = start + 12;

  for (let q = 0; q < qdcount; q++) {
    const nameRes = readName(frame, pos, end);
    if (!nameRes) return queries;
    pos = nameRes.next;
    if (pos + 4 > end) return queries;
    const qtype = (byteAt(frame, pos) << 8) | byteAt(frame, pos + 1);
    queries.push({
      ts,
      srcIp,
      qname: nameRes.name,
      qtype,
      isAnswer,
      answersBytes: 0,
    });
    pos += 4;
  }

  if (isAnswer) {
    let answersBytes = 0;
    for (let a = 0; a < ancount; a++) {
      const nameRes = readName(frame, pos, end);
      if (!nameRes) break;
      pos = nameRes.next;
      if (pos + 10 > end) break;
      const rdlength = (byteAt(frame, pos + 8) << 8) | byteAt(frame, pos + 9);
      answersBytes += rdlength;
      pos += 10 + rdlength;
    }
    for (const q of queries) q.answersBytes = answersBytes;
  }

  return queries;
}

function buildFlows(packets: ParsedPacket[]): Flow[] {
  const map = new Map<string, Flow>();
  for (const p of packets) {
    const key = `${p.srcIp}|${p.dstIp}|${p.proto}|${p.srcPort}|${p.dstPort}`;
    let flow = map.get(key);
    if (!flow) {
      flow = {
        key,
        srcIp: p.srcIp,
        dstIp: p.dstIp,
        proto: p.proto,
        srcPort: p.srcPort,
        dstPort: p.dstPort,
        packets: 0,
        bytes: 0,
        synOnly: 0,
        firstTs: p.ts,
        lastTs: p.ts,
        timestamps: [],
      };
      map.set(key, flow);
    }
    flow.packets += 1;
    flow.bytes += p.bytes;
    if (p.tcpFlags !== null && (p.tcpFlags & 0x02) !== 0 && (p.tcpFlags & 0x10) === 0) {
      flow.synOnly += 1;
    }
    if (p.ts < flow.firstTs) flow.firstTs = p.ts;
    if (p.ts > flow.lastTs) flow.lastTs = p.ts;
    flow.timestamps.push(p.ts);
  }
  return [...map.values()];
}
