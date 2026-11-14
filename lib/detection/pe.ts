/**
 * Minimal dependency-free PE parser + deterministic sample generator.
 * Used for static triage demos: sections, entropy, W^X violations.
 * Not a full validator — flags header lies loudly, never silently.
 */
import {
  type DetectionReport,
  type Finding,
  computeVerdict,
  mulberry32,
  shannonEntropy,
} from "@/lib/detection/types";
import { formatBytes } from "@/lib/detection/format";

const byteAt = (u: Uint8Array, i: number): number => u[i] ?? 0;

export interface PeSection {
  name: string;
  virtualSize: number;
  rawSize: number;
  virtualAddress: number;
  entropy: number;
  characteristics: number;
  rwx: boolean;
}

export interface ParsedPe {
  sections: PeSection[];
  entryPoint: number;
  entrySection: string | null;
  machine: number;
  isPe32: boolean;
  sizeOfImage: number;
}

export class PeError extends Error {}

const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const IMAGE_SCN_MEM_READ = 0x40000000;
const IMAGE_SCN_MEM_WRITE = 0x80000000;
const RWX_MASK = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

export function parsePe(buffer: ArrayBuffer): ParsedPe {
  const view = new DataView(buffer);
  if (buffer.byteLength < 0x40 || view.getUint16(0, true) !== 0x5a4d) {
    throw new PeError("Not a PE file — missing MZ signature.");
  }
  const eLfanew = view.getUint32(0x3c, true);
  if (eLfanew + 24 > buffer.byteLength) {
    throw new PeError("Corrupt PE — e_lfanew points outside the file.");
  }
  if (view.getUint32(eLfanew, true) !== 0x00004550) {
    throw new PeError("Corrupt PE — missing PE\\0\\0 signature.");
  }
  const coff = eLfanew + 4;
  const machine = view.getUint16(coff, true);
  const numberOfSections = view.getUint16(coff + 2, true);
  const sizeOfOptionalHeader = view.getUint16(coff + 16, true);
  if (numberOfSections === 0 || numberOfSections > 96) {
    throw new PeError(`Implausible section count (${numberOfSections}) — refusing to parse.`);
  }
  const optional = coff + 20;
  if (optional + sizeOfOptionalHeader > buffer.byteLength) {
    throw new PeError("Corrupt PE — optional header truncated.");
  }
  const magic = view.getUint16(optional, true);
  const isPe32 = magic === 0x10b;
  if (magic !== 0x10b && magic !== 0x20b) {
    throw new PeError(`Unknown optional-header magic 0x${magic.toString(16)} (expected 0x10b or 0x20b).`);
  }
  const entryPoint = view.getUint32(optional + 16, true);

  const sectionsOffset = optional + sizeOfOptionalHeader;
  const sections: PeSection[] = [];
  const file = new Uint8Array(buffer);

  for (let i = 0; i < numberOfSections; i++) {
    const s = sectionsOffset + i * 40;
    if (s + 40 > buffer.byteLength) break;
    let name = "";
    for (let j = 0; j < 8; j++) {
      const c = byteAt(file, s + j);
      if (c === 0) break;
      name += String.fromCharCode(c);
    }
    const virtualSize = view.getUint32(s + 8, true);
    const virtualAddress = view.getUint32(s + 12, true);
    const rawSize = view.getUint32(s + 16, true);
    const rawPointer = view.getUint32(s + 20, true);
    const characteristics = view.getUint32(s + 36, true);
    const rawEnd = Math.min(rawPointer + rawSize, buffer.byteLength);
    const raw = rawPointer < buffer.byteLength ? file.subarray(rawPointer, rawEnd) : new Uint8Array(0);
    const entropy = shannonEntropy(raw);
    const rwx = (characteristics & RWX_MASK) === RWX_MASK;
    sections.push({ name, virtualSize, rawSize, virtualAddress, entropy, characteristics, rwx });
  }

  return {
    sections,
    entryPoint,
    entrySection: sectionContaining(sections, entryPoint),
    machine,
    isPe32,
    sizeOfImage: view.getUint32(optional + 56, true),
  };
}

function sectionContaining(sections: PeSection[], rva: number): string | null {
  for (const s of sections) {
    if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize, 1)) {
      return s.name;
    }
  }
  return null;
}

export function analyzePe(parsed: ParsedPe): DetectionReport {
  const findings: Finding[] = [];

  for (const section of parsed.sections) {
    if (section.rwx) {
      findings.push({
        rule: "RWX_SECTION",
        severity: "high",
        title: `Section ${section.name} is RWX`,
        detail: `${section.name} carries MEM_EXECUTE|MEM_READ|MEM_WRITE simultaneously — a W^X violation. Legitimate code sections are R-X; writable+executable memory is the hallmark of shellcode staging or unpacking stubs.`,
      });
    }
    if (section.rawSize > 512 && section.entropy > 7.4) {
      findings.push({
        rule: "HIGH_ENTROPY",
        severity: "high",
        title: `${section.name} has entropy ${section.entropy.toFixed(2)} bits/byte`,
        detail: `Near-random byte distribution over ${formatBytes(section.rawSize)} — consistent with an encrypted/packed payload rather than compiled code.`,
      });
    } else if (section.rawSize > 512 && section.entropy > 7.0) {
      findings.push({
        rule: "HIGH_ENTROPY",
        severity: "medium",
        title: `${section.name} entropy ${section.entropy.toFixed(2)} bits/byte`,
        detail: `Elevated entropy (>7.0) suggests compression or packing — worth unpacking before static analysis.`,
      });
    }
    if (
      section.virtualSize > 8192 &&
      section.rawSize > 0 &&
      section.virtualSize >= section.rawSize * 8
    ) {
      findings.push({
        rule: "HOLLOWED_SIZE",
        severity: "medium",
        title: `${section.name}: VirtualSize ${formatBytes(section.virtualSize)} ≫ raw ${formatBytes(section.rawSize)}`,
        detail: `The section occupies far more memory than it contains on disk — the classic signature of process hollowing or self-expanding malware.`,
      });
    }
    if (/^(upx|aspack|themida|mpress|petite)/i.test(section.name)) {
      findings.push({
        rule: "PACKER_NAME",
        severity: "low",
        title: `Packer-style section name: ${section.name}`,
        detail: `Section name matches a known packer family. Packers are not proof of malice — but they justify a full unpack + re-triage.`,
      });
    }
  }

  const entry = parsed.entrySection;
  if (entry) {
    const entrySection = parsed.sections.find((s) => s.name === entry);
    if (entrySection?.rwx) {
      findings.push({
        rule: "ENTRY_IN_RWX",
        severity: "high",
        title: `Entry point inside RWX section ${entry}`,
        detail: `The program entry executes directly from writable+executable memory — shellcode or an unpacking stub, not a normal CRT entry.`,
      });
    }
  }

  const verdict = computeVerdict(findings);
  const high = findings.filter((f) => f.severity === "high").length;
  const summary =
    verdict === "clean"
      ? "No structural red flags: no RWX sections, sane entropy, plausible section sizes. Static triage only — continue with dynamic analysis if suspicion remains."
      : verdict === "suspicious"
        ? `${findings.length} anomaly(ies) warrant a second look. Not conclusive — combine with sandbox detonation and memory capture of any live process.`
        : `${high} high-severity structural finding(s). Strong indicators of a packed or injected implant — isolate any host running this binary and escalate.`;

  const iocs = parsed.sections
    .filter((s) => s.rwx || s.entropy > 7.0)
    .map((s) => `\\${s.name} (entropy ${s.entropy.toFixed(2)})`);

  return {
    verdict,
    summary,
    findings,
    iocs,
    stats: [
      { label: "Sections", value: String(parsed.sections.length) },
      { label: "Entry section", value: entry ?? "unknown" },
      { label: "Machine", value: parsed.machine === 0x14c ? "x86" : parsed.machine === 0x8664 ? "x64" : `0x${parsed.machine.toString(16)}` },
      { label: "Image size", value: formatBytes(parsed.sizeOfImage) },
    ],
  };
}

// ---------------------------------------------------------------------------
// Sample PE generator (deterministic)
// ---------------------------------------------------------------------------

export type PeSampleId = "benign" | "packed" | "hollowed";

export const peSamples = [
  { id: "benign" as PeSampleId, label: "benign.exe — clean binary", blurb: "R-X .text, plausible entropy, entry in .text. Expected: clean." },
  { id: "packed" as PeSampleId, label: "packed.exe — RWX + high entropy", blurb: "Observable packer behavior: RWX section, ~8 bits/byte entropy. Expected: malicious." },
  { id: "hollowed" as PeSampleId, label: "hollowed.exe — hollowing hint", blurb: "VirtualSize ≫ raw size + packed entropy. Expected: suspicious/malicious." },
];

interface SampleSectionSpec {
  name: string;
  bytes: Uint8Array;
  characteristics: number;
  virtualSize?: number;
}

const FILE_ALIGNMENT = 0x200;
const SECTION_ALIGNMENT = 0x1000;

const align = (value: number, alignment: number) =>
  Math.ceil(value / alignment) * alignment;

function fillBytes(kind: "low" | "mid" | "high", length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);
  const rand = mulberry32(seed);
  if (kind === "low") {
    for (let i = 0; i < length; i++) out[i] = i % 64 === 0 ? 0x4d : 0x00;
    return out;
  }
  if (kind === "mid") {
    // ~6.6 bits/byte: printable ASCII with flat distribution
    for (let i = 0; i < length; i++) out[i] = 32 + Math.floor(rand() * 95);
    return out;
  }
  // ~8 bits/byte: full byte range
  for (let i = 0; i < length; i++) out[i] = Math.floor(rand() * 256);
  return out;
}

function writeStr(view: DataView, offset: number, text: string, length: number) {
  for (let i = 0; i < length; i++) {
    view.setUint8(offset + i, i < text.length ? text.charCodeAt(i) : 0);
  }
}

export function buildSamplePe(id: PeSampleId): ArrayBuffer {
  const seed = 1337;
  const sections: SampleSectionSpec[] =
    id === "benign"
      ? [
          { name: ".text", bytes: fillBytes("mid", 0x4000, seed), characteristics: 0x60000020 }, // CNT_CODE | X | R
          { name: ".rdata", bytes: fillBytes("mid", 0x1000, seed + 1), characteristics: 0x40000040 }, // INIT_DATA | R
          { name: ".data", bytes: fillBytes("low", 0x800, seed + 2), characteristics: 0xc0000040 }, // INIT_DATA | R | W
        ]
      : id === "packed"
        ? [
            { name: "UPX0", bytes: new Uint8Array(0x800).fill(0), characteristics: 0xe0000040, virtualSize: 0x00080000 }, // RWX region, near-empty on disk
            { name: ".text", bytes: fillBytes("high", 0x3000, seed + 3), characteristics: 0xe0000020 }, // RWX | CODE
            { name: ".rsrc", bytes: fillBytes("mid", 0x400, seed + 4), characteristics: 0x40000040 },
          ]
        : [
            { name: ".text", bytes: fillBytes("high", 0x600, seed + 5), characteristics: 0x60000020, virtualSize: 0x00060000 }, // RX, inflated VirtualSize
            { name: ".data", bytes: fillBytes("mid", 0xc00, seed + 6), characteristics: 0xc0000040 },
          ];

  const numberOfSections = sections.length;
  const sizeOfOptionalHeader = 0xe0;
  const headersSize = 0x80 + 4 + 20 + sizeOfOptionalHeader + numberOfSections * 40;
  const alignedHeaders = align(headersSize, FILE_ALIGNMENT);

  // Assign raw offsets
  let rawOffset = alignedHeaders;
  let virtualAddress = SECTION_ALIGNMENT;
  const layouts = sections.map((s) => {
    const rawSize = align(Math.max(s.bytes.length, 0x200), FILE_ALIGNMENT);
    const layout = { rawOffset, rawSize, virtualAddress, spec: s };
    rawOffset += rawSize;
    virtualAddress += align(Math.max(s.virtualSize ?? s.bytes.length, SECTION_ALIGNMENT), SECTION_ALIGNMENT);
    return layout;
  });

  const buffer = new ArrayBuffer(rawOffset);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  // DOS header
  bytes[0] = 0x4d;
  bytes[1] = 0x5a;
  view.setUint32(0x3c, 0x80, true); // e_lfanew

  // PE signature
  view.setUint32(0x80, 0x00004550, true);

  // COFF header
  const coff = 0x84;
  view.setUint16(coff, 0x14c, true); // x86
  view.setUint16(coff + 2, numberOfSections, true);
  view.setUint32(coff + 4, Math.floor(Date.UTC(2026, 10, 1) / 1000), true);
  view.setUint16(coff + 16, sizeOfOptionalHeader, true);
  view.setUint16(coff + 18, 0x0102, true); // EXECUTABLE_IMAGE | 32BIT_MACHINE

  // Optional header (PE32)
  const first = layouts[0];
  const second = layouts[1];
  if (!first) {
    throw new PeError("Internal error — sample generator produced no sections.");
  }
  const optional = coff + 20;
  view.setUint16(optional, 0x10b, true); // PE32
  view.setUint8(optional + 2, 14); // linker major
  view.setUint32(optional + 4, 0x2000, true); // SizeOfCode
  view.setUint32(optional + 8, 0x1000, true); // SizeOfInitializedData
  view.setUint32(optional + 16, first.virtualAddress + 16, true); // AddressOfEntryPoint
  view.setUint32(optional + 20, first.virtualAddress, true); // BaseOfCode
  view.setUint32(optional + 24, second?.virtualAddress ?? first.virtualAddress, true); // BaseOfData
  view.setUint32(optional + 28, 0x400000, true); // ImageBase
  view.setUint32(optional + 32, SECTION_ALIGNMENT, true);
  view.setUint32(optional + 36, FILE_ALIGNMENT, true);
  view.setUint16(optional + 40, 6, true); // OS major
  view.setUint16(optional + 48, 6, true); // Subsystem major
  view.setUint16(optional + 68, 3, true); // Subsystem: CUI
  view.setUint32(optional + 56, virtualAddress, true); // SizeOfImage
  view.setUint32(optional + 60, alignedHeaders, true); // SizeOfHeaders

  // Section headers
  let cursor = optional + sizeOfOptionalHeader;
  for (const layout of layouts) {
    const s = layout.spec;
    writeStr(view, cursor, s.name, 8);
    view.setUint32(cursor + 8, (s.virtualSize ?? s.bytes.length) >>> 0, true); // VirtualSize
    view.setUint32(cursor + 12, layout.virtualAddress, true); // VirtualAddress
    view.setUint32(cursor + 16, layout.rawSize, true); // SizeOfRawData
    view.setUint32(cursor + 20, layout.rawOffset, true); // PointerToRawData
    view.setUint32(cursor + 36, s.characteristics >>> 0, true);
    cursor += 40;
  }

  // Section raw data
  for (const layout of layouts) {
    bytes.set(layout.spec.bytes, layout.rawOffset);
  }

  return buffer;
}
