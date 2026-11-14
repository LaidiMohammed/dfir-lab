# Traceback â€” Interactive Digital Forensics Portfolio & Detection Workbench

Two halves, one story:

1. **Portfolio** â€” four investigation labs, methodology-first documents:
   objective â†’ context â†’ numbered steps â†’ deliverables â†’ toolset.
2. **Detection Workbench** (`/workbench`) â€” the labs made runnable: real
   analyzers executing **entirely in the browser**. Paste or upload evidence,
   run the ruleset, export findings as JSON/CSV. No backend, no upload â€”
   forensic evidence never leaves the machine.

Built with Next.js 15 (App Router), TypeScript (strict), Tailwind CSS 4,
shadcn-style components, Lucide icons, and a zero-dependency hand-written
PCAP/PCAPNG parser.

## Labs

| Route | Module | Interactive analyzer |
|---|---|---|
| `/modules/timeline` | 1 â€” Timeline Reconstruction | Windows event CSV: 4625 brute force/spray, success-after-fail, 1102 log clear, 7045 service, encoded PowerShell (`TLX-001..007`) |
| `/modules/memory` | 2 â€” Memory Forensics | pslist CSV/TSV/whitespace: masquerading, maldocâ†’shell chains, offensive tooling, encoded cmdlines (`MEMX-001..005`) |
| `/modules/network` | 3 â€” Network Traffic Analysis for Data Exfiltration | PCAP/PCAPNG in-browser: cleartext creds, beaconing (CV<0.3), bulk exfil, DNS DGA entropy, suspicious ports, port scans, DNS tunneling (QNAME/TXT) (`NETX-001..008`) |
| `/modules/linux` | 4 â€” Linux Server Investigation | auth.log/secure/history: brute force, UID-0 backdoors, SUID, reverse shells, LD_PRELOAD, cron implants (`LDX-001..010`) |

Supporting pages: `/` (hero + 2Ã—2 grid), `/about` (methodology + disclaimer),
`/workbench` (the analyzers).

## Detection engine

Pure TypeScript, no dependencies, fully unit-smoke-testable:

```
lib/detection/
  types.ts     â€” Finding / Severity / AnalysisResult model
  linux.ts     â€” LDX rules      (auth.log / secure / syslog / history)
  timeline.ts  â€” TLX rules      (CSV event exports, header auto-detection)
  memory.ts    â€” MEMX rules     (pslist parsing + masquerade edit-distance)
  pcap.ts      â€” NETX rules     (classic pcap + basic pcapng reader; NETX-006..008: port scan, DNS tunnel)
```

Synthetic lab datasets live in `public/samples/` and are used by the
"Load sample dataset" buttons. Regenerate the capture with:

```bash
node scripts/generate-sample-pcap.mjs
```

Run the detection smoke test (Node â‰¥ 22.18, type stripping):

```bash
node scripts/smoke-test.mjs
```

## Develop

```bash
npm install
npm run dev     # local dev server
npm run lint    # eslint (flat config, next/core-web-vitals + next/typescript)
npx tsc --noEmit
npm run build   # production build â€” 7 static routes
```

## Content model

Static lab content lives in `lib/data/modules.ts` (typed by `lib/types.ts`).
Pages under `app/modules/*/page.tsx` are thin, data-driven Server Components.
Detections are pure functions in `lib/detection/` â€” UI in
`components/workbench/WorkbenchClient.tsx`.

## Ethics

All datasets are fictional or generated inside isolated lab environments.
Techniques and analyzers are published for education and authorized testing
only.
