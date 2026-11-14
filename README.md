# DFIR.LAB — Interactive Digital Forensics Portfolio

Four end-to-end investigation labs, one consistent methodology. Built with
Next.js 15 (App Router), TypeScript (strict), Tailwind CSS 4, shadcn-style
components, and Lucide icons.

## Labs

| Route | Module | Focus |
|---|---|---|
| `/modules/timeline` | 1 — Timeline Reconstruction | Super-timeline of a compromised Windows host |
| `/modules/memory` | 2 — Memory Forensics | RAM analysis of a compromised host |
| `/modules/network` | 3 - Network Traffic Analysis for Data Exfiltration | C2, port scanning, exfiltration via PCAP |
| `/modules/linux` | 4 — Linux Server Investigation | Persistence, attack vector, attacker actions |

Plus `/` (hero + 2×2 module grid) and `/about` (methodology + disclaimer).

## Detection Labs

Every module page ships an interactive **Detection Lab** — run entirely in
your browser (no backend, nothing is uploaded):

| Module | Artifact | What it detects |
|---|---|---|
| `/modules/timeline` | super-timeline CSV (paste or sample) | encoded PowerShell, brute force → success, new service/task, user-writable executables, log clearing |
| `/modules/memory` | PE binary (.exe/.dll, drop or sample) | RWX sections, section entropy packing, VirtualSize≫raw hollowing, packer names |
| `/modules/network` | `.pcap` capture (drop or sample) | port scans, DNS tunneling (QNAME/TXT), C2 beaconing, exfil volume, cleartext protocols |
| `/modules/linux` | auth.log / syslog slice (paste or sample) | SSH brute force → success, UID 0 creation, `curl \| bash`, encoded cron payloads, authorized_keys tampering |

Detectors live in `lib/detection/` (dependency-free, fully client-side);
UI in `components/detection/`. Synthetic attack scenarios are generated
deterministically at runtime — the same parser analyzes user-dropped artifacts.

## Develop

```bash
npm install
npm run dev     # local dev server
npm run lint    # eslint
npx tsc --noEmit
npm run build   # production build — 6 static routes
```

## Content model

All lab content lives in `lib/data/modules.ts` (typed by `lib/types.ts`).
Pages under `app/modules/*/page.tsx` are thin, data-driven Server Components.
Adding or editing a lab means editing data — not markup.

## Ethics

All datasets are fictional or generated in isolated lab environments.
Techniques are documented for education and authorized testing only.
