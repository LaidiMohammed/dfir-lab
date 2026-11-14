# DFIR.LAB — Interactive Digital Forensics Portfolio

Four end-to-end investigation labs, one consistent methodology. Built with
Next.js 15 (App Router), TypeScript (strict), Tailwind CSS 4, shadcn-style
components, and Lucide icons.

## Labs

| Route | Module | Focus |
|---|---|---|
| `/modules/timeline` | 1 — Timeline Reconstruction | Super-timeline of a compromised Windows host |
| `/modules/memory` | 2 — Memory Forensics | RAM analysis of a compromised host |
| `/modules/network` | 3 — Network Traffic Analysis | PCAP forensics of a suspected intrusion |
| `/modules/linux` | 4 — Linux Server Investigation | Persistence, attack vector, attacker actions |

Plus `/` (hero + 2×2 module grid) and `/about` (methodology + disclaimer).

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
