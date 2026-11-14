import type { Metadata } from "next";
import Link from "next/link";
import {
  ArrowRight,
  BookOpenCheck,
  FlaskConical,
  Hash,
  ListOrdered,
  Scale,
  ShieldCheck,
  Timer,
} from "lucide-react";
import { Container } from "@/components/layout/Container";
import { modules } from "@/lib/data/modules";
import { getModuleIcon } from "@/lib/icons";

export const metadata: Metadata = {
  title: "About",
  description:
    "How the DFIR Lab portfolio is built: an evidence-first methodology " +
    "applied across four investigation labs, plus the ethics and legal " +
    "disclaimer that governs every dataset.",
};

const principles = [
  {
    icon: ShieldCheck,
    title: "Evidence first",
    body: "Nothing is altered before it is hashed and copied. Analysis always runs on forensic copies — volatile data is captured before disk, disk is imaged read-only, and every artefact gets a SHA256.",
  },
  {
    icon: Timer,
    title: "Volatile before persistent",
    body: "Order of volatility drives every lab: running processes, network connections, and memory first — disk, logs, and offline artefacts second. What disappears on reboot is collected first.",
  },
  {
    icon: Hash,
    title: "Hash everything",
    body: "Acquisition, extraction, and reporting all carry SHA256 fingerprints. Hashes anchor integrity, prove handling, and let findings be independently verified.",
  },
  {
    icon: ListOrdered,
    title: "Methodology over improvisation",
    body: "Each case follows the same discipline: objective → context → numbered steps → deliverables → toolset. Repeatable, teachable, and auditable end to end.",
  },
  {
    icon: FlaskConical,
    title: "Detection must be runnable",
    body: "Every module ships an interactive Detection Lab — drop a real artifact (PCAP, PE binary, timeline CSV, auth.log) or load a synthetic attack scenario, and the heuristics run entirely in your browser. No uploads, no accounts: analysis never leaves your machine.",
  },
];

export default function AboutPage() {
  return (
    <Container className="py-16 md:py-24">
      {/* Header */}
      <p className="font-mono text-xs uppercase tracking-[0.3em] text-accent">
        {"// About DFIR Lab"}
      </p>
      <h1 className="mt-4 max-w-3xl text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl">
        An evidence-first methodology,
        <br />
        <span className="text-accent">applied four times.</span>
      </h1>
      <p className="mt-6 max-w-2xl text-lg leading-relaxed text-muted-foreground">
        DFIR Lab is an interactive portfolio of four digital forensics
        investigation labs. Each lab is structured like a professional case:
        scope it, collect the right evidence in the right order, analyze it,
        and ship a report an incident responder can actually use.
      </p>

      {/* The four labs */}
      <section className="mt-16">
        <h2 className="text-2xl font-semibold tracking-tight">The four labs</h2>
        <div className="mt-6 grid gap-4 sm:grid-cols-2">
          {modules.map((mod, index) => {
            const Icon = getModuleIcon(mod.icon);
            return (
              <Link
                key={mod.slug}
                href={`/modules/${mod.slug}`}
                className="group flex items-start gap-4 rounded-xl border border-border bg-muted/40 p-5 transition-colors hover:border-accent/60"
              >
                <Icon
                  className="mt-1 h-6 w-6 shrink-0 text-accent"
                  aria-hidden
                />
                <span>
                  <span className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
                    Module 0{index + 1}
                  </span>
                  <span className="mt-1 block font-semibold leading-snug">
                    {mod.title}
                  </span>
                  <span className="mt-2 inline-flex items-center gap-1 font-mono text-xs text-accent">
                    Open lab
                    <ArrowRight
                      className="h-3 w-3 transition-transform group-hover:translate-x-0.5"
                      aria-hidden
                    />
                  </span>
                </span>
              </Link>
            );
          })}
        </div>
      </section>

      {/* Methodology principles */}
      <section className="mt-16">
        <h2 className="text-2xl font-semibold tracking-tight">
          <BookOpenCheck
            className="mr-2 inline h-6 w-6 align-text-bottom text-accent"
            aria-hidden
          />
          Methodology
        </h2>
        <div className="mt-6 grid gap-4 sm:grid-cols-2">
          {principles.map((principle) => (
            <div
              key={principle.title}
              className="rounded-xl border border-border bg-muted/40 p-6"
            >
              <principle.icon
                className="h-6 w-6 text-accent"
                aria-hidden
              />
              <h3 className="mt-3 font-semibold">{principle.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                {principle.body}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Disclaimer */}
      <section className="mt-16 rounded-2xl border border-accent/30 bg-accent-muted p-6 sm:p-8">
        <h2 className="flex items-center gap-3 text-2xl font-semibold tracking-tight">
          <Scale className="h-6 w-6 text-accent" aria-hidden />
          Disclaimer &amp; ethics
        </h2>
        <ul className="mt-4 space-y-3 text-sm leading-relaxed text-foreground/90 sm:text-[15px]">
          <li className="flex items-start gap-3">
            <FlaskConical
              className="mt-0.5 h-5 w-5 shrink-0 text-accent"
              aria-hidden
            />
            Every dataset in these labs is fictional or generated inside
            isolated lab environments (e.g., OWASP Juice Shop, deliberately
            compromised VMs, synthetic PCAPs and memory images). No production
            system, third-party asset, or real user data is involved.
          </li>
          <li className="flex items-start gap-3">
            <ShieldCheck
              className="mt-0.5 h-5 w-5 shrink-0 text-accent"
              aria-hidden
            />
            Techniques described here are published for education and
            authorized testing only. Applying them against systems you do not
            own or lack written permission to assess is illegal in most
            jurisdictions.
          </li>
          <li className="flex items-start gap-3">
            <Scale
              className="mt-0.5 h-5 w-5 shrink-0 text-accent"
              aria-hidden
            />
            DFIR Lab is a learning portfolio, not a certification, legal
            advice, or an incident-response retainer. When in doubt, engage a
            licensed professional and law enforcement.
          </li>
        </ul>
      </section>
    </Container>
  );
}
