import Link from "next/link";
import { ArrowRight, Radar, ShieldCheck } from "lucide-react";
import { Container } from "@/components/layout/Container";
import { modules } from "@/lib/data/modules";
import { getModuleIcon } from "@/lib/icons";

export default function HomePage() {
  return (
    <>
      {/* Hero */}
      <section className="border-b border-border">
        <Container className="flex min-h-[72vh] flex-col justify-center py-20">
          <p className="font-mono text-xs uppercase tracking-[0.3em] text-accent">
            {"// DFIR LAB — Interactive Digital Forensics Portfolio"}
          </p>
          <h1 className="mt-6 max-w-4xl text-5xl font-bold leading-[1.05] tracking-tight sm:text-6xl lg:text-7xl">
            Think like the
            <br />
            <span className="text-accent">attacker.</span> Prove it in the
            evidence.
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-relaxed text-muted-foreground">
            Four end-to-end investigation labs — plus a live, in-browser
            detection workbench that analyzes real auth.logs, event CSVs,
            process lists and PCAP captures. Methodology-first, tool-accurate,
            and built for analysts.
          </p>
          <div className="mt-10 flex flex-col gap-4 sm:flex-row sm:items-center">
            <Link
              href="/modules/timeline"
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-accent px-6 py-3 font-mono text-sm font-bold uppercase tracking-wider text-background transition-opacity hover:opacity-90"
            >
              Explore the modules
              <ArrowRight className="h-4 w-4" aria-hidden />
            </Link>
            <Link
              href="/workbench"
              className="inline-flex items-center justify-center gap-2 rounded-lg border border-accent/50 bg-accent-muted px-6 py-3 font-mono text-sm font-semibold uppercase tracking-wider text-accent transition-all hover:border-accent"
            >
              <Radar className="h-4 w-4" aria-hidden />
              Detection workbench
            </Link>
            <Link
              href="/about"
              className="inline-flex items-center justify-center gap-2 rounded-lg border border-border px-6 py-3 font-mono text-sm font-semibold uppercase tracking-wider text-muted-foreground transition-colors hover:border-accent hover:text-accent"
            >
              Methodology
            </Link>
          </div>
          <div className="mt-12 flex flex-wrap items-center gap-x-6 gap-y-2 font-mono text-xs text-muted-foreground">
            {modules.map((mod, index) => (
              <span key={mod.slug} className="flex items-center gap-2">
                <span className="text-accent">0{index + 1}</span>
                {mod.slug}
              </span>
            ))}
          </div>
        </Container>
      </section>

      {/* Module grid */}
      <section id="modules" className="scroll-mt-20 py-16 md:py-24">
        <Container>
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.3em] text-accent">
                {"// The labs"}
              </p>
              <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
                Four investigations.
                <br />
                One complete kill chain.
              </h2>
            </div>
            <p className="max-w-sm text-sm leading-relaxed text-muted-foreground">
              Each lab walks through the same professional flow: objective →
              context → numbered steps → deliverables → toolset.
            </p>
          </div>

          <div className="mt-12 grid grid-cols-1 gap-6 md:grid-cols-2">
            {modules.map((mod, index) => {
              const Icon = getModuleIcon(mod.icon);
              return (
                <Link
                  key={mod.slug}
                  href={`/modules/${mod.slug}`}
                  className="group flex flex-col rounded-2xl border border-border bg-muted/40 p-6 transition-all hover:-translate-y-1 hover:border-accent/60 focus-visible:border-accent sm:p-7"
                >
                  <div className="flex items-center justify-between">
                    <div
                      className="flex h-12 w-12 items-center justify-center rounded-xl border border-border bg-accent-muted transition-colors group-hover:border-accent/40"
                      aria-hidden
                    >
                      <Icon className="h-6 w-6 text-accent" />
                    </div>
                    <span className="font-mono text-xs text-muted-foreground">
                      MODULE 0{index + 1}
                    </span>
                  </div>
                  <h3 className="mt-5 text-xl font-semibold leading-snug tracking-tight">
                    {mod.title}
                  </h3>
                  <p className="mt-1 font-mono text-xs uppercase tracking-wider text-accent">
                    {mod.subtitle}
                  </p>
                  <p className="mt-3 line-clamp-4 text-sm leading-relaxed text-muted-foreground">
                    {mod.description}
                  </p>
                  <span className="mt-auto inline-flex items-center gap-2 pt-6 font-mono text-sm font-semibold text-accent">
                    Read module
                    <ArrowRight
                      className="h-4 w-4 transition-transform group-hover:translate-x-1"
                      aria-hidden
                    />
                  </span>
                </Link>
              );
            })}
          </div>
        </Container>
      </section>

      {/* Trust strip */}
      <section className="border-t border-border py-10">
        <Container className="flex flex-col items-center gap-4 text-center">
          <ShieldCheck className="h-6 w-6 text-accent" aria-hidden />
          <p className="max-w-2xl font-mono text-xs leading-relaxed text-muted-foreground">
            All datasets are fictional or lab-generated. No real systems were
            accessed. Techniques are documented for education and authorized
            testing only.
          </p>
        </Container>
      </section>
    </>
  );
}
