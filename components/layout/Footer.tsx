import Link from "next/link";
import { Terminal } from "lucide-react";
import { modules } from "@/lib/data/modules";

export function Footer() {
  return (
    <footer className="border-t border-border">
      <div className="mx-auto w-full max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
        <div className="flex flex-col gap-8 md:flex-row md:items-start md:justify-between">
          <div className="space-y-2">
            <Link
              href="/"
              className="flex items-center gap-2 font-mono text-sm font-bold tracking-tight text-foreground transition-colors hover:text-accent"
            >
              <Terminal className="h-4 w-4 text-accent" aria-hidden />
              Trace<span className="text-accent">back</span>
            </Link>
            <p className="max-w-sm text-xs leading-relaxed text-muted-foreground">
              Interactive digital forensics portfolio — four end-to-end
              investigation labs: timeline reconstruction, memory forensics,
              network traffic analysis, and Linux server investigation.
            </p>
          </div>
          <nav aria-label="Modules">
            <ul className="grid grid-cols-2 gap-x-8 gap-y-2 font-mono text-xs text-muted-foreground sm:grid-cols-1">
              {modules.map((mod) => (
                <li key={mod.slug}>
                  <Link
                    href={`/modules/${mod.slug}`}
                    className="transition-colors hover:text-accent"
                  >
                    /modules/{mod.slug}
                  </Link>
                </li>
              ))}
              <li>
                <Link
                  href="/workbench"
                  className="transition-colors hover:text-accent"
                >
                  /workbench
                </Link>
              </li>
              <li>
                <Link
                  href="/about"
                  className="transition-colors hover:text-accent"
                >
                  /about
                </Link>
              </li>
            </ul>
          </nav>
        </div>
        <div className="mt-8 flex flex-col gap-2 border-t border-border pt-6 font-mono text-[11px] text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
          <p>© {new Date().getFullYear()} Traceback — All labs use fictional, lab-based datasets.</p>
          <p>For education &amp; authorized testing only.</p>
        </div>
      </div>
    </footer>
  );
}
