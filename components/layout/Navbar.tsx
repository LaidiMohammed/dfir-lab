import Link from "next/link";
import { Terminal } from "lucide-react";

export function Navbar() {
  return (
    <header className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <Link
          href="/"
          className="flex items-center gap-2 font-mono text-base font-bold tracking-tight text-foreground transition-colors hover:text-accent"
          aria-label="DFIR Lab — home"
        >
          <Terminal className="h-5 w-5 text-accent" aria-hidden />
          DFIR<span className="text-accent">.LAB</span>
        </Link>
        <nav aria-label="Primary navigation">
          <ul className="flex items-center gap-6 font-mono text-sm">
            <li>
              <Link
                href="/#modules"
                className="text-muted-foreground transition-colors hover:text-accent"
              >
                Modules
              </Link>
            </li>
            <li>
              <Link
                href="/about"
                className="text-muted-foreground transition-colors hover:text-accent"
              >
                About
              </Link>
            </li>
          </ul>
        </nav>
      </div>
    </header>
  );
}
