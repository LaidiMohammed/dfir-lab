import { modules } from "@/lib/data/modules";
import { Container } from "@/components/layout/Container";
import { ModuleHeader } from "@/components/modules/ModuleHeader";
import { StepList } from "@/components/modules/StepList";
import { ToolBadge } from "@/components/modules/ToolBadge";
import { DeliverableCard } from "@/components/modules/DeliverableCard";

export const metadata = {
  title: {
    absolute:
      "Forensic Investigation of a Compromised Linux Server — DFIR Lab",
  },
  description:
    "Trace the attack vector, persistence mechanisms, and attacker " +
    "actions on a compromised Linux server. Covers volatile collection, " +
    "log analysis, persistence hunting, SUID detection, and evidence " +
    "hashing.",
};

export default function LinuxForensicsPage() {
  const linuxModule = modules.find((m) => m.slug === "linux");
  if (!linuxModule) {
    throw new Error("Linux module data missing");
  }

  return (
    <Container className="py-16 md:py-24">
      <ModuleHeader module={linuxModule} />

      <section className="mt-16 space-y-6">
        <h2 className="text-2xl font-semibold tracking-tight">Methodology</h2>
        <StepList steps={linuxModule.steps} />
      </section>

      <section className="mt-16">
        <DeliverableCard items={linuxModule.deliverables} />
      </section>

      <section className="mt-16 space-y-4">
        <h2 className="text-2xl font-semibold tracking-tight">Toolset</h2>
        <div className="flex flex-wrap gap-2">
          {linuxModule.tools.map((tool) => (
            <ToolBadge key={tool} name={tool} />
          ))}
        </div>
      </section>
    </Container>
  );
}
