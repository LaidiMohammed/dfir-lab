import { modules } from "@/lib/data/modules";
import { Container } from "@/components/layout/Container";
import { ModuleHeader } from "@/components/modules/ModuleHeader";
import { StepList } from "@/components/modules/StepList";
import { ToolBadge } from "@/components/modules/ToolBadge";
import { DeliverableCard } from "@/components/modules/DeliverableCard";
import { WorkbenchCta } from "@/components/modules/WorkbenchCta";

export const metadata = {
  title: {
    absolute: "Memory Forensics — Traceback",
  },
  description:
    "Analyze volatile memory from a compromised system to expose " +
    "injected code, fileless malware, and live C2 channels — acquisition, " +
    "image identification, process and network analysis, and IOC " +
    "extraction.",
};

export default function MemoryModulePage() {
  const memoryModule = modules.find((m) => m.slug === "memory");
  if (!memoryModule) {
    throw new Error("Memory module data missing");
  }

  return (
    <Container className="py-16 md:py-24">
      <ModuleHeader module={memoryModule} />

            <WorkbenchCta lab="memory" />
      <section className="mt-16 space-y-6">
        <h2 className="text-2xl font-semibold tracking-tight">Methodology</h2>
        <StepList steps={memoryModule.steps} />
      </section>

      <section className="mt-16">
        <DeliverableCard items={memoryModule.deliverables} />
      </section>

      <section className="mt-16 space-y-4">
        <h2 className="text-2xl font-semibold tracking-tight">Toolset</h2>
        <div className="flex flex-wrap gap-2">
          {memoryModule.tools.map((tool) => (
            <ToolBadge key={tool} name={tool} />
          ))}
        </div>
      </section>
    </Container>
  );
}
