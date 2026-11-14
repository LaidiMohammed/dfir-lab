import { modules } from "@/lib/data/modules";
import { Container } from "@/components/layout/Container";
import { ModuleHeader } from "@/components/modules/ModuleHeader";
import { StepList } from "@/components/modules/StepList";
import { ToolBadge } from "@/components/modules/ToolBadge";
import { DeliverableCard } from "@/components/modules/DeliverableCard";

export const metadata = {
  title: {
    absolute: "Timeline Reconstruction — DFIR Lab",
  },
  description:
    "Reconstruct a complete, timestamp-accurate picture of attacker " +
    "activity on a compromised Windows host — acquisition, artifact " +
    "parsing, super-timeline generation, and correlation.",
};

export default function TimelineModulePage() {
  const timelineModule = modules.find((m) => m.slug === "timeline");
  if (!timelineModule) {
    throw new Error("Timeline module data missing");
  }

  return (
    <Container className="py-16 md:py-24">
      <ModuleHeader module={timelineModule} />

      <section className="mt-16 space-y-6">
        <h2 className="text-2xl font-semibold tracking-tight">Methodology</h2>
        <StepList steps={timelineModule.steps} />
      </section>

      <section className="mt-16">
        <DeliverableCard items={timelineModule.deliverables} />
      </section>

      <section className="mt-16 space-y-4">
        <h2 className="text-2xl font-semibold tracking-tight">Toolset</h2>
        <div className="flex flex-wrap gap-2">
          {timelineModule.tools.map((tool) => (
            <ToolBadge key={tool} name={tool} />
          ))}
        </div>
      </section>
    </Container>
  );
}
