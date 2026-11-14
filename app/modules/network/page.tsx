import { modules } from "@/lib/data/modules";
import { Container } from "@/components/layout/Container";
import { ModuleHeader } from "@/components/modules/ModuleHeader";
import { StepList } from "@/components/modules/StepList";
import { ToolBadge } from "@/components/modules/ToolBadge";
import { DeliverableCard } from "@/components/modules/DeliverableCard";

export const metadata = {
  title: {
    absolute: "Network Traffic Analysis for Data Exfiltration — DFIR Lab",
  },
  description:
    "Analyze a PCAP to detect data exfiltration, command-and-control " +
    "channels, and port scanning using Wireshark, tshark, and Zeek. Full " +
    "network forensics workflow from conversation overview to IoC " +
    "blocking.",
};

export default function NetworkModulePage() {
  const networkModule = modules.find((m) => m.slug === "network");
  if (!networkModule) {
    throw new Error("Network module data missing");
  }

  return (
    <Container className="py-16 md:py-24">
      <ModuleHeader module={networkModule} />

      <section className="mt-16 space-y-6">
        <h2 className="text-2xl font-semibold tracking-tight">Methodology</h2>
        <StepList steps={networkModule.steps} />
      </section>

      <section className="mt-16">
        <DeliverableCard items={networkModule.deliverables} />
      </section>

      <section className="mt-16 space-y-4">
        <h2 className="text-2xl font-semibold tracking-tight">Toolset</h2>
        <div className="flex flex-wrap gap-2">
          {networkModule.tools.map((tool) => (
            <ToolBadge key={tool} name={tool} />
          ))}
        </div>
      </section>
    </Container>
  );
}
