import {
  Clock,
  Cpu,
  Network,
  Terminal,
  type LucideIcon,
} from "lucide-react";

/**
 * Maps the `icon` field stored in lib/data/modules.ts to a Lucide component.
 * Keep this in sync with the `icon` values used by the modules data.
 */
export const moduleIcons: Record<string, LucideIcon> = {
  Clock,
  Cpu,
  Network,
  Terminal,
};

export function getModuleIcon(name: string): LucideIcon {
  return moduleIcons[name] ?? Terminal;
}
