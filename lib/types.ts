export interface Step {
  /** 1-based position of the step inside the methodology. */
  order: number;
  title: string;
  body: string;
  tools: string[];
}

export interface Module {
  slug: string;
  title: string;
  subtitle: string;
  description: string;
  objective: string;
  context: string;
  steps: Step[];
  deliverables: string[];
  tools: string[];
  /** Lucide icon name, mapped in lib/icons.ts */
  icon: string;
}
