import type { ActionEffect } from "../lib/action-effects";
import { SidebarCheck, SidebarSection } from "../workbench";

export function ActionEffectsFilter({ value, counts, onChange }: {
  value: ActionEffect[];
  counts: { read: number; write: number };
  onChange: (value: ActionEffect[]) => void;
}) {
  return (
    <SidebarSection
      title="Action effects"
      activeCount={value.length === 1 ? 1 : 0}
      action={value.length ? { label: "Clear action effects filter", text: "Clear", onClick: () => onChange([]) } : undefined}
    >
      {(["read", "write"] as const).map((effect) => (
        <SidebarCheck
          key={effect}
          label={effect === "read" ? "Read-only" : "Write-capable"}
          checked={value.includes(effect)}
          count={counts[effect]}
          onChange={(checked) => onChange(checked ? [...value, effect] : value.filter((item) => item !== effect))}
        />
      ))}
    </SidebarSection>
  );
}
