// Shared pieces for the portal's DataTable views. Column widths, states and
// badges beside cell text come from the kit (DataColumn fit/grow/extra,
// StateCell).
import type { ReactNode } from "react";
import { Badge, Button, Menu } from "../workbench";

/** A column's `extra`: "+N" more items beside a truncating list, so the count never clips. */
export function moreCount(count: number): ReactNode {
  return count > 0 ? <span className="wb-muted">+{count}</span> : null;
}

/** A column's `extra` beside a grant's truncating actions: how many more, and Writes when any action can write. */
export function actionsExtra(more: number, writes: boolean): ReactNode {
  if (!more && !writes) return null;
  return (
    <>
      {moreCount(more)}
      {writes ? <Badge tone="warning">Writes</Badge> : null}
    </>
  );
}

/** The toolbar's "Group" menu: None or one grouping, as checked menu items. */
export function GroupMenu<T extends string>({
  value,
  options,
  onChange
}: {
  value: T | "none";
  options: { value: T; label: string }[];
  onChange: (value: T | "none") => void;
}) {
  const current = options.find((option) => option.value === value);
  return (
    <Menu
      label="Group by"
      items={[
        { type: "heading", label: "Group by" },
        { id: "none", label: "None", checked: value === "none", onSelect: () => onChange("none") },
        ...options.map((option) => ({ id: option.value, label: option.label, checked: value === option.value, onSelect: () => onChange(option.value) }))
      ]}
      trigger={(props) => (
        <Button {...props} icon="layers" title={current ? `Grouped by ${current.label.toLowerCase()}` : "Not grouped"}>
          Group
        </Button>
      )}
    />
  );
}
