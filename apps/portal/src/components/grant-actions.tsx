// Grant action selection in read-only and write-capable columns, and the
// write-capability badge shown for a selection.
import { useState } from "react";
import { actionSelectionCounts, grantActionGroups, selectMatchingActions, type ClassifiedAction } from "../lib/grant-actions";
import { Badge, Button, Checkbox, FilterInput } from "../workbench";

export function GrantActionSelector({
  available,
  selected,
  disabled,
  onChange
}: {
  available: readonly ClassifiedAction[];
  selected: string[];
  disabled: boolean;
  onChange: (selected: string[]) => void;
}) {
  const [search, setSearch] = useState("");
  const groups = grantActionGroups(available, selected, search);
  return (
    <div className="flex flex-col gap-3">
      <FilterInput value={search} onChange={setSearch} placeholder="Filter actions…" label="Filter actions" hotkey={null} />
      <p className="pt-prose">All / None apply to the matching actions in that column. Actions without reviewed read-only metadata are write-capable.</p>
      <div className="pt-columns">
        {groups.map((group) => {
          const matching = group.matching.map((action) => action.action);
          const selectable = group.matching.filter((action) => action.available !== false).map((action) => action.action);
          const category = group.label.toLowerCase();
          return (
            <fieldset className="pt-fieldset" key={group.label}>
              <legend>{group.label}</legend>
              <div className="flex flex-wrap items-center gap-2">
                <span className="wb-small wb-muted mr-auto">
                  {group.selected} of {group.total} selected
                </span>
                {!disabled ? (
                  <>
                    <Button
                      size="sm"
                      aria-label={`Select all matching ${category} actions`}
                      disabled={selectable.every((action) => selected.includes(action))}
                      onClick={() => onChange(selectMatchingActions(selected, selectable, true))}
                    >
                      All
                    </Button>
                    <Button
                      size="sm"
                      aria-label={`Select none of the matching ${category} actions`}
                      disabled={!matching.some((action) => selected.includes(action))}
                      onClick={() => onChange(selectMatchingActions(selected, matching, false))}
                    >
                      None
                    </Button>
                  </>
                ) : null}
              </div>
              <div className="pt-checks pt-checks--scroll">
                {group.matching.length === 0 ? <span className="wb-small wb-muted">No matching actions.</span> : null}
                {group.matching.map((action) => (
                  <Checkbox
                    key={action.action}
                    aria-label={action.action}
                    label={<span className="wb-mono">{action.action}</span>}
                    description={action.available === false ? `Unavailable · ${action.unavailableReason ?? "Not currently executable"}` : action.description}
                    checked={selected.includes(action.action)}
                    disabled={disabled || (action.available === false && !selected.includes(action.action))}
                    onChange={(event) => onChange(selectMatchingActions(selected, [action.action], event.target.checked))}
                  />
                ))}
              </div>
            </fieldset>
          );
        })}
      </div>
    </div>
  );
}

/** "Writes" badge when any selected action is write-capable; missing metadata never claims read-only. */
export function WriteCapability({ available, selected }: { available: readonly ClassifiedAction[]; selected: readonly string[] }) {
  const counts = actionSelectionCounts(available, selected);
  const label = `${counts.readOnly} read-only ${counts.readOnly === 1 ? "action" : "actions"}, ${counts.writeCapable} write-capable ${counts.writeCapable === 1 ? "action" : "actions"}`;
  if (!counts.writeCapable) {
    return (
      <Badge variant="outline" title={label}>
        Read-only
      </Badge>
    );
  }
  return (
    <Badge tone="warning" icon="pencil" title={label}>
      Writes<span className="wb-sr-only">: {label}</span>
    </Badge>
  );
}
