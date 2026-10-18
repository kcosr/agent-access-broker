// Grant action selection in read-only and write-capable columns, and the
// write-capability badge shown for a selection. A command import's actions
// also say whether the Broker or the command checks their resources.
import { useId, useState } from "react";
import { actionSelectionCounts, canGrantAction, grantActionGroups, selectMatchingActions, type ClassifiedAction } from "../lib/grant-actions";
import { Badge, Button, Checkbox, FilterInput } from "../workbench";
import { ActionName } from "./action-name";

export const ACTION_COLUMNS_HINT = "All / None apply to the matching actions in that column. Actions without reviewed read-only metadata are write-capable.";

const actionDescription = (action: ClassifiedAction) =>
  action.available === false ? `Unavailable · ${action.unavailableReason ?? "Not currently executable"}` : action.description;

const CHECKED_BY: Record<NonNullable<ClassifiedAction["resourcesCheckedBy"]>, string> = { broker: "Broker", command: "Command" };

export function GrantActionSelector({
  available,
  selected,
  disabled,
  filterLabel = "Filter actions",
  hint = true,
  commandCaveatId,
  onChange
}: {
  available: readonly ClassifiedAction[];
  selected: string[];
  disabled: boolean;
  filterLabel?: string;
  /** False when the page explains All / None once for several selectors. */
  hint?: boolean;
  /** The element explaining what a command must enforce, which command-checked actions point to. */
  commandCaveatId?: string | undefined;
  onChange: (selected: string[]) => void;
}) {
  const id = useId();
  const [search, setSearch] = useState("");
  const groups = grantActionGroups(available, selected, search);
  return (
    <div className="pt-action-selector">
      <FilterInput value={search} onChange={setSearch} placeholder="Filter actions…" label={filterLabel} hotkey={null} />
      {hint ? <p className="pt-prose">{ACTION_COLUMNS_HINT}</p> : null}
      <div className="pt-action-columns">
        {groups.map((group) => {
          const matching = group.matching.map((action) => action.action);
          const selectable = group.matching.filter(canGrantAction).map((action) => action.action);
          const category = group.label.toLowerCase();
          return (
            <div className="pt-action-column" role="group" aria-labelledby={`${id}-${category}`} key={group.label}>
              <div className="pt-action-column-head">
                <span className="wb-label-caps" id={`${id}-${category}`}>
                  {group.label}
                </span>
                <span className="pt-action-column-count wb-small wb-muted mr-auto">
                  {group.selected} of {group.total}
                </span>
                {!disabled ? (
                  <span className="pt-action-column-buttons">
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
                  </span>
                ) : null}
              </div>
              <div className="pt-action-list">
                {group.matching.length === 0 ? <span className="wb-small wb-muted">No matching actions.</span> : null}
                {group.matching.map((action) => (
                  <Checkbox
                    key={action.action}
                    aria-label={action.action}
                    aria-describedby={action.resourcesCheckedBy === "command" ? commandCaveatId : undefined}
                    label={
                      <span className="wb-mono">
                        <ActionName action={action.action} />
                      </span>
                    }
                    // Descriptions are clamped; the title shows the full text.
                    description={
                      <span title={actionDescription(action)}>
                        {action.resourcesCheckedBy ? <b>Resources checked by: {CHECKED_BY[action.resourcesCheckedBy]}. </b> : null}
                        {actionDescription(action)}
                      </span>
                    }
                    checked={selected.includes(action.action)}
                    disabled={disabled || (!canGrantAction(action) && !selected.includes(action.action))}
                    onChange={(event) => onChange(selectMatchingActions(selected, [action.action], event.target.checked))}
                  />
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/** "Writes" badge when any selected action is write-capable; missing metadata never claims read-only. */
export function WriteCapability({ available, selected }: { available: readonly ClassifiedAction[]; selected: readonly string[] }) {
  if (!selected.length) return null;
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
