import type { AvailabilityRequirement, ResourcesCheckedBy } from "../types";

/** Classification describes upstream effects; it never changes a grant's actions. */
export type ClassifiedAction = { action: string; description?: string; readOnly?: boolean; available?: boolean; unavailableReason?: string; resourcesCheckedBy?: ResourcesCheckedBy; availabilityRequirements?: AvailabilityRequirement[] };

/** Setup prerequisites do not prevent authoring a defined local permission. */
export function canGrantAction(action: ClassifiedAction): boolean {
  return action.available !== false || Boolean(action.availabilityRequirements?.some((requirement) => requirement.kind === "local_runtime"));
}

export function actionSelectionCounts(available: readonly ClassifiedAction[], selected: readonly string[]) {
  const reviewedReads = new Set(available.filter((action) => action.readOnly === true).map((action) => action.action));
  const selectedActions = [...new Set(selected)];
  const readOnly = selectedActions.filter((action) => reviewedReads.has(action)).length;
  return { readOnly, writeCapable: selectedActions.length - readOnly };
}

/** Bulk selection changes only the visible identities, preserving hidden choices. */
export function selectMatchingActions(selected: readonly string[], matching: readonly string[], checked: boolean) {
  if (checked) return [...new Set([...selected, ...matching])];
  const removed = new Set(matching);
  return selected.filter((action) => !removed.has(action));
}

export function grantActionGroups(available: readonly ClassifiedAction[], selected: readonly string[], search: string) {
  const known = new Set(available.map((action) => action.action));
  const choices: ClassifiedAction[] = [
    ...available,
    ...[...new Set(selected)].filter((action) => !known.has(action)).map((action) => ({ action, description: "Not configured", available: false, unavailableReason: "Not in the current catalog" })),
  ];
  const query = search.trim().toLowerCase();
  return [true, false].map((readOnly) => {
    const all = choices.filter((action) => (action.readOnly === true) === readOnly);
    return {
      readOnly,
      label: readOnly ? "Read-only" : "Write-capable",
      selected: all.filter((action) => selected.includes(action.action)).length,
      total: all.length,
      matching: all.filter((action) => !query || `${action.action} ${action.description ?? ""}`.toLowerCase().includes(query)),
    };
  });
}
