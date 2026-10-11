// Human-readable labels for resource selectors, entries, selections, and
// effective-access clauses.
import type { EffectiveAccessClause, ResourceCatalog, ResourceDefinition, ResourceSelection, ResourceSelector, ResourceType } from "../types";
import { resourceTypePluralLabel, type ResourceTypes } from "./resource-types";

export function selectorLabel(types: ResourceTypes, type: ResourceType, selector: ResourceSelector): string {
  if (selector.kind === "all") return `All ${resourceTypePluralLabel(types, type)}`;
  if (selector.kind === "namespace") return `${types.get(type)?.namespace?.membersLabel ?? type} under ${selector.value}`;
  return selector.value;
}

export function resourceLabel(types: ResourceTypes, resource: ResourceDefinition): string {
  const coverage = selectorLabel(types, resource.resourceType, resource.selector);
  return resource.displayName?.trim() ? `${resource.displayName} · ${coverage}` : coverage;
}

export function resourceSelectionLabels(types: ResourceTypes, selection: ResourceSelection, catalog?: ResourceCatalog | null): string[] {
  return [
    ...selection.resourceIds.map((id) => {
      const resource = catalog?.resources.find((entry) => entry.id === id);
      return resource ? resourceLabel(types, resource) : id;
    }),
    ...selection.resourceGroupIds.map((id) => catalog?.resourceGroups.find((entry) => entry.id === id)?.name ?? id)
  ];
}

export function clauseLabel(types: ResourceTypes, type: ResourceType, clause: EffectiveAccessClause): string {
  const includes = clause.included.map((selector) => selectorLabel(types, type, selector)).join(" or ");
  const excludes = clause.excluded.map((selector) => selectorLabel(types, type, selector)).join(", ");
  return excludes ? `${clause.included.length > 1 ? `(${includes})` : includes} except ${excludes}` : includes;
}
