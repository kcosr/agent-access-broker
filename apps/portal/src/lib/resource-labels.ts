// Human-readable labels for resource selectors, entries, selections, and
// effective-access clauses.
import type { EffectiveRequestBoundary, EffectiveScopeBoundary, ResourceCatalog, ResourceDefinition, ResourceSelection, ResourceSelector, ResourceType } from "../types";
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

function scopeBoundaryLabel(types: ResourceTypes, boundary: EffectiveScopeBoundary): string {
  const includes = boundary.included.map((selector) => selectorLabel(types, boundary.resourceType, selector)).join(" or ");
  const excludes = boundary.excluded.map((selector) => selectorLabel(types, boundary.resourceType, selector)).join(", ");
  return excludes ? `${boundary.included.length > 1 ? `(${includes})` : includes} except ${excludes}` : includes;
}

/** A complete request boundary: scopes are joined, never flattened into alternatives. */
export function clauseLabel(types: ResourceTypes, boundary: EffectiveRequestBoundary): string {
  const scopes = Object.entries(boundary.scopes);
  if (scopes.length === 0) return "Action grant";
  if (scopes.length === 1) return scopeBoundaryLabel(types, scopes[0][1]);
  return scopes.map(([name, scope]) => `${name}: (${scopeBoundaryLabel(types, scope)})`).join(" AND ");
}
