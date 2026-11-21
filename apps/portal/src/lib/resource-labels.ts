// Human-readable labels for resource selectors, entries, selections, and
// effective-access clauses.
import type { EffectiveAccessClause, EffectiveAccessScope, LocationBoundary, ResourceCatalog, ResourceDefinition, ResourceSelection, ResourceSelector, ResourceType } from "../types";
import { resourceTypePluralLabel, type ResourceTypes } from "./resource-types";
import { parseContentIdentity } from "./resource-locations";

export function selectorLabel(types: ResourceTypes, type: ResourceType, selector: ResourceSelector): string {
  if (selector.kind === "all") return `All ${resourceTypePluralLabel(types, type)}`;
  if (selector.kind === "namespace") return `${types.get(type)?.namespace?.membersLabel ?? type} under ${selector.value}`;
  if (type === "confluence_content") {
    const identity = parseContentIdentity(selector.value);
    if (!identity) return selector.value;
    const noun = identity.kind === "blog" ? "Blog post" : identity.kind === "folder" ? "Folder" : "Page";
    const coverage = selector.kind === "subtree" ? "root and descendants" : identity.kind === "blog" ? "this blog post only" : "this page only";
    return `${noun} ${identity.id} · ${identity.siteOrigin.slice("https://".length)} · ${coverage}`;
  }
  if (selector.kind === "subtree") return `${selector.value} · root and descendants`;
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

function boundaryLabel(types: ResourceTypes, boundary: LocationBoundary): string {
  const label = (items: LocationBoundary["included"]) => items.map((item) => selectorLabel(types, item.resourceType, item.selector)).join(" or ");
  return `${boundary.included.length ? label(boundary.included) : "No locations"}${boundary.excluded.length ? ` except (${label(boundary.excluded)})` : ""}`;
}

/** Never interpret an unavailable location expression as action-only or empty access. */
export function coverageLabels(types: ResourceTypes, coverage: EffectiveAccessScope): string[] {
  if (coverage.scope === "unscoped") return ["Action grant"];
  if (coverage.scope === "resource") return coverage.clauses.map((clause) => clauseLabel(types, coverage.resourceType, clause));
  if (coverage.projectionStatus === "too_complex") return ["Coverage preview unavailable"];
  return coverage.clauses.map((clause) => {
    const required = clause.required.map((index) => `(${boundaryLabel(types, coverage.boundaries[index])})`).join(" AND ");
    const excluded = clause.excludedRequests.map((index) => `(${boundaryLabel(types, coverage.boundaries[index])})`).join(" or ");
    return `${required || "No locations"}${excluded ? `; does not apply when one of these boundaries covers the whole request: ${excluded}` : ""} · ${clause.credentialMode} · location verification at invocation`;
  });
}
