import { createContext, useContext } from "react";
import type { ResourceSelector, ResourceType, ResourceTypeMetadata } from "../types";

/** Resource types described by the broker, keyed by id in server order. */
export type ResourceTypes = ReadonlyMap<ResourceType, ResourceTypeMetadata>;

export const NO_RESOURCE_TYPES: ResourceTypes = new Map();

export function indexResourceTypes(types: ResourceTypeMetadata[]): ResourceTypes {
  return new Map(types.map((type) => [type.id, type]));
}

const ResourceTypesContext = createContext<ResourceTypes>(NO_RESOURCE_TYPES);

export const ResourceTypesProvider = ResourceTypesContext.Provider;

export function useResourceTypes(): ResourceTypes {
  return useContext(ResourceTypesContext);
}

/**
 * Types that accept new resources, in server order: a removed imported type
 * stays listed for its existing resources but accepts no new ones. `current`
 * keeps an existing resource's own type selectable.
 */
export function creatableResourceTypes(types: ResourceTypes, current?: ResourceType): ResourceTypeMetadata[] {
  return [...types.values()].filter((type) => !type.removed || type.id === current);
}

// A type the broker does not describe is shown by its raw id.
export function resourceTypeLabel(types: ResourceTypes, type: ResourceType): string {
  return types.get(type)?.label ?? type;
}

export function resourceTypePluralLabel(types: ResourceTypes, type: ResourceType): string {
  return types.get(type)?.pluralLabel ?? type;
}

/** Namespace coverage metadata, present only when the type accepts namespace selectors. */
export function namespaceCoverage(types: ResourceTypes, type: ResourceType): ResourceTypeMetadata["namespace"] {
  const metadata = types.get(type);
  return metadata?.selectors.includes("namespace") ? metadata.namespace : undefined;
}

export function selectorPlaceholder(types: ResourceTypes, type: ResourceType, kind: Exclude<ResourceSelector["kind"], "all">): string | undefined {
  const metadata = types.get(type);
  return kind === "namespace" ? metadata?.namespace?.example : metadata?.example;
}
