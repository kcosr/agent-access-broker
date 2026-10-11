import type { PolicyServiceCatalog, ResourceDefinition, ResourceGroupRecord, ResourceSelection } from "../types";

export type GrantResourceCatalog = { resources: ResourceDefinition[]; resourceGroups: ResourceGroupRecord[] };

export function grantResourceChoices(
  catalog: GrantResourceCatalog,
  service: PolicyServiceCatalog | null,
  selection: ResourceSelection,
  executionContexts: string[]
) {
  const types = service ? new Set(Object.values(service.resourceScopes).map((scope) => scope.resourceType)) : null;
  const byId = new Map(catalog.resources.map((resource) => [resource.id, resource]));
  const compatible = (resource: ResourceDefinition) => types === null || types.has(resource.resourceType);
  const compatibleIds = (ids: string[]) => ids.filter((id) => {
    const resource = byId.get(id);
    return resource !== undefined && compatible(resource);
  });
  const groups = catalog.resourceGroups.map((group) => {
    const included = compatibleIds(group.includedResourceIds);
    const excluded = compatibleIds(group.excludedResourceIds);
    const empty = group.includedResourceIds.length === 0 && group.excludedResourceIds.length === 0;
    return { group, included, excluded, empty, relevant: types === null || included.length > 0 || excluded.length > 0 };
  });
  const selectedGroups = groups.filter(({ group }) => selection.resourceGroupIds.includes(group.id));
  const inclusionIds = new Set([...selection.resourceIds, ...selectedGroups.flatMap(({ group }) => group.includedResourceIds)]);
  const hasMismatch = service !== null && (selection.resourceIds.some((id) => {
    const resource = byId.get(id);
    return resource !== undefined && !compatible(resource);
  }) || selectedGroups.some(({ relevant, empty }) => !relevant && !empty));
  // This only checks catalog inclusions. The server preview resolves exclusions,
  // action requirements and effective coverage; never infer authorization here.
  const hasEligibleInclusions = [...inclusionIds].some((id) => {
    const resource = byId.get(id);
    return resource !== undefined && compatible(resource) && resource.enabled
      && executionContexts.some((context) => resource.allowedExecutionContexts.includes(context));
  });
  return {
    byId,
    compatible,
    resources: catalog.resources.filter((resource) => compatible(resource) || selection.resourceIds.includes(resource.id)),
    groups: groups.filter(({ group, empty, relevant }) => relevant || empty || selection.resourceGroupIds.includes(group.id)),
    hasMismatch,
    hasEligibleInclusions
  };
}
