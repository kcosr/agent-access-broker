// Resource and resource-group selection for token restrictions, grants, and
// resource-group membership.
import { useId, useState } from "react";
import type { PolicyServiceCatalog, ResourceCatalog, ResourceDefinition, ResourceSelection, ResourceType } from "../types";
import { grantResourceChoices, type GrantResourceCatalog } from "../lib/grant-resources";
import { resourceLabel } from "../lib/resource-labels";
import { resourceExclusionIssue, resourceTypeLabel, supportsResourceExclusions, useResourceTypes } from "../lib/resource-types";
import { Banner, Checkbox, FilterInput } from "../workbench";

/** A filterable checkbox list of resource entries; unknown selected IDs stay removable. */
export function ResourceChoices({
  resources,
  selected,
  onChange,
  disabled = false,
  label = "Filter resources",
  purpose = "include",
  savedSelection = []
}: {
  resources: ResourceDefinition[];
  selected: string[];
  onChange: (ids: string[]) => void;
  disabled?: boolean;
  label?: string;
  /** Group exclusions only offer types that support them; selected invalid entries remain removable. */
  purpose?: "include" | "exclude";
  /** Existing group exclusions are server-validated; cached metadata cannot invalidate them. */
  savedSelection?: readonly string[];
}) {
  const types = useResourceTypes();
  const [search, setSearch] = useState("");
  const query = search.trim().toLowerCase();
  const matches = resources.filter((resource) => {
    const eligible = purpose === "include" || supportsResourceExclusions(types, resource.resourceType);
    // Selected exclusions remain visible even when current metadata omits them,
    // so an unavailable/stale type never silently changes the draft.
    return (!eligible && selected.includes(resource.id)) || (eligible && `${resourceLabel(types, resource)} ${resourceTypeLabel(types, resource.resourceType)}`.toLowerCase().includes(query));
  });
  const hidden = purpose === "exclude" && resources.some((resource) => !supportsResourceExclusions(types, resource.resourceType));
  return (
    <div className="flex flex-col gap-2">
      {hidden ? <p className="pt-prose wb-small">Only resources whose types support exclusions are offered here. Other resources can still be included.</p> : null}
      <FilterInput value={search} onChange={setSearch} placeholder="Filter resources…" label={label} hotkey={null} />
      <div className="pt-checks pt-checks--scroll">
        {matches.map((resource) => (
          <Checkbox
            key={resource.id}
            label={resourceLabel(types, resource)}
            description={purpose === "exclude"
              ? `${resourceTypeLabel(types, resource.resourceType)} · ${resourceExclusionIssue(types, resource.resourceType, savedSelection.includes(resource.id)) ?? "Exclusion applies regardless of enabled state or execution context"}`
              : `${resourceTypeLabel(types, resource.resourceType)} · ${resource.allowedExecutionContexts.join(", ")}${resource.enabled ? "" : " · Disabled"}`}
            checked={selected.includes(resource.id)}
            disabled={disabled}
            onChange={(event) => onChange(event.target.checked ? [...selected, resource.id] : selected.filter((id) => id !== resource.id))}
          />
        ))}
        {matches.length === 0 ? <span className="wb-small wb-muted">No matching resources.</span> : null}
        {selected
          .filter((id) => !resources.some((resource) => resource.id === id))
          .map((id) => (
            <Checkbox key={id} label={id} description={purpose === "exclude" && savedSelection.includes(id) ? "Saved exclusion. Resource details are unavailable; the broker validates this membership when saving." : "Not in the current catalog"} checked disabled={disabled} onChange={() => onChange(selected.filter((value) => value !== id))} />
          ))}
      </div>
    </div>
  );
}

/**
 * Token restriction picker: resources and groups from the caller's token
 * options. `resourceTypes` limits the entries to those the service's actions
 * use; selected entries stay listed so they remain removable.
 */
export function ResourcePicker({
  selection,
  catalog,
  resourceTypes,
  onChange,
  disabled = false
}: {
  selection: ResourceSelection;
  catalog: ResourceCatalog;
  resourceTypes?: readonly ResourceType[];
  onChange: (selection: ResourceSelection) => void;
  disabled?: boolean;
}) {
  const resources = catalog.resources.filter((resource) => !resourceTypes || resourceTypes.includes(resource.resourceType) || selection.resourceIds.includes(resource.id));
  return (
    <fieldset className="pt-fieldset">
      {/* The surrounding Resources field names this section visually. */}
      <legend className="wb-sr-only">Resources and resource groups</legend>
      <div className="pt-columns">
        <div className="flex flex-col gap-2">
          <span className="wb-label-caps">Resources</span>
          <ResourceChoices resources={resources} selected={selection.resourceIds} onChange={(resourceIds) => onChange({ ...selection, resourceIds })} disabled={disabled} />
        </div>
        <div className="pt-checks">
          <span className="wb-label-caps">Resource groups</span>
          {catalog.resourceGroups.map((group) => (
            <Checkbox
              key={group.id}
              label={group.name}
              checked={selection.resourceGroupIds.includes(group.id)}
              disabled={disabled}
              onChange={(event) =>
                onChange({
                  ...selection,
                  resourceGroupIds: event.target.checked ? [...selection.resourceGroupIds, group.id] : selection.resourceGroupIds.filter((id) => id !== group.id)
                })
              }
            />
          ))}
          {selection.resourceGroupIds
            .filter((id) => !catalog.resourceGroups.some((group) => group.id === id))
            .map((id) => (
              <Checkbox
                key={id}
                label={id}
                description="Not in the current catalog"
                checked
                disabled={disabled}
                onChange={() => onChange({ ...selection, resourceGroupIds: selection.resourceGroupIds.filter((value) => value !== id) })}
              />
            ))}
          {catalog.resourceGroups.length === 0 ? <span className="wb-small wb-muted">No resource groups.</span> : null}
        </div>
      </div>
      <p className="pt-prose">Groups use current membership. Exclusions from any selected group apply across this selection.</p>
    </fieldset>
  );
}

// Grant catalogs include group membership within the caller's management scope.
export function GrantResourcePicker({
  selection,
  catalog,
  service,
  executionContexts,
  onChange,
  disabled = false
}: {
  selection: ResourceSelection;
  catalog: GrantResourceCatalog;
  service: PolicyServiceCatalog | null;
  executionContexts: string[];
  onChange: (selection: ResourceSelection) => void;
  disabled?: boolean;
}) {
  const types = useResourceTypes();
  const idPrefix = useId();
  const [search, setSearch] = useState("");
  const choices = grantResourceChoices(catalog, service, selection, executionContexts);
  const query = search.trim().toLowerCase();
  const matches = choices.resources.filter(
    (resource) =>
      selection.resourceIds.includes(resource.id) ||
      `${resourceLabel(types, resource)} ${resourceTypeLabel(types, resource.resourceType)}`.toLowerCase().includes(query)
  );
  const toggleResource = (id: string, checked: boolean) =>
    onChange({ ...selection, resourceIds: checked ? [...selection.resourceIds, id] : selection.resourceIds.filter((value) => value !== id) });
  const toggleGroup = (id: string, checked: boolean) =>
    onChange({ ...selection, resourceGroupIds: checked ? [...selection.resourceGroupIds, id] : selection.resourceGroupIds.filter((value) => value !== id) });

  function describe(resource: ResourceDefinition, exclusion = false) {
    const unavailable = !exclusion && executionContexts.length > 0 && !executionContexts.some((context) => resource.allowedExecutionContexts.includes(context));
    const parts = [
      resourceTypeLabel(types, resource.resourceType),
      exclusion ? "Exclusion applies regardless of enabled state or execution context" : resource.allowedExecutionContexts.join(", "),
      !exclusion && !resource.enabled ? "Disabled" : null,
      unavailable ? "Not available in selected contexts" : null,
      service && !choices.compatible(resource) ? `Not used by ${service.service}` : null
    ];
    return parts.filter(Boolean).join(" · ");
  }

  function members(ids: string[], exclusion: boolean) {
    if (ids.length === 0) return <span className="wb-small wb-muted">None</span>;
    return (
      <ul className="pt-links">
        {ids.map((id) => {
          const resource = choices.byId.get(id);
          return (
            <li key={id}>
              {resource ? resourceLabel(types, resource) : id}
              <div className="pt-clause-note">{resource ? describe(resource, exclusion) : "Not in the current catalog"}</div>
            </li>
          );
        })}
      </ul>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      {service ? <p className="pt-prose">Showing resource types used by {service.service}. Existing selections remain until you remove them.</p> : null}
      <FilterInput value={search} onChange={setSearch} placeholder="Filter resources…" label="Filter resources" hotkey={null} />
      <div className="pt-checks pt-checks--scroll" role="group" aria-label="Resources">
        {matches.map((resource) => (
          <Checkbox
            key={resource.id}
            aria-label={resourceLabel(types, resource)}
            label={resourceLabel(types, resource)}
            description={describe(resource)}
            checked={selection.resourceIds.includes(resource.id)}
            disabled={disabled}
            onChange={(event) => toggleResource(resource.id, event.target.checked)}
          />
        ))}
        {selection.resourceIds
          .filter((id) => !choices.byId.has(id))
          .map((id) => (
            <Checkbox key={id} aria-label={id} label={id} description="Not in the current catalog" checked disabled={disabled} onChange={() => toggleResource(id, false)} />
          ))}
        {matches.length === 0 ? <span className="wb-small wb-muted">No matching resources.</span> : null}
      </div>
      <div className="pt-checks" role="group" aria-label="Resource groups">
        <span className="wb-label-caps">Resource groups</span>
        {choices.groups.map(({ group, included, excluded, empty, relevant }) => (
          <div key={group.id} data-testid={`grant-resource-group-${group.id}`} className="flex flex-col gap-1">
            <Checkbox
              aria-label={group.name}
              aria-describedby={`${idPrefix}-group-${group.id}`}
              label={group.name}
              description={
                <span id={`${idPrefix}-group-${group.id}`}>
                  {empty
                    ? "No visible members"
                    : !relevant && service
                      ? `Not used by ${service.service}`
                      : included.length === 0 && excluded.length > 0
                        ? `Exclusions only${service ? ` for ${service.service}` : ""}`
                        : `${group.includedResourceIds.length} includes · ${group.excludedResourceIds.length} excludes`}
                </span>
              }
              checked={selection.resourceGroupIds.includes(group.id)}
              disabled={disabled}
              onChange={(event) => toggleGroup(group.id, event.target.checked)}
            />
            <details className="wb-disclosure ml-6">
              <summary>Members shown · {group.includedResourceIds.length} includes · {group.excludedResourceIds.length} excludes</summary>
              <div className="flex flex-col gap-2">
                <span className="wb-label-caps">Includes</span>
                {members(group.includedResourceIds, false)}
                <span className="wb-label-caps">Excludes</span>
                {members(group.excludedResourceIds, true)}
              </div>
            </details>
          </div>
        ))}
        {selection.resourceGroupIds
          .filter((id) => !catalog.resourceGroups.some((group) => group.id === id))
          .map((id) => (
            <Checkbox key={id} aria-label={id} label={id} description="Not in the current catalog" checked disabled={disabled} onChange={() => toggleGroup(id, false)} />
          ))}
        {choices.groups.length === 0 ? <span className="wb-small wb-muted">No matching resource groups.</span> : null}
      </div>
      <p className="pt-prose">
        Groups use current membership. Exclusions from any selected group apply across this selection, even when the excluded resource is disabled or
        unavailable in a selected context.
      </p>
      {choices.hasMismatch ? (
        <Banner tone="warning" slim>
          Some selected resources or groups are not used by {service?.service}. Selections stay unchanged until you remove them.
        </Banner>
      ) : null}
      {service && executionContexts.length > 0 && (selection.resourceIds.length > 0 || selection.resourceGroupIds.length > 0) && !choices.hasEligibleInclusions ? (
        <Banner tone="warning" slim>
          No eligible inclusions for the selected service and execution contexts. This is a catalog check; review Effective access for current coverage. You
          can still save this selection.
        </Banner>
      ) : null}
    </div>
  );
}
