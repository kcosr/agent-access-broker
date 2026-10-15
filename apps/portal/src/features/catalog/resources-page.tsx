import { CatalogMutationError, CatalogUnavailableDrawer } from "./catalog-target";
import { canWriteAdmin } from "../../lib/capabilities";
import { AdminButton, AdminIconButton, AdminForm } from "../../components/admin-access";
// Admin › Catalog › Resources: shared resource scopes used by grants and token
// restrictions. URL-driven table (`?item=<id>`, `?item=new` to add) with a
// drawer for details, private attributes, used-by, edit, enable, and delete.
import { useId, useMemo, useState } from "react";
import { brokerApi } from "../../api";
import type { ResourceGroupRecord, ResourceRecord, ResourceSelector, ResourceType, ResourceWriteBody } from "../../types";
import { resourceLabel, selectorLabel } from "../../lib/resource-labels";
import { creatableResourceTypes, namespaceCoverage, resourceTypeLabel, resourceTypePluralLabel, selectorPlaceholder, useResourceTypes, type ResourceTypes } from "../../lib/resource-types";
import { groupRows, sortRows } from "../../lib/table-sort";
import { urlParam } from "../../lib/url-state";
import { AppLink, Banner, Button, Checkbox, type DataColumn, DataTable, Drawer, DrawerSection, EmptyState, ErrorState, Field, FilterInput, Icon, Input, KeyValue, List, ListFooter, Main, plural, Seg, Select, type SortState, StateCell, StatePill, Switch, TableGroupHeader, Time, Toolbar, ToolbarRow, ToolbarSummary } from "../../workbench";
import { GroupMenu } from "../../components/table-cells";
import { FieldGroup } from "../../components/form";
import { useTableUrlState } from "../../app/list-state";
import { paths } from "../../app/paths";
import { useSession } from "../../app/session";
import { usePolicyCatalog, usePolicyStatus, useResourceCatalog, useResourceUsedBy } from "../../data/queries";
import { CatalogFrame } from "./catalog-frame";
import { ResourceAttributeField, ResourceAttributeValue } from "./resource-attributes";
import { useResourceActions } from "./resource-actions";
import { UsedBySection } from "./used-by";

const STATUSES = ["all", "active", "disabled"] as const;
const SORT_KEYS = ["name", "type", "updated"] as const;
const GROUPINGS = ["none", "type"] as const;

export const RESOURCES_STATE = {
  status: urlParam.oneOf(STATUSES, "all"),
  type: urlParam.text(),
  sort: urlParam.sort(SORT_KEYS),
  group: urlParam.oneOf(GROUPINGS, "none"),
  q: urlParam.text(),
  item: urlParam.text()
};

function resourceTitle(types: ResourceTypes, resource: ResourceRecord) {
  return resource.displayName?.trim() || selectorLabel(types, resource.resourceType, resource.selector);
}

function searchText(types: ResourceTypes, resource: ResourceRecord) {
  return `${resourceLabel(types, resource)} ${resource.id} ${resource.resourceType} ${resourceTypeLabel(types, resource.resourceType)}`.toLowerCase();
}

function filterResources(resources: ResourceRecord[], types: ResourceTypes, state: { status: string; type: string; q: string }) {
  const query = state.q.trim().toLowerCase();
  return resources
    .filter((resource) => (!state.type || resource.resourceType === state.type) && (state.status === "all" || (resource.enabled ? "active" : "disabled") === state.status))
    .filter((resource) => !query || searchText(types, resource).includes(query));
}

/** Resource types in the broker's order, unknown types last. */
function typeOrder(types: ResourceTypes) {
  const order = [...types.keys()];
  const rank = (type: string) => {
    const index = order.indexOf(type);
    return index < 0 ? order.length : index;
  };
  return (a: string, b: string) => rank(a) - rank(b) || a.localeCompare(b);
}

/** Resources in table order: the chosen sort, else by name; regrouped by type when grouped. */
function orderResources(resources: ResourceRecord[], types: ResourceTypes, sort: SortState | null, grouped: boolean) {
  const sorted = sortRows(
    resources,
    sort,
    (resource, key) => (key === "name" ? resourceTitle(types, resource) : key === "type" ? resourceTypeLabel(types, resource.resourceType) : resource.updatedAt),
    (a, b) => resourceTitle(types, a).localeCompare(resourceTitle(types, b)) || a.id.localeCompare(b.id)
  );
  return grouped ? groupRows(sorted, (resource) => resource.resourceType, typeOrder(types)) : sorted;
}

/** Private attribute fields of a resource (exact resources of types that define them). */
function attributeFields(types: ResourceTypes, resource: ResourceRecord) {
  return resource.selector.kind === "exact" ? types.get(resource.resourceType)?.attributes ?? [] : [];
}

function useResourcesModel() {
  const writableActor = canWriteAdmin(useSession().session);
  const types = useResourceTypes();
  const query = useResourceCatalog();
  const status = usePolicyStatus();
  const catalog = usePolicyCatalog();
  const resources = useMemo(() => query.data?.resources ?? [], [query.data]);
  const list = useTableUrlState(RESOURCES_STATE, "item");
  const grouped = list.state.group === "type";
  const shown = useMemo(
    () => orderResources(filterResources(resources, types, list.state), types, list.state.sort, grouped),
    [resources, types, list.state, grouped]
  );
  const creating = writableActor && list.openId === "new";
  const open = !creating && list.openId ? resources.find((resource) => resource.id === list.openId) ?? null : null;
  const counts = {
    all: resources.length,
    active: resources.filter((resource) => resource.enabled).length,
    disabled: resources.filter((resource) => !resource.enabled).length
  };
  return {
    types,
    query,
    resources,
    groups: query.data?.resourceGroups ?? [],
    shown,
    grouped,
    list,
    creating,
    open,
    counts,
    writable: writableActor && Boolean(status.data?.writable),
    statusLoaded: Boolean(status.data),
    storageWritable: Boolean(status.data?.writable),
    contexts: catalog.data?.executionContexts.allowedValues ?? [],
    loading: query.isPending && query.fetchStatus !== "idle"
  };
}

type ResourcesModel = ReturnType<typeof useResourcesModel>;

export function ResourcesPage() {
  const model = useResourcesModel();
  const drawer = model.creating ? <ResourceEditorDrawer model={model} record={null} /> : model.open ? <ResourceDrawer key={model.open.id} model={model} resource={model.open} /> : model.list.openId ? <CatalogUnavailableDrawer kind="resource" id={model.list.openId} loading={model.query.isPending || model.query.isFetching} error={model.query.isError ? model.query.error : null} retry={() => void model.query.refetch()} close={model.list.close} returnFocus={model.list.returnFocus} /> : null;
  return (
    <CatalogFrame section={{ kind: "resources" }} drawer={drawer}>
      <Main
        label="Resources"
        toolbar={<ResourcesToolbar model={model} />}
        header={
          model.statusLoaded && !model.storageWritable ? (
            <div className="pt-header-banners">
              <Banner tone="info" slim>
                Policy writes are not enabled for this broker, so resources are read-only here.
              </Banner>
            </div>
          ) : null
        }
        refetching={model.query.isFetching && !model.loading}
      >
        <List full>
          <ResourceTable model={model} />
          {model.shown.length > 0 ? <ListFooter /> : null}
        </List>
      </Main>
    </CatalogFrame>
  );
}

function ResourcesToolbar({ model }: { model: ResourcesModel }) {
  const { list, counts, shown, types, writable } = model;
  return (
    <Toolbar>
      <ToolbarRow
        primary={
          <AdminButton variant="primary" icon="plus" disabled={!writable} title={writable ? undefined : "Policy writes are not enabled."} onClick={() => list.open("new")}>
            Add resource
          </AdminButton>
        }
      >
        <Seg
          label="Resource status"
          value={list.state.status}
          onChange={(status) => list.setState({ status })}
          options={[
            { value: "all", label: "All", count: counts.all },
            { value: "active", label: "Active", icon: "circle-check", tone: "success", count: counts.active },
            { value: "disabled", label: "Disabled", count: counts.disabled }
          ]}
        />
        <Select inputSize="sm" className="pt-catalog-type-filter" aria-label="Resource type" value={list.state.type} onChange={(event) => list.setState({ type: event.target.value })}>
          <option value="">All types</option>
          {list.state.type && !types.has(list.state.type) ? <option value={list.state.type}>{list.state.type}</option> : null}
          {[...types.values()].map((type) => (
            <option key={type.id} value={type.id}>
              {type.pluralLabel}
            </option>
          ))}
        </Select>
        <FilterInput className="pt-catalog-filter" value={list.state.q} onChange={(q) => list.setState({ q })} placeholder="Filter resources…" debounceMs={150} />
        <GroupMenu value={list.state.group} options={[{ value: "type" as const, label: "Type" }]} onChange={(group) => list.setState({ group })} />
        <ToolbarSummary grow>
          <b>{shown.length}</b> of {counts.all} {plural(counts.all, "resource")}
        </ToolbarSummary>
      </ToolbarRow>
    </Toolbar>
  );
}

function ResourceTable({ model }: { model: ResourcesModel }) {
  const { query, loading, shown, resources, grouped, list, counts, types, writable } = model;
  // Grouped by type or filtered to one type, the Type column would repeat one value.
  const typeColumn = !grouped && !list.state.type;
  const actions = useResourceActions();
  const { reportError } = useSession();
  const [pending, setPending] = useState<string | null>(null);
  const attributes = useMemo(() => resources.some((resource) => attributeFields(types, resource).length > 0), [resources, types]);
  const columns = useMemo<DataColumn<ResourceRecord>[]>(
    () => [
      {
        key: "name",
        header: "Name",
        sortable: true,
        truncate: true,
        minWidth: "20ch",
        cell: (resource) => resourceTitle(types, resource)
      },
      {
        key: "id",
        header: "ID",
        priority: 3,
        className: "wb-cell-mono",
        hug: "22ch",
        cell: (resource) => resource.id
      },
      ...(!typeColumn
        ? []
        : [
            {
              key: "type",
              header: "Type",
              sortable: true,
              priority: 2,
              cell: (resource: ResourceRecord) => <span title={resource.resourceType}>{resourceTypeLabel(types, resource.resourceType)}</span>
            } satisfies DataColumn<ResourceRecord>
          ]),
      {
        key: "coverage",
        header: "Coverage",
        // Without a Type column, coverage takes its place beside an open drawer.
        priority: typeColumn ? 3 : 2,
        truncate: true,
        minWidth: "12ch",
        className: "wb-cell-mono",
        cell: (resource) => {
          const coverage = selectorLabel(types, resource.resourceType, resource.selector);
          return <span title={coverage}>{coverage}</span>;
        }
      },
      {
        key: "contexts",
        header: "Contexts",
        priority: 4,
        className: "wb-cell-mono",
        cell: (resource) => resource.allowedExecutionContexts.join(", ")
      },
      ...(attributes
        ? [
            {
              key: "attributes",
              header: <span title="Private attributes set">Private</span>,
              align: "end",
              priority: 4,
              cell: (resource: ResourceRecord) => {
                const fields = attributeFields(types, resource);
                if (!fields.length) return <span className="wb-muted">—</span>;
                const set = resource.configuredAttributes?.length ?? 0;
                return <span title={`${set} of ${fields.length} private ${plural(fields.length, "attribute")} set`}>{`${set}/${fields.length}`}</span>;
              }
            } satisfies DataColumn<ResourceRecord>
          ]
        : []),
      {
        key: "status",
        header: "Status",
        cell: (resource) => <StateCell label={resource.enabled ? "Active" : "Disabled"} tone={resource.enabled ? "success" : "muted"} quiet={resource.enabled} />
      },
      {
        key: "updated",
        header: "Updated",
        sortable: true,
        firstSortDir: "desc",
        priority: 4,
        cell: (resource) => (resource.updatedAt ? <Time value={resource.updatedAt} /> : null)
      },
      ...(writable
        ? [
            {
              key: "row-actions",
              header: <span className="wb-sr-only">Row actions</span>,
              className: "wb-cell-actions",
              cell: (resource: ResourceRecord) => (
                <div className="wb-row-actions">
                  <AdminIconButton
                    size="sm"
                    icon={resource.enabled ? "pause" : "play"}
                    label={`${resource.enabled ? "Disable" : "Enable"} ${resourceTitle(types, resource)}`}
                    disabled={pending !== null}
                    onClick={() => {
                      setPending(resource.id);
                      actions
                        .setResourceEnabled(resource, !resource.enabled)
                        .catch(reportError)
                        .finally(() => setPending(null));
                    }}
                  />
                </div>
              )
            } satisfies DataColumn<ResourceRecord>
          ]
        : [])
    ],
    [types, typeColumn, attributes, writable, pending, actions, reportError]
  );
  const filtered = Boolean(list.state.q || list.state.type || list.state.status !== "all");
  const empty =
    filtered && counts.all > 0 ? (
      <EmptyState
        compact
        icon="search"
        title="No matching resources"
        actions={
          <Button icon="x" onClick={() => list.setState({ q: "", type: "", status: "all" })}>
            Clear filters
          </Button>
        }
      >
        Adjust the search or filters to show catalog entries.
      </EmptyState>
    ) : (
      <EmptyState
        compact
        icon="database"
        title="No resources"
        actions={
          writable ? (
            <AdminButton variant="primary" icon="plus" onClick={() => list.open("new")}>
              Add resource
            </AdminButton>
          ) : null
        }
      >
        Resources are the shared scopes grants and token restrictions select: a repository, a project, or everything under a namespace.
      </EmptyState>
    );
  const { sort, group, item: _open, ...filters } = list.state;
  return (
    <DataTable
      label="Resources"
      rows={shown}
      rowId={(resource) => resource.id}
      columns={columns}
      sort={sort}
      onSortChange={(next) => list.setState({ sort: next })}
      groupBy={grouped ? (resource) => resource.resourceType : undefined}
      groupHeader={({ key, rows }) => (
        <TableGroupHeader title={resourceTypePluralLabel(types, key)} sub={<span className="wb-mono">{key}</span>} count={`${rows.length} ${plural(rows.length, "resource")}`} />
      )}
      activeId={list.openId}
      rowHref={(resource) => list.itemHref(resource.id)}
      onRowFollow={(resource) => list.open(resource.id, "replace")}
      cursorResetKey={JSON.stringify({ filters, sort, group })}
      rowDim={(resource) => !resource.enabled}
      loading={loading || (query.isError && query.isFetching)}
      error={query.isError ? <ErrorState compact title="Couldn’t load resources" error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} /> : undefined}
      empty={empty}
      bleed
    />
  );
}

function memberships(groups: ResourceGroupRecord[], id: string) {
  return groups.flatMap((group) => [
    ...(group.includedResourceIds.includes(id) ? [{ group, effect: "include" as const }] : []),
    ...(group.excludedResourceIds.includes(id) ? [{ group, effect: "exclude" as const }] : [])
  ]);
}

function ResourceDrawer({ model, resource }: { model: ResourcesModel; resource: ResourceRecord }) {
  const [editing, setEditing] = useState(false);
  if (editing) return <ResourceEditorDrawer model={model} record={resource} onDone={() => setEditing(false)} />;
  return <ResourceDetailDrawer model={model} resource={resource} onEdit={() => setEditing(true)} />;
}

function ResourceDetailDrawer({ model, resource, onEdit }: { model: ResourcesModel; resource: ResourceRecord; onEdit: () => void }) {
  const { types, list, writable, groups } = model;
  const { attempt, reportError } = useSession();
  const actions = useResourceActions();
  const usedBy = useResourceUsedBy("resources", resource.id);
  const [pending, setPending] = useState(false);
  const title = resourceTitle(types, resource);
  const fields = resource.selector.kind === "exact" ? types.get(resource.resourceType)?.attributes ?? [] : [];
  const configured = resource.configuredAttributes ?? [];
  const member = memberships(groups, resource.id);
  const stamp = resource;
  const deletable = writable && usedBy.data !== undefined && usedBy.data.length === 0 && !usedBy.isFetching;
  return (
    <Drawer
      resetKey={resource.id}
      onClose={list.close}
      returnFocus={list.returnFocus}
      label={`Resource ${title}`}
      kicker={
        <>
          <Icon name="database" /> {resourceTypeLabel(types, resource.resourceType)} <span className="wb-num">{resource.id}</span>
        </>
      }
      title={title}
      meta={
        <>
          <StatePill tone={resource.enabled ? "success" : "neutral"} icon={resource.enabled ? "circle-check" : "pause"}>
            {resource.enabled ? "Active" : "Disabled"}
          </StatePill>
          {stamp.updatedAt ? (
            <span>
              updated <Time value={stamp.updatedAt} />
              {stamp.updatedBy ? ` by ${stamp.updatedBy}` : ""}
            </span>
          ) : null}
        </>
      }
      actions={
        <>
          <AdminButton icon="pencil" disabled={!writable} onClick={onEdit}>
            Edit
          </AdminButton>
          <AdminButton
            icon={resource.enabled ? "pause" : "play"}
            disabled={!writable}
            pending={pending}
            onClick={() => {
              setPending(true);
              actions
                .setResourceEnabled(resource, !resource.enabled)
                .catch(reportError)
                .finally(() => setPending(false));
            }}
          >
            {resource.enabled ? "Disable" : "Enable"}
          </AdminButton>
          <AdminButton
            variant="danger-ghost"
            icon="trash"
            disabled={!deletable}
            title={deletable ? undefined : writable ? "Remove every reference before deleting." : "Policy writes are not enabled."}
            onClick={() => actions.confirmDelete("resources", resource, resourceLabel(types, resource), list.close)}
          >
            Delete
          </AdminButton>
        </>
      }
    >
      <DrawerSection title="Details">
        <KeyValue
          labelWidth={140}
          items={[
            { label: "Resource ID", value: <span className="wb-num">{resource.id}</span> },
            { label: "Type", value: resourceTypeLabel(types, resource.resourceType) },
            { label: "Coverage", value: <span className="wb-mono">{selectorLabel(types, resource.resourceType, resource.selector)}</span> },
            { label: "Display name", value: resource.displayName?.trim() || <span className="wb-muted">Defaults to the coverage</span> },
            { label: "Contexts", value: <span className="wb-mono">{resource.allowedExecutionContexts.join(", ")}</span> },
            { label: "Version", value: <span className="wb-num">{resource.version}</span> }
          ]}
        />
        {!resource.enabled ? <p className="pt-prose wb-small">Disabled resources grant nothing, but still apply when excluded by a group.</p> : null}
      </DrawerSection>
      {fields.length ? (
        <DrawerSection title="Private attributes" count={`${configured.length}/${fields.length}`}>
          <div className="wb-form-stack">
            {fields.map((field) =>
              configured.includes(field.name) ? (
                <ResourceAttributeValue
                  key={field.name}
                  field={field}
                  label={field.label}
                  onReveal={async () => (await attempt((current) => brokerApi.revealResourceAttribute(current, resource.id, field.name))).value}
                />
              ) : (
                <KeyValue key={field.name} labelWidth={140} items={[{ label: field.label, value: <span className="wb-muted">Not set</span> }]} />
              )
            )}
          </div>
        </DrawerSection>
      ) : null}
      <DrawerSection title="Resource groups" count={member.length}>
        {member.length ? (
          <ul className="pt-links">
            {member.map(({ group, effect }) => (
              <li key={`${group.id}:${effect}`}>
                <AppLink href={paths.resourceGroups(group.id)} className="wb-link">
                  {group.name}
                </AppLink>{" "}
                <span className="wb-muted">· {effect === "include" ? "included" : "excluded"}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="pt-prose wb-small">Not a member of any resource group.</p>
        )}
      </DrawerSection>
      <UsedBySection query={usedBy} />
    </Drawer>
  );
}

function ResourceEditorDrawer({ model, record, onDone }: { model: ResourcesModel; record: ResourceRecord | null; onDone?: () => void }) {
  const { types, contexts, list } = model;
  const { attempt } = useSession();
  const actions = useResourceActions();
  const formId = useId();
  const [chosenType, setType] = useState<ResourceType | null>(record?.resourceType ?? null);
  // Removed imported types accept no new resources; an existing resource keeps its own.
  const offered = creatableResourceTypes(types, record?.resourceType);
  // New resources start with the first type the broker lists.
  const type = chosenType ?? offered[0]?.id ?? "";
  const namespace = namespaceCoverage(types, type);
  const [kind, setKind] = useState<ResourceSelector["kind"]>(record?.selector.kind ?? "exact");
  const [value, setValue] = useState(record && record.selector.kind !== "all" ? record.selector.value : "");
  const [name, setName] = useState(record?.displayName ?? "");
  const [selectedContexts, setContexts] = useState(record?.allowedExecutionContexts ?? []);
  const [enabled, setEnabled] = useState(record?.enabled ?? true);
  const [attributes, setAttributes] = useState<Record<string, string>>({});
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [attempted, setAttempted] = useState(false);
  const configured = record?.configuredAttributes ?? [];
  const fields = kind === "exact" ? types.get(type)?.attributes ?? [] : [];
  const issues: Record<string, string> = {};
  if (!type) issues.type = "Choose a resource type.";
  if (kind !== "all" && !value.trim()) issues.value = kind === "namespace" ? "Enter the namespace." : "Enter the canonical identifier.";
  if (!selectedContexts.length) issues.contexts = "Select at least one execution context.";
  for (const field of fields) if (field.required && !configured.includes(field.name) && !attributes[field.name]) issues[field.name] = `Enter the ${field.label.toLowerCase()}.`;
  const shown = attempted ? issues : {};
  const close = () => (onDone ? onDone() : list.close());

  async function save() {
    setAttempted(true);
    if (Object.keys(issues).length) return;
    const privateValues = Object.fromEntries(fields.flatMap((field) => (attributes[field.name] ? [[field.name, attributes[field.name]]] : [])));
    const body: ResourceWriteBody = {
      resourceType: type,
      selector: kind === "all" ? { kind } : { kind, value: value.trim() },
      displayName: name.trim() || null,
      allowedExecutionContexts: selectedContexts,
      enabled,
      ...(Object.keys(privateValues).length ? { attributes: privateValues } : {}),
      ...(record ? { expectedVersion: record.version } : {})
    };
    setPending(true);
    setError(null);
    try {
      const saved = await actions.saveResource(body, record?.id);
      setAttributes({});
      if (record) close();
      else list.open(saved.id, "replace");
    } catch (failure) {
      setError(failure);
      setPending(false);
    }
  }

  return (
    <Drawer
      resetKey={record?.id ?? "new"}
      onClose={close}
      returnFocus={record ? list.returnFocus : undefined}
      label={record ? `Edit resource ${resourceTitle(types, record)}` : "Add resource"}
      kicker={
        <>
          <Icon name="database" /> {record ? <>Edit resource <span className="wb-num">{record.id}</span></> : "New resource"}
        </>
      }
      title={record ? resourceTitle(types, record) : "Add resource"}
      footer={
        <>
          <span className="wb-spacer" />
          <Button onClick={close} disabled={pending}>
            Cancel
          </Button>
          <AdminButton type="submit" form={formId} variant="primary" pending={pending}>
            Save resource
          </AdminButton>
        </>
      }
    >
      <AdminForm
        id={formId}
        className="wb-form-stack pt-catalog-form pt-catalog-drawer-form"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <div className="pt-catalog-row">
          <Field label="Resource type" hint={configured.length ? "Fixed while private attributes are stored." : undefined} error={shown.type}>
            <Select
              value={type}
              disabled={configured.length > 0 || pending}
              onChange={(event) => {
                setAttributes({});
                setType(event.target.value);
                if (kind === "namespace" && !namespaceCoverage(types, event.target.value)) setKind("exact");
              }}
            >
              {type && !types.has(type) ? <option value={type}>{type}</option> : null}
              {offered.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.label}
                  {option.removed ? " (removed)" : ""}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Coverage">
            <Select
              value={kind}
              disabled={configured.length > 0 || pending}
              onChange={(event) => {
                setAttributes({});
                setKind(event.target.value as ResourceSelector["kind"]);
              }}
            >
              <option value="exact">Specific resource</option>
              {namespace ? <option value="namespace">{namespace.label}</option> : null}
              <option value="all">All {resourceTypePluralLabel(types, type)}</option>
            </Select>
          </Field>
        </div>
        {kind !== "all" ? (
          <Field label={kind === "namespace" ? "Namespace" : "Canonical identifier"} error={shown.value}>
            <Input mono value={value} disabled={pending} onChange={(event) => setValue(event.target.value)} placeholder={selectorPlaceholder(types, type, kind)} spellCheck={false} />
          </Field>
        ) : null}
        <Field label="Display name" optional>
          <Input value={name} disabled={pending} onChange={(event) => setName(event.target.value)} placeholder="Defaults to the resource coverage" />
        </Field>
        {fields.map((field) => (
          <div key={`${type}:${field.name}`}>
            <ResourceAttributeField
              field={field}
              configured={configured.includes(field.name)}
              value={attributes[field.name] ?? ""}
              busy={pending}
              onChange={(next) => setAttributes((current) => ({ ...current, [field.name]: next }))}
              onReveal={async () => (await attempt((current) => brokerApi.revealResourceAttribute(current, record!.id, field.name))).value}
            />
            {shown[field.name] ? <p className="wb-field-error">{shown[field.name]}</p> : null}
          </div>
        ))}
        <FieldGroup label="Allowed execution contexts" hint={shown.contexts ? <span className="pt-error">{shown.contexts}</span> : undefined}>
          <div className="pt-checks">
            {contexts.map((context) => (
              <Checkbox
                key={context}
                label={<span className="wb-mono">{context}</span>}
                checked={selectedContexts.includes(context)}
                disabled={pending}
                onChange={(event) => setContexts(event.target.checked ? [...selectedContexts, context] : selectedContexts.filter((item) => item !== context))}
              />
            ))}
            {selectedContexts
              .filter((context) => !contexts.includes(context))
              .map((context) => (
                <Checkbox key={context} label={<span className="wb-mono">{context}</span>} description="Not an allowed context" checked disabled={pending} onChange={() => setContexts(selectedContexts.filter((item) => item !== context))} />
              ))}
          </div>
        </FieldGroup>
        <Switch label="Enabled" checked={enabled} disabled={pending} onChange={(event) => setEnabled(event.target.checked)} />
        <p className="pt-prose wb-small">Changes affect existing grants and tokens. Disabled resources still apply when excluded by a group.</p>
        <CatalogMutationError error={error} />
      </AdminForm>
    </Drawer>
  );
}
