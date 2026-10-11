import { CatalogMutationError, CatalogUnavailableDrawer } from "./catalog-target";
import { useSession } from "../../app/session";
import { canWriteAdmin } from "../../lib/capabilities";
import { AdminButton, AdminForm } from "../../components/admin-access";
// Admin › Catalog › Resource groups: flat include/exclude sets of resources.
// URL-driven table (`?item=<id>`, `?item=new` to add) with a drawer for
// members, used-by, edit, and delete.
import { useId, useMemo, useState } from "react";
import type { ResourceGroupRecord, ResourceRecord } from "../../types";
import { resourceLabel } from "../../lib/resource-labels";
import { resourceTypeLabel, useResourceTypes, type ResourceTypes } from "../../lib/resource-types";
import { sortRows } from "../../lib/table-sort";
import { urlParam } from "../../lib/url-state";
import {
  AppLink,
  Banner,
  Button,
  DataTable,
  Drawer,
  DrawerSection,
  EmptyState,
  ErrorState,
  Field,
  FilterInput,
  Icon,
  Input,
  List,
  ListFooter,
  Main,
  Time,
  Toolbar,
  ToolbarRow,
  ToolbarSummary,
  plural,
  type DataColumn
} from "../../workbench";
import { ResourceChoices } from "../../components/resource-picker";
import { useTableUrlState } from "../../app/list-state";
import { paths } from "../../app/paths";
import { usePolicyStatus, useResourceCatalog, useResourceUsedBy } from "../../data/queries";
import { CatalogFrame } from "./catalog-frame";
import { MetaLine } from "./catalog-ui";
import { useResourceActions } from "./resource-actions";
import { UsedBySection } from "./used-by";

const SORT_KEYS = ["name", "includes", "excludes", "updated"] as const;

export const RESOURCE_GROUPS_STATE = {
  sort: urlParam.sort(SORT_KEYS),
  q: urlParam.text(),
  item: urlParam.text()
};

function memberText(types: ResourceTypes, byId: Map<string, ResourceRecord>, id: string) {
  const resource = byId.get(id);
  return resource ? `${resourceLabel(types, resource)} ${resource.id} ${resource.resourceType} ${resourceTypeLabel(types, resource.resourceType)}` : id;
}

function filterGroups(groups: ResourceGroupRecord[], types: ResourceTypes, byId: Map<string, ResourceRecord>, q: string) {
  const query = q.trim().toLowerCase();
  return groups.filter(
    (group) =>
      !query ||
      [group.name, group.id, ...[...group.includedResourceIds, ...group.excludedResourceIds].map((id) => memberText(types, byId, id))].join(" ").toLowerCase().includes(query)
  );
}

function useGroupsModel() {
  const writableActor = canWriteAdmin(useSession().session);
  const types = useResourceTypes();
  const query = useResourceCatalog();
  const status = usePolicyStatus();
  const resources = useMemo(() => query.data?.resources ?? [], [query.data]);
  const groups = useMemo(() => query.data?.resourceGroups ?? [], [query.data]);
  const byId = useMemo(() => new Map(resources.map((resource) => [resource.id, resource])), [resources]);
  const list = useTableUrlState(RESOURCE_GROUPS_STATE, "item");
  const shown = useMemo(
    () =>
      sortRows(
        filterGroups(groups, types, byId, list.state.q),
        list.state.sort,
        (group, key) =>
          key === "name" ? group.name : key === "includes" ? group.includedResourceIds.length : key === "excludes" ? group.excludedResourceIds.length : group.updatedAt,
        (a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id)
      ),
    [groups, types, byId, list.state.q, list.state.sort]
  );
  const creating = writableActor && list.openId === "new";
  const open = !creating && list.openId ? groups.find((group) => group.id === list.openId) ?? null : null;
  return {
    types,
    query,
    resources,
    groups,
    byId,
    shown,
    list,
    creating,
    open,
    writable: writableActor && Boolean(status.data?.writable),
    statusLoaded: Boolean(status.data),
    storageWritable: Boolean(status.data?.writable),
    loading: query.isPending && query.fetchStatus !== "idle"
  };
}

type GroupsModel = ReturnType<typeof useGroupsModel>;

export function ResourceGroupsPage() {
  const model = useGroupsModel();
  const drawer = model.creating ? <GroupEditorDrawer model={model} record={null} /> : model.open ? <GroupDrawer key={model.open.id} model={model} group={model.open} /> : model.list.openId ? <CatalogUnavailableDrawer kind="resource group" id={model.list.openId} loading={model.query.isPending || model.query.isFetching} error={model.query.isError ? model.query.error : null} retry={() => void model.query.refetch()} close={model.list.close} returnFocus={model.list.returnFocus} /> : null;
  return (
    <CatalogFrame section={{ kind: "groups" }} drawer={drawer}>
      <Main
        label="Resource groups"
        toolbar={<GroupsToolbar model={model} />}
        header={
          model.statusLoaded && !model.storageWritable ? (
            <div className="pt-header-banners">
              <Banner tone="info" slim>
                Policy writes are not enabled for this broker, so resource groups are read-only here.
              </Banner>
            </div>
          ) : null
        }
        refetching={model.query.isFetching && !model.loading}
      >
        <List full>
          <GroupTable model={model} />
          {model.shown.length > 0 ? <ListFooter /> : null}
        </List>
      </Main>
    </CatalogFrame>
  );
}

function GroupsToolbar({ model }: { model: GroupsModel }) {
  const { list, shown, groups, writable } = model;
  return (
    <Toolbar>
      <ToolbarRow
        primary={
          <AdminButton variant="primary" icon="plus" disabled={!writable} title={writable ? undefined : "Policy writes are not enabled."} onClick={() => list.open("new")}>
            Add resource group
          </AdminButton>
        }
      >
        <FilterInput value={list.state.q} onChange={(q) => list.setState({ q })} placeholder="Filter groups, members…" debounceMs={150} />
        <ToolbarSummary grow>
          <b>{shown.length}</b> of {groups.length} resource {plural(groups.length, "group")}
        </ToolbarSummary>
      </ToolbarRow>
    </Toolbar>
  );
}

/** Short member names; names shared by several members get their type ("DEMO (Jira project)"). */
function memberNames(types: ResourceTypes, byId: Map<string, ResourceRecord>, ids: string[]) {
  const names = ids.map((id) => {
    const resource = byId.get(id);
    return { resource, name: resource ? resource.displayName?.trim() || resourceLabel(types, resource) : id };
  });
  const seen = new Map<string, number>();
  for (const entry of names) seen.set(entry.name, (seen.get(entry.name) ?? 0) + 1);
  return names.map(({ resource, name }) => ((seen.get(name) ?? 0) > 1 && resource ? `${name} (${resourceTypeLabel(types, resource.resourceType)})` : name));
}

function memberSummary(group: ResourceGroupRecord) {
  return `${group.includedResourceIds.length} ${plural(group.includedResourceIds.length, "include")} · ${group.excludedResourceIds.length} ${plural(group.excludedResourceIds.length, "exclude")}`;
}

function GroupTable({ model }: { model: GroupsModel }) {
  const { query, loading, shown, groups, list, types, byId, writable } = model;
  const columns = useMemo<DataColumn<ResourceGroupRecord>[]>(
    () => [
      {
        key: "name",
        header: "Name",
        sortable: true,
        truncate: true,
        minWidth: "24ch",
        cell: (group) => group.name
      },
      {
        key: "id",
        header: "ID",
        priority: 3,
        className: "wb-cell-mono",
        hug: "22ch",
        cell: (group) => group.id
      },
      {
        key: "includes",
        header: "Includes",
        sortable: true,
        firstSortDir: "desc",
        align: "end",
        priority: 2,
        cell: (group) => (group.includedResourceIds.length ? group.includedResourceIds.length : <span className="wb-muted">0</span>)
      },
      {
        key: "excludes",
        header: "Excludes",
        sortable: true,
        firstSortDir: "desc",
        align: "end",
        priority: 3,
        cell: (group) => (group.excludedResourceIds.length ? group.excludedResourceIds.length : <span className="wb-muted">0</span>)
      },
      {
        key: "members",
        header: "Members",
        priority: 2,
        truncate: true,
        minWidth: "14ch",
        cell: (group) => {
          const included = memberNames(types, byId, group.includedResourceIds);
          const excluded = memberNames(types, byId, group.excludedResourceIds);
          if (!included.length) return <span className="wb-muted">No included resources</span>;
          const title = [`Includes: ${included.join(", ")}`, excluded.length ? `Excludes: ${excluded.join(", ")}` : null].filter(Boolean).join("\n");
          return <span title={title}>{included.join(", ")}</span>;
        }
      },
      {
        key: "updated",
        header: "Updated",
        sortable: true,
        firstSortDir: "desc",
        priority: 4,
        cell: (group) => (group.updatedAt ? <Time value={group.updatedAt} /> : null)
      }
    ],
    [types, byId]
  );
  const empty =
    list.state.q && groups.length > 0 ? (
      <EmptyState
        compact
        icon="search"
        title="No matching resource groups"
        actions={
          <Button icon="x" onClick={() => list.setState({ q: "" })}>
            Clear filters
          </Button>
        }
      >
        Adjust the search to show catalog entries.
      </EmptyState>
    ) : (
      <EmptyState
        compact
        icon="layers"
        title="No resource groups"
        actions={
          writable ? (
            <AdminButton variant="primary" icon="plus" onClick={() => list.open("new")}>
              Add resource group
            </AdminButton>
          ) : null
        }
      >
        Groups bundle resources so grants and token restrictions can select them together; exclusions carve resources back out.
      </EmptyState>
    );
  return (
    <DataTable
      label="Resource groups"
      rows={shown}
      rowId={(group) => group.id}
      columns={columns}
      sort={list.state.sort}
      onSortChange={(sort) => list.setState({ sort })}
      activeId={list.openId}
      rowHref={(group) => list.itemHref(group.id)}
      onRowFollow={(group) => list.open(group.id, "replace")}
      cursorResetKey={JSON.stringify([list.state.q, list.state.sort])}
      rowDim={(group) => group.includedResourceIds.length === 0}
      loading={loading || (query.isError && query.isFetching)}
      error={query.isError ? <ErrorState compact title="Couldn’t load resource groups" error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} /> : undefined}
      empty={empty}
      bleed
    />
  );
}

function Members({ ids, model, exclusion }: { ids: string[]; model: GroupsModel; exclusion: boolean }) {
  const { byId, types } = model;
  if (!ids.length) return <p className="pt-prose wb-small">None</p>;
  return (
    <ul className="pt-links">
      {ids.map((id) => {
        const resource = byId.get(id);
        return (
          <li key={id}>
            {resource ? (
              <AppLink href={paths.resources(id)} className="wb-link">
                {resourceLabel(types, resource)}
              </AppLink>
            ) : (
              <span className="wb-num">{id}</span>
            )}
            <div className="pt-clause-note">
              {resource ? (
                <MetaLine
                  parts={[
                    resourceTypeLabel(types, resource.resourceType),
                    exclusion ? null : <span className="wb-mono">{resource.allowedExecutionContexts.join(", ")}</span>,
                    !resource.enabled ? "Disabled" : null
                  ]}
                />
              ) : (
                "Not in the current catalog"
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function GroupDrawer({ model, group }: { model: GroupsModel; group: ResourceGroupRecord }) {
  const [editing, setEditing] = useState(false);
  if (editing) return <GroupEditorDrawer model={model} record={group} onDone={() => setEditing(false)} />;
  return <GroupDetailDrawer model={model} group={group} onEdit={() => setEditing(true)} />;
}

function GroupDetailDrawer({ model, group, onEdit }: { model: GroupsModel; group: ResourceGroupRecord; onEdit: () => void }) {
  const { list, writable } = model;
  const actions = useResourceActions();
  const usedBy = useResourceUsedBy("resource-groups", group.id);
  const stamp = group;
  const deletable = writable && usedBy.data !== undefined && usedBy.data.length === 0 && !usedBy.isFetching;
  return (
    <Drawer
      resetKey={group.id}
      onClose={list.close}
      returnFocus={list.returnFocus}
      label={`Resource group ${group.name}`}
      kicker={
        <>
          <Icon name="layers" /> Resource group <span className="wb-num">{group.id}</span>
        </>
      }
      title={group.name}
      meta={
        <>
          <span>{memberSummary(group)}</span>
          {stamp.updatedAt ? (
            <span>
              · updated <Time value={stamp.updatedAt} />
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
            variant="danger-ghost"
            icon="trash"
            disabled={!deletable}
            title={deletable ? undefined : writable ? "Remove every reference before deleting." : "Policy writes are not enabled."}
            onClick={() => actions.confirmDelete("resource-groups", group, group.name, list.close)}
          >
            Delete
          </AdminButton>
        </>
      }
    >
      <DrawerSection title="Includes" count={group.includedResourceIds.length}>
        <div className="pt-catalog-flow">
          <Members ids={group.includedResourceIds} model={model} exclusion={false} />
          {!group.includedResourceIds.length ? <p className="pt-prose wb-small">Empty groups provide no access.</p> : null}
        </div>
      </DrawerSection>
      <DrawerSection title="Excludes" count={group.excludedResourceIds.length}>
        <div className="pt-catalog-flow">
          <Members ids={group.excludedResourceIds} model={model} exclusion />
          <p className="pt-prose wb-small">
            Exclusions apply in every context, even for disabled resources. They win across all groups selected within a grant or token restriction.
          </p>
        </div>
      </DrawerSection>
      <UsedBySection query={usedBy} />
    </Drawer>
  );
}

function GroupEditorDrawer({ model, record, onDone }: { model: GroupsModel; record: ResourceGroupRecord | null; onDone?: () => void }) {
  const { list, resources } = model;
  const actions = useResourceActions();
  const formId = useId();
  const [name, setName] = useState(record?.name ?? "");
  const [included, setIncluded] = useState(record?.includedResourceIds ?? []);
  const [excluded, setExcluded] = useState(record?.excludedResourceIds ?? []);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [attempted, setAttempted] = useState(false);
  const nameError = attempted && !name.trim() ? "Enter a group name." : undefined;
  const close = () => (onDone ? onDone() : list.close());

  async function save() {
    setAttempted(true);
    if (!name.trim()) return;
    setPending(true);
    setError(null);
    try {
      const saved = await actions.saveGroup(
        { name: name.trim(), includedResourceIds: included, excludedResourceIds: excluded, ...(record ? { expectedVersion: record.version } : {}) },
        record?.id
      );
      if (record) close();
      else list.open(saved.id, "replace");
    } catch (failure) {
      setError(failure);
      setPending(false);
    }
  }

  return (
    <Drawer
      size="wide"
      resetKey={record?.id ?? "new"}
      onClose={close}
      returnFocus={record ? list.returnFocus : undefined}
      label={record ? `Edit resource group ${record.name}` : "Add resource group"}
      kicker={
        <>
          <Icon name="layers" /> {record ? <>Edit resource group <span className="wb-num">{record.id}</span></> : "New resource group"}
        </>
      }
      title={record ? record.name : "Add resource group"}
      footer={
        <>
          <span>
            {included.length} {plural(included.length, "include")} · {excluded.length} {plural(excluded.length, "exclude")}
          </span>
          <span className="wb-spacer" />
          <Button onClick={close} disabled={pending}>
            Cancel
          </Button>
          <AdminButton type="submit" form={formId} variant="primary" pending={pending}>
            Save resource group
          </AdminButton>
        </>
      }
    >
      <AdminForm
        id={formId}
        className="pt-form pt-catalog-form pt-catalog-drawer-form"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <Field label="Group name" error={nameError}>
          <Input value={name} disabled={pending} onChange={(event) => setName(event.target.value)} />
        </Field>
        <div className="pt-columns pt-catalog-member-columns">
          <fieldset className="pt-fieldset">
            <legend>Included resources</legend>
            <ResourceChoices resources={resources} selected={included} onChange={setIncluded} disabled={pending} label="Filter included resources" />
          </fieldset>
          <fieldset className="pt-fieldset">
            <legend>Excluded resources</legend>
            <ResourceChoices resources={resources} selected={excluded} onChange={setExcluded} disabled={pending} label="Filter excluded resources" />
            <p className="pt-prose wb-small">
              Exclusions apply in every context, even for disabled resources. They win across all groups selected within a grant or token restriction.
            </p>
          </fieldset>
        </div>
        <p className="pt-prose wb-small">Membership changes affect existing grants and tokens. Empty groups provide no access.</p>
        <CatalogMutationError error={error} />
      </AdminForm>
    </Drawer>
  );
}
