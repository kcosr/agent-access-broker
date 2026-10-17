import { RECEIVER_NOTICE } from "../../lib/imports";
import { AdminIconButton, AdminButton } from "../../components/admin-access";
// A service page's Actions tab: every action from the policy catalog; for an
// imported service, every accepted action record with its status, OpenAPI
// operation or who checks a command action's resources, label, and
// enable/disable/retire controls. Rows open a drawer.
import { useMemo, type ReactNode } from "react";
import type { ImportActionRecord, ImportActionStatus, ImportPreviewResult, ImportResourceTypeDeclaration } from "../../import-types";
import type { PolicyActionCatalog } from "../../types";
import { ACTION_GRANT_LABEL } from "../../lib/helpers";
import { availabilityRequirementText } from "../../lib/availability";
import { openApiOperation, openApiSchemeLabel } from "../../lib/import-openapi";
import { COMMAND_CHECK_CAVEAT, COMMAND_KIND, commandResourceCheck, resourceCheckParts, resourceCheckText } from "../../lib/import-command";
import { groupRows, sortRows } from "../../lib/table-sort";
import { urlParam } from "../../lib/url-state";
import { Badge, Banner, Button, type DataColumn, DataTable, Disclosure, Drawer, DrawerSection, EmptyState, FilterInput, Icon, KeyValue, List, ListFooter, plural, Seg, type SortState, StateCell, StatePill, TableGroupHeader, type Tone, Toolbar, ToolbarRow, ToolbarSummary } from "../../workbench";
import { GroupMenu } from "../../components/table-cells";
import { useTableUrlState } from "../../app/list-state";
import { paths } from "../../app/paths";
import { ACTION_STATUS, type CatalogService } from "./catalog-data";
import { LongText } from "./catalog-ui";
import { STATUS_VERB, useImportActions, type ActionStatusChange } from "./import-actions";

const EFFECTS = ["all", "read", "write"] as const;
const SORT_KEYS = ["action", "status"] as const;
const GROUPINGS = ["none", "namespace", "status"] as const;
type Grouping = (typeof GROUPINGS)[number];

export const ACTIONS_STATE = {
  effect: urlParam.oneOf(EFFECTS, "all"),
  sort: urlParam.sort(SORT_KEYS),
  group: urlParam.oneOf(GROUPINGS, "none"),
  q: urlParam.text(),
  action: urlParam.text()
};

export type ActionRow = {
  action: string;
  label: string | null;
  description: string;
  readOnly: boolean;
  /** Imported actions only. */
  record: ImportActionRecord | null;
  status: ImportActionStatus | null;
  catalog: PolicyActionCatalog | null;
};

const STATUS_ORDER: ImportActionStatus[] = ["enabled", "quarantined", "disabled", "retired"];

/** Catalog actions, or an imported service's action records merged with their catalog entries. */
export function serviceActionRows(service: CatalogService): ActionRow[] {
  const catalogActions = new Map((service.catalog?.actions ?? []).map((action) => [action.action, action]));
  if (service.imported) {
    return service.imported.actions.map((record) => ({
      action: record.definition.action,
      label: record.definition.label?.trim() || null,
      description: record.definition.description,
      readOnly: record.definition.readOnly,
      record,
      status: record.status,
      catalog: catalogActions.get(record.definition.action) ?? null
    }));
  }
  return (service.catalog?.actions ?? []).map((action) => ({
    action: action.action,
    label: null,
    description: action.description,
    readOnly: action.readOnly,
    record: null,
    status: null,
    catalog: action
  }));
}

/**
 * Who checks an imported action's resources: the policy catalog's
 * `resourcesCheckedBy` when the Broker reports it, with the type and inputs
 * from the action's declaration.
 */
function actionResourceCheck(row: ActionRow) {
  const check = commandResourceCheck(row.record!.definition);
  return row.catalog?.resourcesCheckedBy ? { ...check, by: row.catalog.resourcesCheckedBy } : check;
}

/** The resource types a command import has accepted, for its actions' "Resources checked by". */
function commandTypes(service: CatalogService | null): readonly ImportResourceTypeDeclaration[] | null {
  return service?.imported?.definition.adapterKind === COMMAND_KIND ? service.imported.acceptedMetadata?.resourceTypes ?? [] : null;
}

function filterRows(rows: ActionRow[], state: { effect: string; q: string }, types: readonly ImportResourceTypeDeclaration[] | null) {
  const query = state.q.trim().toLowerCase();
  return rows.filter((row) => {
    if (state.effect === "read" && !row.readOnly) return false;
    if (state.effect === "write" && row.readOnly) return false;
    if (!query) return true;
    const operation = row.record ? openApiOperation(row.record.definition) : null;
    const checked = row.record && types ? resourceCheckText(actionResourceCheck(row), types) : null;
    return [row.action, row.label, row.description, row.status, operation ? `${operation.method} ${operation.path}` : null, checked, ...Object.keys(row.catalog?.requiredScopes ?? {})]
      .filter(Boolean)
      .join(" ")
      .toLowerCase()
      .includes(query);
  });
}

/** An action's state: an imported action's status, else whether the broker can execute it. */
function actionState(row: ActionRow): { label: string; tone: Tone; quiet: boolean; rank: number; reason?: string | undefined } {
  if (row.status && row.status !== "enabled") {
    return { ...ACTION_STATUS[row.status], quiet: false, rank: STATUS_ORDER.indexOf(row.status) + 1 };
  }
  if (row.catalog?.available === false) return { label: "Unavailable", tone: "warning", quiet: false, rank: 1, reason: row.catalog.unavailableReason };
  return { label: row.status ? ACTION_STATUS.enabled.label : "Available", tone: "success", quiet: true, rank: 0 };
}

/** The namespace group of each action (`issue.*`); actions alone in their namespace gather under "" (Other actions). */
function namespaceKeys(rows: ActionRow[]) {
  const prefix = (action: string) => (action.includes(".") ? action.slice(0, action.indexOf(".")) : "");
  const sizes = new Map<string, number>();
  for (const row of rows) sizes.set(prefix(row.action), (sizes.get(prefix(row.action)) ?? 0) + 1);
  return new Map(rows.map((row) => {
    const key = prefix(row.action);
    return [row.action, key && (sizes.get(key) ?? 0) > 1 ? key : ""];
  }));
}

/**
 * Actions in table order: the chosen sort, else imported actions by status
 * and built-in actions in catalog order; regrouped by namespace ("Other
 * actions" last) or by status when grouped.
 */
function orderActions(rows: ActionRow[], sort: SortState | null, grouping: Grouping, namespaces: Map<string, string>) {
  const sorted = sortRows(
    rows,
    sort,
    (row, key) => (key === "action" ? row.action : actionState(row).rank),
    (a, b) => actionState(a).rank - actionState(b).rank
  );
  if (grouping === "namespace") {
    return groupRows(sorted, (row) => namespaces.get(row.action) ?? "", (a, b) => (a === "") !== (b === "") ? (a === "" ? 1 : -1) : a.localeCompare(b));
  }
  if (grouping === "status") {
    return groupRows(sorted, (row) => row.status ?? "", (a, b) => STATUS_ORDER.indexOf(a as ImportActionStatus) - STATUS_ORDER.indexOf(b as ImportActionStatus));
  }
  return sorted;
}

/** Rows, filters, and the open action for one service. */
export function useServiceActions(service: CatalogService | null) {
  const all = useMemo(() => (service ? serviceActionRows(service) : []), [service]);
  const imported = Boolean(service?.imported);
  const list = useTableUrlState(ACTIONS_STATE, "action");
  // Only imported actions have a status to group by.
  const grouping: Grouping = list.state.group === "status" && !imported ? "none" : list.state.group;
  const namespaces = useMemo(() => namespaceKeys(all), [all]);
  const types = useMemo(() => commandTypes(service), [service]);
  const shown = useMemo(
    () => orderActions(filterRows(all, list.state, types), list.state.sort, grouping, namespaces),
    [all, list.state, types, grouping, namespaces]
  );
  const open = list.openId ? all.find((row) => row.action === list.openId) ?? null : null;
  const counts = { all: all.length, read: all.filter((row) => row.readOnly).length, write: all.filter((row) => !row.readOnly).length };
  return { service, all, shown, open, list, counts, grouping, namespaces };
}

export type ServiceActionsModel = ReturnType<typeof useServiceActions>;

export function ActionsToolbar({ model }: { model: ServiceActionsModel }) {
  const { list, counts, shown, grouping, service } = model;
  return (
    <Toolbar>
      <ToolbarRow>
        <Seg
          label="Action effects"
          value={list.state.effect}
          onChange={(effect) => list.setState({ effect, action: "" })}
          options={[
            { value: "all", label: "All", count: counts.all },
            { value: "read", label: "Read-only", icon: "eye", count: counts.read },
            { value: "write", label: "Write-capable", icon: "pencil", count: counts.write }
          ]}
        />
        <FilterInput value={list.state.q} onChange={(q) => list.setState({ q })} placeholder="Filter actions…" debounceMs={150} />
        <GroupMenu
          value={grouping}
          options={[{ value: "namespace" as const, label: "Namespace" }, ...(service?.imported ? [{ value: "status" as const, label: "Status" }] : [])]}
          onChange={(group) => list.setState({ group })}
        />
        {/* Not grow: the count stays beside the filter and Group when a drawer narrows the pane. */}
        <ToolbarSummary>
          <b>{shown.length}</b> {plural(shown.length, "action")}
        </ToolbarSummary>
      </ToolbarRow>
    </Toolbar>
  );
}

/** Attention banners above the actions table. */
export function ActionsBanners({ model }: { model: ServiceActionsModel }) {
  if (!model.service?.imported?.actions.some((action) => action.status === "quarantined")) return null;
  return (
    <div className="pt-header-banners">
      <Banner tone="warning" slim>
        Quarantined actions require a new discovery review before they can be enabled.
      </Banner>
    </div>
  );
}

/** Status changes an imported action can make now, and why enabling is blocked. */
export function actionTransitions(row: ActionRow, data: ImportPreviewResult | null) {
  const allowed = data?.operatorAllowed === true && data.service.status !== "retired";
  const serviceRetired = data?.service.status === "retired";
  return (["enabled", "disabled", "retired"] as const)
    .filter((status) => status !== row.status)
    .map((status) => ({
      status,
      disabled: !data || serviceRetired || row.status === "retired" || (status === "enabled" && (!allowed || row.status === "quarantined"))
    }));
}

const TRANSITION_ICON = { enabled: "play", disabled: "pause", retired: "ban" } as const;

function scopeCell(row: ActionRow) {
  const scopes = Object.keys(row.catalog?.requiredScopes ?? {});
  if (scopes.length) return scopes.join(", ");
  return row.catalog ? <span className="wb-muted">{ACTION_GRANT_LABEL}</span> : <span className="wb-muted">—</span>;
}

/** The label (when it adds to the action name) and the description on one line. */
function describe(row: ActionRow) {
  const label = row.label && row.label !== row.action ? row.label : null;
  const description = row.description.trim().split("\n")[0] ?? "";
  if (!label && !description) return <span className="wb-muted">—</span>;
  return (
    <span title={[label, row.description.trim()].filter(Boolean).join(" — ")}>
      {label}
      {label && description ? " · " : null}
      {description ? <span className={label ? "wb-muted" : undefined}>{description}</span> : null}
    </span>
  );
}

/** "Broker" or "Command", with the type the action's resources are checked against. */
function checkedByCell(row: ActionRow, types: readonly ImportResourceTypeDeclaration[]) {
  if (!row.record) return <span className="wb-muted">—</span>;
  const check = actionResourceCheck(row);
  const parts = resourceCheckParts(check, types);
  return (
    <span title={check.by === "command" ? COMMAND_CHECK_CAVEAT : undefined}>
      {check.by === "broker" ? "Broker" : "Command"}
      <span className="wb-muted"> · {parts.type ?? "no resource type"}</span>
    </span>
  );
}

function actionColumns({
  operations,
  scopes,
  commandTypes: types,
  rowActions
}: {
  operations: boolean;
  scopes: boolean;
  /** A command import's accepted types: adds "Resources checked by". */
  commandTypes: readonly ImportResourceTypeDeclaration[] | null;
  rowActions: ((row: ActionRow) => ReactNode) | null;
}): DataColumn<ActionRow>[] {
  return [
    {
      key: "action",
      header: "Action",
      sortable: true,
      // Action names are identifiers: they hug, up to a cap (full name on
      // hover); the description takes the spare width.
      hug: "40ch",
      className: "wb-cell-mono",
      cell: (row) => row.action
    },
    {
      key: "description",
      header: "Description",
      priority: 3,
      truncate: true,
      minWidth: "14ch",
      grow: 2,
      cell: describe
    },
    {
      key: "effect",
      header: "Effect",
      priority: 2,
      cell: (row) => (row.readOnly ? <span className="wb-muted">Read-only</span> : <Badge tone="warning">Writes</Badge>)
    },
    ...(operations
      ? [
          {
            key: "operation",
            header: "Operation",
            priority: 3,
            truncate: true,
            minWidth: "12ch",
            className: "wb-cell-mono",
            cell: (row: ActionRow) => {
              const operation = row.record ? openApiOperation(row.record.definition) : null;
              return operation ? <span title={`${operation.method} ${operation.path}`}>{`${operation.method} ${operation.path}`}</span> : <span className="wb-muted">—</span>;
            }
          } satisfies DataColumn<ActionRow>
        ]
      : []),
    ...(scopes
      ? [
          {
            key: "scope",
            header: "Scope",
            priority: 3,
            cell: scopeCell
          } satisfies DataColumn<ActionRow>
        ]
      : []),
    ...(types
      ? [
          {
            key: "checked-by",
            header: "Resources checked by",
            priority: 2,
            truncate: true,
            minWidth: "12ch",
            cell: (row: ActionRow) => checkedByCell(row, types)
          } satisfies DataColumn<ActionRow>
        ]
      : []),
    {
      key: "credentials",
      header: "Credentials",
      priority: 4,
      className: "wb-cell-mono",
      cell: (row) => (row.catalog?.credentialModes.length ? row.catalog.credentialModes.join(", ") : <span className="wb-muted">—</span>)
    },
    {
      key: "status",
      header: "Status",
      sortable: true,
      cell: (row) => {
        const state = actionState(row);
        return <StateCell label={state.label} tone={state.tone} quiet={state.quiet} title={state.reason} />;
      }
    },
    ...(rowActions
      ? [
          {
            key: "row-actions",
            header: <span className="wb-sr-only">Row actions</span>,
            className: "wb-cell-actions",
            cell: rowActions
          } satisfies DataColumn<ActionRow>
        ]
      : [])
  ];
}

function groupTitle(grouping: Grouping, key: string): ReactNode {
  if (grouping === "status") return ACTION_STATUS[key as ImportActionStatus]?.label ?? key;
  return key ? <span className="wb-mono">{key}.*</span> : "Other actions";
}

function ActionTable({ model, data, error, retrying }: { model: ServiceActionsModel; data: ImportPreviewResult | null; error?: ReactNode; retrying: boolean }) {
  const { service, shown, all, list, grouping, namespaces } = model;
  const actions = useImportActions();
  const imported = Boolean(service?.imported);
  const operations = useMemo(() => all.some((row) => row.record && openApiOperation(row.record.definition)), [all]);
  const types = useMemo(() => commandTypes(service), [service]);
  const columns = useMemo(
    () =>
      actionColumns({
        operations,
        // Imported actions carry no catalog scope column: MCP and OpenAPI
        // actions are action grants, and command actions show who checks
        // their resources instead.
        scopes: !imported,
        commandTypes: types,
        rowActions: imported
          ? (row) =>
              row.record && data ? (
                <div className="wb-row-actions">
                  {actionTransitions(row, data).map((transition) => (
                    <AdminIconButton
                      key={transition.status}
                      size="sm"
                      icon={TRANSITION_ICON[transition.status]}
                      label={`${STATUS_VERB[transition.status]} ${row.action}`}
                      disabled={transition.disabled}
                      onClick={() => actions.confirmActionStatus(data, row.action, transition.status)}
                    />
                  ))}
                </div>
              ) : null
          : null
      }),
    [operations, imported, types, data, actions]
  );
  if (!service) return null;
  const empty = !all.length ? (
    <EmptyState
      compact
      icon="list"
      title={service.imported ? "No actions accepted yet." : "No actions"}
      actions={
        service.imported ? (
          <Button icon="download" href={paths.catalogService(service.service, "import")}>
            Open Import
          </Button>
        ) : null
      }
    >
      {service.imported ? "Discover the upstream tools or operations on the Import tab, then review and accept them." : "This service publishes no actions."}
    </EmptyState>
  ) : (
    <EmptyState
      compact
      icon="search"
      title="No matching actions"
      actions={
        <Button icon="x" onClick={() => list.setState({ q: "", effect: "all" })}>
          Clear filters
        </Button>
      }
    >
      Try another effect or search.
    </EmptyState>
  );
  const { sort, group, action: _open, ...filters } = list.state;
  return (
    <DataTable
      label={`${service.displayName} actions`}
      rows={shown}
      rowId={(row) => row.action}
      columns={columns}
      sort={sort}
      onSortChange={(next) => list.setState({ sort: next })}
      groupBy={grouping === "namespace" ? (row) => namespaces.get(row.action) ?? "" : grouping === "status" ? (row) => row.status ?? "" : undefined}
      groupHeader={({ key, rows }) => <TableGroupHeader title={groupTitle(grouping, key)} count={`${rows.length} ${plural(rows.length, "action")}`} />}
      activeId={list.openId}
      rowHref={(row) => list.itemHref(row.action)}
      onRowFollow={(row) => list.open(row.action, "replace")}
      cursorResetKey={JSON.stringify({ filters, sort, group })}
      rowDim={(row) => row.status === "disabled" || row.status === "retired"}
      empty={empty}
      loading={retrying}
      error={error}
      bleed
    />
  );
}

export function ActionDrawer({ model, data }: { model: ServiceActionsModel; data: ImportPreviewResult | null }) {
  const { open, service, list } = model;
  const actions = useImportActions();
  if (!open || !service) return null;
  const operation = open.record ? openApiOperation(open.record.definition) : null;
  const types = commandTypes(service);
  const check = open.record && types ? actionResourceCheck(open) : null;
  const checkParts = check && types ? resourceCheckParts(check, types) : null;
  const checkType = check?.type ? types?.find((type) => type.id === check.type) : undefined;
  const transitions = open.record && data ? actionTransitions(open, data) : [];
  const status = open.status ? ACTION_STATUS[open.status] : null;
  const inputSchema = open.record?.definition.inputSchema ?? open.catalog?.inputSchema;
  return (
    <Drawer
      resetKey={open.action}
      onClose={list.close}
      returnFocus={list.returnFocus}
      label={`Action ${open.action}`}
      kicker={
        <>
          <Icon name={open.readOnly ? "eye" : "pencil"} /> Action <span className="wb-num">{service.service}</span>
        </>
      }
      title={<span className="pt-title-mono">{open.action}</span>}
      meta={
        <>
          {status ? (
            <StatePill tone={status.tone} icon={status.icon}>
              {status.label}
            </StatePill>
          ) : null}
          {open.readOnly ? <Badge tone="success">Read-only</Badge> : <Badge tone="warning">Write-capable</Badge>}
          {open.label && open.label !== open.action ? <span>{open.label}</span> : null}
        </>
      }
      actions={
        transitions.length && data ? (
          <>
            {transitions.map((transition) => (
              <AdminButton
                key={transition.status}
                icon={TRANSITION_ICON[transition.status]}
                variant={transition.status === "retired" ? "danger-ghost" : "default"}
                disabled={transition.disabled}
                onClick={() => actions.confirmActionStatus(data, open.action, transition.status as ActionStatusChange)}
              >
                {STATUS_VERB[transition.status]}
              </AdminButton>
            ))}
          </>
        ) : null
      }
    >
      {open.catalog?.available === false ? (
        <DrawerSection title="Availability">
          <Banner tone="warning" slim>
            {open.catalog.unavailableReason ?? "This action cannot currently execute."}
            {open.catalog.availabilityRequirements?.length ? (
              <ul>{open.catalog.availabilityRequirements.map((requirement) => (
                <li key={`${requirement.kind}:${requirement.reason}`}>{availabilityRequirementText(requirement)}</li>
              ))}</ul>
            ) : null}
          </Banner>
        </DrawerSection>
      ) : null}
      {open.status === "quarantined" ? (
        <DrawerSection title="Quarantined">
          <p className="pt-prose">This action changed or disappeared upstream. Review a new discovery preview on the Import tab before enabling it again.</p>
        </DrawerSection>
      ) : null}
      <DrawerSection title="Details">
        <KeyValue
          labelWidth={150}
          items={[
            { label: "Action", value: <span className="wb-num">{open.action}</span> },
            open.label ? { label: "Label", value: open.label } : null,
            { label: "Effects", value: open.readOnly ? "Reviewed read-only" : "Write-capable" },
            open.catalog
              ? {
                  label: "Required scopes",
                  value: Object.keys(open.catalog.requiredScopes).length ? <span className="wb-mono">{Object.entries(open.catalog.requiredScopes).map(([name, scope]) => `${name}: ${scope.resourceType}`).join(", ")}</span> : ACTION_GRANT_LABEL
                }
              : null,
            open.catalog ? { label: "Credential modes", value: <span className="wb-mono">{open.catalog.credentialModes.join(", ") || "none"}</span> } : null,
            open.catalog?.lookupRequired ? { label: "Lookup", value: "Requires the lookup credential" } : null,
            open.record ? { label: "Version", value: <span className="wb-num">{open.record.version}</span> } : null
          ]}
        />
      </DrawerSection>
      {open.record?.secretInputs.length ? <DrawerSection title="Secret receiver fields"><p className="pt-prose wb-mono">{open.record.secretInputs.map(({ pointer }) => pointer).join(", ")}</p><Banner tone="warning" slim>{RECEIVER_NOTICE}</Banner></DrawerSection> : null}
      {open.description.trim() ? (
        <DrawerSection title="Description">
          <LongText text={open.description} subject={open.action} />
        </DrawerSection>
      ) : null}
      {operation ? (
        <DrawerSection title="OpenAPI operation">
          <KeyValue
            labelWidth={150}
            items={[
              { label: "Operation", value: <span className="wb-mono">{`${operation.method} ${operation.path}`}</span> },
              operation.security ? { label: "Security", value: openApiSchemeLabel(operation.security) } : null
            ]}
          />
        </DrawerSection>
      ) : null}
      {check && checkParts ? (
        <DrawerSection title="Resources">
          <KeyValue
            labelWidth={150}
            items={[
              { label: "Checked by", value: check.by === "broker" ? "Broker" : "Command" },
              {
                label: "Resource type",
                value: checkParts.type ? (
                  <>
                    {checkParts.type} {checkType ? <span className="wb-mono wb-muted">{checkType.brokerType}</span> : null}
                  </>
                ) : (
                  <span className="wb-muted">No resource type: grants cover the whole action</span>
                )
              },
              checkParts.inputs.length ? { label: "From inputs", value: <span className="wb-mono">{checkParts.inputs.join(", ")}</span> } : null
            ]}
          />
          <p className="pt-prose wb-small">
            {check.by === "broker"
              ? "The Broker resolves these inputs against the resource catalog and grants, and denies the call before the command starts unless a grant covers every value."
              : COMMAND_CHECK_CAVEAT}
          </p>
        </DrawerSection>
      ) : null}
      {inputSchema || open.record ? (
        <DrawerSection title="Schemas">
          {inputSchema ? (
            <Disclosure summary={open.record ? "Source input schema" : "Input schema"}>
              <pre className="wb-code pt-catalog-code">{JSON.stringify(inputSchema, null, 2)}</pre>
            </Disclosure>
          ) : null}
          {open.record?.secretInputs.length && open.catalog?.inputSchema ? <Disclosure summary="Broker input schema"><pre className="wb-code pt-catalog-code">{JSON.stringify(open.catalog.inputSchema, null, 2)}</pre></Disclosure> : null}
          {open.record ? (
            <Disclosure summary="Source and annotations">
              <pre className="wb-code pt-catalog-code">
                {JSON.stringify({ source: open.record.definition.source, outputSchema: open.record.definition.outputSchema, annotations: open.record.definition.annotations }, null, 2)}
              </pre>
            </Disclosure>
          ) : null}
        </DrawerSection>
      ) : null}
    </Drawer>
  );
}

/** `error`: a failed catalog refresh, shown above the (stale) actions; `retrying` while it runs again. */
export function ActionsList({ model, data, error, retrying = false }: { model: ServiceActionsModel; data: ImportPreviewResult | null; error?: ReactNode; retrying?: boolean }) {
  return (
    <List full>
      <ActionTable model={model} data={data} error={error} retrying={retrying} />
      {model.shown.length > 0 ? <ListFooter /> : null}
    </List>
  );
}
