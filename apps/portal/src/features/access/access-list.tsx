// Effective agent access for the signed-in user (My access › Access) or an
// administered principal (the user page's Access tab): services, their
// actions per execution context, resource scope, and a detail drawer.
import { useId, useMemo } from "react";
import type { AgentTokenOptions, CredentialMetadata, CredentialTarget } from "../../types";
import { buildAccessSummary, serviceDisplayNames } from "../../lib/access";
import { ACTION_GRANT_LABEL, credentialStatus, credentialTone, credentialsByTarget } from "../../lib/helpers";
import { clauseLabel } from "../../lib/resource-labels";
import { useResourceTypes } from "../../lib/resource-types";
import { urlParam } from "../../lib/url-state";
import { actionEffectsParam, matchesActionEffects, type ActionEffect } from "../../lib/action-effects";
import { ActionEffectsFilter } from "../../components/action-effects-filter";
import {
  AppLink,
  Badge,
  Button,
  DataTable,
  Drawer,
  DrawerSection,
  EmptyState,
  ErrorState,
  FilterInput,
  Icon,
  KeyValue,
  ListFooter,
  Seg,
  Sidebar,
  SidebarItem,
  SidebarSection,
  TableGroupHeader,
  Toolbar,
  ToolbarRow,
  ToolbarSummary,
  plural,
  type DataColumn
} from "../../workbench";
import { GroupMenu } from "../../components/table-cells";
import { groupRows, sortRows } from "../../lib/table-sort";
import type { AccountSubject } from "../../app/active-route";
import { useTableUrlState } from "../../app/list-state";
import { paths } from "../../app/paths";
import { useAgentTokenOptions, useConsoleData } from "../../data/queries";
import { useAgentTokenActions } from "../../mutations/tokens";
import { AccessClauses } from "../../components/effective-access";

const GROUPINGS = ["none", "service"] as const;

export const ACCESS_STATE = {
  sort: urlParam.sort(["action", "service"]),
  group: urlParam.oneOf(GROUPINGS, "none"),
  service: urlParam.text(),
  context: urlParam.text(),
  effect: actionEffectsParam,
  q: urlParam.text(),
  action: urlParam.text()
};

export type AccessRow = {
  key: string;
  service: string;
  action: string;
  description: string;
  contexts: string[];
  resourceType: string | null;
  clauses: ReturnType<typeof buildAccessSummary>[number]["actions"][number]["clauses"];
  resourceLabels: string[];
  /** Explicitly classified read-only (from the token options); anything else may write. */
  readOnly: boolean;
};

type ServiceSummary = {
  service: string;
  displayName: string;
  /** Hosts agents use for a gateway service; empty otherwise. */
  brokerHosts: string[];
  target: CredentialTarget | undefined;
  credential: CredentialMetadata | undefined;
};

/** Table rows for the effective access in one execution context (or all). */
export function accessRows(options: AgentTokenOptions | null, context: string | null, types: ReturnType<typeof useResourceTypes>): AccessRow[] {
  if (!options) return [];
  return buildAccessSummary(options, context).flatMap((service) =>
    service.actions.map((action) => ({
      key: `${service.service}:${action.action}:${action.contexts.join(",")}`,
      service: service.service,
      action: action.action,
      description: action.description,
      contexts: action.contexts,
      resourceType: action.resourceType,
      clauses: action.clauses,
      resourceLabels: action.resourceType === null ? [ACTION_GRANT_LABEL] : action.clauses.map((clause) => clauseLabel(types, action.resourceType!, clause)),
      readOnly: action.readOnly
    }))
  );
}

/** Rows, filters, sidebar, and drawer for one principal's effective access. */
export function useAccessList(subject: AccountSubject) {
  const types = useResourceTypes();
  const data = useConsoleData(subject);
  const options = useAgentTokenOptions(subject);
  const tokenActions = useAgentTokenActions(subject, options.options);
  const contexts = options.options?.executionContexts ?? [];
  const byTarget = useMemo(() => credentialsByTarget(data.credentials), [data.credentials]);
  // Services with granted actions, named from the token options (not agent discovery).
  const services = useMemo<ServiceSummary[]>(() => {
    const names = serviceDisplayNames(options.options, data.targets);
    return (options.options?.services ?? [])
      .map((option) => {
        const target = data.targets.find((item) => item.service === option.service);
        return {
          service: option.service,
          displayName: names.get(option.service) ?? option.service,
          brokerHosts: option.brokerHosts,
          target,
          credential: target ? byTarget.get(`${target.service}/${target.credentialName}`) : undefined
        };
      })
      .sort((a, b) => a.displayName.localeCompare(b.displayName));
  }, [options.options, data.targets, byTarget]);

  const list = useTableUrlState(ACCESS_STATE, "action");
  const context = contexts.includes(list.state.context) ? list.state.context : null;
  const allRows = useMemo(() => accessRows(options.options, context, types), [options.options, context, types]);
  const grouped = list.state.group === "service";
  const shown = useMemo(() => {
    const serviceName = (service: string) => services.find((item) => item.service === service)?.displayName ?? service;
    const byService = (a: string, b: string) => serviceName(a).localeCompare(serviceName(b)) || a.localeCompare(b);
    const sorted = sortRows(
      filterAccessRows(allRows, list.state, services),
      list.state.sort,
      (row, key) => (key === "action" ? row.action : serviceName(row.service)),
      (a, b) => byService(a.service, b.service) || a.action.localeCompare(b.action)
    );
    return grouped ? groupRows(sorted, (row) => row.service, byService) : sorted;
  }, [allRows, list.state, services, grouped]);
  // Facet counts honor the other filters, ignoring their own selection.
  const effectCounts = useMemo(() => {
    const rows = filterAccessRows(allRows, { ...list.state, effect: [] }, services);
    return { read: rows.filter((row) => row.readOnly).length, write: rows.filter((row) => !row.readOnly).length };
  }, [allRows, list.state, services]);
  const serviceRows = useMemo(() => filterAccessRows(allRows, { ...list.state, service: "" }, services), [allRows, list.state, services]);
  const everyRow = useMemo(() => accessRows(options.options, null, types), [options.options, types]);
  const open = list.openId ? everyRow.find((row) => row.key === list.openId) ?? allRows.find((row) => row.key === list.openId) ?? null : null;
  /** Switches the context, dropping a service filter the new context has no actions for. */
  const setContext = (next: string) => {
    const keepService = !list.state.service || !options.options || buildAccessSummary(options.options, next || null).some((item) => item.service === list.state.service);
    list.setState({ context: next, action: "", ...(keepService ? {} : { service: "" }) });
  };
  return { subject, data, options, tokenActions, contexts, context, services, allRows, shown, open, list, setContext, grouped, effectCounts, serviceRows };
}

export function filterAccessRows(rows: AccessRow[], state: { service: string; q: string; effect: readonly ActionEffect[] }, services: Pick<ServiceSummary, "service" | "displayName">[]) {
  const query = state.q.trim().toLowerCase();
  return rows.filter((row) => {
    if (state.service && row.service !== state.service) return false;
    if (!matchesActionEffects(row.readOnly, state.effect)) return false;
    if (!query) return true;
    const name = services.find((service) => service.service === row.service)?.displayName ?? "";
    return [row.service, name, row.action, row.description, ...row.contexts, ...row.resourceLabels].join(" ").toLowerCase().includes(query);
  });
}

export type AccessListModel = ReturnType<typeof useAccessList>;

export function AccessSidebar({ model }: { model: AccessListModel }) {
  const { list, services, serviceRows, contexts, effectCounts } = model;
  const contextName = useId();
  const count = (service: string) => serviceRows.filter((row) => row.service === service).length;
  return (
    <Sidebar label="Access filters">
      <SidebarSection title="Execution context">
        <div role="radiogroup" aria-label="Execution context">
          {[{ value: "", label: "All contexts" }, ...contexts.map((context) => ({ value: context, label: context }))].map(({ value, label }) => (
            <label key={value} className="flex items-center gap-2 px-3 py-1.5 cursor-pointer wb-small">
              <input className="shrink-0" type="radio" name={contextName} value={value} checked={(model.context ?? "") === value} onChange={() => model.setContext(value)} />
              <span className="min-w-0 break-words">{label}</span>
            </label>
          ))}
        </div>
      </SidebarSection>
      <ActionEffectsFilter value={list.state.effect} counts={effectCounts} onChange={(effect) => list.setState({ effect, action: "" })} />
      <SidebarSection title="Services">
        <SidebarItem icon="layers" label="All services" count={serviceRows.length} current={!list.state.service} onClick={() => list.setState({ service: "", action: "" })} />
        {services.map((service) => (
          <SidebarItem
            key={service.service}
            icon="package"
            label={service.displayName}
            title={service.service}
            count={count(service.service)}
            current={list.state.service === service.service}
            onClick={() => list.setState({ service: list.state.service === service.service ? "" : service.service, action: "" })}
          />
        ))}
      </SidebarSection>
    </Sidebar>
  );
}

export function AccessToolbar({ model, embedded = false }: { model: AccessListModel; embedded?: boolean }) {
  const { list, contexts, shown, options, tokenActions } = model;
  const effectCountsId = useId();
  const blocker = options.loading ? "Loading token options…" : tokenActions.issueBlocker();
  const serviceCount = new Set(shown.map((row) => row.service)).size;
  return (
    <Toolbar>
      <ToolbarRow
        primary={tokenActions.writable ?
          <Button variant="primary" icon="plus" disabled={blocker !== null} title={blocker ?? undefined} onClick={() => tokenActions.openIssuePage(list.state.service ? [list.state.service] : [])}>
            Issue token
          </Button> : null
        }
      >
        {embedded && contexts.length > 1 ? (
          <Seg
            label="Execution context"
            value={model.context ?? ""}
            onChange={model.setContext}
            options={[{ value: "", label: "All contexts" }, ...contexts.map((context) => ({ value: context, label: context }))]}
          />
        ) : null}
        {embedded ? (
          <fieldset className="m-0 flex min-w-0 items-center gap-3 border-0 p-0 wb-small">
            <legend className="wb-sr-only">Action effects</legend>
            {(["read", "write"] as const).map((effect) => (
              <label key={effect} className="inline-flex items-center gap-1.5 cursor-pointer">
                <input type="checkbox" aria-describedby={`${effectCountsId}-${effect}`} checked={list.state.effect.includes(effect)} onChange={(event) => list.setState({ effect: event.target.checked ? [...list.state.effect, effect] : list.state.effect.filter((value) => value !== effect), action: "" })} />
                {effect === "read" ? "Read-only" : "Write-capable"} <span id={`${effectCountsId}-${effect}`} className="wb-muted" aria-hidden="true">{model.effectCounts[effect]}</span>
              </label>
            ))}
          </fieldset>
        ) : null}
        <FilterInput value={list.state.q} onChange={(q) => list.setState({ q })} placeholder="Filter actions, resources…" debounceMs={150} />
        <GroupMenu value={list.state.group} options={[{ value: "service" as const, label: "Service" }]} onChange={(group) => list.setState({ group })} />
        <ToolbarSummary grow>
          <b>{shown.length}</b> {plural(shown.length, "action")} · {serviceCount} {plural(serviceCount, "service")}
          {options.options ? <> · policy generation {options.options.policyGeneration}</> : null}
        </ToolbarSummary>
      </ToolbarRow>
    </Toolbar>
  );
}

function credentialLine(service: ServiceSummary) {
  if (!service.target) return null;
  return `credential ${credentialStatus(service.credential).toLowerCase()}`;
}

export function AccessRows({ model }: { model: AccessListModel }) {
  const { data, options, shown, list, services, grouped } = model;
  const query = options.query;
  const byService = useMemo(() => new Map(services.map((service) => [service.service, service])), [services]);
  const columns = useMemo<DataColumn<AccessRow>[]>(
    () => [
      // Action names are identifiers: the column hugs them (long ones end at the
      // cap, full name on hover) and the description takes the spare width.
      {
        key: "action",
        header: "Action",
        primary: true,
        sortable: true,
        hug: "40ch",
        className: "wb-cell-mono",
        cell: (row) => row.action
      },
      ...(grouped
        ? []
        : [
            {
              key: "service",
              header: "Service",
              sortable: true,
              priority: 3,
              cell: (row: AccessRow) => <span title={row.service}>{byService.get(row.service)?.displayName ?? row.service}</span>
            } satisfies DataColumn<AccessRow>
          ]),
      {
        key: "effect",
        header: "Effect",
        cell: (row) => (row.readOnly ? <span className="wb-muted">Read-only</span> : <Badge tone="warning">Write-capable</Badge>)
      },
      {
        key: "resources",
        header: "Resources",
        priority: 2,
        truncate: true,
        minWidth: "12ch",
        cell: (row) => (
          <span title={row.resourceLabels.join("\n")}>
            {row.resourceLabels[0]}
            {row.resourceLabels.length > 1 ? <span className="wb-muted"> +{row.resourceLabels.length - 1} {plural(row.resourceLabels.length - 1, "alternative")}</span> : null}
          </span>
        )
      },
      {
        key: "contexts",
        header: "Contexts",
        priority: 3,
        hug: "24ch",
        className: "wb-cell-mono",
        cell: (row) => row.contexts.join(", ")
      },
      {
        key: "description",
        header: "Description",
        priority: 4,
        truncate: true,
        minWidth: "12ch",
        grow: 3,
        className: "wb-cell-muted",
        title: (row) => row.description || undefined,
        cell: (row) => row.description
      }
    ],
    [grouped, byService]
  );
  const filtered = Boolean(list.state.q || list.state.service || model.context || list.state.effect.length === 1);
  return (
    <>
      <DataTable
        label="Access"
        rows={shown}
        rowId={(row) => row.key}
        columns={columns}
        sort={list.state.sort}
        onSortChange={(sort) => list.setState({ sort })}
        groupBy={grouped ? (row) => row.service : undefined}
        groupHeader={({ key, rows }) => {
          const service = byService.get(key);
          const credential = service ? credentialLine(service) : null;
          return (
            <TableGroupHeader
              title={service?.displayName ?? key}
              sub={
                <>
                  <span className="wb-mono">{key}</span>
                  {credential ? ` · ${credential}` : ""}
                </>
              }
              count={`${rows.length} ${plural(rows.length, "action")}`}
            />
          );
        }}
        activeId={list.openId}
        rowHref={(row) => list.itemHref(row.key)}
        onRowFollow={(row) => list.open(row.key, "replace")}
        cursorResetKey={JSON.stringify({ service: list.state.service, context: list.state.context, effect: list.state.effect, q: list.state.q, sort: list.state.sort, group: list.state.group })}
        loading={options.loading || data.loading || (query.isError && query.isFetching)}
        error={query.isError ? <ErrorState compact title="Couldn’t load access" error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} /> : undefined}
        empty={
          filtered && model.allRows.length > 0 ? (
            <EmptyState
              compact
              icon="search"
              title="No matching access"
              actions={
                <Button icon="x" onClick={() => list.setState({ q: "", service: "", context: "", effect: [], action: "" })}>
                  Clear filters
                </Button>
              }
            >
              Try another service, context, action effect, or search.
            </EmptyState>
          ) : (
            <EmptyState compact icon="shield" title="No access yet">
              {model.context
                ? `No services or actions are available in ${model.context}.`
                : `No services or actions are available${model.subject.administered ? " to this principal" : " to you"} yet. Access comes from grants that an administrator or a service policy manager creates.`}
            </EmptyState>
          )
        }
        bleed
      />
      {shown.length > 0 ? <ListFooter /> : null}
    </>
  );
}

export function AccessDrawer({ model }: { model: AccessListModel }) {
  const { open, list, services, tokenActions, subject } = model;
  if (!open) return null;
  const service = services.find((item) => item.service === open.service);
  const status = service?.target ? credentialStatus(service.credential) : null;
  return (
    <Drawer
      resetKey={open.key}
      onClose={list.close}
      returnFocus={list.returnFocus}
      label={`${open.action} on ${service?.displayName ?? open.service}`}
      kicker={
        <>
          <Icon name="package" /> {service?.displayName ?? open.service} <span className="wb-num">{open.service}</span>
        </>
      }
      title={
        <>
          {open.action} <span className="pt-on">on</span> {service?.displayName ?? open.service}
        </>
      }
      meta={
        <>
          {open.readOnly ? <Badge variant="outline">Read-only</Badge> : <Badge tone="warning">Write-capable</Badge>}
          <span>
            in <span className="wb-mono">{open.contexts.join(", ")}</span>
          </span>
        </>
      }
      actions={
        tokenActions.issueBlocker() === null ? (
          <Button variant="primary" icon="key" onClick={() => tokenActions.openIssuePage([open.service])}>
            Issue token for {service?.displayName ?? open.service}
          </Button>
        ) : null
      }
    >
      <DrawerSection title="Action">
        <p className="pt-prose">{open.description || "No description."}</p>
      </DrawerSection>
      <DrawerSection title="Resources">
        <div className="wb-small wb-fg-2">
          <AccessClauses type={open.resourceType} clauses={open.clauses} />
        </div>
      </DrawerSection>
      <DrawerSection title="Service">
        <KeyValue
          items={[
            { label: "Service", value: service?.displayName ?? open.service },
            { label: "Service ID", value: <span className="wb-num">{open.service}</span> },
            service?.brokerHosts.length ? { label: "Broker hosts", value: <span className="wb-mono">{service.brokerHosts.join(", ")}</span> } : null,
            {
              label: "Credential",
              value: status ? (
                <span className="inline-flex items-center gap-2">
                  <Badge tone={credentialTone(service?.credential)}>{status}</Badge>
                  {!subject.administered ? (
                    <AppLink className="wb-link" href={paths.credentials(`${service?.target?.service}/${service?.target?.credentialName}`)}>
                      Manage
                    </AppLink>
                  ) : null}
                </span>
              ) : (
                <span className="wb-muted">No per-user credential</span>
              )
            }
          ]}
        />
      </DrawerSection>
      <DrawerSection title="How this is evaluated">
        <p className="pt-prose">
          Current policy is evaluated again for every request. This view does not guarantee credential availability or upstream service health.
        </p>
      </DrawerSection>
    </Drawer>
  );
}
