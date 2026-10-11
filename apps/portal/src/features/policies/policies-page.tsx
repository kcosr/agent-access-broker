import { canViewAdmin, canWriteAdmin, canWritePolicies } from "../../lib/capabilities";
// Admin › Policies: grants with status, facets, and a detail drawer.
import { useMemo, type ReactNode } from "react";
import type { PolicyCatalogResult, PolicyGrantRecord, ServicePolicyManagerAssignment } from "../../types";
import { actionSelectionCounts } from "../../lib/grant-actions";
import { actionEffectsParam, matchesActionEffects, type ActionEffect } from "../../lib/action-effects";
import { policyService, policySubjectDisplayLabel, uniqueSortedOptions } from "../../lib/helpers";
import { auditListPath } from "../../lib/audit";
import { useResourceTypes, type ResourceTypes } from "../../lib/resource-types";
import { groupRows, sortRows } from "../../lib/table-sort";
import { urlParam, useUrlState } from "../../lib/url-state";
import type { SortState } from "../../workbench";
import {
  Badge,
  Banner,
  Button,
  Combobox,
  type DataColumn,
  DataTable,
  Disclosure,
  Drawer,
  DrawerSection,
  EmptyState,
  ErrorState,
  FilterInput,
  formatDateTime,
  Icon,
  IconButton,
  KeyValue,
  List,
  ListFooter,
  Main,
  Menu,
  plural,
  Seg,
  Sidebar,
  SidebarCheck,
  SidebarItem,
  SidebarSection,
  StateCell,
  StatePill,
  TableGroupHeader,
  Time,
  Toolbar,
  ToolbarRow,
  ToolbarSummary
} from "../../workbench";
import { useActionRunner } from "../../app/actions";
import { useTableUrlState } from "../../app/list-state";
import { useModal } from "../../app/modal";
import { paths } from "../../app/paths";
import { useSession } from "../../app/session";
import { PortalPage } from "../../app/top-bar";
import { useDeletedPolicyGrants, usePolicyCatalog, usePolicyGrants, usePolicyStatus, useServicePolicyManagers } from "../../data/queries";
import { usePolicyActions } from "../../mutations/policy";
import { EffectiveAccessPanel } from "../../components/effective-access";
import { ActionEffectsFilter } from "../../components/action-effects-filter";
import { WriteCapability } from "../../components/grant-actions";
import { actionsExtra, GroupMenu, moreCount } from "../../components/table-cells";
import { GRANT_STATUS_TONE, SubjectLabel, actionsPreview, preview, resourcesSummary, subjectsPreview } from "./grant-format";
import { grantIsReadOnly } from "./grant-effects";

const STATUSES = ["current", "active", "disabled", "deleted", "all"] as const;
type StatusFilter = (typeof STATUSES)[number];

/** "Current" hides deleted grants; "All" includes them. */
function matchesStatus(filter: StatusFilter, status: string) {
  if (filter === "all") return true;
  if (filter === "current") return status !== "deleted";
  return status === filter;
}

const SORT_KEYS = ["grant", "service", "updated"] as const;
const GROUPINGS = ["none", "service"] as const;

export const POLICY_STATE = {
  status: urlParam.oneOf(STATUSES, "current"),
  sort: urlParam.sort(SORT_KEYS),
  group: urlParam.oneOf(GROUPINGS, "none"),
  q: urlParam.text(),
  service: urlParam.list(),
  subject: urlParam.text(),
  action: urlParam.text(),
  context: urlParam.list(),
  effect: actionEffectsParam,
  grant: urlParam.text()
};

type Facets = { q: string; service: string[]; subject: string; action: string; context: string[]; effect: ActionEffect[] };

function grantText(grant: PolicyGrantRecord, catalog: PolicyCatalogResult | null) {
  return [
    grant.grantRef,
    grant.service,
    grant.description ?? "",
    ...grant.subjects,
    ...grant.subjects.map((subject) => policySubjectDisplayLabel(subject, catalog)),
    ...grant.actions,
    ...grant.executionContexts,
    JSON.stringify(grant.resources)
  ]
    .join(" ")
    .toLowerCase();
}

function matchesFacets(grant: PolicyGrantRecord, facets: Facets, catalog: PolicyCatalogResult | null) {
  const query = facets.q.trim().toLowerCase();
  return (
    (facets.service.length === 0 || facets.service.includes(grant.service)) &&
    (!facets.subject || grant.subjects.includes(facets.subject)) &&
    (!facets.action || grant.actions.includes(facets.action)) &&
    (facets.context.length === 0 || grant.executionContexts.some((context) => facets.context.includes(context))) &&
    (!query || grantText(grant, catalog).includes(query))
  );
}

export function PoliciesPage() {
  const { session } = useSession();
  if (session.role === "service_policy_manager" && !session.policyManagementServices?.length) return <PortalPage><Main label="Policies"><List><EmptyState icon="shield" title="No services assigned">An Administrator must assign managed services to your account.</EmptyState></List></Main></PortalPage>;
  return <ScopedPoliciesPage />;
}

function ScopedPoliciesPage() {
  const { session } = useSession();
  const globalAdmin = canViewAdmin(session);
  const status = usePolicyStatus();
  const catalogQuery = usePolicyCatalog();
  const grantsQuery = usePolicyGrants();
  const managersQuery = useServicePolicyManagers(globalAdmin);
  const catalog = catalogQuery.data ?? null;
  // The broker lists deleted grants only on request: load them for the Deleted and All filters.
  const [urlState] = useUrlState(POLICY_STATE);
  const withDeleted = urlState.status === "deleted" || urlState.status === "all";
  const deletedQuery = useDeletedPolicyGrants(withDeleted);
  const grants = useMemo(() => {
    const current = grantsQuery.data ?? [];
    if (!withDeleted) return current;
    const known = new Set(current.map((grant) => grant.grantRef));
    return [...current, ...(deletedQuery.data ?? []).filter((grant) => !known.has(grant.grantRef))];
  }, [grantsQuery.data, deletedQuery.data, withDeleted]);
  const writable = canWritePolicies(session) && Boolean(status.data?.writable);

  const list = useTableUrlState(POLICY_STATE, "grant");
  const otherFacets = useMemo(() => grants.filter((grant) => matchesFacets(grant, list.state, catalog)), [grants, list.state, catalog]);
  const faceted = useMemo(
    () => otherFacets.filter((grant) => matchesActionEffects(grantIsReadOnly(grant, catalog), list.state.effect)),
    [otherFacets, catalog, list.state.effect]
  );
  const effectCounts = useMemo(() => {
    const counts = { read: 0, write: 0 };
    for (const grant of otherFacets) {
      if (matchesStatus(list.state.status, grant.status)) counts[grantIsReadOnly(grant, catalog) ? "read" : "write"] += 1;
    }
    return counts;
  }, [otherFacets, catalog, list.state.status]);
  const grouped = list.state.group === "service";
  const shown = useMemo(
    () => orderGrants(faceted.filter((grant) => matchesStatus(list.state.status, grant.status)), catalog, list.state.sort, grouped),
    [faceted, list.state.status, list.state.sort, grouped, catalog]
  );
  const counts = useMemo(() => {
    const counts: Record<StatusFilter, number> = { current: 0, active: 0, disabled: 0, deleted: 0, all: faceted.length };
    for (const grant of faceted) {
      if (grant.status !== "deleted") counts.current += 1;
      if (grant.status === "active" || grant.status === "disabled" || grant.status === "deleted") counts[grant.status] += 1;
    }
    // Until deleted grants are loaded, show the broker's (unfiltered) count.
    if (!withDeleted || !deletedQuery.data) counts.deleted = status.data?.counts.deleted ?? 0;
    counts.all = counts.current + counts.deleted;
    return counts;
  }, [faceted, withDeleted, deletedQuery.data, status.data]);
  const open = list.openId ? grants.find((grant) => grant.grantRef === list.openId) ?? null : null;
  const activeFilters = list.state.service.length + list.state.context.length + (list.state.effect.length === 1 ? 1 : 0) + (list.state.subject ? 1 : 0) + (list.state.action ? 1 : 0) + (list.state.q ? 1 : 0);
  const clearFilters = () => list.setState({ q: "", service: [], subject: "", action: "", context: [], effect: [], status: "current" });

  const sidebar = (
    <PoliciesSidebar
      catalog={catalog}
      grants={grants}
      effectCounts={effectCounts}
      state={list.state}
      setState={list.setState}
      managers={globalAdmin ? managersQuery.data ?? [] : null}
    />
  );

  const toolbar = (
    <Toolbar>
      <ToolbarRow
        primary={canWritePolicies(session) ?
          <Button
            variant="primary"
            icon="plus"
            href={paths.grantNew()}
            disabled={!writable || !catalog}
            title={!writable ? `Policy grants are read-only while policy authority is ${status.data?.policyAuthority ?? "unknown"}.` : undefined}
          >
            Create grant
          </Button> : null
        }
      >
        <Seg
          label="Grant status"
          value={list.state.status}
          onChange={(value) => list.setState({ status: value })}
          options={[
            { value: "current", label: "Current", count: counts.current },
            { value: "active", label: "Active", icon: "circle-check", tone: "success", count: counts.active },
            { value: "disabled", label: "Disabled", count: counts.disabled },
            { value: "deleted", label: "Deleted", tone: "danger", count: counts.deleted },
            { value: "all", label: "All", count: counts.all }
          ]}
        />
        <FilterInput value={list.state.q} onChange={(q) => list.setState({ q })} placeholder="Filter grants by subject, action, scope…" debounceMs={150} />
        <GroupMenu value={list.state.group} options={[{ value: "service" as const, label: "Service" }]} onChange={(group) => list.setState({ group })} />
        <ToolbarSummary
          grow
          title={
            status.data
              ? `Policy generation ${status.data.policyGeneration} · ${status.data.policyAuthority} policy authority${
                  status.data.lastUpdatedAt ? ` · last updated ${formatDateTime(status.data.lastUpdatedAt)}${status.data.lastUpdatedBy ? ` by ${status.data.lastUpdatedBy}` : ""}` : ""
                }`
              : undefined
          }
        >
          <b>{shown.length}</b> of {grants.length} {plural(grants.length, "grant")}
        </ToolbarSummary>
      </ToolbarRow>
    </Toolbar>
  );

  return (
    <PortalPage sidebar={sidebar} drawer={open ? <GrantDrawer grant={open} catalog={catalog} onClose={list.close} returnFocus={list.returnFocus} writableAuthority={writable} /> : null}>
      <Main
        label="Policies"
        toolbar={toolbar}
        header={
          status.data && !status.data.writable ? (
            <div className="pt-header-banners">
              <Banner tone="warning" slim>
                Policy grants are read-only while policy authority is {status.data.policyAuthority}. Change them in the broker configuration.
              </Banner>
            </div>
          ) : null
        }
        refetching={grantsQuery.isFetching && !grantsQuery.isPending}
      >
        <List full>
          <GrantTable
            grants={shown}
            catalog={catalog}
            list={list}
            grouped={grouped}
            writableAuthority={writable}
            // Busy while loading or retrying a failed read (the rows shown stay, marked stale).
            loading={
              grantsQuery.isPending ||
              catalogQuery.isPending ||
              (withDeleted && deletedQuery.isPending) ||
              (grantsQuery.isError && grantsQuery.isFetching) ||
              (catalogQuery.isError && catalogQuery.isFetching) ||
              (withDeleted && deletedQuery.isError && deletedQuery.isFetching)
            }
            error={
              grantsQuery.isError ? (
                <ErrorState compact title="Couldn’t load grants" error={grantsQuery.error} onRetry={() => void grantsQuery.refetch()} retrying={grantsQuery.isFetching} />
              ) : catalogQuery.isError ? (
                <ErrorState compact title="Couldn’t load policy catalog" error={catalogQuery.error} onRetry={() => void catalogQuery.refetch()} retrying={catalogQuery.isFetching} />
              ) : withDeleted && deletedQuery.isError ? (
                <ErrorState compact title="Couldn’t load deleted grants" error={deletedQuery.error} onRetry={() => void deletedQuery.refetch()} retrying={deletedQuery.isFetching} />
              ) : undefined
            }
            empty={
              grants.length === 0 ? (
                <EmptyState
                  compact
                  icon="shield"
                  title="No grants yet"
                  actions={
                    writable ? (
                      <Button variant="primary" icon="plus" href={paths.grantNew()}>
                        Create grant
                      </Button>
                    ) : null
                  }
                >
                  {writable ? "Grants give users and groups access to service actions." : "No policy grants are configured."}
                </EmptyState>
              ) : (
                <EmptyState
                  compact
                  icon="search"
                  title="No matching grants"
                  actions={
                    activeFilters > 0 || list.state.status !== "current" ? (
                      <Button icon="x" onClick={clearFilters}>
                        Clear filters
                      </Button>
                    ) : null
                  }
                >
                  Try another status, facet, or search.
                </EmptyState>
              )
            }
          />
          {shown.length > 0 ? <ListFooter /> : null}
        </List>
      </Main>
    </PortalPage>
  );
}

/** Grants in table order: the chosen sort, else service then grant ID; regrouped by service when grouped. */
function orderGrants(grants: PolicyGrantRecord[], catalog: PolicyCatalogResult | null, sort: SortState | null, grouped: boolean) {
  const name = (service: string) => policyService(catalog, service)?.displayName ?? service;
  const byService = (a: string, b: string) => name(a).localeCompare(name(b)) || a.localeCompare(b);
  const sorted = sortRows(
    grants,
    sort,
    (grant, key) => (key === "grant" ? grant.grantRef : key === "service" ? name(grant.service) : grant.updatedAt),
    (a, b) => byService(a.service, b.service) || a.grantRef.localeCompare(b.grantRef)
  );
  return grouped ? groupRows(sorted, (grant) => grant.service, byService) : sorted;
}

const STATUS_LABEL: Record<string, string> = { active: "Active", disabled: "Disabled", deleted: "Deleted" };

function grantColumns({
  catalog,
  types,
  grouped,
  writableAuthority,
  actions
}: {
  catalog: PolicyCatalogResult | null;
  types: ResourceTypes;
  grouped: boolean;
  writableAuthority: boolean;
  actions: (grant: PolicyGrantRecord) => ReactNode;
}): DataColumn<PolicyGrantRecord>[] {
  const service = (grant: PolicyGrantRecord) => policyService(catalog, grant.service);
  return [
    {
      key: "status",
      header: "Status",
      cell: (grant) => <StateCell label={STATUS_LABEL[grant.status] ?? grant.status} tone={GRANT_STATUS_TONE[grant.status] ?? "neutral"} quiet={grant.status === "active"} />,
      extra: (grant) =>
        grant.priority != null ? (
          <Badge variant="outline" title={`Priority ${grant.priority}`}>
            P{grant.priority}
          </Badge>
        ) : null
    },
    {
      key: "grant",
      header: "Grant",
      primary: true,
      sortable: true,
      // Grant IDs are identifiers: hug them up to a cap; the tooltip adds the
      // description, while the link's name stays the grant ID.
      hug: "32ch",
      className: "wb-cell-mono",
      title: (grant) => (grant.description ? `${grant.grantRef}: ${grant.description}` : grant.grantRef),
      cell: (grant) => grant.grantRef
    },
    {
      key: "subjects",
      header: "Subjects",
      priority: 2,
      truncate: true,
      minWidth: "10ch",
      title: (grant) => grant.subjects.map((subject) => policySubjectDisplayLabel(subject, catalog)).join(", "),
      cell: (grant) => subjectsPreview(grant, catalog).text,
      extra: (grant) => moreCount(subjectsPreview(grant, catalog).more)
    },
    ...(grouped
      ? []
      : [
          {
            key: "service",
            header: "Service",
            sortable: true,
            priority: 3,
            cell: (grant: PolicyGrantRecord) => <span title={grant.service}>{service(grant)?.displayName ?? grant.service}</span>
          } satisfies DataColumn<PolicyGrantRecord>
        ]),
    {
      key: "actions",
      header: "Actions",
      priority: 3,
      truncate: true,
      minWidth: "7ch",
      grow: 2,
      title: (grant) => grant.actions.join(", "),
      cell: (grant) => actionsPreview(grant, catalog).text,
      extra: (grant) => actionsExtra(actionsPreview(grant, catalog).more, actionSelectionCounts(service(grant)?.actions ?? [], grant.actions).writeCapable > 0)
    },
    {
      key: "contexts",
      header: "Contexts",
      priority: 4,
      hug: "12ch",
      className: "wb-cell-mono",
      title: (grant) => grant.executionContexts.join(", "),
      cell: (grant) => preview(grant.executionContexts, 3)
    },
    {
      key: "resources",
      header: "Resources",
      priority: 4,
      truncate: true,
      minWidth: "8ch",
      cell: (grant) => {
        const labels = resourcesSummary(grant, catalog, types);
        return <span title={labels.join(", ")}>{preview(labels, 1)}</span>;
      }
    },
    {
      key: "updated",
      header: "Updated",
      sortable: true,
      firstSortDir: "desc",
      priority: 4,
      cell: (grant) => (grant.updatedAt ? <Time value={grant.updatedAt} /> : null)
    },
    {
      key: "row-actions",
      header: <span className="wb-sr-only">Row actions</span>,
      className: "wb-cell-actions",
      cell: (grant) => (grant.writable && writableAuthority && grant.status !== "deleted" ? actions(grant) : null)
    }
  ];
}

function GrantTable({
  grants,
  catalog,
  list,
  grouped,
  writableAuthority,
  loading,
  error,
  empty
}: {
  grants: PolicyGrantRecord[];
  catalog: PolicyCatalogResult | null;
  list: ReturnType<typeof useTableUrlState<typeof POLICY_STATE>>;
  grouped: boolean;
  writableAuthority: boolean;
  loading: boolean;
  error: ReactNode;
  empty: ReactNode;
}) {
  const types = useResourceTypes();
  const policy = usePolicyActions();
  const runner = useActionRunner();
  const columns = useMemo(
    () =>
      grantColumns({
        catalog,
        types,
        grouped,
        writableAuthority,
        actions: (grant) => (
          <div className="wb-row-actions">
            <IconButton size="sm" icon="pencil" label={`Edit ${grant.grantRef}`} href={paths.grantEdit(grant.grantRef)} />
            <Menu
              label={`More actions for ${grant.grantRef}`}
              items={[
                { id: "duplicate", label: "Duplicate", icon: "copy", href: paths.grantNew({ from: grant.grantRef }) },
                grant.status === "active"
                  ? { id: "disable", label: "Disable", icon: "pause", onSelect: () => void runner.run(grant.grantRef, () => policy.setEnabled(grant, false)) }
                  : { id: "enable", label: "Enable", icon: "play", onSelect: () => void runner.run(grant.grantRef, () => policy.setEnabled(grant, true)) },
                { type: "separator" },
                { id: "delete", label: "Delete", icon: "trash", danger: true, onSelect: () => policy.confirmDelete(grant) }
              ]}
              trigger={(props) => <IconButton {...props} size="sm" icon="more" label={`More actions for ${grant.grantRef}`} />}
            />
          </div>
        )
      }),
    [catalog, types, grouped, writableAuthority, policy, runner]
  );
  const { sort, group, grant: _open, ...filters } = list.state;
  return (
    <DataTable
      label="Grants"
      rows={grants}
      rowId={(grant) => grant.grantRef}
      columns={columns}
      sort={sort}
      onSortChange={(next) => list.setState({ sort: next })}
      groupBy={grouped ? (grant) => grant.service : undefined}
      groupHeader={({ key, rows }) => (
        <TableGroupHeader
          title={policyService(catalog, key)?.displayName ?? key}
          sub={<span className="wb-mono">{key}</span>}
          count={`${rows.length} ${plural(rows.length, "grant")}`}
        />
      )}
      activeId={list.openId}
      rowHref={(grant) => list.itemHref(grant.grantRef)}
      onRowFollow={(grant) => list.open(grant.grantRef, "replace")}
      cursorResetKey={JSON.stringify({ filters, sort, group })}
      rowDim={(grant) => grant.status !== "active"}
      loading={loading}
      error={error}
      empty={empty}
      bleed
    />
  );
}

function PoliciesSidebar({
  catalog,
  grants,
  effectCounts,
  state,
  setState,
  managers
}: {
  catalog: PolicyCatalogResult | null;
  grants: PolicyGrantRecord[];
  effectCounts: { read: number; write: number };
  state: Facets & { status: string };
  setState: (patch: Partial<Facets> & { grant?: string }) => void;
  managers: ServicePolicyManagerAssignment[] | null;
}) {
  const { setModal } = useModal();
  const services = catalog?.services ?? [];
  const serviceCount = (service: string) => grants.filter((grant) => grant.service === service).length;
  const configuredContexts = catalog?.executionContexts.allowedValues ?? [];
  const contexts = [...configuredContexts, ...uniqueSortedOptions(grants.flatMap((grant) => grant.executionContexts)).filter((context) => !configuredContexts.includes(context))];
  const subjectValues = uniqueSortedOptions([
    ...(catalog?.subjects.groups.flatMap((group) => (group.groupId ? [`group:${group.groupId}`] : [])) ?? []),
    ...(catalog?.subjects.users.flatMap((user) => (user.principalId ? [`user:${user.principalId}`] : [])) ?? []),
    ...grants.flatMap((grant) => grant.subjects)
  ]);
  const actionServices = state.service.length ? services.filter((service) => state.service.includes(service.service)) : services;
  const serviceActions = new Set(actionServices.flatMap((service) => service.actions.map((action) => action.action)));
  const actions = uniqueSortedOptions([...serviceActions], state.action);
  // A chosen action stays selectable after the service filter changes, marked when no selected service offers it.
  const actionOutside = Boolean(state.action && state.service.length && !serviceActions.has(state.action));
  const toggle = (values: string[], value: string, on: boolean) => (on ? [...values, value] : values.filter((item) => item !== value));
  const { session } = useSession();
  const managedServices = managers ? uniqueSortedOptions(managers.map((assignment) => assignment.service)) : [];
  return (
    <Sidebar label="Grant filters">
      <SidebarSection
        title="Service"
        collapsible
        activeCount={state.service.length}
        action={state.service.length ? { label: "Clear service filter", text: "Clear", onClick: () => setState({ service: [], grant: "" }) } : undefined}
      >
        {services.map((service) => (
          <SidebarCheck
            key={service.service}
            label={service.displayName}
            title={service.service}
            checked={state.service.includes(service.service)}
            onChange={(on) => setState({ service: toggle(state.service, service.service, on), grant: "" })}
            count={serviceCount(service.service)}
          />
        ))}
      </SidebarSection>
      <ActionEffectsFilter value={state.effect} counts={effectCounts} onChange={(effect) => setState({ effect, grant: "" })} />
      <SidebarSection title="Subject" collapsible activeCount={state.subject ? 1 : 0}>
        <div className="pt-side-pad">
          <Combobox
            aria-label="Subject"
            placeholder="Any subject…"
            value={state.subject || null}
            onChange={(value) => setState({ subject: value ?? "", grant: "" })}
            options={subjectValues.map((value) => ({ value, label: policySubjectDisplayLabel(value, catalog) }))}
          />
        </div>
      </SidebarSection>
      <SidebarSection title="Action" collapsible activeCount={state.action ? 1 : 0}>
        <div className="pt-side-pad">
          <Combobox
            aria-label="Action"
            placeholder="Any action…"
            value={state.action || null}
            onChange={(value) => setState({ action: value ?? "", grant: "" })}
            options={actions.map((action) => ({ value: action, label: action === state.action && actionOutside ? `${action} (outside selected services)` : action }))}
          />
          {actionOutside ? <p className="wb-small wb-muted">{state.action} is outside the selected services.</p> : null}
        </div>
      </SidebarSection>
      <SidebarSection
        title="Execution context"
        collapsible
        activeCount={state.context.length}
        action={state.context.length ? { label: "Clear context filter", text: "Clear", onClick: () => setState({ context: [], grant: "" }) } : undefined}
      >
        {contexts.map((context) => (
          <SidebarCheck
            key={context}
            label={<span className="wb-mono">{context}</span>}
            checked={state.context.includes(context)}
            onChange={(on) => setState({ context: toggle(state.context, context, on), grant: "" })}
            count={grants.filter((grant) => grant.executionContexts.includes(context)).length}
          />
        ))}
      </SidebarSection>
      {managers ? (
        <SidebarSection title="Service managers" action={canWriteAdmin(session) ? { label: "Assign service policy manager", onClick: () => setModal({ type: "assignManager" }) } : undefined}>
          {managedServices.length === 0 ? <div className="wb-side-empty">No service policy managers.</div> : null}
          {managedServices.map((service) => (
            <SidebarItem
              key={service}
              icon="user"
              label={policyService(catalog, service)?.displayName ?? service}
              title={`Managers of ${service}`}
              count={managers.filter((assignment) => assignment.service === service).length}
              href={paths.catalogService(service, "managers")}
            />
          ))}
        </SidebarSection>
      ) : null}
    </Sidebar>
  );
}

export function GrantDrawer({
  grant,
  catalog,
  onClose,
  returnFocus,
  writableAuthority
}: {
  grant: PolicyGrantRecord;
  catalog: PolicyCatalogResult | null;
  onClose: () => void;
  returnFocus?: () => HTMLElement | null;
  writableAuthority: boolean;
}) {
  const { session } = useSession();
  const types = useResourceTypes();
  const policy = usePolicyActions();
  const runner = useActionRunner();
  const service = policyService(catalog, grant.service);
  const editable = canWritePolicies(session, grant.service) && grant.writable && writableAuthority && grant.status !== "deleted";
  const readActions = grant.actions.filter((action) => service?.actions.find((item) => item.action === action)?.readOnly === true);
  const writeActions = grant.actions.filter((action) => !readActions.includes(action));
  const auditHref =
    session.auditQueryable && grant.grantId
      ? auditListPath("admin", { service: grant.service, q: `"${grant.grantId}"` })
      : undefined;
  return (
    <Drawer
      resetKey={grant.grantRef}
      onClose={onClose}
      returnFocus={returnFocus}
      label={`Grant ${grant.grantRef}`}
      kicker={
        <>
          <Icon name="shield" /> Grant <span className="wb-num">{grant.grantRef}</span>
          <Badge variant="outline">{grant.writable ? "managed" : "configuration"}</Badge>
        </>
      }
      title={grant.description || grant.grantRef}
      meta={
        <>
          <StatePill tone={GRANT_STATUS_TONE[grant.status] ?? "neutral"}>{grant.status}</StatePill>
          <span>{service?.displayName ?? grant.service}</span>
          {grant.updatedAt ? (
            <span>
              · updated <Time value={grant.updatedAt} />
              {grant.updatedBy ? ` by ${grant.updatedBy}` : ""}
            </span>
          ) : null}
        </>
      }
      actions={
        <>
          {editable ? (
            <Button variant="primary" icon="pencil" href={paths.grantEdit(grant.grantRef)}>
              Edit
            </Button>
          ) : null}
          {canWritePolicies(session, grant.service) && writableAuthority && grant.status !== "deleted" ? (
            <Button icon="copy" href={paths.grantNew({ from: grant.grantRef })}>
              Duplicate
            </Button>
          ) : null}
          {editable ? (
            <Button
              icon={grant.status === "active" ? "pause" : "play"}
              pending={runner.busy}
              onClick={() => void runner.run("toggle", () => policy.setEnabled(grant, grant.status !== "active"))}
            >
              {grant.status === "active" ? "Disable" : "Enable"}
            </Button>
          ) : null}
          {editable ? (
            <Button variant="danger-ghost" icon="trash" onClick={() => policy.confirmDelete(grant, onClose)}>
              Delete
            </Button>
          ) : null}
          {auditHref ? (
            <Button variant="ghost" icon="history" href={auditHref}>
              View audit
            </Button>
          ) : null}
        </>
      }
    >
      {!grant.writable ? (
        <DrawerSection title="Source">
          <p className="pt-prose">This grant comes from the broker configuration file and is read-only here.</p>
        </DrawerSection>
      ) : null}
      <DrawerSection title="Subjects" count={grant.subjects.length}>
        <ul className="pt-links">
          {grant.subjects.map((subject) => (
            <li key={subject}>
              <SubjectLabel subject={subject} catalog={catalog} link={canViewAdmin(session)} />
            </li>
          ))}
        </ul>
      </DrawerSection>
      <DrawerSection title="Actions" count={grant.actions.length} action={<WriteCapability available={service?.actions ?? []} selected={grant.actions} />}>
        <KeyValue
          items={[
            readActions.length ? { label: "Read-only", value: <span className="wb-mono">{readActions.join(", ")}</span> } : null,
            writeActions.length ? { label: "Write-capable", value: <span className="wb-mono">{writeActions.join(", ")}</span> } : null
          ]}
        />
      </DrawerSection>
      <DrawerSection title="Scope">
        <KeyValue
          items={[
            { label: "Resources", value: resourcesSummary(grant, catalog, types).join(", ") },
            { label: "Contexts", value: <span className="wb-mono">{grant.executionContexts.join(", ")}</span> },
            { label: "Credential", value: <span className="wb-mono">{grant.credentialMode}</span> },
            { label: "Priority", value: grant.priority ?? "Default" },
            grant.version != null ? { label: "Version", value: grant.version } : null,
            grant.createdAt ? { label: "Created", value: <><Time value={grant.createdAt} format="datetime" />{grant.createdBy ? <span className="wb-muted"> by {grant.createdBy}</span> : null}</> } : null
          ]}
        />
      </DrawerSection>
      <DrawerSection title="Effective access">
        {grant.status === "active" ? (
          <EffectiveAccessPanel grant={{ service: grant.service, actions: grant.actions, executionContexts: grant.executionContexts, resources: grant.resources }} />
        ) : (
          <p className="pt-prose">No access currently: this grant is {grant.status}.</p>
        )}
      </DrawerSection>
      <DrawerSection title="Raw grant">
        <Disclosure summary="Show JSON">
          <pre className="wb-code">{JSON.stringify(grant, null, 2)}</pre>
        </Disclosure>
      </DrawerSection>
    </Drawer>
  );
}
