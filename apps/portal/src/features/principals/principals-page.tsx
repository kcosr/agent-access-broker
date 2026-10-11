import { ROLE_LABELS } from "../../lib/capabilities";
import type { PrincipalRole } from "../../types";
import { AdminButton } from "../../components/admin-access";
// Admin › Principals: users, service accounts, and groups, with summary
// drawers that open the full user or group page.
import { SignInMethodBadges, signInCategory } from "./sign-in-methods";
import { useMemo } from "react";
import type { GroupRecord, PrincipalRecord } from "../../types";
import { identityDisplayName, uniqueSortedOptions } from "../../lib/helpers";
import { auditListPath } from "../../lib/audit";
import { urlParam } from "../../lib/url-state";
import { sortRows } from "../../lib/table-sort";
import { previewParts } from "../policies/grant-format";
import { moreCount } from "../../components/table-cells";
import { AppLink, Badge, Banner, Button, Chip, Combobox, type DataColumn, DataTable, Drawer, DrawerSection, EmptyState, ErrorState, FilterInput, Icon, IconButton, KeyValue, List, ListFooter, Main, plural, Seg, Sidebar, SidebarItem, SidebarSection, SkeletonBlock, type SortState, StateCell, StatePill, Time, Toolbar, ToolbarRow, ToolbarSummary } from "../../workbench";
import { useTableUrlState } from "../../app/list-state";
import { useModal } from "../../app/modal";
import { paths, type PrincipalListKind } from "../../app/paths";
import { useSession } from "../../app/session";
import { PortalPage } from "../../app/top-bar";
import { useAdminGroup, useAdminGroups, useAdminPrincipals, useConfigStatus, writeAuthorities } from "../../data/queries";

const KINDS = ["users", "service-accounts", "groups"] as const;
const STATUSES = ["all", "active", "disabled"] as const;

const SIGN_IN_FILTERS = ["all", "microsoft", "local", "both", "none"] as const;
const SIGN_IN_LABELS = { all: "All methods", microsoft: "Microsoft only", local: "Local password only", both: "Both", none: "No active methods" };

const SORT_KEYS = ["name", "id", "members", "updated"] as const;

export const PRINCIPALS_STATE = {
  kind: urlParam.oneOf(KINDS, "users"),
  sort: urlParam.sort(SORT_KEYS),
  status: urlParam.oneOf(STATUSES, "all"),
  q: urlParam.text(),
  role: urlParam.oneOf(["all", "user", "auditor", "service_policy_manager", "admin"] as const, "all"),
  signIn: urlParam.oneOf(SIGN_IN_FILTERS, "all"),
  group: urlParam.text(),
  item: urlParam.text()
};

type State = { signIn: (typeof SIGN_IN_FILTERS)[number]; kind: PrincipalListKind; status: (typeof STATUSES)[number]; q: string; role: PrincipalRole | "all"; group: string; sort: SortState | null };

const principalName = (principal: PrincipalRecord) => identityDisplayName(principal.displayName) || principal.principalId;
const groupName = (group: GroupRecord) => identityDisplayName(group.displayName) || group.groupId;

const KIND_LABEL: Record<PrincipalListKind, { plural: string; one: string; create: string }> = {
  users: { plural: "Users", one: "user", create: "Create user" },
  "service-accounts": { plural: "Service accounts", one: "service account", create: "Create service account" },
  groups: { plural: "Groups", one: "group", create: "Create group" }
};

function principalRows(principals: PrincipalRecord[], state: State) {
  const query = state.q.trim().toLowerCase();
  const matching = principals
    .filter((principal) => (state.kind === "service-accounts" ? principal.kind === "service_account" : principal.kind !== "service_account"))
    .filter((principal) => state.status === "all" || principal.status === state.status)
    .filter((principal) => state.kind !== "users" || state.signIn === "all" || signInCategory(principal.signInMethods) === state.signIn)
    .filter((principal) => state.role === "all" || principal.role === state.role)
    .filter((principal) => !state.group || principal.groups.includes(state.group))
    .filter((principal) => !query || [principal.principalId, principal.displayName ?? "", principal.email ?? "", ...principal.groups].join(" ").toLowerCase().includes(query));
  return sortRows(
    matching,
    state.sort,
    (principal, key) => (key === "id" ? principal.principalId : key === "updated" ? principal.updatedAt : principalName(principal)),
    (a, b) => principalName(a).localeCompare(principalName(b)) || a.principalId.localeCompare(b.principalId)
  );
}

function groupRows(groups: GroupRecord[], state: State) {
  const query = state.q.trim().toLowerCase();
  const matching = groups
    .filter((group) => state.status === "all" || group.status === state.status)
    .filter((group) => !query || [group.groupId, group.displayName ?? "", group.description ?? ""].join(" ").toLowerCase().includes(query));
  return sortRows(
    matching,
    state.sort,
    (group, key) => (key === "id" ? group.groupId : key === "members" ? group.memberCount : key === "updated" ? group.updatedAt : groupName(group)),
    (a, b) => groupName(a).localeCompare(groupName(b)) || a.groupId.localeCompare(b.groupId)
  );
}

export function PrincipalsPage() {
  const { setModal } = useModal();
  const principalsQuery = useAdminPrincipals();
  const groupsQuery = useAdminGroups();
  const authorities = writeAuthorities(useConfigStatus().data);
  const principals = principalsQuery.data ?? [];
  const groups = groupsQuery.data ?? [];
  const list = useTableUrlState(PRINCIPALS_STATE, "item");
  const state = list.state;
  const groupsView = state.kind === "groups";
  const shownPrincipals = useMemo(() => (groupsView ? [] : principalRows(principals, state)), [groupsView, principals, state]);
  const shownGroups = useMemo(() => (groupsView ? groupRows(groups, state) : []), [groupsView, groups, state]);
  const shownCount = groupsView ? shownGroups.length : shownPrincipals.length;
  const kindPrincipals = principals.filter((principal) => (state.kind === "service-accounts" ? principal.kind === "service_account" : principal.kind !== "service_account"));
  const kindTotal = groupsView ? groups.length : kindPrincipals.length;
  const statusCount = (status: string) => (groupsView ? groups : kindPrincipals).filter((item) => status === "all" || item.status === status).length;
  const query = groupsView ? groupsQuery : principalsQuery;
  const filtered = Boolean(state.q || state.status !== "all" || state.role !== "all" || state.group || state.signIn !== "all");
  const clearFilters = () => list.setState({ q: "", status: "all", role: "all", group: "", signIn: "all" });
  const openPrincipal = !groupsView && list.openId ? principals.find((principal) => principal.principalId === list.openId) ?? null : null;
  const openGroup = groupsView && list.openId ? groups.find((group) => group.groupId === list.openId) ?? null : null;
  const createDisabled = groupsView && !authorities.groupWritesEnabled;

  const sidebar = (
    <Sidebar label="Principal filters">
      <SidebarSection title="Principals">
        {KINDS.map((kind) => (
          <SidebarItem
            key={kind}
            icon={kind === "users" ? "user" : kind === "service-accounts" ? "server" : "users"}
            label={KIND_LABEL[kind].plural}
            count={kind === "groups" ? groups.length : principals.filter((principal) => (kind === "service-accounts" ? principal.kind === "service_account" : principal.kind !== "service_account")).length}
            current={state.kind === kind}
            onClick={() => list.setState({ kind, item: "", role: "all", group: "", signIn: "all", status: "all" })}
          />
        ))}
      </SidebarSection>
      {state.kind === "users" ? (
        <SidebarSection title="Role" activeCount={state.role !== "all" ? 1 : 0}>
          {(["all", "user", "auditor", "service_policy_manager", "admin"] as const).map((role) => <SidebarItem key={role} label={role === "all" ? "All roles" : ROLE_LABELS[role]} current={state.role === role} onClick={() => list.setState({ role, item: "" })} count={kindPrincipals.filter((principal) => role === "all" || principal.role === role).length} />)}
        </SidebarSection>
      ) : null}
      {state.kind === "users" ? <SidebarSection title="Sign-in methods" activeCount={state.signIn === "all" ? 0 : 1}>
        {SIGN_IN_FILTERS.map((value) => <SidebarItem key={value} label={SIGN_IN_LABELS[value]} current={state.signIn === value} onClick={() => list.setState({ signIn: value, item: "" })} count={kindPrincipals.filter((principal) => value === "all" || signInCategory(principal.signInMethods) === value).length} />)}
      </SidebarSection> : null}
      {!groupsView ? (
        <SidebarSection title="Group" collapsible activeCount={state.group ? 1 : 0}>
          <div className="pt-side-pad">
            <Combobox
              aria-label="Member of group"
              placeholder="Any group…"
              value={state.group || null}
              onChange={(group) => list.setState({ group: group ?? "", item: "" })}
              options={uniqueSortedOptions([...groups.map((group) => group.groupId), ...kindPrincipals.flatMap((principal) => principal.groups)]).map((groupId) => ({
                value: groupId,
                label: identityDisplayName(groups.find((group) => group.groupId === groupId)?.displayName) || groupId
              }))}
            />
          </div>
        </SidebarSection>
      ) : null}
    </Sidebar>
  );

  const toolbar = (
    <Toolbar>
      <ToolbarRow
        primary={
          <AdminButton
            variant="primary"
            icon="plus"
            disabled={createDisabled}
            title={createDisabled ? `Group writes are unavailable while identity authority is ${authorities.identityAuthority}.` : undefined}
            onClick={() => setModal(groupsView ? { type: "createGroup" } : { type: "createPrincipal", kind: state.kind === "service-accounts" ? "service_account" : "user" })}
          >
            {KIND_LABEL[state.kind].create}
          </AdminButton>
        }
      >
        <Seg
          label="Status"
          value={state.status}
          onChange={(status) => list.setState({ status, item: "" })}
          options={[
            { value: "all", label: "All", count: statusCount("all") },
            { value: "active", label: "Active", icon: "circle-check", tone: "success", count: statusCount("active") },
            { value: "disabled", label: "Disabled", icon: "pause", count: statusCount("disabled") }
          ]}
        />
        <FilterInput value={state.q} onChange={(q) => list.setState({ q })} placeholder={`Filter ${KIND_LABEL[state.kind].plural.toLowerCase()}…`} debounceMs={150} />
        <ToolbarSummary grow>
          <b>{shownCount}</b> of {kindTotal} {plural(kindTotal, KIND_LABEL[state.kind].one)}
        </ToolbarSummary>
      </ToolbarRow>
    </Toolbar>
  );

  const cursorResetKey = JSON.stringify({ kind: state.kind, status: state.status, q: state.q, admins: state.role !== "all", group: state.group, signIn: state.signIn, sort: state.sort });
  const empty =
    filtered && kindTotal > 0 ? (
      <EmptyState
        compact
        icon="search"
        title={`No matching ${KIND_LABEL[state.kind].plural.toLowerCase()}`}
        actions={
          <Button icon="x" onClick={clearFilters}>
            Clear filters
          </Button>
        }
      />
    ) : (
      <EmptyState compact icon={groupsView ? "users" : state.kind === "service-accounts" ? "server" : "user"} title={`No ${KIND_LABEL[state.kind].plural.toLowerCase()} yet`}>
        {groupsView
          ? authorities.groupWritesEnabled
            ? "Groups let grants apply to many users at once."
            : "No static groups are configured."
          : state.kind === "service-accounts"
            ? "Service accounts are noninteractive identities for automation that holds agent tokens."
            : "Create the first managed user."}
      </EmptyState>
    );
  const tableProps = {
    sort: state.sort,
    onSortChange: (sort: SortState | null) => list.setState({ sort }),
    activeId: list.openId,
    cursorResetKey,
    loading: query.isPending || (query.isError && query.isFetching),
    error: query.isError ? (
      <ErrorState compact title={`Couldn’t load ${KIND_LABEL[state.kind].plural.toLowerCase()}`} error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} />
    ) : undefined,
    empty,
    bleed: true
  };
  const content = groupsView ? (
    <DataTable
      label="Groups"
      rows={shownGroups}
      rowId={(group) => group.groupId}
      columns={GROUP_COLUMNS}
      rowHref={(group) => list.itemHref(group.groupId)}
      onRowFollow={(group) => list.open(group.groupId, "replace")}
      rowDim={(group) => group.status !== "active"}
      {...tableProps}
    />
  ) : (
    <DataTable
      label={KIND_LABEL[state.kind].plural}
      rows={shownPrincipals}
      rowId={(principal) => principal.principalId}
      columns={state.kind === "service-accounts" ? SERVICE_ACCOUNT_COLUMNS : USER_COLUMNS}
      rowHref={(principal) => list.itemHref(principal.principalId)}
      onRowFollow={(principal) => list.open(principal.principalId, "replace")}
      rowDim={(principal) => principal.status !== "active"}
      {...tableProps}
    />
  );

  return (
    <PortalPage
      sidebar={sidebar}
      drawer={
        openPrincipal ? (
          <PrincipalDrawer principal={openPrincipal} onClose={list.close} returnFocus={list.returnFocus} />
        ) : openGroup ? (
          <GroupDrawer group={openGroup} onClose={list.close} returnFocus={list.returnFocus} />
        ) : null
      }
    >
      <Main
        label="Principals"
        toolbar={toolbar}
        header={
          groupsView && !authorities.groupWritesEnabled && authorities.identityAuthority !== "unknown" ? (
            <div className="pt-header-banners">
              <Banner tone="warning" slim>
                Group writes are unavailable while identity authority is {authorities.identityAuthority}.
              </Banner>
            </div>
          ) : null
        }
        refetching={query.isFetching && !query.isPending}
      >
        <List full>
          {content}
          {shownCount > 0 ? <ListFooter /> : null}
        </List>
      </Main>
    </PortalPage>
  );
}

const statusColumn = <T extends { status: string }>(): DataColumn<T> => ({
  key: "status",
  header: "Status",
  cell: (row) => <StateCell label={row.status === "active" ? "Active" : row.status[0]!.toUpperCase() + row.status.slice(1)} tone={row.status === "active" ? "success" : "muted"} quiet={row.status === "active"} />
});

const openColumn = <T,>(href: (row: T) => string, id: (row: T) => string): DataColumn<T> => ({
  key: "open",
  header: <span className="wb-sr-only">Row actions</span>,
  className: "wb-cell-actions",
  cell: (row) => (
    <div className="wb-row-actions">
      <IconButton size="sm" icon="external" label={`Open ${id(row)}`} href={href(row)} />
    </div>
  )
});

function principalColumns(serviceAccounts: boolean): DataColumn<PrincipalRecord>[] {
  return [
    statusColumn<PrincipalRecord>(),
    {
      key: "name",
      header: "Name",
      primary: true,
      sortable: true,
      truncate: true,
      minWidth: "16ch",
      cell: (principal) => principalName(principal)
    },
    {
      key: "id",
      header: "Principal ID",
      sortable: true,
      priority: 2,
      truncate: true,
      minWidth: "12ch",
      className: "wb-cell-mono",
      cell: (principal) => principal.principalId
    },
    ...(serviceAccounts
      ? []
      : [
          { key: "signInMethods", header: "Sign-in methods", priority: 2, cell: (principal: PrincipalRecord) => <SignInMethodBadges methods={principal.signInMethods} /> } satisfies DataColumn<PrincipalRecord>,
          {
            key: "email",
            header: "Email",
            priority: 4,
            truncate: true,
            minWidth: "12ch",
            cell: (principal: PrincipalRecord) => principal.email ?? ""
          } satisfies DataColumn<PrincipalRecord>,
          {
            key: "role",
            header: "Role",
            priority: 2,
            cell: (principal: PrincipalRecord) => (<Badge tone={principal.role === "admin" ? "info" : "neutral"}>{ROLE_LABELS[principal.role]}</Badge>)
          } satisfies DataColumn<PrincipalRecord>
        ]),
    {
      key: "groups",
      header: "Groups",
      priority: 3,
      truncate: true,
      minWidth: "10ch",
      title: (principal) => principal.groups.join(", ") || undefined,
      cell: (principal) => (principal.groups.length ? previewParts(principal.groups).text : <span className="wb-muted">None</span>),
      extra: (principal) => moreCount(previewParts(principal.groups).more)
    },
    {
      key: "updated",
      header: "Updated",
      sortable: true,
      firstSortDir: "desc",
      priority: 4,
      cell: (principal) => <Time value={principal.updatedAt} />
    },
    openColumn<PrincipalRecord>((principal) => paths.principal(principal.principalId), (principal) => principal.principalId)
  ];
}

const USER_COLUMNS = principalColumns(false);
const SERVICE_ACCOUNT_COLUMNS = principalColumns(true);

const GROUP_COLUMNS: DataColumn<GroupRecord>[] = [
  statusColumn<GroupRecord>(),
  {
    key: "name",
    header: "Name",
    primary: true,
    sortable: true,
    truncate: true,
    minWidth: "16ch",
    cell: (group) => groupName(group)
  },
  {
    key: "id",
    header: "Group ID",
    sortable: true,
    priority: 2,
    truncate: true,
    minWidth: "12ch",
    className: "wb-cell-mono",
    cell: (group) => group.groupId
  },
  {
    key: "members",
    header: "Members",
    sortable: true,
    firstSortDir: "desc",
    align: "end",
    cell: (group) => group.memberCount
  },
  {
    key: "description",
    header: "Description",
    priority: 3,
    truncate: true,
    minWidth: "12ch",
    className: "wb-cell-muted",
    cell: (group) => group.description ?? ""
  },
  {
    key: "updated",
    header: "Updated",
    sortable: true,
    firstSortDir: "desc",
    priority: 4,
    cell: (group) => (group.updatedAt ? <Time value={group.updatedAt} /> : null)
  },
  openColumn<GroupRecord>((group) => paths.group(group.groupId), (group) => group.groupId)
];

function PrincipalDrawer({ principal, onClose, returnFocus }: { principal: PrincipalRecord; onClose: () => void; returnFocus: () => HTMLElement | null }) {
  const { session } = useSession();
  const serviceAccount = principal.kind === "service_account";
  const name = identityDisplayName(principal.displayName);
  return (
    <Drawer
      resetKey={principal.principalId}
      onClose={onClose}
      returnFocus={returnFocus}
      label={name || principal.principalId}
      kicker={
        <>
          <Icon name={serviceAccount ? "server" : "user"} /> {serviceAccount ? "Service account" : "User"} <span className="wb-num">{principal.principalId}</span>
        </>
      }
      title={name || principal.principalId}
      meta={
        <>
          <StatePill tone={principal.status === "active" ? "success" : "neutral"}>{principal.status}</StatePill>
          {<Badge tone={principal.role === "admin" ? "info" : "neutral"}>{ROLE_LABELS[principal.role]}</Badge>}
          {!serviceAccount ? <SignInMethodBadges methods={principal.signInMethods} /> : null}
          {principal.email ? <span>{principal.email}</span> : null}
        </>
      }
      actions={
        <>
          <Button variant="primary" icon="external" href={paths.principal(principal.principalId)}>
            Open
          </Button>
          <Button icon="shield" href={paths.principal(principal.principalId, "grants")}>
            Grants
          </Button>
          <Button icon="key" href={paths.principal(principal.principalId, "tokens")}>
            Tokens
          </Button>
          {session.auditQueryable ? (
            <Button variant="ghost" icon="history" href={auditListPath("admin", { principal: principal.principalId })}>
              View audit
            </Button>
          ) : null}
        </>
      }
    >
      <DrawerSection title="Details">
        <KeyValue
          items={[
            { label: "Principal", value: <span className="wb-num">{principal.principalId}</span> },
            { label: "Kind", value: serviceAccount ? "Service account" : principal.kind === "system" ? "System" : "User" },
            { label: "Email", value: principal.email || <span className="wb-muted">None</span> },
            { label: "Role", value: ROLE_LABELS[principal.role] },
            { label: "Created", value: <><Time value={principal.createdAt} format="datetime" /> <span className="wb-muted">by {principal.createdBy}</span></> },
            { label: "Updated", value: <Time value={principal.updatedAt} format="datetime" /> },
            principal.disabledAt ? { label: "Disabled", value: <Time value={principal.disabledAt} format="datetime" /> } : null
          ]}
        />
      </DrawerSection>
      <DrawerSection title="Groups" count={principal.groups.length}>
        {principal.groups.length ? (
          <div className="wb-inline">
            {principal.groups.map((group) => (
              <AppLink key={group} href={paths.group(group)} className="no-underline">
                <Chip icon="users">{group}</Chip>
              </AppLink>
            ))}
          </div>
        ) : (
          <p className="pt-prose">Not a member of any group.</p>
        )}
      </DrawerSection>
    </Drawer>
  );
}

function GroupDrawer({ group, onClose, returnFocus }: { group: GroupRecord; onClose: () => void; returnFocus: () => HTMLElement | null }) {
  const detail = useAdminGroup(group.groupId);
  const members = detail.data?.members ?? [];
  const name = identityDisplayName(group.displayName);
  return (
    <Drawer
      resetKey={group.groupId}
      onClose={onClose}
      returnFocus={returnFocus}
      label={name || group.groupId}
      kicker={
        <>
          <Icon name="users" /> Group <span className="wb-num">{group.groupId}</span>
        </>
      }
      title={name || group.groupId}
      meta={
        <>
          <StatePill tone={group.status === "active" ? "success" : "neutral"}>{group.status}</StatePill>
          <span>
            {group.memberCount} {plural(group.memberCount, "member")}
          </span>
        </>
      }
      actions={
        <>
          <Button variant="primary" icon="external" href={paths.group(group.groupId)}>
            Open
          </Button>
          <Button icon="shield" href={paths.group(group.groupId, "grants")}>
            Grants
          </Button>
        </>
      }
    >
      <DrawerSection title="Details">
        <KeyValue
          items={[
            { label: "Group", value: <span className="wb-num">{group.groupId}</span> },
            { label: "Description", value: group.description || <span className="wb-muted">None</span> },
            group.createdAt ? { label: "Created", value: <><Time value={group.createdAt} format="datetime" />{group.createdBy ? <span className="wb-muted"> by {group.createdBy}</span> : null}</> } : null,
            group.updatedAt ? { label: "Updated", value: <Time value={group.updatedAt} format="datetime" /> } : null
          ]}
        />
      </DrawerSection>
      <DrawerSection title="Members" count={group.memberCount}>
        {detail.isPending ? (
          <SkeletonBlock lines={3} />
        ) : members.length === 0 ? (
          <p className="pt-prose">No members.</p>
        ) : (
          <ul className="pt-links">
            {members.slice(0, 20).map((member) => (
              <li key={member.principalId}>
                <AppLink className="wb-link" href={paths.principal(member.principalId)}>
                  {identityDisplayName(member.displayName) || member.principalId}
                </AppLink>{" "}
                <span className="wb-num wb-muted">{identityDisplayName(member.displayName) ? member.principalId : ""}</span>
              </li>
            ))}
            {members.length > 20 ? (
              <li>
                <AppLink className="wb-link" href={paths.group(group.groupId, "members")}>
                  All {members.length} members
                </AppLink>
              </li>
            ) : null}
          </ul>
        )}
      </DrawerSection>
    </Drawer>
  );
}
