// Access keys for the signed-in person (My access › Keys) or an account an
// administrator opened (its Keys tab): the rows, a status filter on the
// administrator's tab, a details drawer, and revocation.
import { useMemo } from "react";
import type { AccessKeyView, PrincipalRecord } from "../../types";
import { accessKeyCounts, accessKeyFilterOf, accessKeyLive, accessKeyPills, accessKeyStatusLabel, ACCESS_KEY_FILTERS, type AccessKeyFilter } from "../../lib/access-keys";
import { identityDisplayName, modalHasOneTimeSecret } from "../../lib/helpers";
import { canWriteAdmin } from "../../lib/capabilities";
import { sortRows } from "../../lib/table-sort";
import { urlParam } from "../../lib/url-state";
import {
  Button,
  Chip,
  type DataColumn,
  DataTable,
  Drawer,
  DrawerSection,
  EmptyState,
  ErrorState,
  FilterInput,
  Icon,
  IconButton,
  KeyValue,
  plural,
  Seg,
  StateCell,
  StatePill,
  Time,
  Toolbar,
  ToolbarRow,
  ToolbarSummary
} from "../../workbench";
import type { AccountSubject } from "../../app/active-route";
import { useTableUrlState } from "../../app/list-state";
import { useModal } from "../../app/modal";
import { useSession } from "../../app/session";
import { useAdminPrincipalAccessKeys, useAdminPrincipals, useOwnAccessKeys } from "../../data/queries";
import { useAccessKeyActions } from "../../mutations/access-keys";

const SORT_KEYS = ["name", "created", "expires", "used"] as const;

export const ACCESS_KEY_LIST_STATE = {
  status: urlParam.oneOf(ACCESS_KEY_FILTERS, "current"),
  sort: urlParam.sort(SORT_KEYS),
  q: urlParam.text(),
  key: urlParam.text()
};

/** The user page also lists other tabs' items; one drawer shows at a time. */
const NONE: readonly string[] = [];
const RANK: Record<Exclude<AccessKeyFilter, "all">, number> = { current: 0, expired: 1, revoked: 2 };

/** Rows, filter, drawer and actions for one account's access keys. */
export function useAccessKeyList(subject: AccountSubject, enabled = true) {
  const { session } = useSession();
  const own = useOwnAccessKeys(enabled && !subject.administered);
  const administered = useAdminPrincipalAccessKeys(subject.principalId, enabled && subject.administered);
  const query = subject.administered ? administered : own;
  const keys = useMemo(() => query.data ?? [], [query.data]);
  const actions = useAccessKeyActions(subject);
  const principals = useAdminPrincipals(subject.administered).data;
  const list = useTableUrlState(ACCESS_KEY_LIST_STATE, "key", NONE);
  // The person's own page lists every key; the administrator's tab filters by status.
  const filtered = subject.administered;
  const counts = useMemo(() => accessKeyCounts(keys), [keys]);
  const shown = useMemo(() => {
    const q = list.state.q.trim().toLowerCase();
    const matching = keys
      .filter((key) => !filtered || list.state.status === "all" || accessKeyFilterOf(key) === list.state.status)
      .filter((key) => !filtered || !q || [key.name, key.keyId, ...accessKeyPills(key).map((pill) => pill.label)].join(" ").toLowerCase().includes(q));
    // Unsorted: live keys first, newest first within each.
    return sortRows(
      matching,
      list.state.sort,
      (key, sortKey) => (sortKey === "name" ? key.name : sortKey === "created" ? key.createdAt : sortKey === "expires" ? (key.expiresAt === null ? Infinity : Date.parse(key.expiresAt)) : key.lastUsedAt),
      (a, b) => RANK[accessKeyFilterOf(a)] - RANK[accessKeyFilterOf(b)] || b.createdAt.localeCompare(a.createdAt)
    );
  }, [keys, filtered, list.state.status, list.state.q, list.state.sort]);
  // A newly issued key's details wait until its one-time dialog is done: a
  // drawer opened behind the dialog would take its focus and its Escape.
  const { modal } = useModal();
  const open = list.openId && !modalHasOneTimeSecret(modal) ? keys.find((key) => key.keyId === list.openId) ?? null : null;
  const writable = subject.administered ? canWriteAdmin(session) : true;
  const names = useMemo(() => new Map((principals ?? []).map((principal: PrincipalRecord) => [principal.principalId, identityDisplayName(principal.displayName) || principal.principalId])), [principals]);
  const issuedBy = (principalId: string) => names.get(principalId) ?? principalId;
  return { subject, query, keys, counts, shown, open, list, actions, writable, filtered, issuedBy, loading: query.isPending && query.fetchStatus !== "idle" };
}

export type AccessKeyListModel = ReturnType<typeof useAccessKeyList>;

/** The administrator's toolbar: status filter, search, count, and the issue button with any reason it is unavailable. */
export function AccessKeyToolbar({ model, issue }: { model: AccessKeyListModel; issue: React.ReactNode }) {
  const { list, counts, shown } = model;
  return (
    <Toolbar>
      <ToolbarRow primary={issue}>
        <Seg
          label="Access key status"
          value={list.state.status}
          onChange={(status) => list.setState({ status, key: "" })}
          options={[
            { value: "current", label: "Current", icon: "circle-check", tone: "success", count: counts.current },
            { value: "expired", label: "Expired", count: counts.expired },
            { value: "revoked", label: "Revoked", count: counts.revoked },
            { value: "all", label: "All", count: counts.all }
          ]}
        />
        <FilterInput value={list.state.q} onChange={(q) => list.setState({ q })} placeholder="Filter access keys…" debounceMs={150} />
        <ToolbarSummary grow>
          <b>{shown.length}</b> {plural(shown.length, "key")}
        </ToolbarSummary>
      </ToolbarRow>
    </Toolbar>
  );
}

/** What a key gives access to: one chip per type, a type no longer held marked in words. */
export function AccessKeyPills({ keyView }: { keyView: Pick<AccessKeyView, "accessKeyTypeStates"> }) {
  return (
    <span className="wb-inline pt-key-pills">
      {accessKeyPills(keyView).map((pill) =>
        pill.held ? (
          <Chip key={pill.id}>{pill.label}</Chip>
        ) : (
          <Chip key={pill.id} readOnly icon="ban" className="pt-key-pill-gone" title={`No longer available: this key no longer gives access to ${pill.label}.`}>
            {pill.label}
            <span className="pt-key-pill-flag"> · no longer available</span>
          </Chip>
        )
      )}
    </span>
  );
}

export function AccessKeyStatusCell({ keyView }: { keyView: Pick<AccessKeyView, "status" | "access"> }) {
  const status = accessKeyStatusLabel(keyView);
  return <StateCell label={status.label} tone={status.tone} quiet={status.quiet} title={status.title} />;
}

export function AccessKeyTable({ model, empty, label = "Access keys" }: { model: AccessKeyListModel; empty: React.ReactNode; label?: string }) {
  const { shown, list, actions, writable, subject, query, counts, issuedBy, filtered } = model;
  const columns = useMemo<DataColumn<AccessKeyView>[]>(
    () => [
      { key: "name", header: "Name", sortable: true, truncate: true, minWidth: "16ch", title: (key) => key.name, cell: (key) => key.name },
      { key: "access", header: "Access", priority: 3, cell: (key) => <AccessKeyPills keyView={key} /> },
      { key: "created", header: "Created", sortable: true, firstSortDir: "desc", priority: 3, cell: (key) => <Time value={key.createdAt} /> },
      { key: "expires", header: "Expires", sortable: true, priority: 2, cell: (key) => key.expiresAt === null ? <span className="wb-muted">Never</span> : <Time value={key.expiresAt} /> },
      { key: "used", header: "Last used", sortable: true, firstSortDir: "desc", priority: 2, cell: (key) => (key.lastUsedAt ? <Time value={key.lastUsedAt} /> : <span className="wb-muted">Never</span>) },
      { key: "status", header: "Status", cell: (key) => <AccessKeyStatusCell keyView={key} /> },
      ...(subject.administered ? [{ key: "issued-by", header: "Issued by", priority: 3, truncate: true, minWidth: "10ch", title: (key: AccessKeyView) => key.createdBy, cell: (key: AccessKeyView) => issuedBy(key.createdBy) } satisfies DataColumn<AccessKeyView>] : []),
      {
        key: "row-actions",
        header: <span className="wb-sr-only">Row actions</span>,
        className: "wb-cell-actions",
        cell: (key) => (writable && key.revokedAt === null ? (
          <div className="wb-row-actions">
            <IconButton size="sm" icon="trash" label={`Revoke ${key.name}`} onClick={() => actions.confirmRevoke(key)} />
          </div>
        ) : null)
      }
    ],
    [actions, writable, subject.administered, issuedBy]
  );
  const searching = filtered && Boolean(list.state.q || list.state.status !== "current") && counts.all > 0;
  return (
    <DataTable
      label={label}
      rows={shown}
      rowId={(key) => key.keyId}
      columns={columns}
      sort={list.state.sort}
      onSortChange={(sort) => list.setState({ sort })}
      activeId={list.openId}
      rowHref={(key) => list.itemHref(key.keyId)}
      onRowFollow={(key) => list.open(key.keyId, "replace")}
      cursorResetKey={`${list.state.status}|${list.state.q}|${list.state.sort?.key ?? ""}:${list.state.sort?.dir ?? ""}`}
      rowDim={(key) => !accessKeyLive(key)}
      loading={model.loading || (query.isError && query.isFetching)}
      error={query.isError ? <ErrorState compact title="Couldn’t load access keys" error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} /> : undefined}
      empty={searching ? (
        <EmptyState compact icon="search" title="No matching access keys" actions={<Button onClick={() => list.setState({ q: "", status: "current" })} icon="x">Clear filters</Button>}>
          Try another status or search.
        </EmptyState>
      ) : empty}
      bleed
    />
  );
}

export function AccessKeyDrawer({ model }: { model: AccessKeyListModel }) {
  const { open, list, actions, writable, subject, issuedBy } = model;
  if (!open) return null;
  const status = accessKeyStatusLabel(open);
  const live = writable && open.revokedAt === null;
  return (
    <Drawer
      resetKey={open.keyId}
      onClose={list.close}
      returnFocus={list.returnFocus}
      label={`Access key ${open.name}`}
      kicker={<><Icon name="key" /> Access key <span className="wb-num">{open.keyId}</span></>}
      title={open.name}
      meta={
        <>
          <StatePill tone={status.tone}>{status.label}</StatePill>
          <span>created <Time value={open.createdAt} /></span>
        </>
      }
      actions={live ? <Button variant="danger-ghost" icon="trash" onClick={() => actions.confirmRevoke(open)}>Revoke</Button> : null}
    >
      <DrawerSection title="Gives access to">
        <AccessKeyPills keyView={open} />
        {status.title ? <p className="pt-prose">{status.title}</p> : null}
      </DrawerSection>
      <DrawerSection title="Details">
        <KeyValue
          items={[
            { label: "Key ID", value: <span className="wb-num">{open.keyId}</span> },
            { label: "Owner", value: <span className="wb-num">{open.principalId}</span> },
            { label: "Issued by", value: <>{subject.administered ? issuedBy(open.createdBy) : open.createdBy}{open.origin === "administrator" ? <span className="wb-muted"> · an administrator</span> : null}</> },
            { label: "Created", value: <Time value={open.createdAt} format="datetime" /> },
            { label: "Expires", value: open.expiresAt === null ? "Never" : <Time value={open.expiresAt} format="datetime" /> },
            { label: "Last used", value: open.lastUsedAt ? <Time value={open.lastUsedAt} format="datetime" /> : "Never" },
            open.revokedAt ? { label: "Revoked", value: <><Time value={open.revokedAt} format="datetime" /> <span className="wb-muted">by {open.revokedBy ?? "unknown"}</span></> } : null
          ]}
        />
        {live ? <p className="pt-prose">An access key cannot be changed. Revoke it when it is no longer needed or its value may be exposed.</p> : null}
      </DrawerSection>
    </Drawer>
  );
}
