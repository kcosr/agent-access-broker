// Agent tokens for the signed-in user (Tokens tab) or an administered
// principal (the user page's Tokens tab): status filter, rows, and a drawer.
import { useMemo } from "react";
import type { AgentTokenOptions, BrokerTokenRecord } from "../../types";
import {
  canViewActivity,
  canViewAudit,
  tokenAllowedServiceItems,
  tokenAllowedServicesSummary,
  tokenExecutionContextsSummary,
  tokenStatus,
  type TokenStatus
} from "../../lib/helpers";
import { grantedServiceActions, serviceDisplayNames } from "../../lib/access";
import { auditTokenPath } from "../../lib/audit";
import { urlParam } from "../../lib/url-state";
import { sortRows } from "../../lib/table-sort";
import {
  AppLink,
  Badge,
  Button,
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
  List,
  ListFooter,
  plural,
  Seg,
  StateCell,
  StatePill,
  Time,
  type Tone,
  Toolbar,
  ToolbarRow,
  ToolbarSummary
} from "../../workbench";
import type { AccountSubject } from "../../app/active-route";
import { useActionRunner } from "../../app/actions";
import { useTableUrlState } from "../../app/list-state";
import { useSession } from "../../app/session";
import { useAgentTokenOptions, useConsoleData } from "../../data/queries";
import { useAgentTokenActions } from "../../mutations/tokens";
import { EffectiveAccessDisclosure } from "../../components/effective-access";
import { TokenBoundary } from "./token-boundary";

const STATUS_FILTERS = ["current", "expired", "revoked", "all"] as const;
type StatusFilter = (typeof STATUS_FILTERS)[number];

const SORT_KEYS = ["name", "expires", "used"] as const;

export const TOKEN_LIST_STATE = {
  status: urlParam.oneOf(STATUS_FILTERS, "current"),
  sort: urlParam.sort(SORT_KEYS),
  q: urlParam.text(),
  token: urlParam.text()
};

export const STATUS_TONE: Record<TokenStatus, Tone> = { Active: "success", Paused: "warning", Expired: "muted", Revoked: "neutral" };
const STATUS_ICON = { Active: "circle-check", Paused: "pause", Expired: "clock", Revoked: "ban" } as const;
const STATUS_RANK: Record<TokenStatus, number> = { Active: 0, Paused: 1, Expired: 2, Revoked: 3 };

function matchesStatus(filter: StatusFilter, status: TokenStatus) {
  if (filter === "all") return true;
  if (filter === "current") return status === "Active" || status === "Paused";
  return filter === "expired" ? status === "Expired" : status === "Revoked";
}

/** The user page also lists management tokens (`?mtoken=`); one drawer shows at a time. */
const ADMIN_EXCLUSIVE = ["mtoken"] as const;
const SELF_EXCLUSIVE: readonly string[] = [];

/** Rows, filters, drawer, and actions for one principal's agent tokens. */
export function useTokenList(subject: AccountSubject) {
  const { session } = useSession();
  const data = useConsoleData(subject);
  const options = useAgentTokenOptions(subject);
  const actions = useAgentTokenActions(subject, options.options);
  const tokens = data.tokens;
  const names = useMemo(() => serviceDisplayNames(options.options, data.credentials.connections), [options.options, data.credentials.connections]);
  const counts = useMemo(() => {
    const counts: Record<StatusFilter, number> = { current: 0, expired: 0, revoked: 0, all: tokens.length };
    for (const token of tokens) {
      const status = tokenStatus(token);
      if (status === "Active" || status === "Paused") counts.current += 1;
      else if (status === "Expired") counts.expired += 1;
      else counts.revoked += 1;
    }
    return counts;
  }, [tokens]);
  const list = useTableUrlState(TOKEN_LIST_STATE, "token", subject.administered ? ADMIN_EXCLUSIVE : SELF_EXCLUSIVE);
  const shown = useMemo(() => {
    const query = list.state.q.trim().toLowerCase();
    const matching = tokens
      .filter((token) => matchesStatus(list.state.status, tokenStatus(token)))
      .filter((token) => {
        const services = tokenAllowedServiceItems(token) ?? [];
        return !query || [token.name, token.tokenId, tokenAllowedServicesSummary(token), ...services.map((service) => names.get(service) ?? "")].join(" ").toLowerCase().includes(query);
      });
    // Unsorted: live tokens first (Active, Paused, Expired, Revoked), newest first within a status.
    return sortRows(
      matching,
      list.state.sort,
      (token, key) => (key === "name" ? token.name : key === "expires" ? token.expiresAt : token.lastUsedAt),
      (a, b) => STATUS_RANK[tokenStatus(a)] - STATUS_RANK[tokenStatus(b)] || b.createdAt.localeCompare(a.createdAt)
    );
  }, [tokens, names, list.state.status, list.state.q, list.state.sort]);
  const open = list.openId ? tokens.find((token) => token.tokenId === list.openId) ?? null : null;
  const auditScope = subject.administered ? (canViewAudit(session) ? "admin" : null) : canViewActivity(session) ? "self" : null;
  const activityHref = (record: BrokerTokenRecord) => (auditScope ? auditTokenPath(auditScope, record) : undefined);
  return { subject, data, options, names, actions, counts, shown, open, list, activityHref };
}

export type TokenListModel = ReturnType<typeof useTokenList>;

export function TokenToolbar({ model }: { model: TokenListModel }) {
  const { list, counts, shown, actions, options } = model;
  const blocker = options.loading ? "Loading token options…" : actions.issueBlocker();
  return (
    <Toolbar>
      <ToolbarRow
        primary={actions.writable ?
          <Button variant="primary" icon="plus" onClick={() => actions.openIssuePage()} disabled={blocker !== null} title={blocker ?? undefined}>
            Issue token
          </Button> : null
        }
      >
        <Seg
          label="Token status"
          value={list.state.status}
          onChange={(status) => list.setState({ status, token: "" })}
          options={[
            { value: "current", label: "Current", icon: "circle-check", tone: "success", count: counts.current },
            { value: "expired", label: "Expired", count: counts.expired },
            { value: "revoked", label: "Revoked", count: counts.revoked },
            { value: "all", label: "All", count: counts.all }
          ]}
        />
        <FilterInput value={list.state.q} onChange={(q) => list.setState({ q })} placeholder="Filter tokens…" debounceMs={150} />
        <ToolbarSummary grow>
          <b>{shown.length}</b> {plural(shown.length, "token")}
        </ToolbarSummary>
      </ToolbarRow>
    </Toolbar>
  );
}

export function TokenTable({ model, label = "Tokens" }: { model: TokenListModel; label?: string }) {
  const { data, shown, list, actions, options, names, counts, activityHref } = model;
  const runner = useActionRunner();
  const executionContexts = options.options?.executionContexts;
  const columns = useMemo<DataColumn<BrokerTokenRecord>[]>(
    () => [
      {
        key: "name",
        header: "Name",
        sortable: true,
        // Token names are identifiers: they hug, up to a cap (full name on hover).
        hug: "28ch",
        cell: (token) => token.name
      },
      {
        key: "id",
        header: "ID",
        priority: 4,
        className: "wb-cell-mono",
        title: (token) => token.tokenId,
        cell: (token) => token.tokenId.slice(0, 8)
      },
      {
        key: "status",
        header: "Status",
        cell: (token) => {
          const status = tokenStatus(token);
          return <StateCell label={status} tone={STATUS_TONE[status]} quiet={status === "Active"} />;
        }
      },
      {
        key: "services",
        header: "Services",
        priority: 3,
        hug: "32ch",
        title: (token) => tokenAllowedServiceItems(token)?.join(", ") ?? "Every service the owner's grants allow",
        cell: (token) =>
          tokenAllowedServiceItems(token)
            ?.map((service) => names.get(service) ?? service)
            .join(", ") ?? <span className="wb-muted">All granted</span>,
        extra: (token) =>
          token.scopes.serviceRestrictions ? (
            <Badge variant="outline" title="Restricted to selected actions and resources">
              Restricted
            </Badge>
          ) : null
      },
      {
        key: "contexts",
        header: "Contexts",
        priority: 3,
        className: "wb-cell-mono",
        cell: (token) => tokenExecutionContextsSummary(token, executionContexts)
      },
      {
        key: "expires",
        header: "Expires",
        sortable: true,
        priority: 2,
        cell: (token) => (token.expiresAt ? <Time value={token.expiresAt} /> : <span className="wb-muted">Never</span>)
      },
      {
        key: "used",
        header: "Last used",
        sortable: true,
        firstSortDir: "desc",
        priority: 2,
        cell: (token) => {
          if (!token.lastUsedAt) return <span className="wb-muted">Never</span>;
          const href = activityHref(token);
          return href ? (
            <AppLink className="wb-link" href={href} title={`Show activity for ${token.name}`}>
              <Time value={token.lastUsedAt} />
            </AppLink>
          ) : (
            <Time value={token.lastUsedAt} />
          );
        }
      },
      {
        key: "row-actions",
        header: <span className="wb-sr-only">Row actions</span>,
        className: "wb-cell-actions",
        cell: (token) => {
          const status = tokenStatus(token);
          if (!actions.writable || (status !== "Active" && status !== "Paused")) return null;
          return (
            <div className="wb-row-actions">
              <IconButton
                size="sm"
                icon={status === "Paused" ? "play" : "pause"}
                label={`${status === "Paused" ? "Resume" : "Pause"} ${token.name}`}
                disabled={runner.busy}
                onClick={() => void runner.run(token.tokenId, () => actions.setPaused(token, status !== "Paused"))}
              />
              <IconButton size="sm" icon="trash" label={`Revoke ${token.name}`} onClick={() => actions.confirmRevoke(token)} />
            </div>
          );
        }
      }
    ],
    [executionContexts, names, activityHref, runner, actions]
  );
  const filtered = Boolean(list.state.q || list.state.status !== "current");
  const empty =
    filtered && counts.all > 0 ? (
      <EmptyState
        compact
        icon="search"
        title="No matching tokens"
        actions={
          <Button onClick={() => list.setState({ q: "", status: "current" })} icon="x">
            Clear filters
          </Button>
        }
      >
        Try another status or search.
      </EmptyState>
    ) : (
      <EmptyState
        compact
        icon="key"
        title={model.subject.administered ? "No agent tokens" : "No agent tokens yet"}
        actions={
          actions.issueBlocker() === null ? (
            <Button variant="primary" icon="plus" onClick={() => actions.openIssuePage()}>
              Issue token
            </Button>
          ) : null
        }
      >
        {options.options && options.options.executionContexts.length === 0
          ? "An active grant is needed before an execution-context-bound token can be issued."
          : "Agents authenticate to the broker with a token bound to the contexts and access you choose."}
      </EmptyState>
    );
  return (
    <DataTable
      label={label}
      rows={shown}
      rowId={(token) => token.tokenId}
      // Every column hugs: the table packs left and the spare width stays at the end.
      fill="end"
      columns={columns}
      sort={list.state.sort}
      onSortChange={(sort) => list.setState({ sort })}
      activeId={list.openId}
      rowHref={(token) => list.itemHref(token.tokenId)}
      onRowFollow={(token) => list.open(token.tokenId, "replace")}
      cursorResetKey={`${list.state.status}|${list.state.q}|${list.state.sort?.key ?? ""}:${list.state.sort?.dir ?? ""}`}
      rowDim={(token) => {
        const status = tokenStatus(token);
        return status === "Expired" || status === "Revoked";
      }}
      loading={data.loading || (data.query.isError && data.query.isFetching)}
      error={
        data.query.isError ? (
          <ErrorState compact title="Couldn’t load tokens" error={data.query.error} onRetry={() => void data.query.refetch()} retrying={data.query.isFetching} />
        ) : undefined
      }
      empty={empty}
      bleed
    />
  );
}

export function TokenDrawer({ model }: { model: TokenListModel }) {
  const { open, list, actions, options, activityHref } = model;
  const runner = useActionRunner();
  if (!open) return null;
  return <AgentTokenDrawer record={open} writable={actions.writable} options={options.options} administered={model.subject.administered} activityHref={activityHref(open)} onClose={list.close} returnFocus={list.returnFocus} busy={runner.busy} pending={runner.pending} onPause={(paused) => void runner.run("pause", () => actions.setPaused(open, paused))} onRevoke={() => actions.confirmRevoke(open)} />;
}

function AgentTokenDrawer({
  record,
  writable,
  options,
  administered,
  activityHref,
  onClose,
  returnFocus,
  busy,
  pending,
  onPause,
  onRevoke
}: {
  record: BrokerTokenRecord;
  writable: boolean;
  options: AgentTokenOptions | null;
  administered: boolean;
  activityHref: string | undefined;
  onClose: () => void;
  returnFocus: () => HTMLElement | null;
  busy: boolean;
  pending: string | null;
  onPause: (paused: boolean) => void;
  onRevoke: () => void;
}) {
  const status = tokenStatus(record);
  const live = writable && (status === "Active" || status === "Paused");
  return (
    <Drawer
      resetKey={record.tokenId}
      onClose={onClose}
      returnFocus={returnFocus}
      label={`Token ${record.name}`}
      kicker={
        <>
          <Icon name="key" /> Agent token <span className="wb-num">{record.tokenId}</span>
        </>
      }
      title={record.name}
      meta={
        <>
          <StatePill tone={STATUS_TONE[status]} icon={STATUS_ICON[status]}>
            {status}
          </StatePill>
          {administered ? <span className="wb-num">{record.principalId}</span> : null}
          <span>
            created <Time value={record.createdAt} />
          </span>
        </>
      }
      actions={
        <>
          {live ? (
            <Button icon={status === "Paused" ? "play" : "pause"} onClick={() => onPause(status !== "Paused")} pending={pending === "pause"} disabled={busy && pending !== "pause"}>
              {status === "Paused" ? "Resume token" : "Pause token"}
            </Button>
          ) : null}
          {live ? (
            <Button variant="danger-ghost" icon="trash" onClick={onRevoke}>
              Revoke
            </Button>
          ) : null}
          {activityHref && record.lastUsedAt ? (
            <Button icon="history" href={activityHref}>
              {administered ? "View audit" : "View activity"}
            </Button>
          ) : null}
        </>
      }
    >
      <DrawerSection title="Details">
        <KeyValue
          items={[
            { label: "Token ID", value: <span className="wb-num">{record.tokenId}</span> },
            { label: "Class", value: <span className="wb-num">{record.tokenClass}</span> },
            { label: "Owner", value: <span className="wb-num">{record.principalId}</span> },
            { label: "Created", value: <><Time value={record.createdAt} format="datetime" /> <span className="wb-muted">by {record.createdBy}</span></> },
            { label: "Expires", value: record.expiresAt ? <Time value={record.expiresAt} format="datetime" /> : "Never" },
            {
              label: "Last used",
              value: record.lastUsedAt ? (
                activityHref ? (
                  <AppLink href={activityHref} className="wb-link" title={`Show activity for ${record.name}`}>
                    <Time value={record.lastUsedAt} format="datetime" />
                  </AppLink>
                ) : (
                  <Time value={record.lastUsedAt} format="datetime" />
                )
              ) : (
                "Never"
              )
            },
            record.pausedAt ? { label: "Paused", value: <><Time value={record.pausedAt} format="datetime" /> <span className="wb-muted">by {record.pausedBy ?? "unknown"}</span></> } : null,
            record.revokedAt ? { label: "Revoked", value: <><Time value={record.revokedAt} format="datetime" /> <span className="wb-muted">by {record.revokedBy ?? "unknown"}</span></> } : null
          ]}
        />
        {record.tokenClass === "agent_invoke" && live ? (
          <p className="pt-prose">Pausing blocks the token temporarily. If its secret may be exposed, revoke it instead.</p>
        ) : null}
      </DrawerSection>
      {record.tokenClass === "agent_invoke" ? (
        <DrawerSection title="Boundary">
          <TokenBoundary record={record} options={options} />
        </DrawerSection>
      ) : null}
      {record.tokenClass === "agent_invoke" && status === "Active" ? (
        <DrawerSection title="Effective access">
          <EffectiveAccessDisclosure
            summary="Show what this token can reach now"
            token={{
              allowedServices: record.scopes.allowedServices,
              allowedExecutionContexts: record.scopes.allowedExecutionContexts ?? [],
              serviceRestrictions: record.scopes.serviceRestrictions
            }}
            principalId={administered ? record.principalId : undefined}
            serviceNames={serviceDisplayNames(options)}
            grantedActions={grantedServiceActions(options)}
          />
        </DrawerSection>
      ) : null}
    </Drawer>
  );
}

/** The Tokens page body: the table and its keyboard hints. */
export function TokenListBody({ model }: { model: TokenListModel }) {
  return (
    <List full>
      <TokenTable model={model} />
      {model.shown.length > 0 ? <ListFooter /> : null}
    </List>
  );
}
