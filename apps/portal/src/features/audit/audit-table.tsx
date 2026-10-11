// Audit records as a dense one-line table grouped by day, with cursor paging
// and every list state. Rows come from the server newest first, a page at a
// time, so the columns are not sortable: sorting a partial page would mislead.
import { useMemo, type ReactNode } from "react";
import { auditResourcePresentation } from "../../lib/audit-resources";
import { useResourceTypes, type ResourceTypes } from "../../lib/resource-types";
import { AuditEntityName } from "./audit-resources";
import type { AuditRecord } from "../../types";
import { auditDayGroups, auditRecordPhase, auditTokenLabel, auditUpstreamSummary, showAuditNodeColumn } from "../../lib/audit";
import {
  Banner,
  Button,
  type DataColumn,
  DataTable,
  EmptyState,
  errorMessage,
  ErrorState,
  List,
  ListFooter,
  ListPager,
  plural,
  StateCell,
  TableGroupHeader,
  Time,
  useNow
} from "../../workbench";
import { AUDIT_TIMEOUT_MESSAGE, type AuditEventsModel } from "./audit-data";
import type { AuditUrl } from "./audit-url";
import { PrincipalName, RelatedService, TokenName, decisionMeta, relatedServiceOf } from "./audit-parts";

/** Admin views name the principal; Activity and the user tab name the token. */
export type AuditWho = "principal" | "token";

export type AuditTableProps = {
  /** Accessible name of the table. */
  label: string;
  model: AuditEventsModel;
  url: AuditUrl;
  who: AuditWho;
  principalNames: Map<string, string>;
  tokenNames: Map<string, string>;
  /** Filters beyond the defaults are active (the empty state offers to clear them). */
  filtered: boolean;
};

type ColumnOptions = {
  types: ResourceTypes;
  who: AuditWho;
  principalNames: Map<string, string>;
  tokenNames: Map<string, string>;
  /** Node shows only when the loaded records come from several nodes. */
  showNode: boolean;
};

/*
 * Priorities (see the kit README): p2 survives a default drawer, p3 a 1024px
 * window with the sidebar, p4 needs a roomy pane. Identifier columns (the
 * action, principal or token) hug their content up to a cap, with the full
 * value on hover; Decision is a dot (or a label for exceptions) under a
 * visually hidden header. Optional columns (Token, Phase, Upstream, Reason)
 * appear only when a loaded record has a value. The reason code takes the
 * spare width when shown; otherwise the table packs left (fill="end"). The
 * primary cell reads "<action> on <service>" to assistive tech (the row
 * link's name).
 */
function auditColumns({ types, who, principalNames, tokenNames, showNode }: ColumnOptions): DataColumn<AuditRecord>[] {
  const columns: (DataColumn<AuditRecord> | null)[] = [
    {
      key: "time",
      header: "Time",
      cell: (record) => <Time value={record.timestamp} />
    },
    {
      key: "decision",
      header: <span className="wb-sr-only">Decision</span>,
      cell: (record) => {
        const decision = decisionMeta(record.decision);
        const outcome = auditResourcePresentation(record, types)?.outcome;
        return <StateCell label={outcome?.label ?? decision.label} tone={outcome?.tone ?? decision.tone} quiet={record.decision === "allow"} />;
      }
    },
    {
      key: "service",
      header: "Service",
      cell: (record) => record.service,
      extra: (record) => (relatedServiceOf(record) ? <RelatedService record={record} /> : null)
    },
    {
      key: "action",
      header: "Action",
      primary: true,
      hug: "40ch",
      title: (record) => auditResourcePresentation(record, types)?.summary ?? record.action,
      cell: (record) => (
        <>
          {auditResourcePresentation(record, types)?.summary ?? record.action}
          <span className="wb-sr-only"> on {record.service}</span>
        </>
      )
    },
    {
      key: "target",
      header: "Resource",
      priority: 2,
      hug: "28ch",
      hideWhenEmpty: (record) => !auditResourcePresentation(record, types)?.entity,
      cell: (record) => {
        const entity = auditResourcePresentation(record, types)?.entity;
        return entity ? <AuditEntityName entity={entity} /> : null;
      }
    },
    who === "principal"
      ? {
          key: "principal",
          header: "Principal",
          priority: 2,
          hug: "24ch",
          title: (record) => record.principal,
          cell: (record) => <PrincipalName principal={record.principal} names={principalNames} />
        }
      : {
          key: "token",
          header: "Token",
          priority: 2,
          hug: "24ch",
          hideWhenEmpty: (record) => !auditTokenLabel(record, tokenNames).id,
          cell: (record) => <TokenName record={record} names={tokenNames} short />
        },
    {
      key: "phase",
      header: "Phase",
      priority: 3,
      hideWhenEmpty: true,
      cell: (record) => auditRecordPhase(record)
    },
    {
      key: "upstream",
      header: "Upstream",
      priority: 4,
      className: "wb-tabular",
      hideWhenEmpty: true,
      cell: (record) => auditUpstreamSummary(record)
    },
    showNode
      ? {
          key: "node",
          header: "Node",
          priority: 4,
          className: "wb-cell-mono",
          cell: (record) => record.nodeId
        }
      : null,
    {
      key: "reason",
      header: "Reason",
      priority: 3,
      truncate: true,
      minWidth: "12ch",
      className: "wb-cell-mono pt-audit-reason",
      hideWhenEmpty: true,
      title: (record) => record.reasonCode ?? undefined,
      cell: (record) => record.reasonCode ?? ""
    }
  ];
  return columns.filter((column): column is DataColumn<AuditRecord> => column !== null);
}

/** The table, its paging footer, and every list state for one paging session (a full-width List). */
export function AuditTable({ label, model, url, who, principalNames, tokenNames, filtered }: AuditTableProps) {
  const { events, records } = model;
  const types = useResourceTypes();
  const now = useNow();
  // Day groups: records arrive newest first, so each day is one run of rows.
  const days = useMemo(() => {
    const byRecord = new Map<string, string>();
    const titles = new Map<string, { title: string; sub: string }>();
    for (const group of auditDayGroups(records, now)) {
      titles.set(group.key, { title: group.title, sub: group.sub });
      for (const record of group.records) byRecord.set(record.auditId, group.key);
    }
    return { byRecord, titles };
  }, [records, now]);
  const showNode = useMemo(() => showAuditNodeColumn(records), [records]);
  const columns = useMemo(() => auditColumns({ types, who, principalNames, tokenNames, showNode }), [types, who, principalNames, tokenNames, showNode]);
  const last = records[records.length - 1];

  const loading = model.loading || (records.length === 0 && !events.isError && (events.isPlaceholderData || !events.data));
  // A failed next page belongs to the pager (below); the loaded records stay current.
  const error = events.isFetchNextPageError ? undefined : model.timedOut ? (
    <div className="pt-audit-table-note">
      <Banner tone="warning" title="The audit query timed out" live>
        {AUDIT_TIMEOUT_MESSAGE}
      </Banner>
    </div>
  ) : events.isError ? (
    <ErrorState compact title="Records unavailable" error={events.error} onRetry={model.refresh} retrying={events.isFetching} />
  ) : undefined;
  const empty = (
    <EmptyState
      compact
      icon="search"
      title="No matching records"
      actions={
        filtered ? (
          <Button icon="x" onClick={url.clearFilters}>
            Clear filters
          </Button>
        ) : null
      }
    >
      {filtered ? "No records match these filters in this time range." : "No records in this time range. Try a longer range."}
    </EmptyState>
  );
  const pageError: ReactNode = events.isFetchNextPageError
    ? model.timedOut
      ? AUDIT_TIMEOUT_MESSAGE
      : `More records could not be loaded: ${errorMessage(events.error)}`
    : undefined;

  return (
    <List full>
      <DataTable
        label={label}
        rows={records}
        rowId={(record) => record.auditId}
        columns={columns}
        fill="end"
        groupBy={(record) => days.byRecord.get(record.auditId) ?? "unknown"}
        groupHeader={({ key, rows }) => {
          const day = days.titles.get(key);
          // The last day may continue on the next page.
          const partial = model.hasMore && rows[rows.length - 1] === last;
          return (
            <TableGroupHeader
              title={day?.title ?? "Unknown time"}
              sub={day?.sub}
              count={partial ? `${rows.length}+ records` : `${rows.length} ${plural(rows.length, "record")}`}
            />
          );
        }}
        activeId={url.open.record || null}
        rowHref={(record) => url.recordHref(record)}
        onRowFollow={(record) => url.setOpen({ request: record.brokerRequestId, record: record.auditId }, "replace")}
        cursorResetKey={url.filtersKey}
        loading={loading}
        error={error}
        empty={empty}
        bleed
      />
      {records.length > 0 ? (
        <>
          <ListPager
            shown={records.length}
            noun="record"
            hasMore={model.hasMore}
            // While a filter change or refresh loads a new session, the shown records stay
            // and Load more waits.
            disabled={model.pagingBlocked}
            onLoadMore={() => void events.fetchNextPage()}
            loadingMore={events.isFetchingNextPage}
            error={pageError}
          />
          <ListFooter />
        </>
      ) : null}
    </List>
  );
}
