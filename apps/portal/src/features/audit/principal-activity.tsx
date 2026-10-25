// A principal's audit records for the admin user page's Activity tab: the
// Audit table and record drawer scoped to one principal, with a compact
// toolbar (range, decision, search) and "Open in Audit".
//
// It does not render a page frame. `frame` receives the pieces and places them
// in the page (as the user page's other tabs do):
//
//   <PrincipalActivity
//     principalId={principal.principalId}
//     frame={({ toolbar, drawer, refetching, children }) => (
//       <PortalPage drawer={drawer}>
//         <Main toolbar={pageHeader} header={toolbar} refetching={refetching}>{children}</Main>
//       </PortalPage>
//     )}
//   />
//
// `toolbar` is a kit Toolbar (fixed above the scroll region), `children` is a
// full-width List (the table and its pager) for Main's scroll region, and
// `drawer` belongs in AppShell's drawer slot. State lives in the URL (`range`,
// `decision`, `q`, and the open record's `request`/`record`); other query
// parameters are left alone.
import type { ReactNode } from "react";
import {
  AUDIT_RANGE_PRESETS,
  DEFAULT_AUDIT_RANGE,
  auditListPath,
  type AuditDecision,
  type AuditRange
} from "../../lib/audit";
import {
  Button,
  FilterInput,
  Seg,
  Toolbar,
  ToolbarRow,
  ToolbarSummary,
  findRowTarget,
  plural
} from "../../workbench";
import { paths } from "../../app/paths";
import { useAuditEvents, useAuditGroupNames, useAuditTokenNames } from "./audit-data";
import { AuditDrawer } from "./audit-drawer";
import { AuditTable } from "./audit-table";
import { DECISIONS, RangeSentence } from "./audit-parts";
import { useAuditUrl } from "./audit-url";
import "./audit.css";

const NO_NAMES = new Map<string, string>();

const DECISION_OPTIONS: { value: "" | AuditDecision; label: string }[] = [
  { value: "", label: "All" },
  { value: "allow", label: DECISIONS.allow.filterLabel },
  { value: "deny", label: DECISIONS.deny.filterLabel },
  { value: "error", label: DECISIONS.error.filterLabel }
];

const RANGE_OPTIONS: { value: AuditRange; label: string; title: string }[] = AUDIT_RANGE_PRESETS.map((preset) => ({
  value: preset.value,
  label: preset.value,
  title: preset.label
}));

export type PrincipalActivityParts = {
  /** Compact toolbar: put it in Main's `header` (under the page header and tabs). */
  toolbar: ReactNode;
  /** The record drawer, or null: put it in the page's AppShell `drawer` slot. */
  drawer: ReactNode;
  /** Background refetch, for Main's `refetching`. */
  refetching: boolean;
  /** The table and its pager (a full-width List) for Main's scroll region. */
  children: ReactNode;
};

/** The user page's Activity tab: one principal's records (admin scope, global admins). */
export function PrincipalActivity({ principalId, frame }: { principalId: string; frame: (parts: PrincipalActivityParts) => ReactNode }) {
  const url = useAuditUrl({ scope: "admin", principalId });
  const model = useAuditEvents("admin", url.filters, Boolean(principalId));
  const tokenNames = useAuditTokenNames({ principalId });
  const groupNames = useAuditGroupNames(true);
  const { filters } = url;
  const { events, records } = model;
  const tokenHref = (tokenId: string) =>
    tokenNames.has(tokenId) ? `${paths.principal(principalId, "tokens")}?token=${encodeURIComponent(tokenId)}` : null;

  const toolbar = (
    <Toolbar>
      <ToolbarRow
        primary={
          <Button
            icon="file-text"
            href={auditListPath("admin", { principal: principalId, range: filters.range, from: filters.from, to: filters.to, decision: filters.decision, q: filters.q })}
          >
            Open in Audit
          </Button>
        }
      >
        <Seg label="Time range" size="sm" value={filters.range} onChange={(range) => url.setFilters({ range, from: "", to: "" })} options={RANGE_OPTIONS} />
        <Seg label="Decision" size="sm" value={filters.decision} onChange={(decision) => url.setFilters({ decision })} options={DECISION_OPTIONS} />
        <FilterInput label="Search" value={filters.q} onChange={(q) => url.setFilters({ q })} placeholder={'Search: words, "a phrase", or prefix*'} debounceMs={400} />
        <ToolbarSummary grow>
          {model.loading ? (
            "Loading records…"
          ) : (
            <>
              <b>{records.length}</b> {plural(records.length, "record")}
              {model.hasMore ? " loaded" : ""}
            </>
          )}{" "}
          · <span data-testid="audit-range">
            <RangeSentence range={model.range} />
          </span>{" "}
          · newest first
        </ToolbarSummary>
      </ToolbarRow>
      {url.problem ? (
        <ToolbarRow>
          <p className="pt-error" role="alert">
            {url.problem}
          </p>
        </ToolbarRow>
      ) : null}
    </Toolbar>
  );

  const drawer = url.open.request ? (
    <AuditDrawer
      scope="admin"
      open={url.open}
      onSelect={(record) => url.setOpen({ request: record.brokerRequestId, record: record.auditId }, "replace")}
      onClose={() => url.setOpen(null)}
      returnFocus={() => (url.open.record ? findRowTarget(url.open.record) : null)}
      principalNames={NO_NAMES}
      groupNames={groupNames}
      tokenNames={tokenNames}
      principalId={principalId}
      tokenHref={tokenHref}
    />
  ) : null;

  return frame({
    toolbar,
    drawer,
    refetching: events.isFetching && !events.isFetchingNextPage && records.length > 0,
    children: (
      <AuditTable
        label="Activity records"
        model={model}
        url={url}
        who="token"
        principalNames={NO_NAMES}
        tokenNames={tokenNames}
        filtered={Boolean(filters.decision || filters.q || filters.range !== DEFAULT_AUDIT_RANGE)}
      />
    )
  });
}
