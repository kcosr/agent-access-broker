// URL state for the audit views: server-side filters and the open record
// (`?request=<brokerRequestId>&record=<auditId>`). The URL is the source of
// truth; filter edits replace the history entry, opening a record pushes one.
import { useCallback, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router";
import {
  DEFAULT_AUDIT_FILTERS,
  NO_AUDIT_OPEN,
  auditFiltersProblem,
  auditFiltersSearch,
  auditPageSearch,
  parseAuditFilters,
  parseAuditOpen,
  type AuditFilters,
  type AuditOpen,
  type AuditScope
} from "../../lib/audit";

/** Parameters the embedded (user page) view owns; everything else in the URL belongs to the page. */
const EMBEDDED_KEYS = ["range", "from", "to", "decision", "q", "request", "record"] as const;

export type AuditUrlOptions = {
  scope: AuditScope;
  /**
   * Embedded on a principal's page: the principal is fixed (never in the URL),
   * only range, decision, and search are read, and other page parameters are kept.
   */
  principalId?: string;
};

function withSearch(current: string, next: string, embedded: boolean) {
  if (!embedded) return next;
  const params = new URLSearchParams(current);
  for (const key of EMBEDDED_KEYS) params.delete(key);
  for (const [key, value] of new URLSearchParams(next)) params.append(key, value);
  const query = params.toString();
  return query ? `?${query}` : "";
}

export function useAuditUrl({ scope, principalId }: AuditUrlOptions) {
  const location = useLocation();
  const navigate = useNavigate();
  const embedded = principalId !== undefined;
  const filters = useMemo<AuditFilters>(() => {
    const parsed = parseAuditFilters(location.search, scope);
    if (!embedded) return parsed;
    const { range, from, to, decision, q } = parsed;
    return { ...DEFAULT_AUDIT_FILTERS, range, from, to, decision, q, principal: principalId };
  }, [location.search, scope, embedded, principalId]);
  const open = useMemo(() => parseAuditOpen(location.search), [location.search]);
  /** The applied filters as a key (the table's cursor resets when it changes). */
  const filtersKey = auditFiltersSearch(filters, scope);
  const [problem, setProblem] = useState<string | null>(null);

  const searchFor = useCallback(
    (nextFilters: AuditFilters, nextOpen: AuditOpen) =>
      withSearch(location.search, auditPageSearch(embedded ? { ...nextFilters, principal: "" } : nextFilters, scope, nextOpen), embedded),
    [location.search, embedded, scope]
  );

  const go = useCallback(
    (search: string, history: "push" | "replace") => {
      if (search === location.search) return;
      navigate({ pathname: location.pathname, search }, { replace: history === "replace", state: location.state, preventScrollReset: true });
    },
    [location.pathname, location.search, location.state, navigate]
  );

  // Normalize the address bar to the parsed filters (drops unknown or invalid values).
  const canonical = embedded ? location.search : searchFor(filters, open);
  useEffect(() => {
    if (canonical !== location.search) go(canonical, "replace");
  }, [canonical, location.search, go]);

  /** Applies filter changes (server-side, single-valued); invalid combinations are reported instead. */
  const setFilters = useCallback(
    (patch: Partial<AuditFilters>) => {
      const next = { ...filters, ...patch, ...(embedded ? { principal: principalId } : {}) };
      const issue = auditFiltersProblem(next);
      setProblem(issue);
      if (issue) return false;
      go(searchFor(next, open), "replace");
      return true;
    },
    [filters, embedded, principalId, go, searchFor, open]
  );

  const clearFilters = useCallback(() => {
    setProblem(null);
    go(searchFor({ ...DEFAULT_AUDIT_FILTERS, ...(embedded ? { principal: principalId } : {}) }, open), "replace");
  }, [embedded, principalId, go, searchFor, open]);

  const setOpen = useCallback(
    (next: AuditOpen | null, history: "push" | "replace" = "push") => go(searchFor(filters, next ?? NO_AUDIT_OPEN), history),
    [go, searchFor, filters]
  );

  /** Row link: opens the record, or closes it when it is already open. */
  const recordHref = useCallback(
    (record: { brokerRequestId: string; auditId: string }) =>
      `${location.pathname}${searchFor(filters, open.record === record.auditId ? NO_AUDIT_OPEN : { request: record.brokerRequestId, record: record.auditId })}`,
    [location.pathname, searchFor, filters, open.record]
  );

  return { scope, embedded, filters, filtersKey, open, problem, setProblem, setFilters, clearFilters, setOpen, recordHref };
}

export type AuditUrl = ReturnType<typeof useAuditUrl>;
