import { canViewAdmin } from "../../lib/capabilities";
// Audit reads for the Audit and Activity views and the user page's Activity
// tab: paged record sessions, filter suggestions, request timelines, and the
// caller's token names.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { keepPreviousData, useInfiniteQuery, useQuery, useQueryClient, type InfiniteData } from "@tanstack/react-query";
import { ApiError, brokerApi } from "../../api";
import type { AuditEventsPage, AuditRecord } from "../../types";
import { portalQueryKeys } from "../../lib/portal-queries";
import {
  AUDIT_AUTO_REFRESH_MS,
  auditActionSuggestions,
  auditContinuationParams,
  auditFiltersSearch,
  auditGroupNames,
  auditListParams,
  auditPrincipalSuggestions,
  auditServiceSuggestions,
  auditTokenNames,
  isAuditRequestId,
  resolveAuditRange,
  type AuditFilters,
  type AuditScope,
  type AuditSessionRange,
  type AuditSuggestion
} from "../../lib/audit";
import { adminSubject, useSelfSubject } from "../../app/active-route";
import { useAgentTokenOptions, useConsoleData, usePolicyCatalog, useQueryAccess } from "../../data/queries";

export const AUDIT_TIMEOUT_MESSAGE = "The audit query took too long. Narrow the time range or add filters, then try again.";

export function isAuditError(error: unknown, ...reasonCodes: string[]): error is ApiError {
  return error instanceof ApiError && reasonCodes.includes(error.reasonCode ?? "");
}

type PagingSession = { id: number; key: string; range: AuditSessionRange };

/**
 * One paging session per filter set: a relative range resolves to absolute
 * bounds when the session starts, so "Load more" pages stay consistent.
 * Refresh (and auto-refresh) start a new session with the same filters.
 */
export function useAuditEvents(scope: AuditScope, filters: AuditFilters, enabled = true) {
  const { viewer, signedIn, runQuery } = useQueryAccess();
  const key = auditFiltersSearch(filters, scope);
  const [paging, setPaging] = useState<PagingSession>(() => ({ id: 0, key, range: resolveAuditRange(filters, Date.now()) }));
  let session = paging;
  if (paging.key !== key) {
    // New filters start a new session (state derived during render).
    session = { id: paging.id + 1, key, range: resolveAuditRange(filters, Date.now()) };
    setPaging(session);
  }
  const firstPage = useMemo(() => auditListParams(filters, session.range, scope), [filters, session.range, scope]);
  const events = useInfiniteQuery<AuditEventsPage, Error, InfiniteData<AuditEventsPage>, readonly unknown[], string | null>({
    queryKey: portalQueryKeys.auditEvents(viewer, scope, session.id, firstPage),
    enabled: enabled && signedIn,
    initialPageParam: null,
    queryFn: ({ pageParam }) =>
      runQuery((current) => brokerApi.auditEvents(current, scope, pageParam ? auditContinuationParams(pageParam) : firstPage)),
    getNextPageParam: (lastPage) => lastPage.nextCursor ?? undefined,
    placeholderData: keepPreviousData,
    staleTime: Infinity,
    gcTime: 0
  });
  // Rows shown for another filter set are dimmed while the new session loads;
  // a refresh of the same filters keeps them at full strength.
  const shownKey = useRef(key);
  if (events.data && !events.isPlaceholderData) shownKey.current = key;
  const changing = events.isPlaceholderData && shownKey.current !== key;
  // A failed new session shows no rows rather than the previous session's.
  const staleFailure = events.isError && events.isPlaceholderData;
  const records = useMemo<AuditRecord[]>(
    () => (staleFailure ? [] : events.data?.pages.flatMap((page) => page.items) ?? []),
    [events.data, staleFailure]
  );
  const pagesLoaded = staleFailure ? 0 : events.data?.pages.length ?? 0;
  // Whether the shown records continue on a next page. While a new session
  // loads, TanStack reports no next page (the new query has none yet); the
  // shown session's answer stays, so its Load more stays (disabled) in place.
  const shownHasMore = useRef(false);
  if (!events.isPlaceholderData) shownHasMore.current = events.hasNextPage;
  const hasMore = !staleFailure && shownHasMore.current;

  const filtersRef = useRef(filters);
  filtersRef.current = filters;
  const refresh = useCallback(() => {
    setPaging((current) => ({ id: current.id + 1, key: current.key, range: resolveAuditRange(filtersRef.current, Date.now()) }));
  }, []);

  const [autoRefresh, setAutoRefresh] = useState(false);
  const refreshState = useRef({ pagesLoaded, fetching: events.isFetching });
  refreshState.current = { pagesLoaded, fetching: events.isFetching };
  useEffect(() => {
    if (!autoRefresh) return;
    const timer = window.setInterval(() => {
      const state = refreshState.current;
      if (document.visibilityState !== "visible" || state.pagesLoaded > 1 || state.fetching) return;
      refresh();
    }, AUDIT_AUTO_REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [autoRefresh, refresh]);

  return {
    events,
    records,
    range: session.range,
    pagesLoaded,
    hasMore,
    /** A new session is loading behind the shown records: paging them would mix sessions. */
    pagingBlocked: events.isPlaceholderData,
    loading: events.isPending && !events.data && enabled && signedIn,
    changing,
    timedOut: isAuditError(events.error, "audit_query_timeout"),
    refresh,
    autoRefresh,
    setAutoRefresh,
    autoRefreshPaused: autoRefresh && pagesLoaded > 1
  };
}

export type AuditEventsModel = ReturnType<typeof useAuditEvents>;

/** Canonical broker audit actions for this tier; null when unavailable (suggestions are optional). */
function useAuditOptions(scope: AuditScope) {
  const { viewer, signedIn, runQuery } = useQueryAccess();
  return useQuery({
    queryKey: portalQueryKeys.auditOptions(viewer, scope),
    enabled: signedIn,
    queryFn: () =>
      runQuery(async (current) => {
        try {
          return await brokerApi.auditOptions(current, scope);
        } catch (error) {
          // Preserve normal authentication handling; anything else only loses suggestions.
          if (error instanceof ApiError && (error.status === 401 || error.status === 403)) throw error;
          return null;
        }
      })
  });
}

/**
 * Filter suggestions: services and actions from the broker's canonical audit
 * options plus the configured catalog (Audit) or the caller's granted services
 * from the token options (Activity), and catalog users as principals (Audit).
 */
export function useAuditSuggestions(scope: AuditScope) {
  const { session } = useQueryAccess();
  const options = useAuditOptions(scope);
  const catalog = usePolicyCatalog(scope === "admin").data ?? null;
  const own = useAgentTokenOptions(useSelfSubject(), scope === "self").options;
  const brokerOptions = useMemo(() => options.data?.services ?? [], [options.data]);
  const managed = scope === "admin" && !canViewAdmin(session) ? session.policyManagementServices ?? [] : null;
  const catalogServices = useMemo(
    () =>
      (scope === "admin" ? catalog?.services ?? [] : own?.services ?? []).map((service) => ({
        service: service.service,
        displayName: service.displayName,
        actions: service.actions.map((action) => action.action)
      })),
    [scope, catalog, own]
  );
  const services = useMemo(() => {
    const configured = managed
      ? managed.map((service) => ({ service, displayName: catalogServices.find((item) => item.service === service)?.displayName }))
      : catalogServices;
    return auditServiceSuggestions(configured, brokerOptions);
  }, [managed, catalogServices, brokerOptions]);
  const actionSources = useMemo(() => [...catalogServices, ...brokerOptions], [catalogServices, brokerOptions]);
  const principals = useMemo(() => auditPrincipalSuggestions(catalog?.subjects.users ?? []), [catalog]);
  const principalNames = useMemo(
    () => new Map((catalog?.subjects.users ?? []).flatMap((user) => (user.principalId && user.displayName ? [[user.principalId, user.displayName] as const] : []))),
    [catalog]
  );
  const groupNames = useMemo(() => auditGroupNames(catalog?.subjects.groups ?? []), [catalog]);
  const actions = useCallback(
    (service: string): AuditSuggestion[] => auditActionSuggestions(actionSources, service).map((action) => ({ value: action, label: action })),
    [actionSources]
  );
  return {
    services,
    actionSources,
    actions,
    principals,
    principalNames,
    /** Group display names (Audit), from the same catalog as principal names. */
    groupNames,
    /** The broker could not return suggestions; filters stay editable. */
    unavailable: options.isError || options.data === null,
    refetch: options.refetch
  };
}

export type AuditSuggestions = ReturnType<typeof useAuditSuggestions>;

/** Group display names from the policy catalog, for a viewer who can read it. */
export function useAuditGroupNames(enabled: boolean) {
  const catalog = usePolicyCatalog(enabled).data ?? null;
  return useMemo(() => auditGroupNames(catalog?.subjects.groups ?? []), [catalog]);
}

/**
 * Token names for records: the signed-in user's own tokens (Activity), or an
 * administered principal's (the user page), revoked and expired included.
 */
export function useAuditTokenNames(owner: { self: true } | { principalId: string } | null) {
  const self = useSelfSubject();
  const administered = owner && "principalId" in owner ? adminSubject(owner.principalId) : null;
  const data = useConsoleData(administered ?? self, owner !== null);
  const tokens = owner ? data.tokens : null;
  return useMemo(() => auditTokenNames(tokens ?? []), [tokens]);
}

/** Every record of one broker request that this caller can see, oldest first. */
export function useAuditRequest(scope: AuditScope, brokerRequestId: string) {
  const { viewer, signedIn, runQuery } = useQueryAccess();
  const valid = isAuditRequestId(brokerRequestId);
  const query = useQuery({
    queryKey: portalQueryKeys.auditRequest(viewer, scope, brokerRequestId),
    enabled: signedIn && valid,
    staleTime: 0,
    queryFn: () => runQuery((current) => brokerApi.auditRequest(current, scope, brokerRequestId))
  });
  const records = query.data?.items ?? [];
  return {
    query,
    valid,
    records,
    notFound: !valid || isAuditError(query.error, "audit_request_not_found") || (query.isSuccess && records.length === 0),
    timedOut: isAuditError(query.error, "audit_query_timeout")
  };
}

/** A record already loaded by a list on this page, so the drawer can show it before its timeline loads. */
export function useLoadedAuditRecord(scope: AuditScope, auditId: string) {
  const client = useQueryClient();
  const { viewer } = useQueryAccess();
  if (!auditId) return null;
  const prefix = portalQueryKeys.auditEvents(viewer, scope, 0, {}).slice(0, 5);
  for (const [, data] of client.getQueriesData<InfiniteData<AuditEventsPage>>({ queryKey: prefix })) {
    for (const page of data?.pages ?? []) {
      const found = page.items.find((item) => item.auditId === auditId);
      if (found) return found;
    }
  }
  return null;
}
