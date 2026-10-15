// Browser session client: the cached session, central API error handling, and
// the request runners that retry once after a CSRF token rotation.
import { createContext, useCallback, useContext, useMemo, useState, useEffect, useRef, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router";
import { capabilityKey } from "../lib/capabilities";
import { ApiError, brokerApi } from "../api";
import type { Session } from "../types";
import { errorMessage, sessionExpired } from "../lib/helpers";
import { portalQueryKeys, type PortalQueryRunner } from "../lib/portal-queries";
import { useToast } from "../workbench";
import { useModal } from "./modal";
import { ACCOUNT_PATH } from "./paths";

/** Runs a broker call with the current session and resolves its result; failures reject. */
export type SessionAttempt = <T>(operation: (current: Session) => Promise<T>) => Promise<T>;

export type SignInNotice = { tone: "danger" | "warning" | "info"; text: string };

type SessionValue = {
  session: Session;
  /** Reads the current viewer even after a routed component has unmounted. */
  getSession: () => Session;
  /** The first session read has not answered yet. */
  loading: boolean;
  /** The initial session request failed; sign-in options are still unknown. */
  sessionError: unknown;
  retrySession: () => void;
  retryingSession: boolean;
  setSession: (next: Session | ((current: Session) => Session)) => void;
  /**
   * Runs a broker call, retrying once after a CSRF rotation. Expired sessions
   * sign out and required password changes open Account (both globally);
   * every failure then rejects so the caller can show it where it happened.
   */
  attempt: SessionAttempt;
  /** react-query fetcher: like `attempt`; views show query errors in place. */
  runQuery: PortalQueryRunner;
  /** Reports a failure that has no better place as an error toast. */
  reportError: (error: unknown) => void;
  clearPortalData: () => void;
  /** Where to return after sign-in or a required password change. */
  pendingReturnTo: string;
  setPendingReturnTo: (path: string) => void;
  /** Shown on the sign-in page (session expiry). */
  signInNotice: SignInNotice | null;
  setSignInNotice: (notice: SignInNotice | null) => void;
};

const SessionContext = createContext<SessionValue | null>(null);

export const SIGNED_OUT: Session = { authenticated: false };

/** Failures handled globally (sign-out, password lock); callers need not report them again. */
export function isSessionFailure(error: unknown) {
  return error instanceof ApiError && (sessionExpired(error) || error.reasonCode === "password_change_required");
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const toast = useToast();
  const { setModal } = useModal();
  const [pendingReturnTo, setPendingReturnTo] = useState(() => window.location.pathname);
  const [signInNotice, setSignInNotice] = useState<SignInNotice | null>(null);
  const sessionQuery = useQuery<Session>({
    queryKey: portalQueryKeys.session,
    queryFn: () => brokerApi.session()
  });
  const session = sessionQuery.data ?? SIGNED_OUT;
  const setSession = useCallback(
    (next: Session | ((current: Session) => Session)) =>
      queryClient.setQueryData<Session>(portalQueryKeys.session, (current) => {
        const base = current ?? SIGNED_OUT;
        return typeof next === "function" ? next(base) : next;
      }),
    [queryClient]
  );
  const getSession = useCallback(() => queryClient.getQueryData<Session>(portalQueryKeys.session) ?? SIGNED_OUT, [queryClient]);
  const clearPortalData = useCallback(() => {
    queryClient.removeQueries({ predicate: (query) => query.queryKey[0] !== portalQueryKeys.root[0] || query.queryKey[1] !== "session" });
  }, [queryClient]);

  const previousCapabilities = useRef(capabilityKey(session));
  useEffect(() => {
    const next = capabilityKey(session);
    if (previousCapabilities.current !== next) {
      const previous = previousCapabilities.current;
      previousCapabilities.current = next;
      queryClient.removeQueries({ predicate: (query) => query.queryKey.includes(previous) });
      // A completed agent-token response still belongs to the same signed-in
      // viewer when only their capabilities changed during issuance.
      setModal((current) => current?.type === "reveal" && current.viewerPrincipal && session.authenticated && !session.passwordChangeRequired && current.viewerPrincipal === session.principal ? current : null);
    }
  }, [session, queryClient, setModal]);
  const authorizationRefresh = useRef<Promise<Session> | null>(null);

  /** Global consequences of a failure; true when the failure was a session change. */
  const handleSessionFailure = useCallback(
    (error: unknown) => {
      if (!(error instanceof ApiError)) return false;
      if (sessionExpired(error)) {
        setPendingReturnTo(window.location.pathname);
        setSession(SIGNED_OUT);
        clearPortalData();
        setModal(null);
        setSignInNotice({ tone: "danger", text: errorMessage(error) });
        return true;
      }
      if (error.reasonCode === "password_change_required") {
        setSession((current) => ({ ...current, passwordChangeRequired: true }));
        setModal(null);
        navigate(ACCOUNT_PATH);
        toast("Change your password to continue.", { tone: "error" });
        return true;
      }
      return false;
    },
    [clearPortalData, navigate, setModal, setSession, toast]
  );

  const reportError = useCallback(
    (error: unknown) => {
      if (isSessionFailure(error)) return;
      toast(errorMessage(error), { tone: "error" });
    },
    [toast]
  );

  const attempt = useCallback<SessionAttempt>(
    async (operation) => {
      try {
        return await operation(session);
      } catch (error) {
        if (!(error instanceof ApiError && error.reasonCode === "csrf_invalid")) {
          handleSessionFailure(error);
          if (error instanceof ApiError && error.status === 403) {
            authorizationRefresh.current ??= brokerApi.session().finally(() => { authorizationRefresh.current = null; });
            try { setSession(await authorizationRefresh.current); } catch { /* The original denial remains authoritative. */ }
          }
          throw error;
        }
        // CSRF token rotated: refresh the session and retry the call once.
        const refreshed = await brokerApi.session().catch((refreshError: unknown) => {
          handleSessionFailure(refreshError);
          throw refreshError;
        });
        setSession(refreshed);
        if (!refreshed.authenticated) {
          const expired = new ApiError("Session expired", 401, "identity_required");
          handleSessionFailure(expired);
          throw expired;
        }
        if (refreshed.passwordChangeRequired) {
          const locked = new ApiError("Password change required", 403, "password_change_required");
          handleSessionFailure(locked);
          throw locked;
        }
        try {
          return await operation(refreshed);
        } catch (retryError) {
          handleSessionFailure(retryError);
          throw retryError;
        }
      }
    },
    [session, setSession, handleSessionFailure]
  );

  const value = useMemo<SessionValue>(
    () => ({
      session,
      getSession,
      loading: sessionQuery.isPending,
      sessionError: sessionQuery.isError && !sessionQuery.data ? sessionQuery.error : null,
      retrySession: () => { void sessionQuery.refetch(); },
      retryingSession: sessionQuery.isFetching,
      setSession,
      attempt,
      runQuery: attempt,
      reportError,
      clearPortalData,
      pendingReturnTo,
      setPendingReturnTo,
      signInNotice,
      setSignInNotice
    }),
    [session, getSession, sessionQuery.isPending, sessionQuery.isError, sessionQuery.error, sessionQuery.isFetching, sessionQuery.refetch, setSession, attempt, reportError, clearPortalData, pendingReturnTo, signInNotice]
  );
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession() {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession must be used inside SessionProvider");
  return value;
}
