// Keep an in-flight issuance fenced across route/capability remounts. Secrets
// are returned directly to the caller; this provider stores only pending keys.
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { brokerApi } from "../api";
import type { AgentTokenIssueBody } from "../types";
import { canWriteSubject } from "../lib/capabilities";
import type { AccountSubject } from "./active-route";
import { useSession } from "./session";

type IssuedToken = Awaited<ReturnType<typeof brokerApi.issueToken>>;
type TokenIssuanceValue = {
  pending: (subject: AccountSubject) => boolean;
  issue: (subject: AccountSubject, body: AgentTokenIssueBody) => Promise<IssuedToken>;
};
const TokenIssuanceContext = createContext<TokenIssuanceValue | null>(null);
const issuanceKey = (viewer: string | undefined, subject: AccountSubject) => JSON.stringify([viewer, subject.principalId]);

export function TokenIssuanceProvider({ children }: { children: ReactNode }) {
  const { session, getSession, attempt } = useSession();
  const inFlight = useRef(new Set<string>());
  const [pendingKeys, setPendingKeys] = useState<ReadonlySet<string>>(inFlight.current);
  const issue = useCallback(async (subject: AccountSubject, body: AgentTokenIssueBody) => {
    const viewer = getSession().principal;
    const key = issuanceKey(viewer, subject);
    if (inFlight.current.has(key)) throw new Error("A token is already being issued for this owner. Wait for it to finish.");
    inFlight.current.add(key);
    setPendingKeys(new Set(inFlight.current));
    try {
      return await attempt((current) => {
        if (!viewer || !current.authenticated || current.principal !== viewer || !canWriteSubject(current, subject) || current.passwordChangeRequired || (!subject.administered && subject.principalId !== viewer)) {
          throw new Error("You no longer have permission to issue this token.");
        }
        return subject.administered
          ? brokerApi.adminPrincipalIssueAgentToken(current, subject.principalId, body)
          : brokerApi.issueToken(current, body);
      });
    } finally {
      inFlight.current.delete(key);
      setPendingKeys(new Set(inFlight.current));
    }
  }, [attempt, getSession]);
  const value = useMemo(() => ({ pending: (subject: AccountSubject) => inFlight.current.has(issuanceKey(session.principal, subject)), issue }), [pendingKeys, session.principal, issue]);
  return <TokenIssuanceContext.Provider value={value}>{children}</TokenIssuanceContext.Provider>;
}

export function useTokenIssuance() {
  const value = useContext(TokenIssuanceContext);
  if (!value) throw new Error("useTokenIssuance must be used inside TokenIssuanceProvider");
  return value;
}
