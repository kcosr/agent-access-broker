import { canWriteSubject } from "../lib/capabilities";
// Agent token mutations for the signed-in user or an administered principal,
// and administrators' management (setup/admin) tokens. Mutations reject on
// failure; callers show the error.
import { useMemo } from "react";
import { brokerApi } from "../api";
import type { AgentTokenOptions, BrokerTokenRecord } from "../types";
import { useLocation, useNavigate } from "react-router";
import { paths, portalReturnTo } from "../app/paths";
import { useAdminPrincipal } from "../data/queries";
import { useToast } from "../workbench";
import { useSession } from "../app/session";
import { useModal } from "../app/modal";
import type { AccountSubject } from "../app/active-route";
import { usePortalInvalidation } from "../data/invalidation";

export function useAgentTokenActions(subject: AccountSubject, agentTokenOptions: AgentTokenOptions | null) {
  const { session, attempt } = useSession();
  const toast = useToast();
  const { confirm } = useModal();
  const invalidate = usePortalInvalidation();
  const { administered, principalId } = subject;
  const owner = useAdminPrincipal(principalId, administered);
  const navigate = useNavigate();
  const location = useLocation();

  return useMemo(() => {
    function refresh() {
      invalidate.console();
      if (administered) invalidate.admin();
    }

    /** Why a token cannot be issued right now, or null. */
    function issueBlocker() {
      if (!canWriteSubject(session, subject)) return "You do not have permission to issue tokens here.";
      if (administered && !owner.data) return "The token owner is unavailable. Refresh the portal and try again.";
      if (administered && owner.data?.status !== "active") return "Tokens cannot be issued for a disabled principal.";
      const ttlPolicy = administered ? session.tokenIssuancePolicy?.administered?.agentInvoke : session.tokenIssuancePolicy?.selfAgentInvoke;
      if (!ttlPolicy) return "Token issuance policy is unavailable. Refresh the portal and try again.";
      if (!agentTokenOptions) return "Token options are unavailable. Refresh the portal and try again.";
      if (agentTokenOptions.executionContexts.length === 0) return "This principal needs an active policy grant before an execution-context-bound token can be issued.";
      if (!principalId) return "The token owner is unavailable. Refresh the portal and try again.";
      return null;
    }

    /** Opens the creation page; selected services prefill all currently granted actions. */
    function openIssuePage(services: string[] = []) {
      const blocker = issueBlocker();
      if (blocker) {
        toast(blocker, { tone: "error" });
        return;
      }
      const creationPath = administered ? paths.principalTokenNew(principalId) : paths.tokenNew();
      // The palette's global action on an existing draft is already fulfilled.
      if (location.pathname === creationPath && services.length === 0) return;
      const returnTo = location.pathname === creationPath
        ? portalReturnTo(new URLSearchParams(location.search).get("returnTo")) ?? (administered ? paths.principalTokens(principalId) : paths.tokens())
        : `${location.pathname}${location.search}${location.hash}`;
      const params = { services, returnTo };
      navigate(administered ? paths.principalTokenNew(principalId, params) : paths.tokenNew(params));
    }

    async function setPaused(record: BrokerTokenRecord, paused: boolean) {
      await attempt((current) => {
        if (administered) {
          return paused
            ? brokerApi.adminPrincipalPauseAgentToken(current, principalId, record.tokenId)
            : brokerApi.adminPrincipalResumeAgentToken(current, principalId, record.tokenId);
        }
        return paused ? brokerApi.pauseToken(current, record.tokenId) : brokerApi.resumeToken(current, record.tokenId);
      });
      toast(paused ? "Token paused" : "Token resumed", { tone: "success" });
      refresh();
    }

    async function revoke(record: BrokerTokenRecord) {
      await attempt((current) =>
        administered ? brokerApi.adminPrincipalRevokeAgentToken(current, principalId, record.tokenId) : brokerApi.revokeToken(current, record.tokenId)
      );
      toast("Token revoked", { tone: "success" });
      refresh();
    }

    function confirmRevoke(record: BrokerTokenRecord) {
      confirm({
        title: "Revoke token?",
        body: `Revoke ${record.name}? Agents using this token lose access immediately. This cannot be undone.`,
        confirmLabel: "Revoke token",
        onConfirm: () => revoke(record)
      });
    }

    return { writable: canWriteSubject(session, subject), issueBlocker, openIssuePage, setPaused, revoke, confirmRevoke };
  }, [administered, principalId, agentTokenOptions, session, attempt, toast, confirm, invalidate, owner.data, navigate, location.pathname, location.search, location.hash]);
}

export function useManagementTokenActions() {
  const { session, attempt } = useSession();
  const toast = useToast();
  const { setModal, confirm } = useModal();
  const invalidate = usePortalInvalidation();

  return useMemo(() => {
    function openIssueDialog(principalId: string, tokenClass: "user_manage" | "admin") {
      const administered = session.tokenIssuancePolicy?.administered;
      const ttlPolicy = tokenClass === "admin" ? administered?.admin : administered?.userManage;
      if (!ttlPolicy) {
        toast("Token issuance policy is unavailable. Refresh the portal and try again.", { tone: "error" });
        return;
      }
      setModal({ type: "managementToken", principalId, tokenClass, ttlPolicy });
    }

    async function issue(principalId: string, tokenClass: "user_manage" | "admin", name: string, lifetime: string) {
      const issued = await attempt((current) =>
        brokerApi.adminPrincipalIssueToken(current, principalId, { name: name.trim(), tokenClass, scopes: {}, ttl: lifetime })
      );
      setModal({ type: "reveal", token: issued.token, record: issued.record, principalId });
      invalidate.admin();
    }

    async function revoke(record: BrokerTokenRecord) {
      await attempt((current) => brokerApi.adminRevokeToken(current, record.tokenId));
      toast("Token revoked", { tone: "success" });
      invalidate.admin();
    }

    function confirmRevoke(record: BrokerTokenRecord) {
      confirm({ title: "Revoke token?", body: `Revoke ${record.name}? This cannot be undone.`, confirmLabel: "Revoke token", onConfirm: () => revoke(record) });
    }

    return { openIssueDialog, issue, revoke, confirmRevoke };
  }, [session, attempt, toast, setModal, confirm, invalidate]);
}
