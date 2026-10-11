import { canWriteSubject } from "../lib/capabilities";
// Agent token mutations for the signed-in user or an administered principal,
// and administrators' management (setup/admin) tokens. Mutations reject on
// failure; callers show the error.
import { useMemo } from "react";
import { brokerApi } from "../api";
import type { AgentTokenModal } from "../app-types";
import type { AgentTokenIssueBody, AgentTokenOptions, BrokerTokenRecord } from "../types";
import { buildAgentTokenServiceRestrictions } from "../lib/helpers";
import { useToast } from "../workbench";
import { useSession } from "../app/session";
import { useModal } from "../app/modal";
import type { AccountSubject } from "../app/active-route";
import { usePortalInvalidation } from "../data/invalidation";

export function useAgentTokenActions(subject: AccountSubject, agentTokenOptions: AgentTokenOptions | null) {
  const { session, attempt } = useSession();
  const toast = useToast();
  const { setModal, confirm } = useModal();
  const invalidate = usePortalInvalidation();
  const { administered, principalId } = subject;

  return useMemo(() => {
    function refresh() {
      invalidate.console();
      if (administered) invalidate.admin();
    }

    /** Why a token cannot be issued right now, or null. */
    function issueBlocker() {
      if (!canWriteSubject(session, subject)) return "You do not have permission to issue tokens here.";
      const ttlPolicy = administered ? session.tokenIssuancePolicy?.administered?.agentInvoke : session.tokenIssuancePolicy?.selfAgentInvoke;
      if (!ttlPolicy) return "Token issuance policy is unavailable. Refresh the portal and try again.";
      if (!agentTokenOptions) return "Token options are unavailable. Refresh the portal and try again.";
      if (agentTokenOptions.executionContexts.length === 0) return "This principal needs an active policy grant before an execution-context-bound token can be issued.";
      if (!principalId) return "The token owner is unavailable. Refresh the portal and try again.";
      return null;
    }

    /** Opens the issue dialog; `services` starts it restricted to those services. */
    function openIssueDialog(services: string[] = []) {
      const ttlPolicy = administered ? session.tokenIssuancePolicy?.administered?.agentInvoke : session.tokenIssuancePolicy?.selfAgentInvoke;
      const blocker = issueBlocker();
      if (blocker || !ttlPolicy || !agentTokenOptions) {
        toast(blocker ?? "Token options are unavailable.", { tone: "error" });
        return;
      }
      const available = services.filter((service) => agentTokenOptions.services.some((option) => option.service === service));
      setModal({
        type: "token",
        administrative: administered,
        targetPrincipalId: principalId,
        options: agentTokenOptions,
        accessMode: available.length ? "restricted" : "policy",
        screen: "edit",
        selectedExecutionContexts: [...agentTokenOptions.executionContexts],
        selectedServices: available,
        selectedActions: Object.fromEntries(
          available.map((service) => [service, agentTokenOptions.services.find((option) => option.service === service)?.actions.map((action) => action.action) ?? []])
        ),
        resourceSelections: {},
        name: "",
        lifetime: ttlPolicy.defaultTtl ?? ttlPolicy.options[0] ?? "",
        ttlPolicy
      });
    }

    async function issue(modal: AgentTokenModal) {
      const never = modal.lifetime === "never";
      const restricted = modal.accessMode === "restricted" && modal.selectedServices.length > 0;
      const body: AgentTokenIssueBody = {
        name: modal.name,
        ttl: never ? undefined : modal.lifetime || undefined,
        never: never || undefined,
        allowedServices: restricted ? modal.selectedServices : undefined,
        allowedExecutionContexts: modal.selectedExecutionContexts,
        serviceRestrictions: restricted
          ? buildAgentTokenServiceRestrictions(modal.selectedServices, modal.selectedActions, modal.resourceSelections, modal.options)
          : undefined
      };
      try {
        const issued = await attempt((current) =>
          modal.administrative ? brokerApi.adminPrincipalIssueAgentToken(current, modal.targetPrincipalId, body) : brokerApi.issueToken(current, body)
        );
        setModal({
          type: "reveal",
          token: issued.token,
          record: issued.record,
          principalId: modal.targetPrincipalId,
          options: modal.options
        });
        invalidate.console();
        if (modal.administrative) invalidate.admin();
      } catch (error) {
        // Options may have changed underneath the dialog.
        invalidate.agentTokenOptions();
        throw error;
      }
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

    return { writable: canWriteSubject(session, subject), issueBlocker, openIssueDialog, issue, setPaused, revoke, confirmRevoke };
  }, [administered, principalId, agentTokenOptions, session, attempt, toast, setModal, confirm, invalidate]);
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
