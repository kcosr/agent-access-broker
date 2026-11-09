// Administrator mutations on users and service accounts: creation, profile,
// role, local groups, passwords, and Microsoft login links. Mutations reject
// on failure; callers show the error.
import { useMemo } from "react";
import { useNavigate } from "react-router";
import { brokerApi } from "../api";
import type { MicrosoftEnrollment, PrincipalRole, PrincipalAgentTokenIssuanceSetting } from "../types";
import { generateTemporaryPassword } from "../lib/helpers";
import { useToast } from "../workbench";
import { paths } from "../app/paths";
import { useSession } from "../app/session";
import { useModal } from "../app/modal";
import { usePortalInvalidation } from "../data/invalidation";

export type PrincipalPatch = { displayName?: string | null; email?: string | null; status?: string };
export type NewPrincipal = {
  displayName: string;
  email: string;
  groups: string[];
  role: PrincipalRole;
  selfServiceEnabled: boolean;
  agentTokenIssuance: PrincipalAgentTokenIssuanceSetting;
} & (
  | { kind: "user"; signIn: "microsoft"; principalId?: never }
  | { kind: "user"; signIn: "local"; principalId: string }
  | { kind: "service_account"; principalId: string; signIn?: never }
);

export function usePrincipalActions() {
  const { attempt, session } = useSession();
  const toast = useToast();
  const { setModal, confirm } = useModal();
  const invalidate = usePortalInvalidation();
  const navigate = useNavigate();

  return useMemo(() => {
    function refreshMembership() {
      invalidate.oauthConnections();
      invalidate.admin();
      invalidate.agentTokenOptions();
      void invalidate.session();
    }

    /**
     * Creates the principal with its access settings, then its password and groups.
     * Rejects only when the principal itself was not created; a partial setup
     * opens the new page with a warning (and the password when one was set).
     */
    async function create(input: NewPrincipal) {
      const interactiveUser = input.kind === "user";
      const enrollLocal = input.signIn === "local";
      const created = await attempt((current) => brokerApi.adminCreatePrincipal(current, {
        ...(input.signIn === "microsoft"
          ? { kind: input.kind, microsoftEnrollment: { email: input.email.trim() } }
          : { kind: input.kind, principalId: input.principalId.trim() }),
        displayName: input.displayName.trim() || undefined,
        email: input.email.trim() || undefined,
        role: input.role,
        selfServiceEnabled: input.selfServiceEnabled,
        agentTokenIssuance: input.agentTokenIssuance
      }));
      if (typeof created?.principalId !== "string" || !created.principalId.trim()) {
        throw new Error(`${interactiveUser ? "User" : "Service account"} may have been created, but the server did not return its identifier. Check ${interactiveUser ? "Users" : "Service accounts"} before trying again.`);
      }
      const principalId = created.principalId;
      let generatedPassword = "";
      let passwordSet = false;
      try {
        if (enrollLocal) {
          generatedPassword = generateTemporaryPassword(principalId);
          await attempt((current) => brokerApi.adminEnableLocalPassword(current, principalId, generatedPassword, true));
          passwordSet = true;
        }
        for (const group of input.groups) await attempt((current) => brokerApi.adminAddGroup(current, principalId, group));
      } catch {
        refreshMembership();
        navigate(paths.principal(principalId));
        if (!interactiveUser) {
          setModal(null);
          toast("Service account created, but group setup did not complete. Finish it on the Groups tab.", { tone: "error", duration: 8000 });
        } else if (passwordSet) {
          toast("User created, but setup did not complete. Copy the password now, then finish setup.", { tone: "error", duration: 8000 });
          setModal({ type: "passwordReveal", principalId, password: generatedPassword, action: "created" });
        } else {
          setModal(null);
          toast("User created, but setup did not complete. Finish setup on Overview.", { tone: "error", duration: 8000 });
        }
        return;
      }
      toast(interactiveUser ? "User created" : "Service account created", { tone: "success" });
      refreshMembership();
      navigate(paths.principal(principalId));
      setModal(enrollLocal ? { type: "passwordReveal", principalId, password: generatedPassword, action: "created" } : null);
    }

    async function patch(principalId: string, change: PrincipalPatch) {
      await attempt((current) => brokerApi.adminPatchPrincipal(current, principalId, change));
      toast(change.status === "disabled" ? "Principal disabled" : change.status === "active" ? "Principal enabled" : "Profile saved", { tone: "success" });
      refreshMembership();
    }

    async function setAccess(principalId: string, change: { role?: PrincipalRole; selfServiceEnabled?: boolean; agentTokenIssuance?: PrincipalAgentTokenIssuanceSetting }) {
      const saved = await attempt((current) => brokerApi.adminSetAccess(current, principalId, change));
      toast("Account access updated", { tone: "success" });
      invalidate.admin();
      invalidate.agentTokenOptions();
      await invalidate.session();
      invalidate.oauthConnections();
      return saved;
    }

    async function addGroup(principalId: string, group: string) {
      await attempt((current) => brokerApi.adminAddGroup(current, principalId, group));
      toast("Group added", { tone: "success" });
      refreshMembership();
    }

    async function removeGroup(principalId: string, group: string) {
      const removed = await attempt((current) => brokerApi.adminRemoveGroup(current, principalId, group));
      toast(
        removed.effectiveMembershipRemains
          ? "Local membership removed. Microsoft membership remains effective until its displayed expiry."
          : "Group removed",
        { tone: "success" }
      );
      refreshMembership();
    }

    function confirmRemoveGroup(principalId: string, group: string) {
      confirm({ title: "Remove group?", body: `Remove ${principalId} from ${group}? Grants reached through it stop applying.`, confirmLabel: "Remove group", onConfirm: () => removeGroup(principalId, group) });
    }

    async function resetPassword(principalId: string) {
      const generatedPassword = generateTemporaryPassword(principalId);
      await attempt((current) => brokerApi.adminResetLocalPassword(current, principalId, generatedPassword, true));
      const refresh = () => {
        invalidate.admin();
        void invalidate.session();
      };
      // Reset revokes our own local session. Preserve its newly issued secret until
      // the reveal closes; expired-session handling would otherwise clear the modal.
      const ownLocalSession = principalId === session.principal && session.loginMethod === "local_password";
      if (!ownLocalSession) refresh();
      setModal({ type: "passwordReveal", principalId, password: generatedPassword, action: "reset", afterClose: ownLocalSession ? refresh : undefined });
    }

    async function enablePassword(principalId: string) {
      const generatedPassword = generateTemporaryPassword(principalId);
      await attempt((current) => brokerApi.adminEnableLocalPassword(current, principalId, generatedPassword, true));
      invalidate.admin();
      void invalidate.session();
      setModal({ type: "passwordReveal", principalId, password: generatedPassword, action: "enabled" });
    }

    function confirmResetPassword(principalId: string) {
      confirm({
        title: "Reset local password?",
        body: `Generate a new temporary password for ${principalId}? Their local-password browser sessions end, and they must change it at next local sign-in. Microsoft sessions remain active.`,
        confirmLabel: "Reset local password",
        onConfirm: () => resetPassword(principalId)
      });
    }

    async function updateLoginMethod(principalId: string, action: "disable" | "unlock") {
      await attempt((current) =>
        action === "disable" ? brokerApi.adminDisableLocalPassword(current, principalId) : brokerApi.adminUnlockLocalPassword(current, principalId)
      );
      toast(action === "disable" ? "Local password disabled" : "Local password unlocked", { tone: "success" });
      invalidate.admin();
      void invalidate.session();
    }

    function confirmDisablePassword(principalId: string) {
      confirm({
        title: "Disable local password?",
        body: `${principalId} can no longer sign in with a password until an administrator explicitly re-enables local password sign-in.`,
        confirmLabel: "Disable local password sign-in",
        onConfirm: () => updateLoginMethod(principalId, "disable")
      });
    }

    async function createMicrosoftEnrollment(principalId: string, email: string) {
      await attempt((current) => brokerApi.adminCreateMicrosoftEnrollment(current, principalId, email.trim()));
      toast("Microsoft enrollment created", { tone: "success" });
      refreshMembership();
    }

    async function editMicrosoftEnrollment(enrollment: MicrosoftEnrollment, email: string) {
      await attempt((current) => brokerApi.adminEditMicrosoftEnrollment(current, enrollment.principalId, {
        enrollmentId: enrollment.enrollmentId, expectedRevision: enrollment.revision, email: email.trim()
      }));
      toast("Microsoft enrollment saved", { tone: "success" });
      refreshMembership();
    }

    async function cancelMicrosoftEnrollment(enrollment: MicrosoftEnrollment) {
      await attempt((current) => brokerApi.adminCancelMicrosoftEnrollment(current, enrollment.principalId, {
        enrollmentId: enrollment.enrollmentId, expectedRevision: enrollment.revision
      }));
      toast("Microsoft enrollment cancelled", { tone: "success" });
      refreshMembership();
    }

    async function linkMicrosoft(principalId: string, userObjectId: string) {
      await attempt((current) => brokerApi.adminLinkMicrosoftLogin(current, principalId, userObjectId));
      toast("Microsoft login linked", { tone: "success" });
      refreshMembership();
    }

    async function unlinkMicrosoft(principalId: string) {
      await attempt((current) => brokerApi.adminUnlinkMicrosoftLogin(current, principalId));
      toast("Microsoft login unlinked", { tone: "success" });
      refreshMembership();
    }

    function confirmUnlinkMicrosoft(principalId: string) {
      confirm({
        title: "Unlink Microsoft login?",
        body: "Its OIDC browser sessions end and Microsoft-derived groups are removed. Other tokens, local roles, local groups, and direct grants remain.",
        confirmLabel: "Unlink Microsoft login",
        onConfirm: () => unlinkMicrosoft(principalId)
      });
    }

    return {
      create,
      patch,
      setAccess,

      addGroup,
      removeGroup,
      confirmRemoveGroup,
      resetPassword,
      enablePassword,
      confirmResetPassword,
      updateLoginMethod,
      confirmDisablePassword,
      createMicrosoftEnrollment,
      editMicrosoftEnrollment,
      cancelMicrosoftEnrollment,
      linkMicrosoft,
      unlinkMicrosoft,
      confirmUnlinkMicrosoft
    };
  }, [attempt, session, toast, setModal, confirm, invalidate, navigate]);
}
