// Administrator mutations on users and service accounts: creation, profile,
// role, local groups, passwords, and Microsoft login links. Mutations reject
// on failure; callers show the error.
import { useMemo } from "react";
import { useNavigate } from "react-router";
import { brokerApi } from "../api";
import type { PrincipalRecord, PrincipalRole } from "../types";
import { generateTemporaryPassword } from "../lib/helpers";
import { useToast } from "../workbench";
import { paths } from "../app/paths";
import { useSession } from "../app/session";
import { useModal } from "../app/modal";
import { usePortalInvalidation } from "../data/invalidation";

export type PrincipalPatch = { displayName?: string | null; email?: string | null; status?: string };
export type NewPrincipal = {
  kind: "user" | "service_account";
  principalId: string;
  displayName: string;
  email: string;
  groups: string[];
  role: PrincipalRole;
  selfServiceEnabled: boolean;
  enableLocalPassword: boolean;
};

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
    }

    /**
     * Creates the principal, then its temporary password, groups, and role.
     * Rejects only when the principal itself was not created; a partial setup
     * opens the new page with a warning (and the password when one was set).
     */
    async function create(input: NewPrincipal) {
      const principalId = input.principalId.trim();
      const interactiveUser = input.kind === "user";
      const enrollLocal = interactiveUser && input.enableLocalPassword;
      const generatedPassword = enrollLocal ? generateTemporaryPassword(principalId) : "";
      let created: PrincipalRecord | null = null;
      let passwordSet = false;
      try {
        await attempt(async (current) => {
          created = await brokerApi.adminCreatePrincipal(current, {
            principalId,
            kind: input.kind,
            displayName: input.displayName.trim() || undefined,
            email: input.email.trim() || undefined,
            role: input.role,
            selfServiceEnabled: input.selfServiceEnabled
          });
          if (enrollLocal) {
            await brokerApi.adminEnableLocalPassword(current, principalId, generatedPassword, true);
            passwordSet = true;
          }
          for (const group of input.groups) await brokerApi.adminAddGroup(current, principalId, group);
        });
      } catch (error) {
        if (!created) throw error;
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
      if (interactiveUser && !enrollLocal) toast("User has no sign-in methods. Link Microsoft or explicitly enable local password sign-in on Overview.", { duration: 10000 });
      setModal(enrollLocal ? { type: "passwordReveal", principalId, password: generatedPassword, action: "created" } : null);
    }

    async function patch(principalId: string, change: PrincipalPatch) {
      await attempt((current) => brokerApi.adminPatchPrincipal(current, principalId, change));
      toast(change.status === "disabled" ? "Principal disabled" : change.status === "active" ? "Principal enabled" : "Profile saved", { tone: "success" });
      refreshMembership();
    }

    async function setAccess(principalId: string, change: { role?: PrincipalRole; selfServiceEnabled?: boolean }) {
      await attempt((current) => brokerApi.adminSetAccess(current, principalId, change));
      toast("Account access updated", { tone: "success" });
      invalidate.admin();
      if (principalId === session.principal) await invalidate.session();
      invalidate.oauthConnections();
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
      linkMicrosoft,
      unlinkMicrosoft,
      confirmUnlinkMicrosoft
    };
  }, [attempt, session, toast, setModal, confirm, invalidate, navigate]);
}
