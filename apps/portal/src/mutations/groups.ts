// Administrator mutations on groups, their local members, and Microsoft group
// mappings. Mutations reject on failure; callers show the error.
import { useMemo } from "react";
import { useNavigate } from "react-router";
import { brokerApi } from "../api";
import { useToast } from "../workbench";
import { paths } from "../app/paths";
import { useSession } from "../app/session";
import { useModal } from "../app/modal";
import { usePortalInvalidation } from "../data/invalidation";

export type GroupPatch = { displayName?: string | null; description?: string | null; status?: string };
export type NewGroup = { groupId: string; displayName: string; description: string };

export function useGroupActions() {
  const { attempt } = useSession();
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

    async function create(input: NewGroup) {
      const groupId = input.groupId.trim();
      await attempt((current) =>
        brokerApi.adminCreateGroup(current, {
          groupId,
          displayName: input.displayName.trim() || undefined,
          description: input.description.trim() || undefined
        })
      );
      toast("Group created", { tone: "success" });
      setModal(null);
      invalidate.admin();
      navigate(paths.group(groupId));
    }

    async function patch(groupId: string, change: GroupPatch) {
      await attempt((current) => brokerApi.adminPatchGroup(current, groupId, change));
      toast(change.status === "disabled" ? "Group disabled" : change.status === "active" ? "Group enabled" : "Group saved", { tone: "success" });
      refreshMembership();
    }

    function confirmDisable(groupId: string) {
      confirm({
        title: "Disable group?",
        body: `Grants that name ${groupId} stop applying to its members until it is enabled again. Memberships are kept.`,
        confirmLabel: "Disable group",
        onConfirm: () => patch(groupId, { status: "disabled" })
      });
    }

    async function addMember(groupId: string, principalId: string) {
      await attempt((current) => brokerApi.adminAddGroupMember(current, groupId, principalId));
      toast("Member added", { tone: "success" });
      refreshMembership();
    }

    async function removeMember(groupId: string, principalId: string) {
      const removed = await attempt((current) => brokerApi.adminRemoveGroupMember(current, groupId, principalId));
      toast(
        removed.effectiveMembershipRemains
          ? "Local membership removed. Microsoft membership remains effective until its displayed expiry."
          : "Member removed",
        { tone: "success" }
      );
      refreshMembership();
    }

    function confirmRemoveMember(groupId: string, principalId: string) {
      confirm({ title: "Remove member?", body: `Remove ${principalId} from ${groupId}?`, confirmLabel: "Remove member", onConfirm: () => removeMember(groupId, principalId) });
    }

    async function createMapping(groupId: string, externalGroupId: string) {
      await attempt((current) => brokerApi.adminCreateExternalGroupBinding(current, groupId, externalGroupId));
      toast("Microsoft group mapping created", { tone: "success" });
      refreshMembership();
    }

    async function setMappingStatus(groupId: string, bindingId: string, status: "active" | "disabled") {
      await attempt((current) => brokerApi.adminPatchExternalGroupBinding(current, groupId, bindingId, status));
      toast(status === "active" ? "Microsoft group mapping enabled" : "Microsoft group mapping disabled", { tone: "success" });
      refreshMembership();
    }

    async function deleteMapping(groupId: string, bindingId: string) {
      await attempt((current) => brokerApi.adminDeleteExternalGroupBinding(current, groupId, bindingId));
      toast("Microsoft group mapping deleted", { tone: "success" });
      refreshMembership();
    }

    function confirmDeleteMapping(groupId: string, bindingId: string) {
      confirm({
        title: "Delete Microsoft group mapping?",
        body: "Future Microsoft logins will no longer receive this broker group through it.",
        confirmLabel: "Delete mapping",
        onConfirm: () => deleteMapping(groupId, bindingId)
      });
    }

    return { create, patch, confirmDisable, addMember, removeMember, confirmRemoveMember, createMapping, setMappingStatus, deleteMapping, confirmDeleteMapping };
  }, [attempt, toast, setModal, confirm, invalidate, navigate]);
}
