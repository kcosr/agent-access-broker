// Policy grant and service policy manager mutations. Mutations reject on API
// failure; callers show the error.
import { useMemo } from "react";
import { brokerApi } from "../api";
import type { PolicyGrantDraft } from "../app-types";
import type { GroupPolicyReference, PolicyCatalogResult, PolicyGrantRecord, PolicyValidationMessage } from "../types";
import { policyGrantBody, policyGrantKey } from "../lib/helpers";
import { useToast } from "../workbench";
import { useSession } from "../app/session";
import { useModal } from "../app/modal";
import { usePortalInvalidation } from "../data/invalidation";

type GrantLike = PolicyGrantRecord | GroupPolicyReference;

export type GrantSaveResult = { saved: true; grantRef: string } | { saved: false; messages: PolicyValidationMessage[] };

export class ReadOnlyGrantError extends Error {
  constructor() {
    super("This policy grant is read-only.");
  }
}

function writableVersion(grant: GrantLike) {
  const version = grant.version;
  if (!grant.writable || version === undefined || version === null) throw new ReadOnlyGrantError();
  return version;
}

export function usePolicyActions() {
  const { attempt } = useSession();
  const toast = useToast();
  const { confirm } = useModal();
  const invalidate = usePortalInvalidation();

  return useMemo(() => {
    function refresh() {
      invalidate.oauthConnections();
      invalidate.admin();
      invalidate.console();
    }

    /** Validates locally and on the broker, then creates or updates the grant. */
    async function save(draft: PolicyGrantDraft, catalog: PolicyCatalogResult | null): Promise<GrantSaveResult> {
      const { body, messages } = policyGrantBody(draft, catalog);
      if (!body) return { saved: false, messages };
      const validationBody = { ...body };
      if (draft.mode === "edit" && draft.grantRef) validationBody.grantId = draft.grantRef;
      const validation = await attempt((current) => brokerApi.adminValidatePolicyGrant(current, validationBody));
      if (!validation.valid) {
        return { saved: false, messages: validation.errors.length ? validation.errors : validation.warnings };
      }
      if (draft.mode === "edit") {
        const grantRef = draft.grantRef;
        if (!grantRef) throw new ReadOnlyGrantError();
        const updated = await attempt((current) => brokerApi.adminPatchPolicyGrant(current, grantRef, body));
        toast("Policy grant updated", { tone: "success" });
        refresh();
        return { saved: true, grantRef: updated.grant.grantId };
      }
      const created = await attempt((current) => brokerApi.adminCreatePolicyGrant(current, body));
      toast("Policy grant created", { tone: "success" });
      refresh();
      return { saved: true, grantRef: created.grant.grantId };
    }

    async function setEnabled(grant: GrantLike, enabled: boolean) {
      const version = writableVersion(grant);
      await attempt((current) =>
        enabled
          ? brokerApi.adminEnablePolicyGrant(current, policyGrantKey(grant), version)
          : brokerApi.adminDisablePolicyGrant(current, policyGrantKey(grant), version)
      );
      toast(enabled ? "Policy grant enabled" : "Policy grant disabled", { tone: "success" });
      refresh();
    }

    async function addSubject(grant: GrantLike, subject: string) {
      const version = writableVersion(grant);
      await attempt((current) => brokerApi.adminAddPolicyGrantSubject(current, policyGrantKey(grant), version, subject));
      toast("Policy grant subject added", { tone: "success" });
      refresh();
    }

    /** Adds a direct subject; asks first when the user already reaches the grant through a group. */
    async function requestAddSubject(grant: GrantLike, subject: string, groupDerivedGroups?: string[]) {
      if (groupDerivedGroups) {
        const groups = groupDerivedGroups.length ? groupDerivedGroups.join(", ") : "active group membership";
        confirm({
          title: "Add direct grant subject?",
          body: `This user already reaches ${policyGrantKey(grant)} through ${groups}. Add ${subject} as a direct subject anyway?`,
          confirmLabel: "Add direct subject",
          tone: "primary",
          onConfirm: () => addSubject(grant, subject)
        });
        return;
      }
      await addSubject(grant, subject);
    }

    async function removeSubject(grant: GrantLike, subject: string, lastSubjectBehavior: "reject" | "disable_grant") {
      const version = writableVersion(grant);
      await attempt((current) => brokerApi.adminRemovePolicyGrantSubject(current, policyGrantKey(grant), version, subject, lastSubjectBehavior));
      toast(lastSubjectBehavior === "disable_grant" ? "Policy grant disabled" : "Policy grant subject removed", { tone: "success" });
      refresh();
    }

    function confirmRemoveSubject(reference: GrantLike, subject: string) {
      const final = reference.status === "active" && reference.subjects.length === 1 && reference.subjects[0] === subject;
      confirm({
        title: final ? "Remove and disable grant?" : "Remove grant subject?",
        body: final
          ? `Remove ${subject} from ${policyGrantKey(reference)}? This is the last subject, so the grant will be disabled.`
          : `Remove ${subject} from ${policyGrantKey(reference)}?`,
        confirmLabel: final ? "Remove and disable" : "Remove subject",
        onConfirm: () => removeSubject(reference, subject, final ? "disable_grant" : "reject")
      });
    }

    async function remove(grant: GrantLike) {
      const version = writableVersion(grant);
      await attempt((current) => brokerApi.adminDeletePolicyGrant(current, policyGrantKey(grant), version));
      toast("Policy grant deleted", { tone: "success" });
      refresh();
    }

    function confirmDelete(grant: GrantLike, onDeleted?: () => void) {
      confirm({
        title: "Delete policy grant?",
        body: `Delete ${policyGrantKey(grant)}? It stops applying to requests immediately.`,
        confirmLabel: "Delete grant",
        onConfirm: async () => {
          await remove(grant);
          onDeleted?.();
        }
      });
    }

    async function assignManager(service: string, principalId: string) {
      await attempt((current) => brokerApi.adminGrantServicePolicyManager(current, service, principalId));
      toast("Service policy manager assigned", { tone: "success" });
      invalidate.admin();
    }

    async function revokeManager(service: string, principalId: string) {
      const result = await attempt((current) => brokerApi.adminRevokeServicePolicyManager(current, service, principalId));
      toast(result.removed ? "Service policy manager revoked" : "Service policy manager was already revoked", { tone: "success" });
      invalidate.admin();
    }

    function confirmRevokeManager(service: string, principalId: string) {
      confirm({
        title: "Revoke service policy manager?",
        body: `Revoke ${principalId}'s policy management authority for ${service}? Grants they created stay in place.`,
        confirmLabel: "Revoke manager",
        onConfirm: () => revokeManager(service, principalId)
      });
    }

    return {
      save,
      setEnabled,
      addSubject,
      requestAddSubject,
      removeSubject,
      confirmRemoveSubject,
      remove,
      confirmDelete,
      assignManager,
      revokeManager,
      confirmRevokeManager
    };
  }, [attempt, toast, confirm, invalidate]);
}
