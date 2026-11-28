// Access key and username mutations: a person's own keys, an administrator's
// keys for an account, and an account's username. Mutations reject on
// failure; callers show the error.
import { useMemo } from "react";
import { brokerApi } from "../api";
import type { AccessKeyIssueBody, AccessKeyView, AccountUsernameSetBody } from "../types";
import { useToast } from "../workbench";
import { useSession } from "../app/session";
import { useModal } from "../app/modal";
import type { AccountSubject } from "../app/active-route";
import { usePortalInvalidation } from "../data/invalidation";

/** Issue and revoke for the signed-in person (`administered: false`) or an account an administrator opened. */
export function useAccessKeyActions(subject: AccountSubject) {
  const { attempt, getSession } = useSession();
  const toast = useToast();
  const { confirm } = useModal();
  const invalidate = usePortalInvalidation();
  const { administered, principalId } = subject;

  return useMemo(() => {
    // Both sides of the account: the person's own views and any administrative
    // view of it (its Keys tab and the username's live key count), which an
    // administrator may have open for their own account.
    function refresh() {
      invalidate.accessKeys();
      invalidate.admin();
    }

    /**
     * Issues one key. The secret is returned to the caller only while the same
     * person is signed in; it is never stored, cached or retried.
     */
    async function issue(body: AccessKeyIssueBody) {
      const viewer = getSession().principal;
      const issued = await attempt((current) => {
        if (!viewer || !current.authenticated || current.principal !== viewer || current.passwordChangeRequired || (!administered && principalId !== viewer)) {
          throw new Error("You are no longer signed in as the account this key was for.");
        }
        return administered ? brokerApi.adminIssueAccessKey(current, principalId, body) : brokerApi.issueAccessKey(current, body);
      });
      refresh();
      return { issued, viewer };
    }

    async function revoke(key: Pick<AccessKeyView, "keyId" | "name">) {
      await attempt((current) => (administered ? brokerApi.adminRevokeAccessKey(current, key.keyId) : brokerApi.revokeAccessKey(current, key.keyId)));
      toast("Access key revoked", { tone: "success" });
      refresh();
    }

    function confirmRevoke(key: Pick<AccessKeyView, "keyId" | "name">) {
      confirm({
        title: "Revoke access key?",
        body: `Revoke ${key.name}? Tools using this access key lose access immediately. This cannot be undone.`,
        confirmLabel: "Revoke access key",
        onConfirm: () => revoke(key)
      });
    }

    return { issue, revoke, confirmRevoke, refresh };
  }, [administered, principalId, attempt, getSession, toast, confirm, invalidate]);
}

/** An administrator's username changes for one account. */
export function useAccountUsernameActions(principalId: string) {
  const { attempt } = useSession();
  const toast = useToast();
  const invalidate = usePortalInvalidation();
  return useMemo(() => {
    function refresh() {
      invalidate.admin();
      invalidate.accessKeys();
    }
    async function set(body: AccountUsernameSetBody) {
      const result = await attempt((current) => brokerApi.adminSetAccountUsername(current, principalId, body));
      toast("Username saved", { tone: "success" });
      refresh();
      return result;
    }
    async function confirmName(accountUsername: string) {
      const result = await attempt((current) => brokerApi.adminConfirmAccountUsername(current, principalId, accountUsername));
      toast("Username confirmed", { tone: "success" });
      refresh();
      return result;
    }
    return { set, confirm: confirmName };
  }, [principalId, attempt, toast, invalidate]);
}
