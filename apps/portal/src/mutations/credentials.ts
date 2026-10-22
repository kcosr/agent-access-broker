// Credential connection mutations for the signed-in user or an administered
// principal. Every mutation rejects on failure; callers show the error.
import { useMemo } from "react";
import { brokerApi } from "../api";
import type { ConnectionConsumer, CredentialMetadata, CredentialTokenProfile, CredentialVerificationInput } from "../types";
import { useToast } from "../workbench";
import { useSession } from "../app/session";
import type { AccountSubject } from "../app/active-route";
import { usePortalInvalidation } from "../data/invalidation";
import { credentialVerifiedMessage } from "../lib/helpers";
import { tokenTypeValues } from "../lib/credentials";

/** Whether verifying through this consumer needs a repository to check access against. */
export function credentialVerificationNeedsRepository(consumer: ConnectionConsumer) {
  return consumer.credentialVerificationInputs.includes("repository");
}

export function useCredentialActions(subject: AccountSubject) {
  const { attempt } = useSession();
  const toast = useToast();
  const invalidate = usePortalInvalidation();
  const { administered, principalId } = subject;

  return useMemo(() => {
    function refresh() {
      invalidate.console();
      if (administered) invalidate.admin();
    }

    /** Stores a token of the chosen `type` for `connection`, replacing any stored one, its type included. */
    async function save(connection: string, type: CredentialTokenProfile, values: Record<string, string>) {
      const secret = tokenTypeValues(type, values);
      await attempt((current) =>
        administered
          ? brokerApi.adminPrincipalSaveCredential(current, principalId, connection, type.profile, secret)
          : brokerApi.saveCredential(current, connection, type.profile, secret)
      );
      toast("Credential saved", { tone: "success" });
      refresh();
    }

    async function verify(connection: string, input: CredentialVerificationInput = {}) {
      try {
        const verified = await attempt((current) =>
          administered
            ? brokerApi.adminPrincipalVerifyCredential(current, principalId, connection, input)
            : brokerApi.verifyCredential(current, connection, input)
        );
        toast(credentialVerifiedMessage(verified.verificationStatus), { tone: "success" });
      } finally {
        // A failed verification is recorded on the credential too.
        refresh();
      }
    }

    async function remove(connection: string) {
      await attempt((current) =>
        administered ? brokerApi.adminPrincipalDeleteCredential(current, principalId, connection) : brokerApi.deleteCredential(current, connection)
      );
      toast("Credential deleted", { tone: "success" });
      refresh();
    }

    /** Deletes a stored row the configuration no longer selects, by its ID. */
    async function removeRetained(credential: CredentialMetadata) {
      await attempt((current) =>
        administered ? brokerApi.adminDeleteCredential(current, credential.credentialId) : brokerApi.deleteRetainedCredential(current, credential.credentialId)
      );
      toast("Stored credential deleted", { tone: "success" });
      refresh();
    }

    return { save, verify, remove, removeRetained };
  }, [administered, principalId, attempt, toast, invalidate]);
}
