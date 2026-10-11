import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ApiError, brokerApi } from "../../api";
import { useSession } from "../../app/session";
import { useModal } from "../../app/modal";
import { AdminButton, AdminForm, AdminOnly } from "../../components/admin-access";
import { FormError } from "../../components/form";
import { useIdentityAccess, useIdentityBindings } from "../../data/queries";
import { errorMessage } from "../../lib/helpers";
import { validIdentityUsername } from "../../lib/identity-access";
import { portalQueryKeys, viewerKey } from "../../lib/portal-queries";
import type { PrincipalUsernameBinding } from "../../types";
import { Badge, ErrorState, Input, Select, SettingsRow, SettingsSection, SkeletonBlock, Time, useToast } from "../../workbench";

const conflictMessage = "Identity settings changed. Review the refreshed state before trying again.";

export function IdentityAccessSection({ principalId, principalActive }: { principalId: string; principalActive: boolean }) {
  const { session, attempt } = useSession();
  const queryClient = useQueryClient();
  const toast = useToast();
  const query = useIdentityAccess(principalId);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const access = query.data;

  async function togglePause() {
    if (!access) return;
    setPending(true);
    setError(null);
    try {
      const result = await attempt((current) => brokerApi.adminSetIdentityAccess(current, principalId, { paused: !access.paused, expectedVersion: access.version }));
      queryClient.setQueryData(portalQueryKeys.identityAccess(viewerKey(session), principalId), result);
      toast(result.paused ? "Identity access paused" : "Identity access resumed", { tone: "success" });
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 409) {
        await query.refetch();
        setError(conflictMessage);
      } else setError(errorMessage(failure));
    } finally {
      setPending(false);
    }
  }

  return (
    <SettingsSection
      title="Identity access"
      description="Pause trusted username and fingerprint access together. Independently valid issued Broker tokens and browser sign-in remain available."
      actions={access ? <Badge tone={access.paused ? "warning" : "neutral"}>{access.paused ? "Paused" : "Not paused"}</Badge> : null}
    >
      {query.isError ? <ErrorState title="Couldn’t load identity access" error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} /> : access ? (
        <>
          <SettingsRow label="Shared pause" group help="Applies even when no identity token is configured. It does not stop work already admitted or access authorized by other services.">
            <AdminButton icon={access.paused ? "play" : "pause"} pending={pending} disabled={query.isFetching} onClick={() => void togglePause()}>
              {access.paused ? "Resume identity access" : "Pause identity access"}
            </AdminButton>
            <span className="wb-muted">Version {access.version} · Updated <Time value={access.updatedAt} format="datetime" /> by {access.updatedBy}</span>
          </SettingsRow>
          {!principalActive ? <p className="pt-prose">This principal is disabled. Identity access also requires an active principal.</p> : null}
          <FormError error={error} />
        </>
      ) : <SkeletonBlock lines={2} />}
      <UsernameBindings principalId={principalId} paused={access?.paused} />
    </SettingsSection>
  );
}

function UsernameBindings({ principalId, paused }: { principalId: string; paused?: boolean }) {
  const { attempt } = useSession();
  const { confirm, closeModal } = useModal();
  const toast = useToast();
  const query = useIdentityBindings(principalId);
  const [namespace, setNamespace] = useState("");
  const [username, setUsername] = useState("");
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const data = query.data;
  const namespaceAvailable = data?.configuredNamespaces.some((entry) => entry.namespace === namespace) ?? false;
  const usernameInvalid = username.length > 0 && !validIdentityUsername(username);

  async function mutate(action: "create" | "toggle" | "delete", binding?: PrincipalUsernameBinding) {
    setPending(binding?.bindingId ?? "create");
    setError(null);
    try {
      await attempt<unknown>((current) => {
        if (action === "create") return brokerApi.adminCreateIdentityBinding(current, principalId, { namespace, username });
        if (!binding) throw new Error("Select a username binding.");
        return action === "delete"
          ? brokerApi.adminDeleteIdentityBinding(current, principalId, binding.bindingId, binding.version)
          : brokerApi.adminSetIdentityBinding(current, principalId, binding.bindingId, { enabled: !binding.enabled, expectedVersion: binding.version });
      });
      if (action === "create") setUsername("");
      toast(action === "create" ? "Username binding added" : action === "delete" ? "Username binding deleted" : "Username binding updated", { tone: "success" });
      await query.refetch();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 409) {
        await query.refetch();
        // A fresh version needs a fresh deliberate action, including a fresh deletion confirmation.
        if (action === "delete") closeModal();
        setError(action === "create" ? errorMessage(failure) : conflictMessage);
      } else if (action === "delete") throw failure;
      else setError(errorMessage(failure));
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="mt-6">
      <h3 className="wb-settings-sec-title">Username bindings</h3>
      <p className="pt-prose">Names match exactly, including case. Disabled bindings reserve their names. To rename or reassign a name, delete its binding and create a new one.</p>
      {paused ? <p className="pt-prose">The shared identity pause currently blocks all username bindings.</p> : null}
      {query.isError ? <ErrorState title="Couldn’t load username bindings" error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} /> : data ? (
        <>
          {data.bindings.length ? (
            <div className="wb-table-card overflow-x-auto">
              <table className="wb-table" aria-label="Username bindings">
                <thead><tr><th scope="col">Namespace</th><th scope="col">Exact username</th><th scope="col">State</th><th scope="col">Version</th><th scope="col"><span className="wb-sr-only">Actions</span></th></tr></thead>
                <tbody>{data.bindings.map((binding) => (
                  <tr key={binding.bindingId}>
                    <td className="wb-num">{binding.namespace}</td>
                    <td className="wb-num">{binding.username}</td>
                    <td><Badge tone={binding.enabled && binding.namespaceAvailable ? "success" : "neutral"}>{binding.enabled ? "Enabled" : "Disabled"}</Badge>{!binding.namespaceAvailable ? <Badge tone="warning">Namespace unavailable</Badge> : null}</td>
                    <td>{binding.version}</td>
                    <td className="wb-cell-actions"><div className="flex justify-end gap-1">
                      <AdminButton size="sm" disabled={pending !== null || query.isFetching} onClick={() => void mutate("toggle", binding)} aria-label={`${binding.enabled ? "Disable" : "Enable"} binding ${binding.namespace}/${binding.username}`}>{binding.enabled ? "Disable" : "Enable"}</AdminButton>
                      <AdminButton size="sm" variant="danger-ghost" disabled={pending !== null || query.isFetching} aria-label={`Delete binding ${binding.namespace}/${binding.username}`} onClick={() => confirm({
                        title: "Delete username binding?",
                        body: `Delete ${binding.namespace}/${binding.username}? This frees the name for a new binding and ends access through this binding. Issued Broker tokens and fingerprint inventory remain unchanged.`,
                        confirmLabel: "Delete binding",
                        tone: "danger",
                        onConfirm: () => mutate("delete", binding)
                      })}>Delete</AdminButton>
                    </div></td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          ) : <p className="pt-prose">No username bindings.</p>}
          <AdminOnly>
            {data.configuredNamespaces.length ? (
              <AdminForm onSubmit={(event) => { event.preventDefault(); if (namespaceAvailable && validIdentityUsername(username) && pending === null) void mutate("create"); }}>
                <SettingsRow label="Identity namespace" help="Namespaces are configured by trusted callers on the broker.">
                  <Select value={namespace} onChange={(event) => setNamespace(event.target.value)} disabled={pending !== null} options={[
                    { value: "", label: "Choose a namespace" },
                    ...data.configuredNamespaces.map((entry) => ({ value: entry.namespace, label: `${entry.namespace} (${entry.credentialTransports.map((transport) => transport === "authorization_user" ? "direct" : "forwarded").join(", ")})` }))
                  ]} />
                </SettingsRow>
                <SettingsRow label="Exact username" help="1–128 ASCII letters, digits, periods, underscores, @, + or -. Spaces are not allowed.">
                  <Input mono value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="off" spellCheck={false} aria-invalid={usernameInvalid} disabled={pending !== null} />
                </SettingsRow>
                <FormError error={usernameInvalid ? "Enter an exact username using the allowed characters; spaces are not removed." : null} />
                <div className="wb-settings-actions"><AdminButton type="submit" pending={pending === "create"} disabled={!namespaceAvailable || !validIdentityUsername(username) || pending !== null || query.isFetching}>Add username binding</AdminButton></div>
              </AdminForm>
            ) : <p className="pt-prose">No username identity namespaces are configured. Configure a trusted caller before adding a binding.</p>}
          </AdminOnly>
          <FormError error={error} />
        </>
      ) : <SkeletonBlock lines={3} />}
    </div>
  );
}
