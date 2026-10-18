import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ApiError, brokerApi } from "../../api";
import { useSession } from "../../app/session";
import { useModal } from "../../app/modal";
import { AdminButton, AdminForm, AdminOnly } from "../../components/admin-access";
import { FormError } from "../../components/form";
import { useIdentityAccess, useIdentityBindings, useIdentityToken } from "../../data/queries";
import { canWriteAdmin } from "../../lib/capabilities";
import { errorMessage } from "../../lib/helpers";
import { validIdentityUsername } from "../../lib/identity-access";
import { portalQueryKeys, viewerKey } from "../../lib/portal-queries";
import type { IdentityPathSettings, IdentityTokenMetadata, PrincipalUsernameBinding } from "../../types";
import { Badge, Checkbox, ErrorState, Input, Select, SettingsRow, SettingsSection, SkeletonBlock, Switch, Time, useToast } from "../../workbench";

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
      description="Pause trusted username and fingerprint access together, or control each access path below. Independently valid issued Broker tokens and browser sign-in remain available."
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
      <AccessPaths principalId={principalId} paused={access?.paused} />
    </SettingsSection>
  );
}

/** The identity token, always first and never deletable, then each username binding. */
function AccessPaths({ principalId, paused }: { principalId: string; paused?: boolean | undefined }) {
  const { session, attempt } = useSession();
  const writable = canWriteAdmin(session);
  const queryClient = useQueryClient();
  const { confirm, closeModal } = useModal();
  const toast = useToast();
  const tokenQuery = useIdentityToken(principalId);
  const bindingsQuery = useIdentityBindings(principalId);
  const [namespace, setNamespace] = useState("");
  const [username, setUsername] = useState("");
  const [readOnly, setReadOnly] = useState(false);
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const token = tokenQuery.data;
  const data = bindingsQuery.data;
  const busy = pending !== null || tokenQuery.isFetching || bindingsQuery.isFetching;
  const namespaceAvailable = data?.configuredNamespaces.some((entry) => entry.namespace === namespace) ?? false;
  const usernameInvalid = username.length > 0 && !validIdentityUsername(username);

  async function updateToken(metadata: IdentityTokenMetadata, change: IdentityPathSettings) {
    setPending("token");
    setError(null);
    try {
      const result = await attempt((current) => brokerApi.adminUpdateIdentityToken(current, principalId, { ...change, expectedRevision: metadata.revision }));
      queryClient.setQueryData<IdentityTokenMetadata>(portalQueryKeys.identityToken(viewerKey(session), principalId), result);
      toast("Identity token updated", { tone: "success" });
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 409) {
        await tokenQuery.refetch();
        setError(conflictMessage);
      } else setError(errorMessage(failure));
    } finally {
      setPending(null);
    }
  }

  async function mutateBinding(action: "create" | "update" | "delete", binding?: PrincipalUsernameBinding, change?: IdentityPathSettings) {
    setPending(binding?.bindingId ?? "create");
    setError(null);
    try {
      await attempt<unknown>((current) => {
        if (action === "create") return brokerApi.adminCreateIdentityBinding(current, principalId, { namespace, username, readOnly });
        if (!binding) throw new Error("Select a username binding.");
        return action === "delete"
          ? brokerApi.adminDeleteIdentityBinding(current, principalId, binding.bindingId, binding.version)
          : brokerApi.adminUpdateIdentityBinding(current, principalId, binding.bindingId, { ...change, expectedVersion: binding.version });
      });
      if (action === "create") {
        setUsername("");
        setReadOnly(false);
      }
      toast(action === "create" ? "Username binding added" : action === "delete" ? "Username binding deleted" : "Username binding updated", { tone: "success" });
      await bindingsQuery.refetch();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 409) {
        await bindingsQuery.refetch();
        // A fresh version needs a fresh deliberate action, including a fresh deletion confirmation.
        if (action === "delete") closeModal();
        setError(action === "create" ? errorMessage(failure) : conflictMessage);
      } else if (action === "delete") throw failure;
      else setError(errorMessage(failure));
    } finally {
      setPending(null);
    }
  }

  const loadFailure = tokenQuery.isError ? tokenQuery : bindingsQuery.isError ? bindingsQuery : null;
  return (
    <div className="mt-6">
      <h3 className="wb-settings-sec-title">Access paths</h3>
      <p className="pt-prose">
        Each path has its own Enabled and Read-only settings. A read-only path can list and call only actions classified as reads, within this person’s grants. Changing a
        setting ends the path’s open MCP sessions.
      </p>
      <p className="pt-prose mt-2">Usernames match exactly, including case. Disabled bindings reserve their names. To rename or reassign a name, delete its binding and create a new one.</p>
      {paused ? <p className="pt-prose mt-2">The shared identity pause currently blocks every access path.</p> : null}
      {loadFailure ? <ErrorState title="Couldn’t load access paths" error={loadFailure.error} onRetry={() => void loadFailure.refetch()} retrying={loadFailure.isFetching} /> : token && data ? (
        <>
          <div className="wb-table-card overflow-x-auto mt-3">
            <table className="wb-table" aria-label="Access paths">
              <thead>
                <tr>
                  <th scope="col">Access path</th>
                  <th scope="col">Status</th>
                  <th scope="col">Enabled</th>
                  <th scope="col">Read-only</th>
                  <th scope="col">Version</th>
                  <th scope="col"><span className="wb-sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row" className="pt-identity-path">
                    <span className="pt-identity-path-name">Identity token</span>
                    <span className="wb-small wb-muted">Built-in · fingerprint access</span>
                  </th>
                  <td><Badge tone={token.configured ? "success" : "neutral"}>{token.configured ? "Configured" : "Not configured"}</Badge></td>
                  <td>
                    <PathSetting writable={writable} label="Identity token enabled" checked={token.enabled} on="Enabled" off="Disabled" disabled={busy} onChange={(enabled) => void updateToken(token, { enabled })} />
                  </td>
                  <td>
                    <PathSetting writable={writable} label="Identity token read-only" checked={token.readOnly} on="Read-only" off="Full access" disabled={busy} onChange={(value) => void updateToken(token, { readOnly: value })} />
                  </td>
                  <td>{token.revision}</td>
                  <td />
                </tr>
                {data.bindings.map((binding) => {
                  const name = `${binding.namespace}/${binding.username}`;
                  return (
                    <tr key={binding.bindingId}>
                      <th scope="row" className="pt-identity-path">
                        <span className="pt-identity-path-name wb-num">{name}</span>
                        <span className="wb-small wb-muted">Username binding</span>
                      </th>
                      <td><Badge tone={binding.namespaceAvailable ? "neutral" : "warning"}>{binding.namespaceAvailable ? "Namespace available" : "Namespace unavailable"}</Badge></td>
                      <td>
                        <PathSetting writable={writable} label={`Binding ${name} enabled`} checked={binding.enabled} on="Enabled" off="Disabled" disabled={busy} onChange={(enabled) => void mutateBinding("update", binding, { enabled })} />
                      </td>
                      <td>
                        <PathSetting writable={writable} label={`Binding ${name} read-only`} checked={binding.readOnly} on="Read-only" off="Full access" disabled={busy} onChange={(value) => void mutateBinding("update", binding, { readOnly: value })} />
                      </td>
                      <td>{binding.version}</td>
                      <td className="wb-cell-actions">
                        <div className="flex justify-end gap-1">
                          <AdminButton size="sm" variant="danger-ghost" disabled={busy} aria-label={`Delete binding ${name}`} onClick={() => confirm({
                            title: "Delete username binding?",
                            body: `Delete ${name}? This frees the name for a new binding and ends access through this binding. Issued Broker tokens and the identity token remain unchanged.`,
                            confirmLabel: "Delete binding",
                            tone: "danger",
                            onConfirm: () => mutateBinding("delete", binding)
                          })}>Delete</AdminButton>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {!data.bindings.length ? <p className="pt-prose mt-2">No username bindings.</p> : null}
          <AdminOnly>
            {data.configuredNamespaces.length ? (
              <AdminForm className="mt-4" onSubmit={(event) => { event.preventDefault(); if (namespaceAvailable && validIdentityUsername(username) && pending === null) void mutateBinding("create"); }}>
                <SettingsRow label="Identity namespace" help="Namespaces are configured by trusted callers on the broker.">
                  <Select value={namespace} onChange={(event) => setNamespace(event.target.value)} disabled={pending !== null} options={[
                    { value: "", label: "Choose a namespace" },
                    ...data.configuredNamespaces.map((entry) => ({ value: entry.namespace, label: `${entry.namespace} (${entry.credentialTransports.map((transport) => transport === "authorization_user" ? "direct" : "forwarded").join(", ")})` }))
                  ]} />
                </SettingsRow>
                <SettingsRow label="Exact username" help="1–128 ASCII letters, digits, periods, underscores, @, + or -. Spaces are not allowed.">
                  <Input mono value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="off" spellCheck={false} aria-invalid={usernameInvalid} disabled={pending !== null} />
                </SettingsRow>
                <SettingsRow label="Read-only" help="The binding can list and call only actions classified as reads. You can change this later.">
                  <Checkbox checked={readOnly} onChange={(event) => setReadOnly(event.target.checked)} disabled={pending !== null} />
                </SettingsRow>
                <FormError error={usernameInvalid ? "Enter an exact username using the allowed characters; spaces are not removed." : null} />
                <div className="wb-settings-actions"><AdminButton type="submit" pending={pending === "create"} disabled={!namespaceAvailable || !validIdentityUsername(username) || busy}>Add username binding</AdminButton></div>
              </AdminForm>
            ) : <p className="pt-prose mt-4">No username identity namespaces are configured. Configure a trusted caller before adding a binding.</p>}
          </AdminOnly>
          <FormError error={error} />
        </>
      ) : <SkeletonBlock lines={3} />}
    </div>
  );
}

/** One Enabled or Read-only setting: a switch for administrators, its state as text for auditors. */
function PathSetting({ writable, label, checked, on, off, disabled, onChange }: {
  writable: boolean;
  label: string;
  checked: boolean;
  on: string;
  off: string;
  disabled: boolean;
  onChange: (checked: boolean) => void;
}) {
  if (!writable) return <span>{checked ? on : off}</span>;
  return <Switch size="sm" aria-label={label} checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />;
}
