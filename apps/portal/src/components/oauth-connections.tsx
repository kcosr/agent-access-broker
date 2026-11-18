// OAuth connections for the signed-in user, one per registration that their
// credential connections use: connect, reconnect, replace an account without
// identity evidence, and disconnect. Used on Credentials and on an imported
// service's Import tab. Administrators can inspect and disconnect a principal's
// connections; only the owner can connect or reconnect.
import { useEffect, useMemo, useRef, useState } from "react";
import { brokerApi, type OAuthReturnPath } from "../api";
import type { AdminOAuthConnectionTarget, OAuthConnectionTarget, RemoteRevocation } from "../types";
import { Badge, Button, KeyValue, ListRow, useToast, type Tone } from "../workbench";
import { useSession } from "../app/session";
import { useModal } from "../app/modal";
import { usePortalInvalidation } from "../data/invalidation";
import { refreshOAuthOnReturn, reserveOAuthWindow } from "../lib/oauth-window";
import { consumerSummary } from "../lib/credentials";
import type { AccountSubject } from "../app/active-route";
import { canWriteSubject } from "../lib/capabilities";

const STATUS: Record<string, { label: string; tone: Tone }> = {
  ready: { label: "Connected", tone: "success" },
  reconnect_required: { label: "Reconnect required", tone: "warning" },
  operator_action_required: { label: "Operator action required", tone: "danger" },
  disconnected: { label: "Not connected", tone: "neutral" }
};
export const OTHER_AUTHORIZATION_OPEN = "Finish or close the other authorization tab before connecting this account.";
const CONNECT_UNAVAILABLE = {
  no_personal_access: { reason: "Reconnect requires an active grant for your personal account.", disconnect: "You can still disconnect this account." },
  service_unavailable: { reason: "This service is unavailable for connection.", disconnect: "You can still disconnect an existing account." },
  login_binding_required: {
    reason: "Connecting requires a Microsoft sign-in linked to your Broker account. Ask an administrator to link it.",
    disconnect: "You can still disconnect an existing account."
  }
};
export const AUTHORIZATION_TAB_NOTICE = "Closing the authorization tab may leave consent pending for up to five minutes.";
const PROVIDER_APPLICATIONS = "in GitLab: Preferences › Applications › Authorized applications";
// A registration's remote revocation concerns token families the broker
// ended: disconnected, replaced by a reconnect or another account, or ended
// by a lost renewal. It never describes the current connection, which may
// use another account.
const REVOKE_ENDED = `Revoke the broker application's access at the provider, signed in to the account that connection used (${PROVIDER_APPLICATIONS}).`;
function administeredProviderCleanup(principal: string) {
  return `The user ${principal} must revoke the broker application's access at the provider, signed in to the account that connection used (${PROVIDER_APPLICATIONS}), or a provider administrator must revoke it.`;
}
function remoteRevocationStates(revokeEnded: string): Record<Exclude<RemoteRevocation, "not_requested">, { label: string; tone: Tone; message: string }> {
  return {
    pending: {
      label: "Revocation pending",
      tone: "warning",
      message: "The broker is still revoking the tokens of an ended connection at the provider and retries while the provider is unavailable."
    },
    revoked: { label: "Revoked at provider", tone: "success", message: "The provider revoked the tokens of the connections the broker ended." },
    failed: {
      label: "Revocation failed",
      tone: "danger",
      message: `The provider did not revoke every token of an ended connection. ${revokeEnded}`
    },
    unconfirmed: {
      label: "Revocation unconfirmed",
      tone: "danger",
      message: `A token renewal's outcome was lost for an ended connection, so the provider may hold a token the broker never received. ${revokeEnded}`
    }
  };
}
const REMOTE_REVOCATION = remoteRevocationStates(REVOKE_ENDED);
// After a disconnect, the result also covers the account just disconnected.
const REVOKE_AT_PROVIDER = `Revoke the broker application's access in your account settings at the provider (${PROVIDER_APPLICATIONS}).`;
function disconnectRevocation(revokeAtProvider: string): Record<Exclude<RemoteRevocation, "not_requested">, string> {
  return {
    pending: "Access through the broker has ended. The broker is still revoking the account's tokens at the provider and retries while it is unavailable.",
    revoked: "Access through the broker has ended, and the provider revoked every token the broker held for the account.",
    failed: `Access through the broker has ended, but the provider did not revoke every token. ${revokeAtProvider}`,
    unconfirmed: `Access through the broker has ended, but a token renewal's outcome was lost, so the provider may hold a token the broker never received. ${revokeAtProvider}`
  };
}
const IDENTITY_UNAVAILABLE = "Upstream account identity unavailable; reconnecting asks to confirm replacing the connection.";

/** Why Connect is unavailable; it offers disconnect only when there is an owned connection to disconnect. */
export function oauthConnectUnavailableMessage(target: OAuthConnectionTarget) {
  const unavailable = target.connectUnavailableReason ? CONNECT_UNAVAILABLE[target.connectUnavailableReason] : null;
  if (!unavailable) return null;
  return target.canDisconnect ? `${unavailable.reason} ${unavailable.disconnect}` : unavailable.reason;
}

export function oauthConnectionStatus(target: AdminOAuthConnectionTarget) {
  return STATUS[target.connection?.status ?? "disconnected"] ?? { label: (target.connection?.status ?? "unknown").replaceAll("_", " "), tone: "neutral" as Tone };
}

export function oauthConnected(target: Pick<OAuthConnectionTarget, "connection">) {
  return Boolean(target.connection?.connectionId);
}

/** The connected upstream account, or why there is none. */
export function oauthAccountLabel(target: AdminOAuthConnectionTarget) {
  return target.connection?.displayName ?? (oauthConnected(target) ? "Connection authorized" : "No account connected");
}

/**
 * What the broker knows about revoking the tokens of a registration's ended
 * connections at the provider; none when it kept nothing to revoke. Claims
 * about current access come only from a current connection that is ready,
 * which no remote revocation concerns: revoking at the provider also ends
 * it when it uses the same account.
 */
export function oauthRemoteRevocation(target: Pick<AdminOAuthConnectionTarget, "remoteRevocation" | "connection">, principal?: string) {
  const state = target.remoteRevocation;
  const states = principal ? remoteRevocationStates(administeredProviderCleanup(principal)) : REMOTE_REVOCATION;
  const revocation = state && state !== "not_requested" ? states[state] ?? null : null;
  if (!revocation) return null;
  if (!oauthConnected(target) || target.connection?.status !== "ready") return revocation;
  const current =
    state === "failed" || state === "unconfirmed"
      ? `The current connection keeps working, but revoking at the provider ends it too when it uses the same account; ${principal ? "the user must reconnect afterwards" : "reconnect afterwards"}.`
      : "The current connection is not affected.";
  return { ...revocation, message: `${revocation.message} ${current}` };
}

/** Whether a registration's ended connections need provider-side cleanup: their revocation failed or is unconfirmed. */
export function oauthRevocationNeedsAttention(state: RemoteRevocation | null) {
  return state === "failed" || state === "unconfirmed";
}

/** The notice after a disconnect, by its remote revocation result. */
export function oauthDisconnectNotice(state: RemoteRevocation, principal?: string): { message: string; tone: "success" | "error" } {
  const ended = principal ? `Account disconnected for ${principal}.` : "Account disconnected.";
  const revocation = disconnectRevocation(principal ? administeredProviderCleanup(principal) : REVOKE_AT_PROVIDER);
  if (state === "not_requested" || !(state in revocation)) return { message: `${ended} Consent at the provider is not removed.`, tone: "success" };
  return { message: `${ended} ${revocation[state]}`, tone: state === "failed" || state === "unconfirmed" ? "error" : "success" };
}

/** A note when the provider does not identify the connected account. */
export function oauthIdentityNote(target: AdminOAuthConnectionTarget) {
  return oauthConnected(target) && !target.connection?.subjectId ? IDENTITY_UNAVAILABLE : null;
}

/** Scope evidence may be retained from consent when a refresh omits scope. */
export function oauthScopeEvidence(target: AdminOAuthConnectionTarget) {
  if (!target.connection?.connectionId) return null;
  const scopes = target.connection.targets.find((entry) => entry.id === target.target)?.scopes ?? [];
  return scopes.length ? `Known scopes: ${scopes.join(", ")}` : "Scope details unavailable";
}

/** What connecting allows; none for a cleanup-only row, whose profile is unknown. */
export function oauthConnectionPermissions(target: AdminOAuthConnectionTarget) {
  if (target.scopeMode === null) return null;
  if (target.scopeMode === "explicit") return target.connectionDescription ?? "Permissions are shown during connection.";
  const evidence = oauthScopeEvidence(target);
  return `Server-default permissions${evidence ? ` · ${evidence}` : ""}`;
}

/** The services an OAuth connection serves, for the disconnect confirmation. */
function affectedServices(target: AdminOAuthConnectionTarget) {
  const services = consumerSummary(target.consumers, target.otherConsumers);
  return services ? `${services} ${target.consumers.length + target.otherConsumers === 1 ? "stops" : "stop"} using this account.` : "Every service using this account stops working.";
}

/**
 * Connect/disconnect actions; authorization opens separately so this view
 * stays mounted. `importedService` names the import whose administrator
 * discovery the connection serves (the Import tab).
 */
export function useOAuthConnectionActions(returnPath: OAuthReturnPath, importedService?: string, subject?: AccountSubject) {
  const { session, attempt, reportError } = useSession();
  const principal = subject?.administered ? subject.principalId : undefined;
  const writable = !subject || canWriteSubject(session, subject);
  const { confirm } = useModal();
  const toast = useToast();
  const invalidate = usePortalInvalidation();
  const [pending, setPending] = useState<string | null>(null);
  const active = useRef<{ registration: string; window: ReturnType<typeof reserveOAuthWindow> } | null>(null);
  useEffect(() => refreshOAuthOnReturn(invalidate.oauthConnections), [invalidate]);
  useEffect(() => () => {
    active.current?.window.dispose();
    active.current = null;
  }, []);
  return useMemo(() => {
    function focusActive(target: OAuthConnectionTarget) {
      if (!active.current) return false;
      if (active.current.registration === target.registration) active.current.window.focus();
      else reportError(new Error(OTHER_AUTHORIZATION_OPEN));
      return true;
    }

    async function start(target: OAuthConnectionTarget, replace: boolean) {
      if (focusActive(target)) return;
      const popup = reserveOAuthWindow(target.registration, () => {
        if (active.current?.window !== popup) return;
        active.current = null;
        setPending(null);
        invalidate.oauthConnections();
      });
      active.current = { registration: target.registration, window: popup };
      setPending(target.registration);
      const intent = replace ? "replace_account" : target.connection?.connectionId ? "reconnect" : "connect";
      await popup.authorize(() => attempt((current) => brokerApi.oauthConnect(current, target.registration, intent, returnPath, importedService)));
    }

    function connect(target: OAuthConnectionTarget) {
      if (principal) return;
      if (focusActive(target)) return;
      // Without identity evidence a new authorization may be a different account.
      if (target.connection?.connectionId && !target.connection.subjectId) {
        confirm({
          title: "Replace this connection?",
          body: `The authorization server does not identify the upstream account. The new authorization may belong to a different account and will replace the stored connection. ${affectedServices(target)}`,
          confirmLabel: "Replace connection",
          tone: "primary",
          onConfirm: () => start(target, true)
        });
        return;
      }
      start(target, false).catch(reportError);
    }

    function disconnect(target: AdminOAuthConnectionTarget) {
      if (!writable) return;
      confirm({
        title: "Disconnect account?",
        body: `Disconnect ${principal ? `${principal}'s ${target.displayName} connection` : target.displayName} from the broker? ${affectedServices(target)} Where the provider supports it, the broker also revokes the account's tokens there.${principal ? " The user can connect again while permitted by their account settings and grants." : ""}`,
        confirmLabel: "Disconnect",
        onConfirm: async () => {
          const result = await attempt((current) =>
            principal ? brokerApi.adminPrincipalOAuthDisconnect(current, principal, target.registration) : brokerApi.oauthDisconnect(current, target.registration)
          );
          const notice = oauthDisconnectNotice(result.remoteRevocation, principal);
          toast(notice.message, { tone: notice.tone });
          invalidate.portal();
        }
      });
    }

    return { connect, disconnect, pending };
  }, [attempt, reportError, confirm, toast, invalidate, returnPath, importedService, pending, principal, writable]);
}

export type OAuthConnectionActions = ReturnType<typeof useOAuthConnectionActions>;

/** Connect/Reconnect and Disconnect for one registration. */
export function OAuthConnectionButtons({ target, connections, subject }: { target: OAuthConnectionTarget | AdminOAuthConnectionTarget; connections: OAuthConnectionActions; subject?: AccountSubject }) {
  const { session } = useSession();
  const ownerTarget = !subject?.administered && "canConnect" in target ? target : null;
  const writable = !subject || canWriteSubject(session, subject);
  const connected = oauthConnected(target);
  const pending = connections.pending === target.registration;
  const otherPending = connections.pending !== null && !pending;
  return (
    <span className="wb-btn-group">
      {ownerTarget ? (
        <Button
          size="sm"
          variant={connected ? "default" : "primary"}
          disabled={otherPending || (!pending && !ownerTarget.canConnect)}
          title={pending ? "Return to the open authorization tab" : otherPending ? OTHER_AUTHORIZATION_OPEN : oauthConnectUnavailableMessage(ownerTarget) ?? "Opens in a new tab"}
          onClick={() => connections.connect(ownerTarget)}
        >
          {pending ? "Return to authorization tab" : connected ? "Reconnect" : "Connect account"}
        </Button>
      ) : null}
      {connected && writable && (ownerTarget || target.canDisconnect) ? (
        <Button size="sm" variant="danger-ghost" disabled={!target.canDisconnect || pending} onClick={() => connections.disconnect(target)}>
          Disconnect
        </Button>
      ) : null}
    </span>
  );
}

/** One row per registration (render inside a ListGroup or Rows). */
export function OAuthConnectionRow({ target, connections }: { target: OAuthConnectionTarget; connections: OAuthConnectionActions }) {
  const status = oauthConnectionStatus(target);
  const unavailable = oauthConnectUnavailableMessage(target);
  const identity = oauthIdentityNote(target);
  const revocation = oauthRemoteRevocation(target);
  const pending = connections.pending === target.registration;
  return (
    <ListRow
      itemId={`oauth:${target.registration}`}
      icon="link"
      iconTone={status.tone}
      title={target.displayName}
      titleExtra={
        <>
          <Badge tone={status.tone}>{status.label}</Badge>
          {revocation ? <Badge tone={revocation.tone}>{revocation.label}</Badge> : null}
        </>
      }
      meta={
        <>
          <span>{oauthAccountLabel(target)}</span>
          {target.connection?.reason ? (
            <>
              <span className="wb-sep">·</span>
              <span>{target.connection.reason.replaceAll("_", " ")}</span>
            </>
          ) : null}
        </>
      }
      description={
        <>
          {oauthConnectionPermissions(target)}
          {identity ? ` ${identity}` : ""}
          {unavailable ? ` ${unavailable}` : ""}
          {revocation ? ` ${revocation.message}` : ""}
          {pending ? ` ${AUTHORIZATION_TAB_NOTICE}` : ""}
        </>
      }
      side={<OAuthConnectionButtons target={target} connections={connections} />}
    />
  );
}

/** Account, permissions and availability of one registration (the Credentials drawer). */
export function OAuthConnectionDetails({ target, pending, principal }: { target: OAuthConnectionTarget | AdminOAuthConnectionTarget; pending: boolean; principal?: string }) {
  const unavailable = !principal && "canConnect" in target ? oauthConnectUnavailableMessage(target) : null;
  const identity = principal ? (oauthConnected(target) && !target.connection?.subjectId ? "Upstream account identity unavailable." : null) : oauthIdentityNote(target);
  const permissions = oauthConnectionPermissions(target);
  const revocation = oauthRemoteRevocation(target, principal);
  return (
    <KeyValue
      items={[
        { label: "Account", value: oauthAccountLabel(target) },
        revocation ? { label: "Remote revocation", value: `${revocation.label}. ${revocation.message}` } : null,
        target.connection?.reason ? { label: "Reason", value: target.connection.reason.replaceAll("_", " ") } : null,
        permissions ? { label: "Permissions", value: permissions } : null,
        identity ? { label: "Identity", value: identity } : null,
        unavailable ? { label: "Connect", value: unavailable } : null,
        pending ? { label: "Authorization", value: AUTHORIZATION_TAB_NOTICE } : null
      ]}
    />
  );
}
