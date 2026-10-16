// OAuth connections for the signed-in user, one per registration that their
// credential connections use: connect, reconnect, replace an account without
// identity evidence, and disconnect. Used on Credentials and on an imported
// service's Import tab.
import { useEffect, useMemo, useRef, useState } from "react";
import { brokerApi, type OAuthReturnPath } from "../api";
import type { OAuthConnectionTarget, RemoteRevocation } from "../types";
import { Badge, Button, KeyValue, ListRow, useToast, type Tone } from "../workbench";
import { useSession } from "../app/session";
import { useModal } from "../app/modal";
import { usePortalInvalidation } from "../data/invalidation";
import { refreshOAuthOnReturn, reserveOAuthWindow } from "../lib/oauth-window";
import { consumerSummary } from "../lib/credentials";

const STATUS: Record<string, { label: string; tone: Tone }> = {
  ready: { label: "Connected", tone: "success" },
  reconnect_required: { label: "Reconnect required", tone: "warning" },
  operator_action_required: { label: "Operator action required", tone: "danger" },
  disconnected: { label: "Not connected", tone: "neutral" }
};
export const OTHER_AUTHORIZATION_OPEN = "Finish or close the other authorization tab before connecting this account.";
const CONNECT_UNAVAILABLE = {
  no_personal_access: "Reconnect requires an active grant for your personal account. You can still disconnect this account.",
  service_unavailable: "This service is unavailable for connection. You can still disconnect an existing account.",
  login_binding_required: "Connecting requires a Microsoft sign-in linked to your Broker account. Ask an administrator to link it. You can still disconnect an existing account."
};
export const AUTHORIZATION_TAB_NOTICE = "Closing the authorization tab may leave consent pending for up to five minutes.";
const REVOKE_AT_PROVIDER = "Revoke the broker application's access in your account settings at the provider (in GitLab: Preferences › Applications › Authorized applications).";
const REMOTE_REVOCATION: Record<Exclude<RemoteRevocation, "not_requested">, { label: string; tone: Tone; message: string }> = {
  pending: {
    label: "Revocation pending",
    tone: "warning",
    message: "Access through the broker has ended. The broker is still revoking the account's tokens at the provider and retries while it is unavailable."
  },
  revoked: { label: "Revoked at provider", tone: "success", message: "The provider revoked every token the broker held for the account." },
  failed: {
    label: "Revocation failed",
    tone: "danger",
    message: `Access through the broker has ended, but the provider did not revoke every token. ${REVOKE_AT_PROVIDER}`
  },
  unconfirmed: {
    label: "Revocation unconfirmed",
    tone: "danger",
    message: `Access through the broker has ended, but a token renewal's outcome was lost, so the provider may hold a token the broker never received. ${REVOKE_AT_PROVIDER}`
  }
};
const IDENTITY_UNAVAILABLE = "Upstream account identity unavailable; reconnecting asks to confirm replacing the connection.";

export function oauthConnectUnavailableMessage(target: OAuthConnectionTarget) {
  return target.connectUnavailableReason ? CONNECT_UNAVAILABLE[target.connectUnavailableReason] : null;
}

export function oauthConnectionStatus(target: OAuthConnectionTarget) {
  return STATUS[target.connection?.status ?? "disconnected"] ?? { label: (target.connection?.status ?? "unknown").replaceAll("_", " "), tone: "neutral" as Tone };
}

export function oauthConnected(target: OAuthConnectionTarget) {
  return Boolean(target.connection?.connectionId);
}

/** The connected upstream account, or why there is none. */
export function oauthAccountLabel(target: OAuthConnectionTarget) {
  return target.connection?.displayName ?? (oauthConnected(target) ? "Connection authorized" : "No account connected");
}

/** What the broker knows about revoking ended tokens at the provider; none when it kept nothing to revoke. */
export function oauthRemoteRevocation(state: RemoteRevocation | null | undefined) {
  return state && state !== "not_requested" ? REMOTE_REVOCATION[state] ?? null : null;
}

/** The notice after a disconnect, by its remote revocation result. */
export function oauthDisconnectNotice(state: RemoteRevocation): { message: string; tone: "success" | "error" } {
  const revocation = oauthRemoteRevocation(state);
  if (!revocation) return { message: "Account disconnected. Consent at the provider is not removed.", tone: "success" };
  return { message: `Account disconnected. ${revocation.message}`, tone: state === "failed" || state === "unconfirmed" ? "error" : "success" };
}

/** A note when the provider does not identify the connected account. */
export function oauthIdentityNote(target: OAuthConnectionTarget) {
  return oauthConnected(target) && !target.connection?.subjectId ? IDENTITY_UNAVAILABLE : null;
}

/** Scope evidence may be retained from consent when a refresh omits scope. */
export function oauthScopeEvidence(target: OAuthConnectionTarget) {
  if (!target.connection?.connectionId) return null;
  const scopes = target.connection.targets.find((entry) => entry.id === target.target)?.scopes ?? [];
  return scopes.length ? `Known scopes: ${scopes.join(", ")}` : "Scope details unavailable";
}

/** What connecting allows; none for a cleanup-only row, whose profile is unknown. */
export function oauthConnectionPermissions(target: OAuthConnectionTarget) {
  if (target.scopeMode === null) return null;
  if (target.scopeMode === "explicit") return target.connectionDescription ?? "Permissions are shown during connection.";
  const evidence = oauthScopeEvidence(target);
  return `Server-default permissions${evidence ? ` · ${evidence}` : ""}`;
}

/** The services an OAuth connection serves, for the disconnect confirmation. */
function affectedServices(target: OAuthConnectionTarget) {
  const services = consumerSummary(target.consumers, target.otherConsumers);
  return services ? `${services} ${target.consumers.length + target.otherConsumers === 1 ? "stops" : "stop"} using this account.` : "Every service using this account stops working.";
}

/**
 * Connect/disconnect actions; authorization opens separately so this view
 * stays mounted. `importedService` names the import whose administrator
 * discovery the connection serves (the Import tab).
 */
export function useOAuthConnectionActions(returnPath: OAuthReturnPath, importedService?: string) {
  const { attempt, reportError } = useSession();
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

    function disconnect(target: OAuthConnectionTarget) {
      confirm({
        title: "Disconnect account?",
        body: `Disconnect ${target.displayName} from the broker? ${affectedServices(target)} Where the provider supports it, the broker also revokes the account's tokens there.`,
        confirmLabel: "Disconnect",
        onConfirm: async () => {
          const result = await attempt((current) => brokerApi.oauthDisconnect(current, target.registration));
          const notice = oauthDisconnectNotice(result.remoteRevocation);
          toast(notice.message, { tone: notice.tone });
          invalidate.portal();
        }
      });
    }

    return { connect, disconnect, pending };
  }, [attempt, reportError, confirm, toast, invalidate, returnPath, importedService, pending]);
}

export type OAuthConnectionActions = ReturnType<typeof useOAuthConnectionActions>;

/** Connect/Reconnect and Disconnect for one registration. */
export function OAuthConnectionButtons({ target, connections }: { target: OAuthConnectionTarget; connections: OAuthConnectionActions }) {
  const connected = oauthConnected(target);
  const pending = connections.pending === target.registration;
  const otherPending = connections.pending !== null && !pending;
  return (
    <span className="wb-btn-group">
      <Button
        size="sm"
        variant={connected ? "default" : "primary"}
        disabled={otherPending || (!pending && !target.canConnect)}
        title={pending ? "Return to the open authorization tab" : otherPending ? OTHER_AUTHORIZATION_OPEN : oauthConnectUnavailableMessage(target) ?? "Opens in a new tab"}
        onClick={() => connections.connect(target)}
      >
        {pending ? "Return to authorization tab" : connected ? "Reconnect" : "Connect account"}
      </Button>
      {connected ? (
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
  const revocation = oauthRemoteRevocation(target.remoteRevocation);
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
export function OAuthConnectionDetails({ target, pending }: { target: OAuthConnectionTarget; pending: boolean }) {
  const unavailable = oauthConnectUnavailableMessage(target);
  const identity = oauthIdentityNote(target);
  const permissions = oauthConnectionPermissions(target);
  const revocation = oauthRemoteRevocation(target.remoteRevocation);
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
