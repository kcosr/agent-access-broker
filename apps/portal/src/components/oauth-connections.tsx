// Delegated OAuth connections (Connected accounts) for the signed-in user:
// connect, reconnect, replace an account without identity evidence, and
// disconnect. Used on Credentials and on an imported service's Import tab.
import { useEffect, useMemo, useRef, useState } from "react";
import { brokerApi, type OAuthReturnPath } from "../api";
import type { OAuthConnectionTarget } from "../types";
import { Badge, Button, DataTable, ListRow, StateCell, type Tone } from "../workbench";
import { useSession } from "../app/session";
import { useModal } from "../app/modal";
import { usePortalInvalidation } from "../data/invalidation";
import { refreshOAuthOnReturn, reserveOAuthWindow } from "../lib/oauth-window";

const STATUS: Record<string, { label: string; tone: Tone }> = {
  ready: { label: "Connected", tone: "success" },
  reconnect_required: { label: "Reconnect required", tone: "warning" },
  operator_action_required: { label: "Operator action required", tone: "danger" },
  disconnected: { label: "Not connected", tone: "neutral" }
};
const OTHER_AUTHORIZATION_OPEN = "Finish or close the other authorization tab before connecting this service.";
const CONNECT_UNAVAILABLE = {
  no_personal_access: "Reconnect requires an active grant for your personal account. You can still disconnect this account.",
  service_unavailable: "This service is unavailable for connection. You can still disconnect an existing account."
};
const AUTHORIZATION_TAB_NOTICE = "Closing the authorization tab may leave consent pending for up to five minutes.";

function oauthConnectUnavailableMessage(target: OAuthConnectionTarget) {
  return target.connectUnavailableReason ? CONNECT_UNAVAILABLE[target.connectUnavailableReason] : null;
}

export function oauthConnectionStatus(target: OAuthConnectionTarget) {
  return STATUS[target.connection?.status ?? "disconnected"] ?? { label: (target.connection?.status ?? "unknown").replaceAll("_", " "), tone: "neutral" as Tone };
}

/** Scope evidence may be retained from consent when a refresh omits scope. */
function oauthScopeEvidence(target: OAuthConnectionTarget) {
  if (!target.connection?.connectionId) return null;
  const scopes = target.connection.targets.find((entry) => entry.id === target.target)?.scopes ?? [];
  return scopes.length ? `Known scopes: ${scopes.join(", ")}` : "Scope details unavailable";
}

function oauthConnectionPermissions(target: OAuthConnectionTarget) {
  if (target.scopeMode === "explicit") return target.connectionDescription ?? "Permissions are shown during connection.";
  const evidence = oauthScopeEvidence(target);
  return `Server-default permissions${evidence ? ` · ${evidence}` : ""}`;
}

/** Connect/disconnect actions; authorization opens separately so this view stays mounted. */
export function useOAuthConnectionActions(returnPath: OAuthReturnPath) {
  const { attempt, reportError } = useSession();
  const { confirm } = useModal();
  const invalidate = usePortalInvalidation();
  const [pending, setPending] = useState<string | null>(null);
  const active = useRef<{ service: string; window: ReturnType<typeof reserveOAuthWindow> } | null>(null);
  useEffect(() => refreshOAuthOnReturn(invalidate.oauthConnections), [invalidate]);
  useEffect(() => () => {
    active.current?.window.dispose();
    active.current = null;
  }, []);
  return useMemo(() => {
    function focusActive(target: OAuthConnectionTarget) {
      if (!active.current) return false;
      if (active.current.service === target.service) active.current.window.focus();
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
      active.current = { service: target.service, window: popup };
      setPending(target.service);
      const intent = replace ? "replace_account" : target.connection?.connectionId ? "reconnect" : "connect";
      await popup.authorize(() => attempt((current) => brokerApi.oauthConnect(current, target.service, intent, returnPath)));
    }

    function connect(target: OAuthConnectionTarget) {
      if (focusActive(target)) return;
      // Without identity evidence a new authorization may be a different account.
      if (target.connection?.connectionId && !target.connection.subjectId) {
        confirm({
          title: "Replace this connection?",
          body: "The authorization server does not identify the upstream account. The new authorization may belong to a different account and will replace the stored connection for every service that shares this OAuth registration.",
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
        body: `Disconnect ${target.serviceDisplayName} from the broker? Every service that uses this connection stops working. Consent at the provider is not removed.`,
        confirmLabel: "Disconnect",
        onConfirm: async () => {
          await attempt((current) => brokerApi.oauthDisconnect(current, target.service));
          invalidate.portal();
        }
      });
    }

    return { connect, disconnect, pending };
  }, [attempt, reportError, confirm, invalidate, returnPath, pending]);
}

/** One row per connection target (render inside a ListGroup or Rows). */
export function OAuthConnectionRow({
  target,
  pending,
  onConnect,
  onDisconnect
}: {
  target: OAuthConnectionTarget;
  pending: boolean;
  onConnect: () => void;
  onDisconnect: () => void;
}) {
  const status = oauthConnectionStatus(target);
  const connected = Boolean(target.connection?.connectionId);
  const unavailable = oauthConnectUnavailableMessage(target);
  const account = target.connection?.displayName ?? (connected ? "Connection authorized" : "No account connected");
  return (
    <ListRow
      itemId={`oauth:${target.service}`}
      icon="link"
      iconTone={status.tone}
      title={target.serviceDisplayName}
      titleExtra={<Badge tone={status.tone}>{status.label}</Badge>}
      meta={
        <>
          <span>{account}</span>
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
          {connected && !target.connection?.subjectId ? " Upstream account identity unavailable; reconnecting asks to confirm replacing the connection." : ""}
          {unavailable ? ` ${unavailable}` : ""}
          {pending ? ` ${AUTHORIZATION_TAB_NOTICE}` : ""}
        </>
      }
      side={
        <span className="wb-btn-group">
          <Button size="sm" variant={connected ? "default" : "primary"} disabled={!pending && !target.canConnect} title={pending ? "Return to the open authorization tab" : unavailable ?? "Opens in a new tab"} onClick={onConnect}>
            {pending ? "Return to authorization tab" : connected ? "Reconnect" : "Connect account"}
          </Button>
          {connected ? (
            <Button size="sm" variant="danger-ghost" disabled={!target.canDisconnect || pending} onClick={onDisconnect}>
              Disconnect
            </Button>
          ) : null}
        </span>
      }
    />
  );
}

/** Connected accounts as a table (My access › Credentials): one row per connection target. */
export function OAuthConnectionsTable({ targets, connections }: { targets: OAuthConnectionTarget[]; connections: ReturnType<typeof useOAuthConnectionActions> }) {
  const wrapPermissions = targets.some((target) => target.scopeMode === "server_default" || target.connectUnavailableReason !== null);
  const table = (
    <DataTable
      label="Connected accounts"
      rows={targets}
      rowId={(target) => `oauth:${target.service}`}
      columns={[
        {
          key: "status",
          header: "Status",
          cell: (target) => {
            const status = oauthConnectionStatus(target);
            return <StateCell label={status.label} tone={status.tone} quiet={target.connection?.status === "ready"} />;
          }
        },
        { key: "service", header: "Service", primary: true, truncate: true, minWidth: "14ch", cell: (target) => target.serviceDisplayName },
        {
          key: "account",
          header: "Account",
          truncate: true,
          minWidth: "12ch",
          cell: (target) => {
            const connected = Boolean(target.connection?.connectionId);
            const account = target.connection?.displayName ?? (connected ? "Connection authorized" : "No account connected");
            return (
              <span title={connected && !target.connection?.subjectId ? "Upstream account identity unavailable; reconnecting asks to confirm replacing the connection." : undefined}>
                {account}
                {target.connection?.reason ? <span className="wb-muted"> · {target.connection.reason.replaceAll("_", " ")}</span> : null}
              </span>
            );
          }
        },
        {
          key: "permissions",
          header: "Permissions",
          priority: 4,
          truncate: !wrapPermissions,
          wrap: wrapPermissions,
          minWidth: wrapPermissions ? "26ch" : "12ch",
          className: "wb-cell-muted",
          cell: (target) => {
            const evidence = target.scopeMode === "server_default" ? oauthScopeEvidence(target) : null;
            const unavailable = oauthConnectUnavailableMessage(target);
            return <span><span>{target.scopeMode === "explicit" ? target.connectionDescription ?? "Shown during connection" : "Server-default permissions"}</span>{evidence ? <><br /><span className="wb-small">{evidence}</span></> : null}{unavailable ? <><br /><span className="wb-small">{unavailable}</span></> : null}</span>;
          }
        },
        {
          key: "row-actions",
          header: <span className="wb-sr-only">Row actions</span>,
          className: "wb-cell-actions",
          cell: (target) => {
            const connected = Boolean(target.connection?.connectionId);
            const pending = connections.pending === target.service;
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
                  <Button size="sm" variant="danger-ghost" disabled={!target.canDisconnect || connections.pending === target.service} onClick={() => connections.disconnect(target)}>
                    Disconnect
                  </Button>
                ) : null}
              </span>
            );
          }
        }
      ]}
      bleed
    />
  );
  return <>{connections.pending ? <p className="wb-small wb-muted">Finish or close the open authorization tab before connecting another service. {AUTHORIZATION_TAB_NOTICE}</p> : null}{table}</>;
}
