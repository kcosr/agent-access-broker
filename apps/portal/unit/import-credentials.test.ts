import { vi } from "vitest";
vi.mock("../src/app/session", () => ({ useSession: () => ({ session: { authenticated: true, role: "admin", selfServiceEnabled: true, principal: "admin" } }) }));
import { describe, expect, test } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { ImportAuthentication, ImportBinding, ImportOAuthRegistration, ImportPreviewResult } from "../src/import-types";
import type { OAuthConnectionTarget } from "../src/types";
import { importAuthenticationFor, importCredentialBindings, importOAuthError, matchingImportRegistrations, retainedImportBinding, type ImportCredentialDraft } from "../src/lib/import-credentials";
import { ImportEditor } from "../src/features/catalog/import-editor";
import { inlineFrame } from "../src/features/catalog/catalog-ui";
import { OAuthConnectionButtons, OAuthConnectionDetails, OAuthConnectionRow, oauthDisconnectNotice, type OAuthConnectionActions } from "../src/components/oauth-connections";
import { needsAttention, type CredentialRow } from "../src/features/credentials/credential-list";

const endpoint = "https://tools.example.test/mcp";
const registration: ImportOAuthRegistration = { id: "tools", issuer: "https://login.example.test", resource: endpoint, permissionProfiles: [{ id: "read", scopeMode: "explicit", scopes: ["metrics.read"] }, { id: "write", scopeMode: "explicit", scopes: ["metrics.read", "metrics.write"] }] };
// The dialect ID is the Broker's metadata, not a portal constant.
const group = (registrations: ImportOAuthRegistration[]): ImportAuthentication => ({ importKind: "mcp_http", dialectId: "tools_oauth", registrations });
const mcp = group([registration]);
const draft: ImportCredentialDraft = { shared: true, personal: true, personalAuth: "oauth", registrationId: "tools", profile: "read", delivery: { kind: "bearer" } };

describe("imported personal authentication", () => {
  test("the selected import kind's companion supplies its registrations", () => {
    const other: ImportAuthentication = { importKind: "other_http", dialectId: "other_oauth", registrations: [registration] };
    expect(importAuthenticationFor([other, mcp], "mcp_http")).toBe(mcp);
    expect(importAuthenticationFor([other], "mcp_http")).toBeUndefined();
    expect(importAuthenticationFor([mcp], "openapi_http")).toBeUndefined();
  });
  test("only approved endpoint-specific registrations and profiles can enable OAuth", () => {
    expect(matchingImportRegistrations(mcp, endpoint)).toEqual([registration]);
    expect(matchingImportRegistrations(mcp, "https://other.example.test/mcp")).toEqual([]);
    expect(matchingImportRegistrations(undefined, endpoint)).toEqual([]);
    expect(importOAuthError(undefined, endpoint, "tools", "read", false, false)).toContain("no OAuth authentication");
    expect(importOAuthError(group([]), endpoint, "tools", "read", false, false)).toContain("not approved");
    expect(importOAuthError(mcp, endpoint, "other", "read", false, false)).toContain("registration");
    expect(importOAuthError(mcp, endpoint, "tools", "unknown", false, false)).toContain("profile");
    expect(importOAuthError(mcp, endpoint, "tools", "read", false, false)).toBeNull();
    expect(importOAuthError(mcp, endpoint, "tools", "read", true, false)).toContain("Bearer");
    expect(importOAuthError(mcp, endpoint, "tools", "read", false, true)).toContain("transport");
  });
  test("OAuth is personal Bearer authority while the shared mode remains a static token", () => {
    expect(importCredentialBindings([], draft, mcp)).toEqual([
      { ownerMode: "service", mechanism: "static_token", delivery: { kind: "bearer" }, status: "configured" },
      { ownerMode: "per_user", mechanism: "oauth", delivery: { kind: "bearer" }, status: "configured", adapterId: "tools_oauth", registrationId: "tools", profile: "read" },
    ]);
    // Without a companion no dialect is invented; saving is blocked instead.
    expect(importCredentialBindings([], draft, undefined)[1]).not.toHaveProperty("adapterId");
  });
  test("unchanged binding order is retained when editing other configuration", () => {
    const existing = importCredentialBindings([], draft, mcp).reverse();
    expect(importCredentialBindings(existing, draft, mcp)).toEqual(existing);
  });
  test("retained modes and unsupported authentication are not silently removed or activated", () => {
    const retained: ImportBinding = { ownerMode: "per_user", mechanism: "oauth", delivery: { kind: "bearer" }, status: "unsupported", adapterId: "future_adapter", registrationId: "unavailable", profile: "custom" };
    expect(retainedImportBinding(retained, mcp)).toBe(true);
    expect(importCredentialBindings([retained], { ...draft, shared: false, personal: false, personalAuth: "retained" }, mcp)).toEqual([retained]);
    const changed = importCredentialBindings([retained], { ...draft, shared: false }, mcp);
    expect(changed[0]).toMatchObject({ status: "configured", adapterId: "tools_oauth", registrationId: "tools", profile: "read" });
    expect(retainedImportBinding(changed[0], mcp)).toBe(false);
    expect(importCredentialBindings(changed, { ...draft, shared: false, personalAuth: "static_token" }, mcp)[0]).toEqual({ ownerMode: "per_user", mechanism: "static_token", delivery: { kind: "bearer" }, status: "configured" });
  });
  test("a stored binding of an unavailable companion is retained by its stored dialect", () => {
    const stored = importCredentialBindings([], { ...draft, shared: false }, mcp);
    // The kind's companion is not selected, or names another dialect.
    for (const authentication of [undefined, { ...mcp, dialectId: "replacement_oauth" }]) {
      expect(retainedImportBinding(stored[0], authentication)).toBe(true);
      expect(importCredentialBindings(stored, { ...draft, shared: false, personalAuth: "retained" }, authentication)).toEqual(stored);
    }
    expect(retainedImportBinding(undefined, undefined)).toBe(false);
    expect(retainedImportBinding({ ownerMode: "per_user", mechanism: "static_token", delivery: { kind: "bearer" }, status: "configured" }, undefined)).toBe(false);
  });
  test("the editor shows approved permissions and retains a missing registration visibly", () => {
    const binding = importCredentialBindings([], { ...draft, shared: false }, mcp);
    const data: ImportPreviewResult = { catalogRevision: 1, operatorAllowed: true, scopedMcp: { ready: false, issues: [{ code: "service_unavailable", actions: [] }], truncated: false }, scopedMcpWarnings: [], importAuthentication: [mcp], preview: null, affectedGrants: [], affectedGrantsByAction: {}, service: { definition: { service: "metrics", displayName: "Metrics", adapterKind: "mcp_http", endpoint, connectionSettings: {}, executionBindings: binding, discovery: { kind: "per_user", principal: "admin" }, transportAuth: false }, status: "draft", version: 1, actions: [], slotVersions: {}, credentialInputs: {}, createdAt: "", updatedAt: "", createdBy: "admin", updatedBy: "admin" } };
    const renderGroups = (authentication: ImportAuthentication[], preview = data) => renderToStaticMarkup(createElement(ImportEditor, { availableKinds: ["mcp_http"], principal: "admin", data: preview, authentication, onClose: () => {}, onSave: async () => true, frame: inlineFrame }));
    const render = (registrations: ImportOAuthRegistration[]) => renderGroups([group(registrations)]);
    const current = render([registration]);
    expect(current).toContain("OAuth registration");
    expect(current).toContain("metrics.read");
    expect(current).toContain("Authorization server:");
    expect(current).toContain("connect your OAuth account");
    const defaults = render([{ ...registration, permissionProfiles: [{ id: "read", scopeMode: "server_default", scopes: [] }] }]);
    expect(defaults).toContain("Server-default permissions");
    expect(defaults).not.toContain("Requested scopes:");
    const missing = render([]);
    expect(missing).toContain("tools (unavailable)");
    expect(missing).toContain("existing binding is retained");
    expect(data.service.definition.executionBindings[0].registrationId).toBe("tools");
    // Without the kind's companion the binding is retained by its stored
    // dialect, with no OAuth fields and no credential-change confirmation.
    const unselected = renderGroups([], { ...data, affectedGrants: ["grant1"] });
    expect(unselected).toContain("Retain unavailable binding (tools_oauth)");
    expect(unselected).not.toContain("OAuth registration");
    expect(unselected).not.toContain("existing grant(s)");
  });
  const consumer = { service: "metrics", displayName: "Metrics", credentialVerificationInputs: [] };
  const oauthTarget = (overrides: Partial<OAuthConnectionTarget> = {}): OAuthConnectionTarget => ({
    registration: "tools", displayName: "Metrics", connectionDescription: "Read metrics", consumers: [consumer], otherConsumers: 0,
    permissionProfile: "read", scopeMode: "explicit", requestedScopes: ["metrics.read"], target: endpoint,
    canConnect: true, connectUnavailableReason: null, canDisconnect: false, remoteRevocation: "not_requested", connection: null, ...overrides
  });
  const idle: OAuthConnectionActions = { pending: null, connect: () => {}, disconnect: () => {} };
  // The Import tab's row, and the Credentials drawer's details with its buttons.
  const surfaces = (target: OAuthConnectionTarget, connections: OAuthConnectionActions = idle) => [
    renderToStaticMarkup(createElement(OAuthConnectionRow, { target, connections })),
    renderToStaticMarkup(
      createElement("div", null, createElement(OAuthConnectionDetails, { target, pending: connections.pending === target.registration }), createElement(OAuthConnectionButtons, { target, connections }))
    )
  ];
  const buttons = (html: string) => html.match(/<button\b[^>]*>[\s\S]*?<\/button>/g) ?? [];

  test("server-default permissions show unknown or known evidence on both connection surfaces", () => {
    const target = oauthTarget({ connectionDescription: "Connect your account to authorize this imported service.", permissionProfile: "access", scopeMode: "server_default", requestedScopes: [] });
    for (const html of surfaces(target)) {
      expect(html).toContain("Server-default permissions");
      expect(html).not.toContain("Connect your account to authorize this imported service.");
      expect(html).not.toContain("Scope details unavailable");
    }
    target.connection = { connectionId: "connection", subjectId: null, displayName: null, status: "ready", reason: null, targets: [{ id: "other-resource", name: "Other", audience: "other-resource", scopes: ["unrelated.read"] }] };
    for (const html of surfaces(target)) {
      expect(html).toContain("Server-default permissions");
      expect(html).toContain("Scope details unavailable");
      expect(html).not.toContain("unrelated.read");
    }
    target.connection.targets.push({ id: endpoint, name: "MCP resource", audience: endpoint, scopes: ["metrics.read"] });
    for (const html of surfaces(target)) {
      expect(html).toContain("Server-default permissions");
      expect(html).toContain("Known scopes: metrics.read");
      expect(html).not.toContain("Scope details unavailable");
      expect(html).not.toContain("Reported scopes");
    }
  });
  test("a connected issuer without identity evidence is not displayed as a known account", () => {
    const target = oauthTarget({ canDisconnect: true, connection: { connectionId: "connection", subjectId: null, displayName: null, status: "ready", reason: null, targets: [] } });
    for (const html of surfaces(target)) {
      expect(html).toContain("Connection authorized");
      expect(html).toContain("Upstream account identity unavailable");
      expect(html).toContain("Reconnect");
      expect(html).not.toContain("No account connected");
    }
  });
  test.each([
    ["no_personal_access", "Reconnect requires an active grant for your personal account. You can still disconnect this account."],
    ["service_unavailable", "This service is unavailable for connection. You can still disconnect an existing account."],
    ["login_binding_required", "Connecting requires a Microsoft sign-in linked to your Broker account. Ask an administrator to link it. You can still disconnect an existing account."]
  ] as const)("cleanup rows explain %s and allow local disconnect on both surfaces", (reason, explanation) => {
    const target = oauthTarget({ consumers: [], otherConsumers: 1, canConnect: false, connectUnavailableReason: reason, canDisconnect: true, connection: { connectionId: "connection", subjectId: "reader", displayName: "Reader", status: "ready", reason: null, targets: [] } });
    for (const html of surfaces(target)) {
      expect(html).toContain(explanation);
      expect(buttons(html).find((button) => button.includes("Reconnect"))).toContain("disabled");
      expect(buttons(html).find((button) => button.includes(">Disconnect<"))).not.toContain("disabled");
      expect(html).not.toContain("credential right");
    }
  });
  test("a registration no connection selects any more renders for disconnect only, without permission text", () => {
    const target = oauthTarget({
      displayName: "tools", connectionDescription: null, consumers: [], otherConsumers: 0,
      permissionProfile: null, scopeMode: null, requestedScopes: [], target: null,
      canConnect: false, connectUnavailableReason: "no_personal_access", canDisconnect: true,
      connection: { connectionId: "connection", subjectId: "reader", displayName: "Reader", status: "ready", reason: null, targets: [] }
    });
    for (const html of surfaces(target)) {
      expect(buttons(html).find((button) => button.includes(">Disconnect<"))).not.toContain("disabled");
      expect(buttons(html).find((button) => button.includes("Reconnect"))).toContain("disabled");
      expect(html).not.toContain("Permissions");
      expect(html).not.toContain("Server-default permissions");
      expect(html).not.toContain("Scope details unavailable");
      expect(html).toContain("Reader");
    }
  });
  test.each([
    ["pending", "Revocation pending", "still revoking the tokens of an ended connection"],
    ["revoked", "Revoked at provider", "revoked the tokens of the connections the broker ended"],
    ["failed", "Revocation failed", "did not revoke every token of an ended connection"],
    ["unconfirmed", "Revocation unconfirmed", "token renewal&#x27;s outcome was lost for an ended connection"]
  ] as const)("a %s remote revocation shows on both connection surfaces", (state, label, explanation) => {
    for (const html of surfaces(oauthTarget({ remoteRevocation: state }))) {
      expect(html).toContain(label);
      expect(html).toContain(explanation);
      // Without a current connection the row claims nothing about current access.
      expect(html).not.toContain("current connection");
      expect(html).not.toContain("Access through the broker has ended");
    }
  });
  // A reconnect, or a replacement by another account, superseded the
  // previous family; its revocation never describes the new, usable connection.
  const replaced = (displayName: string, remoteRevocation: OAuthConnectionTarget["remoteRevocation"]) =>
    oauthTarget({
      canDisconnect: true,
      remoteRevocation,
      connection: { connectionId: "connection-2", subjectId: displayName.toLowerCase(), displayName, status: "ready", reason: null, targets: [] }
    });
  test.each([
    ["reconnect", "Reader"],
    ["account replacement", "Other Reader"]
  ] as const)("after a %s, the previous family's revocation is not described as the current connection's", (_, account) => {
    for (const [state, explanation] of [
      ["pending", "still revoking the tokens of an ended connection"],
      ["revoked", "revoked the tokens of the connections the broker ended"]
    ] as const) {
      for (const html of surfaces(replaced(account, state))) {
        expect(html).toContain(account);
        expect(html).toContain(explanation);
        expect(html).toContain("The current connection is not affected.");
        expect(html).not.toContain("Access through the broker has ended");
        expect(html).not.toContain("every token the broker held for the account");
        expect(buttons(html).find((button) => button.includes(">Disconnect<"))).not.toContain("disabled");
      }
    }
    for (const html of surfaces(replaced(account, "failed"))) {
      expect(html).toContain("Revocation failed");
      expect(html).toContain("did not revoke every token of an ended connection");
      // The cleanup names the account the ended connection used, which may not be the displayed one.
      expect(html).toContain("signed in to the account that connection used");
      expect(html).toContain("revoking at the provider ends it too when it uses the same account; reconnect afterwards.");
      expect(html).not.toContain("Access through the broker has ended");
      expect(html).not.toContain("The current connection is not affected.");
    }
  });
  test("a connection that needs reconnect after a lost renewal gets no claim about current access", () => {
    const target = oauthTarget({
      canDisconnect: true,
      remoteRevocation: "unconfirmed",
      connection: { connectionId: "connection", subjectId: "reader", displayName: "Reader", status: "reconnect_required", reason: "oauth_refresh_uncertain", targets: [] }
    });
    for (const html of surfaces(target)) {
      expect(html).toContain("Revocation unconfirmed");
      expect(html).toContain("token renewal&#x27;s outcome was lost for an ended connection");
      expect(html).not.toContain("current connection");
    }
  });
  test("a cleanup-only row for a remote revocation offers no disconnect", () => {
    const target = oauthTarget({ consumers: [], otherConsumers: 1, canConnect: false, connectUnavailableReason: "no_personal_access", canDisconnect: false, remoteRevocation: "failed" });
    for (const html of surfaces(target)) {
      expect(html).toContain("Reconnect requires an active grant for your personal account.");
      expect(html).not.toContain("still disconnect");
      expect(html).not.toContain(">Disconnect<");
      expect(html).toContain("Revocation failed");
    }
  });
  test("failed and unconfirmed revocations need attention, also beside a ready replacement connection", () => {
    const row = (target: OAuthConnectionTarget): CredentialRow => ({ kind: "oauth", key: target.registration, oauth: target });
    const ready = { connectionId: "connection", subjectId: "reader", displayName: "Reader", status: "ready" as const, reason: null, targets: [] };
    const cleanupOnly = (remoteRevocation: OAuthConnectionTarget["remoteRevocation"]) =>
      oauthTarget({ consumers: [], otherConsumers: 0, canConnect: false, connectUnavailableReason: "no_personal_access", canDisconnect: false, remoteRevocation });
    const replaced = (remoteRevocation: OAuthConnectionTarget["remoteRevocation"]) => oauthTarget({ canDisconnect: true, remoteRevocation, connection: ready });
    for (const state of ["failed", "unconfirmed"] as const) {
      expect(needsAttention(row(cleanupOnly(state)))).toBe(true);
      expect(needsAttention(row(replaced(state)))).toBe(true);
    }
    for (const state of ["not_requested", "pending", "revoked"] as const) {
      expect(needsAttention(row(cleanupOnly(state)))).toBe(false);
      expect(needsAttention(row(replaced(state)))).toBe(false);
    }
    const rows = [row(cleanupOnly("failed")), row(replaced("unconfirmed")), row(replaced("revoked")), row(oauthTarget())];
    expect(rows.filter(needsAttention)).toEqual([rows[0], rows[1]]);
  });
  test("failed and unconfirmed revocations ask for the provider-side revocation; nothing is shown when none was requested", () => {
    for (const html of surfaces(oauthTarget({ remoteRevocation: "unconfirmed" }))) {
      expect(html).toContain("Preferences › Applications › Authorized applications");
    }
    for (const html of surfaces(oauthTarget({ remoteRevocation: "failed" }))) {
      expect(html).toContain("Revoke the broker application&#x27;s access");
    }
    for (const html of surfaces(oauthTarget())) {
      expect(html).not.toContain("Revocation");
      expect(html).not.toContain("Revoked at provider");
    }
    expect(oauthDisconnectNotice("not_requested")).toEqual({ message: "Account disconnected. Consent at the provider is not removed.", tone: "success" });
    // The disconnect notice describes the account just disconnected.
    expect(oauthDisconnectNotice("revoked")).toEqual({
      message: "Account disconnected. Access through the broker has ended, and the provider revoked every token the broker held for the account.",
      tone: "success"
    });
    expect(oauthDisconnectNotice("pending").message).toContain("still revoking the account's tokens");
    expect(oauthDisconnectNotice("failed")).toMatchObject({ tone: "error" });
    expect(oauthDisconnectNotice("unconfirmed").message).toContain("Authorized applications");
    expect(oauthDisconnectNotice("unconfirmed").tone).toBe("error");
  });
  test("an entitled unconnected account offers Connect without a rights-management step", () => {
    for (const html of surfaces(oauthTarget())) {
      const connect = buttons(html).find((button) => button.includes("Connect account"));
      expect(connect).toBeDefined();
      expect(connect).not.toContain("disabled");
      expect(html).not.toContain(">Disconnect<");
      expect(html).not.toContain("active grant");
    }
  });
  test("an active connection keeps its return action enabled despite a broker eligibility change", () => {
    const target = oauthTarget({ canConnect: false, connectUnavailableReason: "no_personal_access" });
    for (const html of surfaces(target, { ...idle, pending: target.registration })) {
      const action = buttons(html).find((button) => button.includes("Return to authorization tab"));
      expect(action).toBeDefined();
      expect(action).not.toContain("disabled");
      expect(action).not.toContain("aria-busy");
      expect(html).toContain("consent pending for up to five minutes");
    }
  });
  test("another registration explains why Connect is unavailable while an authorization tab is open", () => {
    const html = renderToStaticMarkup(createElement(OAuthConnectionButtons, { target: oauthTarget(), connections: { ...idle, pending: "other-registration" } }));
    const action = buttons(html).find((button) => button.includes("Connect account"));
    expect(action).toContain("disabled");
    expect(action).toContain("Finish or close the other authorization tab before connecting this account.");
    expect(html).not.toContain("Return to authorization tab");
  });
});
