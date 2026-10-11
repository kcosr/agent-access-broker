import { vi } from "vitest";
vi.mock("../src/app/session", () => ({ useSession: () => ({ session: { authenticated: true, role: "admin", selfServiceEnabled: true, principal: "admin" } }) }));
import { describe, expect, test } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { ImportBinding, ImportOAuthRegistration, ImportPreviewResult } from "../src/import-types";
import type { OAuthConnectionTarget } from "../src/types";
import { importCredentialBindings, importOAuthError, matchingImportRegistrations, type ImportCredentialDraft } from "../src/lib/import-credentials";
import { ImportEditor } from "../src/features/catalog/import-editor";
import { inlineFrame } from "../src/features/catalog/catalog-ui";
import { OAuthConnectionRow, OAuthConnectionsTable } from "../src/components/oauth-connections";

const endpoint = "https://tools.example.test/mcp";
const registration: ImportOAuthRegistration = { id: "tools", adapterId: "mcp_oauth", issuer: "https://login.example.test", resource: endpoint, permissionProfiles: [{ id: "read", scopeMode: "explicit", scopes: ["metrics.read"] }, { id: "write", scopeMode: "explicit", scopes: ["metrics.read", "metrics.write"] }] };
const draft: ImportCredentialDraft = { shared: true, personal: true, personalAuth: "oauth", registrationId: "tools", profile: "read", delivery: { kind: "bearer" } };

describe("imported personal authentication", () => {
  test("only approved endpoint-specific registrations and profiles can enable OAuth", () => {
    expect(matchingImportRegistrations([registration], endpoint)).toEqual([registration]);
    expect(matchingImportRegistrations([registration], "https://other.example.test/mcp")).toEqual([]);
    expect(importOAuthError([], endpoint, "tools", "read", false, false)).toContain("not approved");
    expect(importOAuthError([registration], endpoint, "other", "read", false, false)).toContain("registration");
    expect(importOAuthError([registration], endpoint, "tools", "unknown", false, false)).toContain("profile");
    expect(importOAuthError([registration], endpoint, "tools", "read", false, false)).toBeNull();
    expect(importOAuthError([registration], endpoint, "tools", "read", true, false)).toContain("Bearer");
    expect(importOAuthError([registration], endpoint, "tools", "read", false, true)).toContain("transport");
  });
  test("OAuth is personal Bearer authority while the shared mode remains a static token", () => {
    expect(importCredentialBindings([], draft)).toEqual([
      { ownerMode: "service", mechanism: "static_token", delivery: { kind: "bearer" }, status: "configured" },
      { ownerMode: "per_user", mechanism: "oauth", delivery: { kind: "bearer" }, status: "configured", adapterId: "mcp_oauth", registrationId: "tools", profile: "read" },
    ]);
  });
  test("unchanged binding order is retained when editing other configuration", () => {
    const existing = importCredentialBindings([], draft).reverse();
    expect(importCredentialBindings(existing, draft)).toEqual(existing);
  });
  test("retained modes and unsupported authentication are not silently removed or activated", () => {
    const retained: ImportBinding = { ownerMode: "per_user", mechanism: "oauth", delivery: { kind: "bearer" }, status: "unsupported", adapterId: "future_adapter", registrationId: "unavailable", profile: "custom" };
    expect(importCredentialBindings([retained], { ...draft, shared: false, personal: false, personalAuth: "retained" })).toEqual([retained]);
    const changed = importCredentialBindings([retained], { ...draft, shared: false });
    expect(changed[0]).toMatchObject({ status: "configured", adapterId: "mcp_oauth", registrationId: "tools", profile: "read" });
    expect(importCredentialBindings(changed, { ...draft, shared: false, personalAuth: "static_token" })[0]).toEqual({ ownerMode: "per_user", mechanism: "static_token", delivery: { kind: "bearer" }, status: "configured" });
  });
  test("the editor shows approved permissions and retains a missing registration visibly", () => {
    const binding = importCredentialBindings([], { ...draft, shared: false });
    const data: ImportPreviewResult = { catalogRevision: 1, operatorAllowed: true, scopedMcp: { ready: false, issues: [{ code: "service_unavailable", actions: [] }], truncated: false }, scopedMcpWarnings: [], oauthRegistrations: [registration], preview: null, affectedGrants: [], affectedGrantsByAction: {}, service: { definition: { service: "metrics", displayName: "Metrics", adapterKind: "mcp_http", endpoint, connectionSettings: {}, executionBindings: binding, discovery: { kind: "per_user", principal: "admin" }, transportAuth: false }, status: "draft", version: 1, actions: [], slotVersions: {}, createdAt: "", updatedAt: "", createdBy: "admin", updatedBy: "admin" } };
    const render = (registrations: ImportOAuthRegistration[]) => renderToStaticMarkup(createElement(ImportEditor, { availableKinds: ["mcp_http"], principal: "admin", data, registrations, onClose: () => {}, onSave: async () => true, frame: inlineFrame }));
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
  });
  test("server-default permissions show unknown or known evidence on both connection surfaces", () => {
    const target: OAuthConnectionTarget = { service: "metrics", serviceDisplayName: "Metrics", connectionDescription: "Connect your account to authorize this imported service.", registration: "tools", permissionProfile: "access", scopeMode: "server_default", requestedScopes: [], target: endpoint, canConnect: true, connectUnavailableReason: null, canDisconnect: false, connection: null };
    const render = () => [
      renderToStaticMarkup(createElement(OAuthConnectionRow, { target, pending: false, onConnect: () => {}, onDisconnect: () => {} })),
      renderToStaticMarkup(createElement(OAuthConnectionsTable, { targets: [target], connections: { pending: null, connect: () => {}, disconnect: () => {} } }))
    ];
    for (const html of render()) {
      expect(html).toContain("Server-default permissions");
      expect(html).not.toContain("Connect your account to authorize this imported service.");
      expect(html).not.toContain("Scope details unavailable");
    }
    target.connection = { connectionId: "connection", subjectId: null, displayName: null, status: "ready", reason: null, targets: [{ id: "other-resource", name: "Other", audience: "other-resource", scopes: ["unrelated.read"] }] };
    for (const html of render()) {
      expect(html).toContain("Server-default permissions");
      expect(html).toContain("Scope details unavailable");
      expect(html).not.toContain("unrelated.read");
    }
    target.connection.targets.push({ id: endpoint, name: "MCP resource", audience: endpoint, scopes: ["metrics.read"] });
    for (const html of render()) {
      expect(html).toContain("Server-default permissions");
      expect(html).toContain("Known scopes: metrics.read");
      expect(html).not.toContain("Scope details unavailable");
      expect(html).not.toContain("Reported scopes");
    }
    const table = render()[1];
    expect(table).toContain('class="wb-cell-flow"');
    expect(table).toContain('Server-default permissions</span><br/><span class="wb-small">Known scopes: metrics.read');
  });
  test("a connected issuer without identity evidence is not displayed as a known account", () => {
    const target: OAuthConnectionTarget = { service: "metrics", serviceDisplayName: "Metrics", connectionDescription: "Read metrics", registration: "tools", permissionProfile: "read", scopeMode: "explicit", requestedScopes: ["metrics.read"], target: endpoint, canConnect: true, connectUnavailableReason: null, canDisconnect: true, connection: { connectionId: "connection", subjectId: null, displayName: null, status: "ready", reason: null, targets: [] } };
    const html = renderToStaticMarkup(createElement(OAuthConnectionRow, { target, pending: false, onConnect: () => {}, onDisconnect: () => {} }));
    expect(html).toContain("Connection authorized");
    expect(html).toContain("Upstream account identity unavailable");
    expect(html).toContain("Reconnect");
    expect(html).not.toContain("No account connected");
  });
  test.each([
    ["no_personal_access", "Reconnect requires an active grant for your personal account. You can still disconnect this account."],
    ["service_unavailable", "This service is unavailable for connection. You can still disconnect an existing account."]
  ] as const)("cleanup rows explain %s and allow local disconnect on both surfaces", (reason, explanation) => {
    const target: OAuthConnectionTarget = { service: "metrics", serviceDisplayName: "Metrics", connectionDescription: "Read metrics", registration: "tools", permissionProfile: "read", scopeMode: "explicit", requestedScopes: ["metrics.read"], target: endpoint, canConnect: false, connectUnavailableReason: reason, canDisconnect: true, connection: { connectionId: "connection", subjectId: "reader", displayName: "Reader", status: "ready", reason: null, targets: [] } };
    const views = [
      renderToStaticMarkup(createElement(OAuthConnectionRow, { target, pending: false, onConnect: () => {}, onDisconnect: () => {} })),
      renderToStaticMarkup(createElement(OAuthConnectionsTable, { targets: [target], connections: { pending: null, connect: () => {}, disconnect: () => {} } }))
    ];
    for (const html of views) {
      expect(html).toContain(explanation);
      const buttons = html.match(/<button\b[^>]*>[\s\S]*?<\/button>/g) ?? [];
      expect(buttons.find((button) => button.includes("Reconnect"))).toContain("disabled");
      expect(buttons.find((button) => button.includes(">Disconnect<"))).not.toContain("disabled");
      expect(html).not.toContain("credential right");
    }
  });
  test("an entitled unconnected account offers Connect without a rights-management step", () => {
    const target: OAuthConnectionTarget = { service: "metrics", serviceDisplayName: "Metrics", connectionDescription: "Read metrics", registration: "tools", permissionProfile: "read", scopeMode: "explicit", requestedScopes: ["metrics.read"], target: endpoint, canConnect: true, connectUnavailableReason: null, canDisconnect: false, connection: null };
    for (const html of [
      renderToStaticMarkup(createElement(OAuthConnectionRow, { target, pending: false, onConnect: () => {}, onDisconnect: () => {} })),
      renderToStaticMarkup(createElement(OAuthConnectionsTable, { targets: [target], connections: { pending: null, connect: () => {}, disconnect: () => {} } }))
    ]) {
      const connect = html.match(/<button\b[^>]*>[\s\S]*?<\/button>/g)?.find((button) => button.includes("Connect account"));
      expect(connect).toBeDefined();
      expect(connect).not.toContain("disabled");
      expect(html).not.toContain(">Disconnect<");
      expect(html).not.toContain("active grant");
    }
  });
  test("an active connection keeps its return action enabled despite a broker eligibility change", () => {
    const target: OAuthConnectionTarget = { service: "metrics", serviceDisplayName: "Metrics", connectionDescription: "Read metrics", registration: "tools", permissionProfile: "read", scopeMode: "explicit", requestedScopes: ["metrics.read"], target: endpoint, canConnect: false, connectUnavailableReason: "no_personal_access", canDisconnect: false, connection: null };
    const views = [
      renderToStaticMarkup(createElement(OAuthConnectionRow, { target, pending: true, onConnect: () => {}, onDisconnect: () => {} })),
      renderToStaticMarkup(createElement(OAuthConnectionsTable, { targets: [target], connections: { pending: target.service, connect: () => {}, disconnect: () => {} } }))
    ];
    for (const html of views) {
      const action = html.match(/<button\b[^>]*>[\s\S]*?<\/button>/g)?.find((button) => button.includes("Return to authorization tab"));
      expect(action).toBeDefined();
      expect(action).not.toContain("disabled");
      expect(action).not.toContain("aria-busy");
      expect(html).toContain("consent pending for up to five minutes");
    }
  });
  test("another service explains why Connect is unavailable while an authorization tab is open", () => {
    const target: OAuthConnectionTarget = { service: "metrics", serviceDisplayName: "Metrics", connectionDescription: "Read metrics", registration: "tools", permissionProfile: "read", scopeMode: "explicit", requestedScopes: ["metrics.read"], target: endpoint, canConnect: true, connectUnavailableReason: null, canDisconnect: false, connection: null };
    const html = renderToStaticMarkup(createElement(OAuthConnectionsTable, { targets: [target], connections: { pending: "other-service", connect: () => {}, disconnect: () => {} } }));
    const action = html.match(/<button\b[^>]*>[\s\S]*?<\/button>/g)?.find((button) => button.includes("Connect account"));
    expect(action).toContain("disabled");
    expect(action).toContain("Finish or close the other authorization tab before connecting this service.");
    expect(html).toContain("Finish or close the open authorization tab before connecting another service.");
    expect(html).not.toContain("Return to authorization tab");
  });
});
