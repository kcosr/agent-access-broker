// The signed-in user's Credentials list: an OAuth row's status names its
// connection state and, beside it, a remote revocation that needs cleanup.
// Permissions, connect availability and other revocation states are in the
// row's drawer and the Connect button's tooltip, not in a table column.
import { describe, expect, test, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import type { CredentialList, OAuthConnectionTarget, RemoteRevocation } from "../src/types";

const mocks = vi.hoisted(() => ({
  credentials: { connections: [], retained: [] } as CredentialList,
  oauth: [] as OAuthConnectionTarget[]
}));
vi.mock("../src/app/session", () => ({
  useSession: () => ({ session: { authenticated: true, principal: "viewer", role: "user", selfServiceEnabled: true }, reportError: vi.fn(), attempt: vi.fn() })
}));
vi.mock("../src/app/modal", () => ({ useModal: () => ({ setModal: vi.fn(), confirm: vi.fn() }) }));
vi.mock("../src/data/invalidation", () => ({ usePortalInvalidation: () => ({ oauthConnections: vi.fn(), portal: vi.fn() }) }));
vi.mock("../src/mutations/credentials", () => ({ useCredentialActions: () => ({ save: vi.fn(), remove: vi.fn(), removeRetained: vi.fn(), verify: vi.fn() }) }));
vi.mock("../src/data/queries", () => ({
  useConsoleData: () => ({
    query: { isError: false, isFetching: false, error: null, refetch: vi.fn() },
    targets: [],
    credentials: mocks.credentials,
    tokens: [],
    loading: false
  }),
  useOAuthConnections: () => ({ data: mocks.oauth, isError: false, error: null, refetch: vi.fn() })
}));
import { CredentialDrawer, CredentialRows, CredentialToolbar, useCredentialList } from "../src/features/credentials/credential-list";

const stamp = { createdAt: "2026-10-01T00:00:00Z", updatedAt: "2026-10-01T00:00:00Z", createdBy: "viewer", updatedBy: "viewer" };
const rest = { service: "gitlab", displayName: "GitLab REST", credentialVerificationInputs: [] };
const metrics = { service: "metrics", displayName: "Metrics", credentialVerificationInputs: [] };
const token = { credentialId: "credential-ci", ownerPrincipal: "viewer", ownerKind: "user", connection: "ci", profile: "ci-token", credentialKind: "bearer_token", metadata: {}, status: "active", verificationStatus: "upstream_verified", lastVerifiedAt: stamp.updatedAt, ...stamp };
const credentials: CredentialList = {
  connections: [{ connection: "ci", displayName: "CI", method: "token", consumers: [], otherConsumers: 0, profile: "ci-token", credentialKind: "bearer_token", registration: null, remoteRevocation: null, credential: token }],
  retained: []
};
type Connection = NonNullable<OAuthConnectionTarget["connection"]>;
const connection = (status: Connection["status"], targets: Connection["targets"] = []): Connection => ({
  connectionId: "connection-gitlab", subjectId: "reader", displayName: "Reader", status, reason: status === "reconnect_required" ? "oauth_refresh_uncertain" : null, targets
});
/** GitLab, an explicit profile whose provider revokes ended connections. */
const gitlab = (remoteRevocation: RemoteRevocation, current: Connection | null): OAuthConnectionTarget => ({
  registration: "gitlab", displayName: "GitLab account", connectionDescription: "Lets agents act as your GitLab account.", consumers: [rest], otherConsumers: 0,
  permissionProfile: "default", scopeMode: "explicit", requestedScopes: ["api"], target: "https://gitlab.example.test",
  canConnect: true, connectUnavailableReason: null, canDisconnect: current !== null, remoteRevocation, connection: current
});
/** An imported service's server-default profile the user can no longer reconnect. */
const imported: OAuthConnectionTarget = {
  registration: "metrics", displayName: "Default metrics", connectionDescription: "Connect your account to authorize this imported service.", consumers: [metrics], otherConsumers: 0,
  permissionProfile: "access", scopeMode: "server_default", requestedScopes: [], target: "https://metrics.example.test/mcp",
  canConnect: false, connectUnavailableReason: "no_personal_access", canDisconnect: true, remoteRevocation: "not_requested",
  connection: { ...connection("ready", [{ id: "https://metrics.example.test/mcp", name: "MCP resource", audience: "https://metrics.example.test/mcp", scopes: ["metrics.read"] }]), connectionId: "connection-metrics" }
};

function Harness() {
  const model = useCredentialList({ administered: false, principalId: "viewer" });
  return createElement("div", null, createElement(CredentialToolbar, { model }), createElement(CredentialRows, { model }), createElement(CredentialDrawer, { model }));
}
/** The user's Credentials page with these OAuth rows, with `open` as the drawer's row key. */
function render(oauth: OAuthConnectionTarget[], open?: string) {
  mocks.credentials = credentials;
  mocks.oauth = oauth;
  const search = open ? `?credential=${encodeURIComponent(open)}` : "";
  return renderToStaticMarkup(createElement(MemoryRouter, { initialEntries: [`/ui/credentials${search}`] }, createElement(Harness)));
}
function tableRow(html: string, key: string) {
  return (html.match(/<tr\b[\s\S]*?<\/tr>/g) ?? []).find((row) => row.includes(`data-wb-row="${key}"`)) ?? "";
}
/** A row's first cell, the Status column. */
function statusCell(row: string) {
  return /<t[dh]\b[\s\S]*?<\/t[dh]>/.exec(row)?.[0] ?? "";
}
/** Rendered text without markup or attributes such as tooltips. */
function text(html: string) {
  return html.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ");
}
function drawer(html: string) {
  return html.slice(html.indexOf("<aside"));
}
function columnHeaders(html: string) {
  const head = /<thead>([\s\S]*?)<\/thead>/.exec(html)?.[1] ?? "";
  return (head.match(/<th\b[\s\S]*?<\/th>/g) ?? []).map((cell) => text(cell).trim());
}
const DANGER_BADGE = '<span class="wb-badge wb-tone-danger" title="';

describe("the Credentials list", () => {
  test("has no Permissions column; permissions and connect availability stay in the drawer and the Connect tooltip", () => {
    const html = render([gitlab("not_requested", connection("ready")), imported], "oauth:metrics");
    expect(columnHeaders(html)).toEqual(["Status", "Connection", "Used by", "Method", "Verified", "Row actions"]);
    const metricsRow = tableRow(html, "oauth:metrics");
    const gitlabRow = tableRow(html, "oauth:gitlab");
    for (const absent of ["Server-default permissions", "Known scopes", "Reconnect requires an active grant", "Connect your account to authorize"]) {
      expect(text(metricsRow)).not.toContain(absent);
    }
    expect(text(gitlabRow)).not.toContain("Lets agents act as your GitLab account.");
    // The disabled Reconnect button still explains why.
    expect(metricsRow).toMatch(/<button[^>]*disabled=""[^>]*title="Reconnect requires an active grant for your personal account\. You can still disconnect this account\."/);
    const details = drawer(html);
    expect(details).toContain("Server-default permissions · Known scopes: metrics.read");
    expect(details).toContain("Reconnect requires an active grant for your personal account. You can still disconnect this account.");
    expect(drawer(render([gitlab("not_requested", connection("ready"))], "oauth:gitlab"))).toContain("Lets agents act as your GitLab account.");
  });

  test.each([
    ["failed", "Revocation failed", "did not revoke every token of an ended connection"],
    ["unconfirmed", "Revocation unconfirmed", "token renewal&#x27;s outcome was lost for an ended connection"]
  ] as const)("shows a %s remote revocation beside a ready connection's status, explained by its tooltip", (state, label, explanation) => {
    const html = render([gitlab(state, connection("ready"))]);
    const status = statusCell(tableRow(html, "oauth:gitlab"));
    // The connection status is spelled out beside the badge rather than left as a quiet dot.
    expect(status).not.toContain("wb-state-cell--quiet");
    expect(status).toContain('<span class="wb-state-cell-label">Connected</span>');
    expect(status).toContain(`${DANGER_BADGE}`);
    const badge = new RegExp(`${DANGER_BADGE}([^"]*)">${label}</span>`).exec(status);
    expect(badge?.[1]).toContain(explanation);
    expect(badge?.[1]).toContain("The current connection keeps working, but revoking at the provider ends it too when it uses the same account; reconnect afterwards.");
    expect(text(tableRow(html, "oauth:gitlab"))).not.toContain(explanation);
    expect(html).toMatch(/Needs attention[\s\S]*?>1</);
  });

  test("keeps the connection's own status beside the badge when it is not connected or needs reconnecting", () => {
    const cleanup = statusCell(tableRow(render([{ ...gitlab("failed", null), consumers: [], canConnect: false, connectUnavailableReason: "no_personal_access" }]), "oauth:gitlab"));
    expect(cleanup).toContain('<span class="wb-state-cell-label">Not connected</span>');
    expect(cleanup).toContain(">Revocation failed</span>");
    // Without a current connection the tooltip claims nothing about current access.
    expect(cleanup).not.toContain("current connection");
    const reconnect = statusCell(tableRow(render([gitlab("unconfirmed", connection("reconnect_required"))]), "oauth:gitlab"));
    expect(reconnect).toContain("wb-tone-warning");
    expect(reconnect).toContain('<span class="wb-state-cell-label">Reconnect required</span>');
    expect(reconnect).toContain(">Revocation unconfirmed</span>");
  });

  test.each([
    ["not_requested", null],
    ["pending", "Revocation pending"],
    ["revoked", "Revoked at provider"]
  ] as const)("leaves a %s remote revocation to the drawer", (state, label) => {
    const html = render([gitlab(state, connection("ready"))], "oauth:gitlab");
    const row = tableRow(html, "oauth:gitlab");
    // A ready connection stays the quiet normal state, with no badge.
    expect(statusCell(row)).toContain("wb-state-cell--quiet");
    expect(statusCell(row)).not.toContain("wb-badge");
    expect(row).not.toContain("Revocation");
    expect(row).not.toContain("Revoked at provider");
    if (label) expect(drawer(html)).toContain(`${label}.`);
    expect(html).toMatch(/Needs attention[\s\S]*?>0</);
  });
});
