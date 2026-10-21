// An administered principal's Credentials tab: its OAuth registrations come
// from the administrator credential list, read-only, with their remote
// revocation and no connect or disconnect for administrators or auditors.
import { beforeEach, describe, expect, test, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import type { ConnectionConsumer, CredentialList, OAuthConnectionTarget, RemoteRevocation } from "../src/types";

const mocks = vi.hoisted(() => ({
  session: { authenticated: true, principal: "admin", role: "admin" as string, selfServiceEnabled: true },
  credentials: { connections: [], retained: [] } as CredentialList,
  oauthEnabled: [] as boolean[]
}));
vi.mock("../src/app/session", () => ({ useSession: () => ({ session: mocks.session, reportError: vi.fn(), attempt: vi.fn() }) }));
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
  useOAuthConnections: (enabled: boolean) => {
    mocks.oauthEnabled.push(enabled);
    return { data: undefined, isError: false, error: null, refetch: vi.fn() };
  }
}));
import { administeredOAuthRegistrations } from "../src/lib/credentials";
import { CredentialDrawer, CredentialRows, CredentialToolbar, credentialCounts, credentialRows, needsAttention, useCredentialList } from "../src/features/credentials/credential-list";
import { adminSubject } from "../src/app/active-route";

const stamp = { createdAt: "2026-10-01T00:00:00Z", updatedAt: "2026-10-01T00:00:00Z", createdBy: "admin", updatedBy: "admin" };
const rest = { service: "gitlab", displayName: "GitLab REST", credentialVerificationInputs: [] };
const git = { service: "gitlab_git", displayName: "GitLab Git", credentialVerificationInputs: ["repository"] };
const mail = { service: "gmail", displayName: "Gmail", credentialVerificationInputs: [] };
const jira = { service: "jira", displayName: "Jira", credentialVerificationInputs: [] };
const confluence = { service: "confluence", displayName: "Confluence", credentialVerificationInputs: [] };
const oauthConnection = (connection: string, displayName: string, registration: string, consumers: ConnectionConsumer[], otherConsumers: number, remoteRevocation: RemoteRevocation | null) => ({
  connection, displayName, method: "oauth" as const, consumers, otherConsumers, profile: null, credentialKind: null, registration, remoteRevocation, credential: null
});
const token = { credentialId: "credential-ci", ownerPrincipal: "morgan", ownerKind: "user", connection: "ci", profile: "ci-token", credentialKind: "bearer_token", metadata: {}, status: "active", verificationStatus: "upstream_verified", lastVerifiedAt: stamp.updatedAt, ...stamp };
/** Morgan's administrator credential list, with GitLab's remote revocation in `state`. */
function morgan(state: RemoteRevocation | null): CredentialList {
  return {
    connections: [
      { connection: "ci", displayName: "CI", method: "token", consumers: [], otherConsumers: 0, profile: "ci-token", credentialKind: "bearer_token", registration: null, remoteRevocation: null, credential: token },
      oauthConnection("gitlab", "GitLab", "gitlab", [rest, git], 0, state),
      oauthConnection("gmail", "Gmail", "google", [mail], 0, "not_requested"),
      // Jira and Confluence share one Atlassian registration through two connections.
      oauthConnection("jira", "Atlassian", "atlassian", [jira], 0, null),
      oauthConnection("confluence", "Confluence", "atlassian", [confluence], 1, "not_requested"),
      // Cleanup-only: Morgan lost every grant on it, and its revocation failed.
      oauthConnection("gitlab_ops", "GitLab Ops", "gitlab-ops", [], 2, "failed")
    ],
    retained: [{ credentialId: "credential-old", ownerPrincipal: "morgan", ownerKind: "user", service: "ci", name: "legacy", profile: "ci-token", credentialKind: "bearer_token", metadata: {}, status: "active", ...stamp }]
  };
}

function Harness() {
  const model = useCredentialList(adminSubject("morgan"));
  return createElement("div", null, createElement(CredentialToolbar, { model }), createElement(CredentialRows, { model }), createElement(CredentialDrawer, { model }));
}
/** The administered Credentials tab of Morgan, with `open` as the drawer's row key. */
function render(role: "admin" | "auditor", credentials: CredentialList, open?: string) {
  mocks.session.role = role;
  mocks.credentials = credentials;
  const search = open ? `?credential=${encodeURIComponent(open)}` : "";
  return renderToStaticMarkup(createElement(MemoryRouter, { initialEntries: [`/ui/admin/principals/morgan/credentials${search}`] }, createElement(Harness)));
}
/** One table row's markup, by its row key. */
function tableRow(html: string, key: string) {
  return (html.match(/<tr\b[\s\S]*?<\/tr>/g) ?? []).find((row) => row.includes(`data-wb-row="${key}"`)) ?? "";
}
/** A row's first cell, the Status column. */
function statusCell(row: string) {
  return /<t[dh]\b[\s\S]*?<\/t[dh]>/.exec(row)?.[0] ?? "";
}
function escapeRegExp(text: string) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
/** The table's column header texts. */
function columnHeaders(html: string) {
  const head = /<thead>([\s\S]*?)<\/thead>/.exec(html)?.[1] ?? "";
  return (head.match(/<th\b[\s\S]*?<\/th>/g) ?? []).map((cell) => cell.replace(/<[^>]*>/g, "").trim());
}
/** The drawer's markup. */
function drawer(html: string) {
  return html.slice(html.indexOf("<aside"));
}
/** The drawer's header actions. */
function drawerActions(html: string) {
  return /<div class="wb-drawer-actions">([\s\S]*?)<\/div>/.exec(drawer(html))?.[1];
}
const OWNER_ACTIONS = [">Connect account<", ">Reconnect<", ">Disconnect<", "Return to authorization tab"];

beforeEach(() => {
  mocks.oauthEnabled.length = 0;
});

describe("an administered principal's OAuth registrations", () => {
  test("are one row per registration with the registration's connections and consumers together", () => {
    const registrations = administeredOAuthRegistrations(morgan("revoked"));
    expect(registrations.map((registration) => registration.registration)).toEqual(["gitlab", "google", "atlassian", "gitlab-ops"]);
    expect(registrations[2]).toEqual({
      registration: "atlassian",
      displayName: "Atlassian",
      connections: ["jira", "confluence"],
      consumers: [jira, confluence],
      otherConsumers: 1,
      // The first connection's state was unavailable; another reported it.
      remoteRevocation: "not_requested"
    });
    expect(registrations[3]).toMatchObject({ connections: ["gitlab_ops"], consumers: [], otherConsumers: 2, remoteRevocation: "failed" });
  });

  test("come from the administrator list, never from the signed-in user's own OAuth connections", () => {
    const own: OAuthConnectionTarget = {
      registration: "own", displayName: "Own", connectionDescription: null, consumers: [], otherConsumers: 0, permissionProfile: null, scopeMode: null, requestedScopes: [], target: null,
      canConnect: true, connectUnavailableReason: null, canDisconnect: true, remoteRevocation: "failed", connection: null
    };
    const administered = credentialRows(true, [], morgan("pending"), [own]);
    expect(administered.map((row) => `${row.kind}:${row.key}`)).toEqual([
      "token:ci",
      "administered-oauth:oauth:gitlab",
      "administered-oauth:oauth:google",
      "administered-oauth:oauth:atlassian",
      "administered-oauth:oauth:gitlab-ops",
      "retained:retained:credential-old"
    ]);
    // The personal list keeps its own registrations and ignores the connections' OAuth rows.
    expect(credentialRows(false, [], morgan("pending"), [own]).filter((row) => row.kind.endsWith("oauth")).map((row) => `${row.kind}:${row.key}`)).toEqual(["oauth:oauth:own"]);
    render("admin", morgan("pending"));
    expect(mocks.oauthEnabled).toEqual([false]);
  });

  test.each([
    ["pending", "Revocation pending", "still revoking the tokens of an ended connection"],
    ["revoked", "Revoked at provider", "revoked the tokens of the connections the broker ended"],
    ["failed", "Revocation failed", "did not revoke every token of an ended connection"],
    ["unconfirmed", "Revocation unconfirmed", "token renewal&#x27;s outcome was lost for an ended connection"]
  ] as const)("show a %s remote revocation as concerning ended connections in the drawer, and in the row's status only when it needs cleanup", (state, label, explanation) => {
    const html = render("admin", morgan(state), "oauth:gitlab");
    const row = tableRow(html, "oauth:gitlab");
    const cleanup = state === "failed" || state === "unconfirmed";
    expect(drawer(html)).toContain(label);
    expect(drawer(html)).toContain(explanation);
    // The row's status keeps who manages the account and adds a revocation
    // that needs cleanup as a danger badge, explained by its tooltip; a
    // pending or successful revocation shows only in the drawer.
    const status = statusCell(row);
    expect(status).toContain("Managed by user");
    expect(status).toContain('title="Only the user can connect, reconnect or disconnect this account, from their own Credentials page."');
    expect(status.includes('<span class="wb-badge wb-tone-danger" title="')).toBe(cleanup);
    expect(row.includes(label)).toBe(cleanup);
    expect(row.includes(explanation)).toBe(cleanup);
    if (cleanup) expect(status).toMatch(new RegExp(`<span class="wb-badge wb-tone-danger" title="[^"]*${escapeRegExp(explanation)}[^"]*">${label}</span>`));
    for (const surface of [row, drawer(html)]) {
      // No current connection is known, so none is described.
      expect(surface).not.toContain("current connection is not affected");
      expect(surface).not.toContain("Not connected");
      expect(surface).not.toContain("Connected");
    }
    for (const surface of [row, drawer(html)]) {
      // The administrator cannot act on the account; the user, or a provider administrator, revokes.
      expect(surface.includes("The user must revoke the broker application&#x27;s access at the provider")).toBe(cleanup);
      expect(surface.includes("Preferences › Applications › Authorized applications")).toBe(cleanup);
      expect(surface).not.toContain("Revoke the broker application&#x27;s access");
    }
    expect(drawer(html)).toContain("OAuth registration");
    expect(drawer(html)).toContain(">gitlab</span>");
    expect(drawer(html)).toContain("Managed by user");
  });

  test("show no revocation when none was requested, and an unknown state as unknown", () => {
    const html = render("admin", morgan(null), "oauth:gitlab");
    expect(tableRow(html, "oauth:google")).not.toContain("Revocation");
    expect(tableRow(html, "oauth:google")).not.toContain("Revoked at provider");
    expect(tableRow(html, "oauth:gitlab")).not.toContain("Revocation");
    expect(drawer(html)).toContain("Unknown: OAuth is inactive or its state is unavailable.");
    expect(drawer(render("admin", morgan(null), "oauth:google"))).toContain("Not requested: the broker kept nothing to revoke at the provider.");
    // Both connections of the shared registration are named.
    expect(drawer(render("admin", morgan(null), "oauth:atlassian"))).toContain(">jira, confluence</span>");
  });

  test("list no Permissions column; the remote revocation's explanation is in the drawer and the status tooltip", () => {
    const html = render("auditor", morgan("failed"));
    // An auditor has no row actions, not even for the retained row.
    expect(columnHeaders(html)).toEqual(["Status", "Connection", "Used by", "Method", "Verified"]);
    // Only the badge's label is cell text.
    const text = tableRow(html, "oauth:gitlab").replace(/<[^>]*>/g, " ");
    expect(text).toContain("Revocation failed");
    expect(text).not.toContain("did not revoke every token");
  });

  test("list a cleanup-only registration with no current grants", () => {
    const html = render("admin", morgan("revoked"), "oauth:gitlab-ops");
    const row = tableRow(html, "oauth:gitlab-ops");
    expect(row).toContain("No current grants");
    expect(statusCell(row)).toContain("Managed by user");
    expect(statusCell(row)).toContain(">Revocation failed</span>");
    expect(drawer(html)).toContain("No service this account is granted uses this connection now.");
    expect(drawer(html)).toContain("Also used by 2 other services this account is not granted.");
  });

  test.each(["admin", "auditor"] as const)("offer an %s no connect, reconnect or disconnect, and explain why", (role) => {
    for (const state of ["pending", "revoked", "failed", "unconfirmed"] as const) {
      for (const open of ["oauth:gitlab", "oauth:gitlab-ops"]) {
        const html = render(role, morgan(state), open);
        const rows = ["oauth:gitlab", "oauth:gitlab-ops", "oauth:google", "oauth:atlassian"].map((key) => tableRow(html, key));
        for (const surface of [...rows, drawer(html)]) {
          expect(surface).not.toBe("");
          for (const action of OWNER_ACTIONS) expect(surface).not.toContain(action);
        }
        for (const row of rows) expect(row).not.toContain("<button");
        expect(drawerActions(html)).toBe("");
        expect(html).toContain("OAuth connections are read-only here: only the user can connect, reconnect or disconnect them, from their own Credentials page.");
        expect(drawer(html)).toContain("Only the user can connect, reconnect or disconnect this account, from their own Credentials page.");
        expect(drawer(html)).toContain("This view does not show its connection status or connected account.");
      }
    }
    // An administrator may still delete a retained stored row; an auditor may not.
    const retained = tableRow(render(role, morgan("failed")), "retained:credential-old");
    expect(retained.includes(">Delete<")).toBe(role === "admin");
  });

  test("need attention when their revocation failed or is unconfirmed, and are not counted as set up", () => {
    for (const [state, attention] of [["not_requested", 1], ["pending", 1], ["revoked", 1], ["failed", 2], ["unconfirmed", 2], [null, 1]] as const) {
      const rows = credentialRows(true, [], morgan(state), undefined);
      const gitlab = rows.find((row) => row.key === "oauth:gitlab")!;
      expect(needsAttention(gitlab)).toBe(state === "failed" || state === "unconfirmed");
      // The cleanup-only registration's failed revocation always counts.
      expect(rows.filter(needsAttention).map((row) => row.key)).toEqual(attention === 2 ? ["oauth:gitlab", "oauth:gitlab-ops"] : ["oauth:gitlab-ops"]);
      // Only the token connection can be set up from here; OAuth status is the owner's.
      expect(credentialCounts(rows)).toEqual({ all: 6, settable: 1, attention, missing: 0, unused: 1 });
    }
    const html = render("auditor", morgan("unconfirmed"));
    expect(html).toMatch(/Needs attention[\s\S]*?>2</);
    expect(html).toContain("<b>1</b> of 1 set up");
    // With OAuth rows alone there is nothing to set up from here.
    const oauthOnly = morgan("failed");
    oauthOnly.connections = oauthOnly.connections.filter((connection) => connection.method === "oauth");
    expect(render("admin", oauthOnly)).not.toContain("of 0 set up");
  });
});
