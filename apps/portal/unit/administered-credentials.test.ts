// Administrative OAuth uses its own endpoint and the same status, details and
// confirmation as personal credentials; auditors never get mutation controls.
import { beforeEach, describe, expect, test, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import type { AdminOAuthConnectionTarget, CredentialList, OAuthConnectionTarget, RemoteRevocation } from "../src/types";
import type { ConfirmOptions } from "../src/app/modal";

const mocks = vi.hoisted(() => ({
  session: { authenticated: true, principal: "admin", role: "admin" as string, selfServiceEnabled: false },
  credentials: { connections: [], retained: [] } as CredentialList,
  oauth: [] as AdminOAuthConnectionTarget[],
  oauthError: false,
  ownQuery: vi.fn(), adminQuery: vi.fn(), confirm: vi.fn(), disconnect: vi.fn(), ownDisconnect: vi.fn(), portal: vi.fn(), toast: vi.fn()
}));
vi.mock("../src/app/session", () => ({ useSession: () => ({ session: mocks.session, reportError: vi.fn(), attempt: (operation: (session: object) => unknown) => operation(mocks.session) }) }));
vi.mock("../src/app/modal", () => ({ useModal: () => ({ confirm: mocks.confirm }) }));
vi.mock("../src/api", () => ({ brokerApi: { adminPrincipalOAuthDisconnect: mocks.disconnect, oauthDisconnect: mocks.ownDisconnect } }));
vi.mock("../src/workbench", async (original) => ({ ...await original<typeof import("../src/workbench")>(), useToast: () => mocks.toast }));
vi.mock("../src/data/invalidation", () => ({ usePortalInvalidation: () => ({ oauthConnections: vi.fn(), portal: mocks.portal }) }));
vi.mock("../src/mutations/credentials", () => ({ useCredentialActions: () => ({ save: vi.fn(), remove: vi.fn(), removeRetained: vi.fn(), verify: vi.fn() }) }));
vi.mock("../src/data/queries", () => ({
  useConsoleData: () => ({ query: { isError: false, isFetching: false, error: null, refetch: vi.fn() }, targets: [], credentials: mocks.credentials, tokens: [], loading: false }),
  useOAuthConnections: (enabled: boolean) => {
    mocks.ownQuery(enabled);
    // A previously cached personal result must not leak into the administered view.
    return { data: [{ ...registration("own", "ready"), canConnect: true, connectUnavailableReason: null }], isError: false, refetch: vi.fn() };
  },
  useAdminOAuthConnections: (principal: string, enabled: boolean) => {
    mocks.adminQuery(principal, enabled);
    return { data: mocks.oauth, isError: mocks.oauthError, error: mocks.oauthError ? new Error("OAuth store unavailable") : null, isFetching: false, refetch: vi.fn() };
  }
}));
import { CredentialDrawer, CredentialRows, CredentialToolbar, credentialCounts, credentialRows, needsAttention, useCredentialList, type CredentialListModel } from "../src/features/credentials/credential-list";
import { oauthDisconnectNotice } from "../src/components/oauth-connections";
import { adminSubject } from "../src/app/active-route";
import { portalQueryKeys } from "../src/lib/portal-queries";

const rest = { service: "gitlab", displayName: "GitLab REST", credentialVerificationSupported: true, credentialVerificationInputs: [] };
const git = { service: "gitlab_git", displayName: "GitLab Git", credentialVerificationSupported: true, credentialVerificationInputs: ["repository"] };
function registration(id: string, status: NonNullable<OAuthConnectionTarget["connection"]>["status"], remoteRevocation: RemoteRevocation = "not_requested"): AdminOAuthConnectionTarget {
  return {
    registration: id, displayName: id === "gitlab" ? "GitLab" : id, connectionDescription: "GitLab access", consumers: [rest, git], otherConsumers: 1,
    permissionProfile: "default", scopeMode: "explicit", requestedScopes: ["api"], target: "https://gitlab.example.test", canDisconnect: status !== "disconnected", remoteRevocation,
    connection: { connectionId: status === "disconnected" ? null : `connection-${id}`, subjectId: "morgan-upstream", displayName: status === "disconnected" ? null : "Morgan upstream", status, reason: status === "reconnect_required" ? "oauth_refresh_uncertain" : null, targets: [] }
  };
}
let model: CredentialListModel;
function Harness() {
  model = useCredentialList(adminSubject("morgan"));
  return createElement("div", null, createElement(CredentialToolbar, { model }), createElement(CredentialRows, { model }), createElement(CredentialDrawer, { model }));
}
function render(role: "admin" | "auditor" = "admin", open?: string) {
  mocks.session.role = role;
  const search = open ? `?credential=${encodeURIComponent(open)}` : "";
  return renderToStaticMarkup(createElement(MemoryRouter, { initialEntries: [`/ui/admin/principals/morgan/credentials${search}`] }, createElement(Harness)));
}
function tableRow(html: string, key: string) {
  return (html.match(/<tr\b[\s\S]*?<\/tr>/g) ?? []).find((row) => row.includes(`data-wb-row="${key}"`)) ?? "";
}
function drawer(html: string) { return html.slice(html.indexOf("<aside")); }

beforeEach(() => {
  vi.clearAllMocks();
  mocks.oauthError = false;
  mocks.credentials = { connections: [{ connection: "obsolete", displayName: "Old projection", method: "oauth", consumers: [], otherConsumers: 0, tokenProfiles: [], registration: "obsolete", remoteRevocation: "failed", credential: null }], retained: [] };
  mocks.oauth = [registration("gitlab", "ready")];
  mocks.disconnect.mockResolvedValue({ disconnected: true, remoteRevocation: "revoked" });
});

describe("administrative OAuth connections", () => {
  test("uses the selected principal's independent list and never merges the token list or viewer's cached OAuth", () => {
    const html = render();
    expect(mocks.ownQuery).toHaveBeenCalledWith(false);
    expect(mocks.adminQuery).toHaveBeenCalledWith("morgan", true);
    expect(tableRow(html, "oauth:gitlab")).toContain("Connected");
    expect(html).not.toContain("Old projection");
    expect(html).not.toContain('data-wb-row="oauth:own"');
    expect(credentialRows([], mocks.credentials, undefined)).toEqual([]);
    expect(portalQueryKeys.adminOAuthConnections("admin", "morgan")).not.toEqual(portalQueryKeys.adminOAuthConnections("admin", "avery"));
    expect(portalQueryKeys.adminOAuthConnections("admin", "morgan")).not.toEqual(portalQueryKeys.adminOAuthConnections("auditor", "morgan"));
    expect(portalQueryKeys.adminOAuthConnections("admin", "morgan")).not.toEqual(portalQueryKeys.oauthConnections("admin"));
  });

  test.each(["admin", "auditor"] as const)("shows %s the current account, status and permissions with owner-only consent actions absent", (role) => {
    const html = render(role, "oauth:gitlab");
    expect(tableRow(html, "oauth:gitlab")).toContain("Morgan upstream");
    expect(drawer(html)).toContain("Connected");
    expect(drawer(html)).toContain("GitLab access");
    expect(html).not.toContain("Managed by user");
    for (const action of [">Connect account<", ">Reconnect<", "Return to authorization tab"]) expect(html).not.toContain(action);
    expect(tableRow(html, "oauth:gitlab").includes(">Disconnect</button>")).toBe(role === "admin");
    expect(drawer(html).includes(">Disconnect</button>")).toBe(role === "admin");
    expect(html).toContain("<b>1</b> of 1 set up");
    if (role === "auditor") expect(html).not.toContain("Row actions");
  });

  test("retains cleanup-only rows and applies the same missing/attention filters", () => {
    mocks.oauth = [registration("gitlab", "reconnect_required"), { ...registration("retired", "disconnected", "failed"), connection: null, consumers: [], otherConsumers: 0, permissionProfile: null, scopeMode: null, target: null }];
    const html = render("admin", "oauth:retired");
    expect(tableRow(html, "oauth:gitlab")).toContain("Reconnect required");
    expect(tableRow(html, "oauth:retired")).toContain("Not connected");
    expect(tableRow(html, "oauth:retired")).toContain("Revocation failed");
    expect(tableRow(html, "oauth:retired")).not.toContain("<button");
    expect(drawer(html)).toContain("No service this account is granted uses this connection now.");
    expect(credentialCounts(model.rows)).toEqual({ all: 2, settable: 2, attention: 2, missing: 1, unused: 0 });
    expect(model.rows.every(needsAttention)).toBe(true);
  });

  test("keeps grant-loss and unselected owned connections disconnectable", () => {
    mocks.oauth = [{ ...registration("unselected", "ready"), consumers: [], permissionProfile: null, scopeMode: null, target: null }];
    const html = render("admin", "oauth:unselected");
    expect(tableRow(html, "oauth:unselected")).toContain("No current grants");
    expect(drawer(html)).toContain(">Disconnect</button>");
  });

  test.each(["failed", "unconfirmed"] as const)("words %s provider cleanup for the target user, without suggesting the admin's own account", (state) => {
    mocks.oauth = [registration("gitlab", "ready", state)];
    const html = render("admin", "oauth:gitlab");
    expect(drawer(html)).toContain("The user morgan must revoke");
    expect(drawer(html)).toContain("the user must reconnect afterwards");
    expect(html).not.toContain("in your account settings");
    const notice = oauthDisconnectNotice(state, "morgan");
    expect(notice.message).toContain("Account disconnected for morgan.");
    expect(notice.message).toContain("The user morgan must revoke");
    expect(notice.tone).toBe("error");
  });

  test("does not suggest an administrator can reconnect an unidentified account", () => {
    mocks.oauth[0].connection!.subjectId = null;
    const html = render("admin", "oauth:gitlab");
    expect(drawer(html)).toContain("Upstream account identity unavailable.");
    expect(drawer(html)).not.toContain("reconnecting asks to confirm");
  });

  test("shows explicit unavailability and withholds cached statuses and actions when the query fails", () => {
    mocks.oauthError = true;
    const html = render("admin", "oauth:gitlab");
    expect(html).toContain("OAuth connection status unavailable");
    expect(html).toContain("OAuth store unavailable");
    expect(html).not.toContain("Not connected");
    expect(html).not.toContain("No credential connections");
    expect(html).not.toContain("Morgan upstream");
    expect(html).not.toContain(">Disconnect</button>");
  });

  test("uses one confirmation naming the target and services before calling the administrative DELETE", async () => {
    render();
    model.connections.disconnect(mocks.oauth[0]);
    expect(mocks.confirm).toHaveBeenCalledOnce();
    expect(mocks.disconnect).not.toHaveBeenCalled();
    const confirmation: ConfirmOptions = mocks.confirm.mock.calls[0][0];
    expect(confirmation.title).toBe("Disconnect account?");
    expect(confirmation.confirmLabel).toBe("Disconnect");
    expect(confirmation.body).toContain("morgan's GitLab connection");
    expect(confirmation.body).toContain("GitLab REST, GitLab Git and 1 other service stop using this account.");
    expect(confirmation.body).toContain("The user can connect again while permitted");
    await confirmation.onConfirm();
    expect(mocks.disconnect).toHaveBeenCalledWith(mocks.session, "morgan", "gitlab");
    expect(mocks.ownDisconnect).not.toHaveBeenCalled();
    expect(mocks.portal).toHaveBeenCalledOnce();
    expect(mocks.toast.mock.calls[0][0]).toContain("Account disconnected for morgan.");
  });

  test("leaves a failed mutation to the shared confirmation error state without claiming success", async () => {
    mocks.disconnect.mockRejectedValue(new Error("disconnect refused"));
    render();
    model.connections.disconnect(mocks.oauth[0]);
    await expect((mocks.confirm.mock.calls[0][0] as ConfirmOptions).onConfirm()).rejects.toThrow("disconnect refused");
    expect(mocks.portal).not.toHaveBeenCalled();
    expect(mocks.toast).not.toHaveBeenCalled();
  });

  test("an auditor cannot start a disconnect even through the action hook", () => {
    render("auditor");
    model.connections.disconnect(mocks.oauth[0]);
    expect(mocks.confirm).not.toHaveBeenCalled();
    expect(mocks.disconnect).not.toHaveBeenCalled();
  });
});
