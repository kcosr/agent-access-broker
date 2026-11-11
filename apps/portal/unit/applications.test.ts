// Registered applications in the portal: the approval page, the personal
// Applications list and the administrator's Access paths rows.
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, test, vi } from "vitest";
import { ApiError, brokerApi } from "../src/api";
import { isPortalPath, ROUTE, sanitizedUiReturnTo } from "../src/app/paths";
import { ApplicationAccessTable } from "../src/features/account/applications-section";
import { ConsentCard, InvalidRequest } from "../src/features/applications/authorize-page";
import { ApplicationAccessRow } from "../src/features/principals/identity-access";
import {
  applicationAccessLevel,
  applicationAccessName,
  applicationAccessRestricted,
  applicationAccessState,
  applicationDenialMessage,
  applicationLevelLabel,
  applicationLevelSummary,
  applicationRedirectTarget,
  applicationTokensNotice,
  authorizationInvalid,
  catalogListsApplications,
  liveTokenSummary,
  refusedApprovalReason,
  validAuthorizationRequestId
} from "../src/lib/applications";
import { portalQueryKeys } from "../src/lib/portal-queries";
import type { ApplicationAccess, ApplicationAuthorization, Session } from "../src/types";

afterEach(() => vi.unstubAllGlobals());

const REQUEST_ID = "request-id-fixture-".padEnd(43, "x");
const session: Session = { authenticated: true, principal: "alex", displayName: "Alex Example", role: "user", selfServiceEnabled: false, csrfHeader: "x-csrf-token", csrfToken: "fixture-csrf" };
const request: ApplicationAuthorization = { applicationId: "example-runner", applicationName: "Example Runner", connect: "read_write", readOnly: false, canConnect: true, denialReason: null, expiresAt: "2026-01-01T00:10:00Z" };
const access: ApplicationAccess = {
  accessId: "11111111-2222-4333-8444-555555555555", principalId: "alex", applicationId: "example-runner", applicationName: "Example Runner", applicationAvailable: true,
  connect: "read_write", enabled: true, readOnly: false, effectiveReadOnly: false, version: 3, connected: true,
  createdAt: "2026-01-01T00:00:00Z", connectedAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-02T00:00:00Z", updatedBy: "admin", lastUsedAt: null, liveTokenCount: 2
};
const noop = () => undefined;

describe("authorization requests", () => {
  test("only a 43-character base64url request ID is asked about", () => {
    expect(REQUEST_ID).toHaveLength(43);
    expect(validAuthorizationRequestId(REQUEST_ID)).toBe(true);
    expect(validAuthorizationRequestId("A_-".repeat(14) + "A")).toBe(true);
    for (const value of [undefined, "", REQUEST_ID.slice(1), `${REQUEST_ID}A`, `${REQUEST_ID.slice(1)}=`, `${REQUEST_ID.slice(1)}/`, `${REQUEST_ID.slice(2)}%2F`]) {
      expect(validAuthorizationRequestId(value), String(value)).toBe(false);
    }
  });

  test("the approval page is a portal path, so sign-in returns to it", () => {
    const path = `/ui/authorize/${REQUEST_ID}`;
    expect(ROUTE.authorize).toBe("/ui/authorize/:requestId");
    expect(isPortalPath(path)).toBe(true);
    expect(sanitizedUiReturnTo(path)).toBe(path);
    expect(isPortalPath("/ui/authorize")).toBe(false);
    expect(isPortalPath(`${path}/extra`)).toBe(false);
  });

  test("each denial reason has one plain sentence, and unknown reasons a general one", () => {
    expect(applicationDenialMessage("connecting_disabled")).toBe("Connecting this application is turned off on this broker.");
    expect(applicationDenialMessage("access_disabled")).toBe("An administrator disabled your access for this application.");
    expect(applicationDenialMessage("not_human")).toBe("Only a person’s account can connect an application, and this is a service account.");
    expect(applicationDenialMessage("account_disabled")).toBe("Your broker account is disabled.");
    for (const reason of ["new_reason", "", null, undefined, "constructor", "toString"]) {
      expect(applicationDenialMessage(reason), String(reason)).toBe("The broker does not allow this account to connect the application.");
    }
  });

  test("a refused approval carries its reason; an invalid request is recognized by its reason code", () => {
    const refused = new ApiError("application access denied", 403, "application_access_denied", undefined, undefined, undefined, undefined, undefined, { denialReason: "access_disabled" });
    expect(refusedApprovalReason(refused)).toBe("access_disabled");
    expect(refusedApprovalReason(new ApiError("application access denied", 403, "application_access_denied"))).toBe("");
    expect(refusedApprovalReason(new ApiError("denied", 403, "management_denied", undefined, undefined, undefined, undefined, undefined, { denialReason: "access_disabled" }))).toBeNull();
    expect(refusedApprovalReason(new Error("network"))).toBeNull();
    expect(authorizationInvalid(new ApiError("not found", 404, "application_authorization_invalid"))).toBe(true);
    expect(authorizationInvalid(new ApiError("not found", 404, "principal_not_found"))).toBe(false);
    expect(authorizationInvalid(new Error("network"))).toBe(false);
  });

  test("only an absolute web address is opened after a decision", () => {
    expect(applicationRedirectTarget("https://runner.example.test/auth/broker/callback?code=c&state=s")).toBe("https://runner.example.test/auth/broker/callback?code=c&state=s");
    expect(applicationRedirectTarget("http://127.0.0.1:8080/callback?error=access_denied&state=s")).toBe("http://127.0.0.1:8080/callback?error=access_denied&state=s");
    for (const value of ["javascript:alert(1)", "data:text/html,x", "/ui/account", "//runner.example.test/callback", "", null, undefined, 7]) {
      expect(applicationRedirectTarget(value), String(value)).toBeNull();
    }
  });
});

describe("the approval page", () => {
  const card = (props: Partial<Parameters<typeof ConsentCard>[0]> = {}) =>
    renderToStaticMarkup(createElement(ConsentCard, { request, session, denial: null, pending: null, leaving: false, error: null, onDecide: noop, onSwitchAccount: noop, ...props }));

  test("names the application, the fixed level and the signed-in account, and offers Approve and Cancel", () => {
    const markup = card();
    expect(markup).toContain(">Connect Example Runner?</h1>");
    expect(markup).toContain("Example Runner is asking to act as you through the Agent Access Broker.");
    expect(markup).toContain("it can use what you are already allowed to use, at the access level below, and nothing more.");
    expect(markup).toContain("<strong>Read and write</strong>");
    expect(markup).toContain("It can read and make changes, as you can.");
    expect(markup).toContain("An administrator sets the access level; you cannot change it here.");
    expect(markup).toContain("Alex Example · ");
    expect(markup).toContain(">alex</span>");
    expect(markup.match(/<button/g)).toHaveLength(3);
    for (const label of ["Approve", "Cancel", "Use a different account"]) expect(markup).toContain(`${label}</`);
    expect(markup).not.toContain("disabled");
  });

  test("states a read-only level plainly", () => {
    const markup = card({ request: { ...request, connect: "read_only", readOnly: true } });
    expect(markup).toContain("<strong>Read-only</strong>");
    expect(markup).toContain("It can read what you can read, and cannot make changes.");
    expect(markup).not.toContain("Read and write");
  });

  test("a second answer is not accepted while one is being sent or the browser is leaving", () => {
    const approving = card({ pending: "approve" });
    expect(approving).toMatch(/<button[^>]*aria-busy="true"[^>]*>.*?Approve/s);
    expect(approving.match(/<button[^>]* disabled=""/g)).toHaveLength(2);
    const leaving = card({ pending: "cancel", leaving: true });
    expect(leaving).toContain("Returning to Example Runner…");
    expect(leaving.match(/<button[^>]* disabled=""/g)).toHaveLength(2);
  });

  test.each(["connecting_disabled", "access_disabled", "not_human", "account_disabled", "new_reason"])("a person who may not connect (%s) is told why and can only return", (reason) => {
    const markup = card({ request: { ...request, canConnect: false }, denial: reason });
    expect(markup).toContain(">You can’t connect Example Runner</h1>");
    expect(markup).toContain(applicationDenialMessage(reason));
    expect(markup).toContain("Return to Example Runner</");
    expect(markup).not.toContain("Approve");
    expect(markup).not.toContain("Access level");
    expect(markup).toContain(">alex</span>");
  });

  test("an invalid request offers no way onward", () => {
    const markup = renderToStaticMarkup(createElement(InvalidRequest));
    expect(markup).toContain("This request is no longer valid");
    expect(markup).toContain("It has expired, was already answered, or does not exist.");
    expect(markup).not.toMatch(/<a |<button|href=/);
  });

  test("nothing shown names the request", () => {
    for (const markup of [card(), card({ denial: "access_disabled" }), card({ error: "Request failed" }), renderToStaticMarkup(createElement(InvalidRequest))]) {
      expect(markup).not.toContain(REQUEST_ID);
    }
  });
});

describe("application access", () => {
  test("the catalog lists the personal routes only while applications are registered", () => {
    expect(catalogListsApplications({ routes: [{ operation: "tokens.list" }, { operation: "applications.access.list" }] })).toBe(true);
    expect(catalogListsApplications({ routes: [{ operation: "tokens.list" }, { operation: "admin.principals.application_access.list" }] })).toBe(false);
    expect(catalogListsApplications({ routes: [] })).toBe(false);
    expect(catalogListsApplications({} as never)).toBe(false);
  });

  test("one state per access, and the level in the same words everywhere", () => {
    expect(applicationAccessState(access)).toEqual({ label: "Connected", tone: "success" });
    expect(applicationAccessState({ ...access, enabled: false })).toEqual({ label: "Disabled by an administrator", tone: "warning" });
    expect(applicationAccessState({ ...access, connected: false, enabled: false })).toEqual({ label: "Not connected", tone: "neutral" });
    expect(applicationAccessState({ ...access, connect: "none" })).toEqual({ label: "Connecting turned off", tone: "warning" });
    expect(applicationAccessState({ ...access, applicationAvailable: false, connect: null, connected: false })).toEqual({ label: "Application unavailable", tone: "warning" });
    expect(applicationLevelLabel(true)).toBe("Read-only");
    expect(applicationLevelLabel(false)).toBe("Read and write");
    expect([applicationLevelSummary("read_write"), applicationLevelSummary("read_only"), applicationLevelSummary("none"), applicationLevelSummary(null)]).toEqual(["Level: read and write", "Level: read-only", "Level: none", "Level: not available"]);
    // An application that is not registered gives no level, whatever the row's own setting.
    expect(applicationAccessLevel(access)).toBe("Read and write");
    expect(applicationAccessLevel({ applicationAvailable: true, effectiveReadOnly: true })).toBe("Read-only");
    expect(applicationAccessLevel({ applicationAvailable: false, effectiveReadOnly: false })).toBeNull();
    expect(applicationAccessLevel({ applicationAvailable: false, effectiveReadOnly: true })).toBeNull();
    expect([applicationAccessRestricted(access), applicationAccessRestricted({ enabled: false, readOnly: false }), applicationAccessRestricted({ enabled: true, readOnly: true })]).toEqual([false, true, true]);
    expect([liveTokenSummary(0), liveTokenSummary(1), liveTokenSummary(2)]).toEqual(["0 live tokens", "1 live token", "2 live tokens"]);
    expect(applicationAccessName(access)).toBe("Example Runner");
    expect(applicationAccessName({ applicationName: null, applicationId: "example-runner" })).toBe("example-runner");
  });

  test("the personal list shows the connection date, level, state, last use, live tokens and Remove", () => {
    const rows = [access, { ...access, accessId: "b", applicationName: "Example Notes", readOnly: true, effectiveReadOnly: true, enabled: false, lastUsedAt: "2026-01-03T00:00:00Z", liveTokenCount: 0 }, { ...access, accessId: "c", applicationId: "retired-runner", applicationName: null, applicationAvailable: false, connect: null }];
    const markup = renderToStaticMarkup(createElement(ApplicationAccessTable, { access: rows, busy: false, onRemove: noop }));
    expect(markup).toContain('aria-label="Applications"');
    for (const heading of ["Application", "Access level", "Status", "Last used", "Live tokens"]) expect(markup).toContain(`>${heading}</th>`);
    const [, first, second, third] = markup.split("<tr>").slice(1);
    expect(first).toContain(">Example Runner</span>");
    expect(first).toMatch(/Connected <time[^>]*>[^<]+<\/time><\/span><\/th><td class="whitespace-nowrap">Read and write<\/td>/);
    expect(first).toContain("Connected");
    expect(first).toContain("Never");
    expect(first).toContain("<td>2</td>");
    expect(first).toContain('aria-label="Remove Example Runner"');
    expect(second).toContain(">Example Notes</span>");
    expect(second).toContain("<td class=\"whitespace-nowrap\">Read-only</td>");
    expect(second).toContain("Disabled by an administrator");
    expect(second).not.toContain("Never");
    expect(third).toContain(">retired-runner</span>");
    expect(third).toContain("Application unavailable");
    expect(third).toContain('<td class="whitespace-nowrap"><span class="wb-muted">Not available</span></td>');
    expect(third).not.toContain("Read and write");
  });

  describe("the administrator's access path row", () => {
    const row = (changes: Partial<ApplicationAccess> = {}, writable = true) =>
      renderToStaticMarkup(createElement(ApplicationAccessRow, { access: { ...access, ...changes }, writable, busy: false, onChange: noop, onRemove: noop }));

    test("has the path controls, the level, the live tokens and Remove", () => {
      const markup = row();
      expect(markup).toContain("Example Runner");
      expect(markup).toContain("Application · Level: read and write · 2 live tokens");
      expect(markup).toContain("Connected");
      expect(markup).toMatch(/<input aria-label="Application Example Runner enabled" type="checkbox" role="switch"[^>]* checked=""\/>/);
      expect(markup).toMatch(/<input aria-label="Application Example Runner read-only" type="checkbox" role="switch"[^>]*"\/>/);
      expect(markup).toContain("<td>3</td>");
      expect(markup).toContain('aria-label="Remove application Example Runner"');
    });

    test("shows read-only as fixed when the application's level is read-only", () => {
      const markup = row({ connect: "read_only", readOnly: false, effectiveReadOnly: true });
      expect(markup).toContain("Application · Level: read-only · 2 live tokens");
      expect(markup).toContain("Fixed by the application’s level");
      expect(markup).not.toContain("read-only\"");
      expect(markup).toContain('aria-label="Application Example Runner enabled"');
    });

    test("keeps the settings of a row that is not connected editable and removable", () => {
      const markup = row({ connected: false, readOnly: true, effectiveReadOnly: true, liveTokenCount: 0 });
      expect(markup).toContain("Not connected");
      expect(markup).toContain("0 live tokens");
      expect(markup).toContain('aria-label="Application Example Runner enabled"');
      expect(markup).toContain('aria-label="Application Example Runner read-only"');
      expect(markup).toContain('aria-label="Remove application Example Runner"');
    });

    test("names an unregistered application by its ID and marks it unavailable", () => {
      const markup = row({ applicationName: null, applicationAvailable: false, connect: null, applicationId: "retired-runner" });
      expect(markup).toContain("retired-runner");
      expect(markup).toContain("Application unavailable");
      expect(markup).toContain("Application · Level: not available · 2 live tokens");
      expect(markup).not.toMatch(/read and write|Level: read-only/);
      expect(markup).toContain('aria-label="Application retired-runner read-only"');
    });

    test("is text without controls for an auditor", () => {
      const markup = row({ enabled: false, readOnly: true }, false);
      expect(markup).not.toMatch(/<input|<button/);
      expect(markup).toContain("<td><span>Disabled</span></td>");
      expect(markup).toContain("<td><span>Read-only</span></td>");
    });
  });
});

describe("a reload's application tokens", () => {
  test("says nothing when no token was ended", () => {
    expect(applicationTokensNotice(undefined)).toBeNull();
    expect(applicationTokensNotice({ status: "reconciled", applications: [] })).toBeNull();
    expect(applicationTokensNotice({ status: "other" } as never)).toBeNull();
  });

  test("names each application, its ended tokens and why", () => {
    expect(applicationTokensNotice({ status: "reconciled", applications: [
      { applicationId: "example-runner", reason: "registration_narrowed", revokedTokens: 3 },
      { applicationId: "retired-runner", reason: "registration_removed", revokedTokens: 1 },
      { applicationId: "example-notes", reason: "connecting_disabled", revokedTokens: 2 },
      { applicationId: "example-reports", reason: "new_reason", revokedTokens: 4 }
    ] })).toEqual({ failed: false, text: "Ended application tokens: example-runner 3 (registration narrowed), retired-runner 1 (no longer registered), example-notes 2 (connecting turned off), example-reports 4 (new reason)" });
  });

  test("reports a failed step as a failure that is retried", () => {
    expect(applicationTokensNotice({ status: "failed" })).toEqual({ failed: true, text: "Application tokens the new configuration no longer allows were not ended; the next reload or restart tries again." });
  });
});

describe("the API client", () => {
  const ok = () => vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ ok: true, result: { access: [] } }))));

  test("uses the canonical routes, CSRF on every request and the current version on administrator changes", async () => {
    const fetch = ok();
    vi.stubGlobal("fetch", fetch);
    await brokerApi.applicationAuthorization(session, REQUEST_ID);
    await brokerApi.decideApplicationAuthorization(session, REQUEST_ID, "approve");
    await brokerApi.decideApplicationAuthorization(session, REQUEST_ID, "cancel");
    await brokerApi.applicationAccess(session);
    await brokerApi.removeApplicationAccess(session, "access/1");
    await brokerApi.adminApplicationAccess(session, "user/1");
    await brokerApi.adminUpdateApplicationAccess(session, "user/1", "access/1", { enabled: false, expectedVersion: 3 });
    await brokerApi.adminUpdateApplicationAccess(session, "user/1", "access/1", { readOnly: true, expectedVersion: 4 });
    await brokerApi.adminRemoveApplicationAccess(session, "user/1", "access/1", 5);
    expect(fetch.mock.calls.map(([url, init]) => [url, init.method ?? "GET", init.body && JSON.parse(init.body)])).toEqual([
      [`/v1/applications/authorizations/${REQUEST_ID}`, "GET", undefined],
      [`/v1/applications/authorizations/${REQUEST_ID}/decision`, "POST", { decision: "approve" }],
      [`/v1/applications/authorizations/${REQUEST_ID}/decision`, "POST", { decision: "cancel" }],
      ["/v1/applications/access", "GET", undefined],
      ["/v1/applications/access/access%2F1", "DELETE", undefined],
      ["/v1/admin/principals/user%2F1/application-access", "GET", undefined],
      ["/v1/admin/principals/user%2F1/application-access/access%2F1", "PATCH", { enabled: false, expectedVersion: 3 }],
      ["/v1/admin/principals/user%2F1/application-access/access%2F1", "PATCH", { readOnly: true, expectedVersion: 4 }],
      ["/v1/admin/principals/user%2F1/application-access/access%2F1?expectedVersion=5", "DELETE", undefined]
    ]);
    for (const [, init] of fetch.mock.calls) {
      expect(new Headers(init.headers).get("x-csrf-token")).toBe("fixture-csrf");
      expect(init.credentials).toBe("same-origin");
    }
  });

  test("lists return the access rows and the catalog is read without rendered auth", async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true, result: { access: [access] } })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true, result: { access: [] } })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ version: "v", routes: [{ operation: "applications.access.list" }] })));
    vi.stubGlobal("fetch", fetch);
    await expect(brokerApi.applicationAccess(session)).resolves.toEqual([access]);
    await expect(brokerApi.adminApplicationAccess(session, "alex")).resolves.toEqual([]);
    await expect(brokerApi.routeCatalog().then(catalogListsApplications)).resolves.toBe(true);
    expect(fetch.mock.calls[2]![0]).toBe("/v1/spec/catalog?auth=omit");
  });

  test("a refused approval, an invalid request and a stale version keep their status, reason and details", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: false, reasonCode: "application_access_denied", error: { message: "application access denied" }, details: { denialReason: "connecting_disabled" } }), { status: 403 })));
    const refused = await brokerApi.decideApplicationAuthorization(session, REQUEST_ID, "approve").catch((error: unknown) => error);
    expect(refused).toMatchObject({ status: 403, reasonCode: "application_access_denied", details: { denialReason: "connecting_disabled" } });
    expect(refusedApprovalReason(refused)).toBe("connecting_disabled");
    expect((refused as Error).message).not.toContain(REQUEST_ID);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: false, reasonCode: "application_authorization_invalid", error: { message: "application authorization request is not valid" } }), { status: 404 })));
    const invalid = await brokerApi.applicationAuthorization(session, REQUEST_ID).catch((error: unknown) => error);
    expect(authorizationInvalid(invalid)).toBe(true);
    expect((invalid as ApiError).details).toBeUndefined();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: false, reasonCode: "version_conflict", error: { message: "version conflict" } }), { status: 409 })));
    await expect(brokerApi.adminUpdateApplicationAccess(session, "alex", access.accessId, { enabled: false, expectedVersion: 1 })).rejects.toMatchObject({ status: 409, reasonCode: "version_conflict" });
  });

  test("application queries are isolated by viewer, request and principal", () => {
    const keys = [
      portalQueryKeys.applicationsRegistered("alex"),
      portalQueryKeys.applicationAccess("alex"),
      portalQueryKeys.applicationAccess("sam"),
      portalQueryKeys.applicationAuthorization("alex", REQUEST_ID),
      portalQueryKeys.applicationAuthorization("alex", `${REQUEST_ID.slice(1)}y`),
      portalQueryKeys.adminApplicationAccess("admin", "alex"),
      portalQueryKeys.adminApplicationAccess("auditor", "alex"),
      portalQueryKeys.adminApplicationAccess("admin", "sam")
    ];
    expect(new Set(keys.map((key) => JSON.stringify(key))).size).toBe(keys.length);
  });
});
