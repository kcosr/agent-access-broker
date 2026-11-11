// Registered applications in the portal: the approval page, the personal
// Applications list and the administrator's Access paths rows.
// Mocked UI contracts: every API call is answered by an explicit fixture and
// no Broker runs. `applications-live.spec.ts` drives a real Broker.
import { expect, test, type Page, type Request } from "@playwright/test";
import type { ApplicationAccess, ApplicationAuthorization, ApplicationTokensOutcome, PrincipalRole } from "../src/types";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

let assets: PortalAssets;
test.beforeAll(async () => { assets = await servePortalAssets(); });
test.afterAll(async () => { await assets.close(); });

const REQUEST_ID = "request-id-fixture-".padEnd(43, "x");
const CONSENT_PATH = `/ui/authorize/${REQUEST_ID}`;
const CALLBACK = "https://runner.example.test/auth/broker/callback";
const STATE = "state-fixture";
const CODE = "code-fixture";
const stamp = "2026-11-02T00:00:00Z";
const ok = (result: unknown) => ({ json: { ok: true, result } });
const refusal = (status: number, reasonCode: string, message: string, details?: unknown) => ({ status, json: { ok: false, reasonCode, error: { message }, ...(details ? { details } : {}) } });
const invalid = refusal(404, "application_authorization_invalid", "application authorization request is not valid");

function access(changes: Partial<ApplicationAccess> = {}): ApplicationAccess {
  return {
    accessId: "access-runner", principalId: "alex", applicationId: "example-runner", applicationName: "Example Runner", applicationAvailable: true,
    connect: "read_write", enabled: true, readOnly: false, effectiveReadOnly: false, version: 1, connected: true,
    createdAt: stamp, connectedAt: stamp, updatedAt: stamp, updatedBy: "alex", lastUsedAt: null, liveTokenCount: 2, ...changes
  };
}

type Model = ReturnType<typeof newModel>;
function newModel() {
  return {
    signedIn: true,
    /** Whose cookie the browser holds; another tab can change it under an open page. */
    account: "alex" as "alex" | "sam",
    /** The CSRF token of the current session. */
    csrf: "csrf-fixture",
    /** Runs when a decision arrives, before the Broker checks it. */
    beforeDecision: null as null | (() => void),
    role: "user" as PrincipalRole,
    selfServiceEnabled: false,
    authorization: { applicationId: "example-runner", applicationName: "Example Runner", connect: "read_write", readOnly: false, canConnect: true, denialReason: null, expiresAt: "2099-01-01T00:10:00Z" } as ApplicationAuthorization | null,
    /** Answers a decision; the default approves or cancels back to the application. */
    decide: null as null | ((decision: string) => { status?: number; json: unknown } | Promise<{ status?: number; json: unknown }>),
    registered: true,
    /** What the next configuration reload reports about application tokens. */
    reloadTokens: undefined as ApplicationTokensOutcome | undefined,
    access: [] as ApplicationAccess[],
    adminAccess: [] as ApplicationAccess[],
    /** Fails the next administrator change with a stale version, after another administrator's change. */
    adminConflict: false,
    authorizationReads: 0,
    decisions: [] as { decision: unknown; csrf: string | null }[],
    writes: [] as { method: string; path: string; query: string; body: unknown }[],
    logins: [] as unknown[],
    callbacks: [] as { url: string; method: string; navigation: boolean; resourceType: string; mainFrame: boolean }[],
    console: [] as string[],
    errors: [] as string[]
  };
}

function sessionOf(model: Model) {
  const loginOptions = { localPassword: { enabled: true }, microsoft: { enabled: true, available: true, displayName: "Microsoft", startPath: "/v1/auth/oidc/microsoft/start" } };
  if (!model.signedIn) return { authenticated: false, loginOptions };
  return {
    authenticated: true, principal: model.role !== "user" ? "viewer" : model.account, displayName: model.role !== "user" ? "Viewer" : model.account === "alex" ? "Alex Example" : "Sam Example", role: model.role, selfServiceEnabled: model.selfServiceEnabled,
    loginMethod: "local_password", signInMethods: { localPassword: "active", microsoft: "absent" }, csrfHeader: "x-csrf-token", csrfToken: model.csrf, loginOptions
  };
}

function callbackUrl(decision: string) {
  const url = new URL(CALLBACK);
  if (decision === "approve") url.searchParams.set("code", CODE);
  else url.searchParams.set("error", "access_denied");
  url.searchParams.set("state", STATE);
  return url.toString();
}

async function fixture(page: Page, configure: (model: Model) => void = () => undefined) {
  const model = newModel();
  configure(model);
  page.on("pageerror", (error) => model.errors.push(error.message));
  page.on("console", (message) => model.console.push(message.text()));
  // The application: a page of its own, reached only by a top-level navigation.
  await page.route("https://runner.example.test/**", async (route) => {
    const request: Request = route.request();
    model.callbacks.push({ url: request.url(), method: request.method(), navigation: request.isNavigationRequest(), resourceType: request.resourceType(), mainFrame: request.frame() === page.mainFrame() });
    await route.fulfill({ contentType: "text/html", body: "<!doctype html><title>Example Runner</title><h1>Back in Example Runner</h1>" });
  });
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    const method = request.method();
    const body = method === "GET" || method === "DELETE" ? null : request.postDataJSON() as Record<string, unknown>;
    if (path === "/v1/auth/session") return route.fulfill(ok(sessionOf(model)));
    if (path === "/v1/auth/local/login") {
      model.logins.push(body);
      model.signedIn = true;
      return route.fulfill(ok({ ...sessionOf(model), returnTo: body?.returnTo }));
    }
    if (path === "/v1/auth/logout") {
      model.signedIn = false;
      return route.fulfill(ok(sessionOf(model)));
    }
    if (path === "/v1/auth/oidc/microsoft/start") {
      // The provider round trip, reduced to its result: a session and the return path.
      model.logins.push({ microsoftReturnTo: url.searchParams.get("returnTo") });
      model.signedIn = true;
      return route.fulfill({ status: 303, headers: { location: url.searchParams.get("returnTo") ?? "/ui" } });
    }
    if (!model.signedIn) return route.fulfill(refusal(401, "identity_required", "identity is required"));
    if (path === "/v1/spec/catalog") return route.fulfill({ json: { version: "fixture", routes: model.registered ? [{ operation: "applications.access.list" }] : [] } });
    if (path === "/v1/resource-types") return route.fulfill({ json: { resourceTypes: [] } });
    if (path === "/v1/me") return route.fulfill(ok({ serviceLimits: [] }));
    if (path === `/v1/applications/authorizations/${REQUEST_ID}`) {
      model.authorizationReads += 1;
      return route.fulfill(model.authorization ? ok(model.authorization) : invalid);
    }
    if (path === `/v1/applications/authorizations/${REQUEST_ID}/decision`) {
      model.beforeDecision?.();
      model.decisions.push({ decision: body?.decision, csrf: request.headers()["x-csrf-token"] ?? null });
      // As the Broker does: a CSRF token belongs to one session.
      if (request.headers()["x-csrf-token"] !== model.csrf) return route.fulfill(refusal(403, "csrf_invalid", "csrf token is invalid"));
      const decision = String(body?.decision);
      return route.fulfill(model.decide ? await model.decide(decision) : ok({ decision, redirectTo: callbackUrl(decision) }));
    }
    if (path === "/v1/applications/access") return route.fulfill(ok({ access: model.access }));
    if (path.startsWith("/v1/applications/access/")) {
      model.writes.push({ method, path, query: url.search, body });
      model.access = model.access.filter((item) => item.accessId !== path.split("/").pop());
      return route.fulfill(ok({ removed: true }));
    }
    if (path === "/v1/admin/principals/alex/application-access") return route.fulfill(ok({ access: model.adminAccess }));
    if (path.startsWith("/v1/admin/principals/alex/application-access/")) {
      model.writes.push({ method, path, query: url.search, body });
      const id = path.split("/").pop();
      const current = model.adminAccess.find((item) => item.accessId === id);
      if (!current) return route.fulfill(refusal(404, "application_access_not_found", "application access was not found"));
      if (model.adminConflict) {
        model.adminConflict = false;
        model.adminAccess = model.adminAccess.map((item) => item.accessId === id ? { ...item, readOnly: true, effectiveReadOnly: true, version: item.version + 1, liveTokenCount: 0 } : item);
        return route.fulfill(refusal(409, "version_conflict", "version conflict"));
      }
      if (method === "DELETE") {
        model.adminAccess = model.adminAccess.filter((item) => item.accessId !== id);
        return route.fulfill(ok({ removed: true }));
      }
      const { expectedVersion: _expected, ...change } = body ?? {};
      const next = { ...current, ...change, version: current.version + 1, liveTokenCount: 0 } as ApplicationAccess;
      next.effectiveReadOnly = next.readOnly || next.connect === "read_only";
      model.adminAccess = model.adminAccess.map((item) => item.accessId === id ? next : item);
      return route.fulfill(ok(next));
    }
    if (path === "/v1/credentials") return route.fulfill(ok({ connections: [], retained: [] }));
    if (path === "/v1/tokens/options") return route.fulfill(ok({ policyGeneration: 1, agentTokenIssuancePolicy: { source: "default", contexts: [] }, executionContexts: ["default"], services: [], resources: [], resourceGroups: [] }));
    if (path === "/v1/admin/policy/catalog") return route.fulfill(ok({ services: [], subjects: { users: [], groups: [], anonymous: false }, resources: [], resourceGroups: [], executionContexts: { allowedValues: ["default"], defaultContext: "default" } }));
    const status = { identityAuthority: "managed", policyAuthority: "managed", generation: 1, loadedAt: stamp, configHash: "fixture", bodyHardCapBytes: 1024, reloadTimeoutMs: 1000, shutdownTimeoutMs: 1000 };
    if (path === "/v1/admin/config/status") return route.fulfill(ok(status));
    if (path === "/v1/admin/config/reload") return route.fulfill(ok({ ...status, generation: 2, previousGeneration: 1, previousConfigHash: "fixture", applicationTokens: model.reloadTokens }));
    if (path === "/v1/admin/principals/alex") {
      return route.fulfill(ok({ principalId: "alex", kind: "user", displayName: "Alex Example", status: "active", role: "user", selfServiceEnabled: false, groups: [], groupMemberships: [], activePolicyGroupSubjects: [], policyReferenceSections: [], signInMethods: { localPassword: "active", microsoft: "absent" }, agentTokenIssuance: { mode: "inherit", allowedExecutionContexts: [] }, agentTokenIssuancePolicy: { source: "default", contexts: [] }, createdAt: stamp, updatedAt: stamp, createdBy: "admin" }));
    }
    if (path.endsWith("/identity-token")) return route.fulfill(ok({ principalId: "alex", configured: false, enabled: true, readOnly: false, revision: 1, updatedAt: stamp }));
    if (path.endsWith("/identity-access")) return route.fulfill(ok({ principalId: "alex", incarnation: "fixture", paused: false, version: 1, updatedAt: stamp, updatedBy: "admin" }));
    if (path.endsWith("/identity-bindings")) return route.fulfill(ok({ bindings: [], configuredNamespaces: [] }));
    return route.fulfill(ok([]));
  });
  return model;
}

/** The decision arrived at the application as one top-level GET page load, never a fetch or a form post. */
async function expectReturnedToApplication(page: Page, model: Model, decision: "approve" | "cancel") {
  await expect(page.getByRole("heading", { name: "Back in Example Runner", exact: true })).toBeVisible();
  expect(page.url()).toBe(callbackUrl(decision));
  expect(model.callbacks).toEqual([{ url: callbackUrl(decision), method: "GET", navigation: true, resourceType: "document", mainFrame: true }]);
}

/** Neither the request nor the outcome it returns reached the console. */
function expectNothingLeaked(model: Model) {
  expect(model.errors).toEqual([]);
  for (const text of model.console) {
    for (const secret of [REQUEST_ID, STATE, CODE]) expect(text).not.toContain(secret);
  }
}

test.describe("approval page", () => {
  test("approving returns the browser to the application with a top-level navigation", async ({ page }) => {
    const model = await fixture(page);
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    const request = page.getByRole("main", { name: "Application request", exact: true });
    await expect(request.getByRole("heading", { name: "Connect Example Runner?", exact: true, level: 1 })).toBeVisible();
    await expect(request).toContainText("Example Runner is asking to act as you through the Agent Access Broker. If you approve, it can use what you are already allowed to use, at the access level below, and nothing more.");
    await expect(request).toContainText("Read and write");
    await expect(request).toContainText("It can read and make changes, as you can.");
    await expect(request).toContainText("An administrator sets the access level; you cannot change it here.");
    await expect(request).toContainText("Alex Example · alex");
    // A focused page: no portal navigation, links, search or account menu, and no command palette.
    await expect(page.getByRole("navigation")).toHaveCount(0);
    await expect(page.getByRole("link")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Account", exact: true })).toHaveCount(0);
    await page.keyboard.press("Control+k");
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(request.getByRole("button")).toHaveText(["Approve", "Cancel", "Use a different account"]);
    await expect(page.getByText(REQUEST_ID)).toHaveCount(0);
    await request.getByRole("button", { name: "Approve", exact: true }).click();
    await expectReturnedToApplication(page, model, "approve");
    expect(model.decisions).toEqual([{ decision: "approve", csrf: "csrf-fixture" }]);
    expectNothingLeaked(model);
  });

  test("cancelling returns access_denied to the application", async ({ page }) => {
    const model = await fixture(page, (m) => { m.authorization = { ...m.authorization!, connect: "read_only", readOnly: true }; });
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    const request = page.getByRole("main", { name: "Application request", exact: true });
    await expect(request).toContainText("Read-only");
    await expect(request).toContainText("It can read what you can read, and cannot make changes.");
    await request.getByRole("button", { name: "Cancel", exact: true }).click();
    await expectReturnedToApplication(page, model, "cancel");
    expect(new URL(page.url()).searchParams.get("error")).toBe("access_denied");
    expect(model.decisions).toEqual([{ decision: "cancel", csrf: "csrf-fixture" }]);
    expectNothingLeaked(model);
  });

  for (const [reason, sentence] of [
    ["connecting_disabled", "Connecting this application is turned off on this broker."],
    ["access_disabled", "An administrator disabled your access for this application."],
    ["not_human", "Only a person’s account can connect an application, and this is a service account."],
    ["account_disabled", "Your broker account is disabled."]
  ] as const) {
    test(`a person who may not connect (${reason}) is told why and can only return to the application`, async ({ page }) => {
      const model = await fixture(page, (m) => { m.authorization = { ...m.authorization!, canConnect: false, denialReason: reason }; });
      await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
      const request = page.getByRole("main", { name: "Application request", exact: true });
      await expect(request.getByRole("heading", { name: "You can’t connect Example Runner", exact: true, level: 1 })).toBeVisible();
      await expect(request.getByText(sentence, { exact: true })).toBeVisible();
      await expect(request).toContainText("Alex Example · alex");
      await expect(request.getByRole("button")).toHaveText(["Return to Example Runner", "Use a different account"]);
      await request.getByRole("button", { name: "Return to Example Runner", exact: true }).click();
      await expectReturnedToApplication(page, model, "cancel");
      expect(model.decisions).toEqual([{ decision: "cancel", csrf: "csrf-fixture" }]);
      expectNothingLeaked(model);
    });
  }

  test("an unknown, answered or expired request is a plain error page that goes nowhere", async ({ page }) => {
    const model = await fixture(page, (m) => { m.authorization = null; });
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    const request = page.getByRole("main", { name: "Application request", exact: true });
    await expect(request.getByRole("heading", { name: "This request is no longer valid", exact: true, level: 1 })).toBeVisible();
    await expect(request).toContainText("It has expired, was already answered, or does not exist. Go back to the application and start again.");
    await expect(request.getByRole("button")).toHaveCount(0);
    await expect(page.getByRole("link")).toHaveCount(0);
    expect(new URL(page.url()).pathname).toBe(CONSENT_PATH);
    expect(model.decisions).toEqual([]);
    expect(model.callbacks).toEqual([]);
    // A path that cannot be a request is not asked about.
    await page.goto(`${assets.baseUrl}/ui/authorize/not-a-request`);
    await expect(request.getByRole("heading", { name: "This request is no longer valid", exact: true, level: 1 })).toBeVisible();
    expect(model.authorizationReads).toBe(1);
    expectNothingLeaked(model);
  });

  test("a request that expires before the answer becomes the plain error page", async ({ page }) => {
    const model = await fixture(page, (m) => { m.decide = () => invalid; });
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    const request = page.getByRole("main", { name: "Application request", exact: true });
    await request.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(request.getByRole("heading", { name: "This request is no longer valid", exact: true, level: 1 })).toBeVisible();
    await expect(request.getByRole("button")).toHaveCount(0);
    expect(model.callbacks).toEqual([]);
    expectNothingLeaked(model);
  });

  test("a request whose application or redirect address was removed is invalid for Approve and for Cancel", async ({ page }) => {
    // The Broker answers the decision without an address to return to.
    for (const [button, start] of [["Approve", null], ["Cancel", null], ["Return to Example Runner", "access_disabled"]] as const) {
      const model = await fixture(page, (m) => {
        m.decide = () => invalid;
        if (start) m.authorization = { ...m.authorization!, canConnect: false, denialReason: start };
      });
      await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
      const request = page.getByRole("main", { name: "Application request", exact: true });
      await request.getByRole("button", { name: button, exact: true }).click();
      await expect(request.getByRole("heading", { name: "This request is no longer valid", exact: true, level: 1 })).toBeVisible();
      await expect(request.getByRole("button")).toHaveCount(0);
      expect(new URL(page.url()).pathname).toBe(CONSENT_PATH);
      expect(model.callbacks).toEqual([]);
      expectNothingLeaked(model);
      await page.unrouteAll({ behavior: "wait" });
    }
  });

  test("a refused approval shows the reason and Cancel still returns to the application", async ({ page }) => {
    const model = await fixture(page, (m) => {
      m.decide = (decision) => decision === "approve"
        ? refusal(403, "application_access_denied", "application access denied", { denialReason: "access_disabled" })
        : ok({ decision, redirectTo: callbackUrl(decision) });
    });
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    const request = page.getByRole("main", { name: "Application request", exact: true });
    await request.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(request.getByRole("heading", { name: "You can’t connect Example Runner", exact: true, level: 1 })).toBeVisible();
    await expect(request.getByText("An administrator disabled your access for this application.", { exact: true })).toBeVisible();
    await expect(request.getByRole("button", { name: "Approve", exact: true })).toHaveCount(0);
    expect(model.callbacks).toEqual([]);
    await request.getByRole("button", { name: "Return to Example Runner", exact: true }).click();
    await expectReturnedToApplication(page, model, "cancel");
    expect(model.decisions.map((entry) => entry.decision)).toEqual(["approve", "cancel"]);
    expectNothingLeaked(model);
  });

  test("a second click cannot send a second answer", async ({ page }) => {
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    const model = await fixture(page, (m) => {
      m.decide = async (decision) => { await held; return ok({ decision, redirectTo: callbackUrl(decision) }); };
    });
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    const request = page.getByRole("main", { name: "Application request", exact: true });
    const approve = request.getByRole("button", { name: "Approve", exact: true });
    await approve.dblclick();
    await expect(approve).toHaveAttribute("aria-busy", "true");
    await expect(request.getByRole("button", { name: "Cancel", exact: true })).toBeDisabled();
    await expect(request.getByRole("button", { name: "Use a different account", exact: true })).toBeDisabled();
    await approve.click({ force: true });
    await approve.press("Enter");
    await request.getByRole("button", { name: "Cancel", exact: true }).click({ force: true });
    expect(model.decisions).toHaveLength(1);
    release();
    await expectReturnedToApplication(page, model, "approve");
    expect(model.decisions).toEqual([{ decision: "approve", csrf: "csrf-fixture" }]);
  });

  test("a failed answer can be tried again", async ({ page }) => {
    let failures = 1;
    const model = await fixture(page, (m) => {
      m.decide = (decision) => failures-- > 0 ? refusal(503, "audit_unavailable", "The audit log is unavailable") : ok({ decision, redirectTo: callbackUrl(decision) });
    });
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    const request = page.getByRole("main", { name: "Application request", exact: true });
    await request.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(request.getByRole("alert")).toHaveText("The audit log is unavailable (audit_unavailable)");
    expect(model.callbacks).toEqual([]);
    await request.getByRole("button", { name: "Approve", exact: true }).click();
    await expectReturnedToApplication(page, model, "approve");
    expect(model.decisions).toHaveLength(2);
  });

  test("local sign-in returns to the request", async ({ page }) => {
    const model = await fixture(page, (m) => { m.signedIn = false; });
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
    await expect(page.getByText("Sign in to review an application’s request to act as you.", { exact: true })).toBeVisible();
    // The request is not read before sign-in.
    expect(model.authorizationReads).toBe(0);
    await page.getByLabel("Principal", { exact: true }).fill("alex");
    await page.getByLabel("Password", { exact: true }).fill("synthetic-password");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Connect Example Runner?", exact: true })).toBeVisible();
    expect(new URL(page.url()).pathname).toBe(CONSENT_PATH);
    expect(model.logins).toEqual([{ principalId: "alex", password: "synthetic-password", returnTo: CONSENT_PATH }]);
    await page.getByRole("button", { name: "Approve", exact: true }).click();
    await expectReturnedToApplication(page, model, "approve");
  });

  test("Microsoft sign-in is started with the request as its return path", async ({ page }) => {
    const model = await fixture(page, (m) => { m.signedIn = false; });
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    await page.getByRole("button", { name: "Sign in with Microsoft", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Connect Example Runner?", exact: true })).toBeVisible();
    expect(new URL(page.url()).pathname).toBe(CONSENT_PATH);
    expect(model.logins).toEqual([{ microsoftReturnTo: CONSENT_PATH }]);
  });

  test("a session that ends on the page signs in again and comes back", async ({ page }) => {
    const model = await fixture(page);
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    await expect(page.getByRole("heading", { name: "Connect Example Runner?", exact: true })).toBeVisible();
    model.signedIn = false;
    await page.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
    expect(model.callbacks).toEqual([]);
    await page.getByLabel("Principal", { exact: true }).fill("alex");
    await page.getByLabel("Password", { exact: true }).fill("synthetic-password");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Connect Example Runner?", exact: true })).toBeVisible();
    expect(new URL(page.url()).pathname).toBe(CONSENT_PATH);
  });

  test("an account switched in another tab is shown before anything is sent", async ({ page }) => {
    const model = await fixture(page);
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    const request = page.getByRole("main", { name: "Application request", exact: true });
    await expect(request).toContainText("Alex Example · alex");
    // Another tab signs in as someone else: the cookie changes under this page.
    model.account = "sam";
    model.csrf = "csrf-sam";
    await request.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(request).toContainText("Sam Example · sam");
    await expect(request.getByRole("status")).toHaveText("You are now signed in as a different account than this page showed. Nothing was sent. Check “Signed in as” before you answer.");
    await expect(request).not.toContainText("Alex Example");
    expect(model.decisions).toEqual([]);
    expect(model.callbacks).toEqual([]);
    // Only a new, explicit answer on the page that names the new account is sent.
    await request.getByRole("button", { name: "Approve", exact: true }).click();
    await expectReturnedToApplication(page, model, "approve");
    expect(model.decisions).toEqual([{ decision: "approve", csrf: "csrf-sam" }]);
    expectNothingLeaked(model);
  });

  test("a decision refused for a changed session is never replayed for the other account", async ({ page }) => {
    const model = await fixture(page);
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    const request = page.getByRole("main", { name: "Application request", exact: true });
    await expect(request).toContainText("Alex Example · alex");
    // The cookie changes after the page checked the session and before the decision arrives.
    model.beforeDecision = () => { model.account = "sam"; model.csrf = "csrf-sam"; model.beforeDecision = null; };
    await request.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(request).toContainText("Sam Example · sam");
    await expect(request.getByRole("status")).toContainText("You are now signed in as a different account than this page showed. Nothing was sent.");
    // The one decision that was sent carried the first account's token and was refused; none followed.
    expect(model.decisions).toEqual([{ decision: "approve", csrf: "csrf-fixture" }]);
    expect(model.callbacks).toEqual([]);
    await expect(request.getByRole("button", { name: "Approve", exact: true })).toBeEnabled();
    await request.getByRole("button", { name: "Cancel", exact: true }).click();
    await expectReturnedToApplication(page, model, "cancel");
    expect(model.decisions).toEqual([{ decision: "approve", csrf: "csrf-fixture" }, { decision: "cancel", csrf: "csrf-sam" }]);
    expectNothingLeaked(model);
  });

  test("a rotated CSRF token asks the same account again instead of resending", async ({ page }) => {
    const model = await fixture(page);
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    const request = page.getByRole("main", { name: "Application request", exact: true });
    model.beforeDecision = () => { model.csrf = "csrf-rotated"; model.beforeDecision = null; };
    await request.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(request.getByRole("status")).toHaveText("Your sign-in was refreshed and nothing was sent. Check the request and choose again.");
    await expect(request).toContainText("Alex Example · alex");
    expect(model.decisions).toEqual([{ decision: "approve", csrf: "csrf-fixture" }]);
    expect(model.callbacks).toEqual([]);
    // The request was read again for the answer that follows.
    expect(model.authorizationReads).toBe(2);
    await request.getByRole("button", { name: "Approve", exact: true }).click();
    await expectReturnedToApplication(page, model, "approve");
    expect(model.decisions).toEqual([{ decision: "approve", csrf: "csrf-fixture" }, { decision: "approve", csrf: "csrf-rotated" }]);
  });

  test("a person on the wrong account can switch without leaving the request", async ({ page }) => {
    const model = await fixture(page);
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    await page.getByRole("button", { name: "Use a different account", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
    expect(new URL(page.url()).pathname).toBe(CONSENT_PATH);
    expect(model.decisions).toEqual([]);
    expect(model.callbacks).toEqual([]);
  });

  test("the page fits a phone and is usable from the keyboard", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    const model = await fixture(page);
    await page.goto(`${assets.baseUrl}${CONSENT_PATH}`);
    const request = page.getByRole("main", { name: "Application request", exact: true });
    await expect(request.getByRole("heading", { name: "Connect Example Runner?", exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    for (const name of ["Approve", "Cancel"]) {
      const box = await request.getByRole("button", { name, exact: true }).boundingBox();
      expect(box!.x).toBeGreaterThanOrEqual(0);
      expect(box!.x + box!.width).toBeLessThanOrEqual(390);
    }
    // Nothing is focused on arrival, so Enter cannot approve by accident.
    expect(await page.evaluate(() => document.activeElement === document.body)).toBe(true);
    await request.getByRole("button", { name: "Cancel", exact: true }).focus();
    await page.keyboard.press("Enter");
    await expectReturnedToApplication(page, model, "cancel");
  });
});

test.describe("personal Applications list", () => {
  test("an account without self-service lands on Account and can remove an application", async ({ page }) => {
    const model = await fixture(page, (m) => {
      m.access = [
        access({ lastUsedAt: "2026-11-03T00:00:00Z" }),
        access({ accessId: "access-notes", applicationId: "example-notes", applicationName: "Example Notes", connect: "read_only", effectiveReadOnly: true, enabled: false, liveTokenCount: 0 }),
        access({ accessId: "access-retired", applicationId: "retired-runner", applicationName: null, applicationAvailable: false, connect: null, liveTokenCount: 0 })
      ];
    });
    await page.goto(`${assets.baseUrl}/ui`);
    await expect(page).toHaveURL(/\/ui\/account$/);
    const section = page.getByRole("region", { name: "Applications", exact: true });
    await expect(section).toContainText("Applications you approved to act as you through the broker.");
    const table = section.getByRole("table", { name: "Applications", exact: true });
    await expect(table.getByRole("columnheader")).toHaveText(["Application", "Access level", "Status", "Last used", "Live tokens", "Actions"]);
    const runner = table.getByRole("row", { name: /^Example Runner/ });
    await expect(runner.getByRole("cell")).toContainText(["Read and write", "Connected"]);
    await expect(runner.getByRole("rowheader")).toContainText(/Connected [A-Z][a-z]+ \d+/);
    await expect(runner.getByRole("cell").nth(3)).toHaveText("2");
    await expect(table.getByRole("row", { name: /^Example Notes/ }).getByRole("cell")).toContainText(["Read-only", "Disabled by an administrator"]);
    await expect(table.getByRole("row", { name: /^Example Notes/ })).toContainText("Never");
    const retired = table.getByRole("row", { name: /^retired-runner/ });
    await expect(retired.getByRole("cell")).toContainText(["Not available", "Application unavailable"]);
    await expect(retired).not.toContainText("Read and write");
    await runner.getByRole("button", { name: "Remove Example Runner", exact: true }).click();
    const confirm = page.getByRole("alertdialog", { name: "Remove application?", exact: true });
    await expect(confirm).toContainText("Remove Example Runner? This ends its access at once: every token it holds for you stops working, and it must ask for your approval again before it can act as you.");
    await confirm.getByRole("button", { name: "Cancel", exact: true }).click();
    expect(model.writes).toEqual([]);
    await runner.getByRole("button", { name: "Remove Example Runner", exact: true }).click();
    await confirm.getByRole("button", { name: "Remove application", exact: true }).click();
    await expect(page.getByText("Example Runner removed", { exact: true })).toBeVisible();
    await expect(runner).toHaveCount(0);
    await expect(table.getByRole("row")).toHaveCount(3);
    expect(model.writes).toEqual([{ method: "DELETE", path: "/v1/applications/access/access-runner", query: "", body: null }]);
    // Removing does not lift an administrator's restriction, and the confirmation says so.
    await table.getByRole("row", { name: /^Example Notes/ }).getByRole("button", { name: "Remove Example Notes", exact: true }).click();
    await expect(confirm).toContainText("it must ask for your approval again before it can act as you. The restriction an administrator set stays in place if you connect it again.");
    await confirm.getByRole("button", { name: "Cancel", exact: true }).click();
    expect(model.errors).toEqual([]);
  });

  test("an application already disconnected elsewhere just leaves the list", async ({ page }) => {
    const model = await fixture(page, (m) => { m.access = [access()]; });
    await page.goto(`${assets.baseUrl}/ui/account`);
    const section = page.getByRole("region", { name: "Applications", exact: true });
    const runner = section.getByRole("row", { name: /^Example Runner/ });
    await expect(runner).toBeVisible();
    // The application revoked its own refresh token meanwhile.
    model.access = [];
    await page.route("**/v1/applications/access/access-runner", (route) => route.fulfill(refusal(404, "application_access_not_found", "application access was not found")));
    await runner.getByRole("button", { name: "Remove Example Runner", exact: true }).click();
    await page.getByRole("alertdialog", { name: "Remove application?", exact: true }).getByRole("button", { name: "Remove application", exact: true }).click();
    await expect(page.getByRole("alertdialog")).toHaveCount(0);
    await expect(section.getByRole("heading", { name: "No applications connected", exact: true })).toBeVisible();
    expect(model.errors).toEqual([]);
  });

  test("is shown empty while applications are registered and hidden when there is nothing to show", async ({ page }) => {
    const model = await fixture(page);
    await page.goto(`${assets.baseUrl}/ui/account`);
    const section = page.getByRole("region", { name: "Applications", exact: true });
    await expect(section.getByRole("heading", { name: "No applications connected", exact: true })).toBeVisible();
    await expect(section).toContainText("An application asks for your approval the first time it needs the broker.");
    await expect(section.getByRole("table")).toHaveCount(0);
    // No application registered and none approved: no section.
    model.registered = false;
    await page.reload();
    await expect(page.getByRole("region", { name: "Profile", exact: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "Appearance", exact: true })).toBeVisible();
    await expect(section).toHaveCount(0);
    // An approval whose application is no longer registered is still shown.
    model.access = [access({ applicationName: null, applicationAvailable: false, connect: null })];
    await page.reload();
    await expect(section.getByRole("row", { name: /^example-runner/ })).toContainText("Application unavailable");
    expect(model.errors).toEqual([]);
  });

  test("an account with self-service reaches it from Account settings", async ({ page }) => {
    await fixture(page, (m) => { m.selfServiceEnabled = true; m.access = [access()]; });
    await page.goto(`${assets.baseUrl}/ui/access`);
    await page.getByRole("button", { name: "Account", exact: true }).click();
    await page.getByRole("menuitem", { name: "Account settings", exact: true }).click();
    await expect(page.getByRole("region", { name: "Applications", exact: true }).getByRole("row", { name: /^Example Runner/ })).toBeVisible();
  });
});

test.describe("administrator access paths", () => {
  const rows = () => [
    access(),
    access({ accessId: "access-notes", applicationId: "example-notes", applicationName: "Example Notes", connect: "read_only", effectiveReadOnly: true, liveTokenCount: 1 }),
    // Disconnected by the person, kept because an administrator made it read-only.
    access({ accessId: "access-kept", applicationId: "example-reports", applicationName: "Example Reports", readOnly: true, effectiveReadOnly: true, connected: false, version: 4, liveTokenCount: 0 }),
    access({ accessId: "access-retired", applicationId: "retired-runner", applicationName: null, applicationAvailable: false, connect: null, liveTokenCount: 0 })
  ];

  test("each application is a row with Enabled, Read-only and Remove", async ({ page }) => {
    const model = await fixture(page, (m) => { m.role = "admin"; m.adminAccess = rows(); });
    await page.goto(`${assets.baseUrl}/ui/admin/principals/alex`);
    const identity = page.getByRole("region", { name: "Identity access", exact: true });
    await expect(identity).toContainText("An application the person approved obtains its own tokens for them. Its Read-only setting only narrows the application’s level, and changing a setting or removing the access ends the tokens it holds at once.");
    const paths = identity.getByRole("table", { name: "Access paths", exact: true });
    await expect(paths.getByRole("row")).toHaveCount(6);
    await expect(paths.getByRole("row").nth(1)).toHaveAccessibleName(/^Identity token/);
    const runner = paths.getByRole("row", { name: /^Example Runner/ });
    await expect(runner).toContainText("Application · Level: read and write · 2 live tokens");
    await expect(runner).toContainText("Connected");
    const enabled = runner.getByRole("switch", { name: "Application Example Runner enabled", exact: true });
    const readOnly = runner.getByRole("switch", { name: "Application Example Runner read-only", exact: true });
    await expect(enabled).toBeChecked();
    await expect(readOnly).not.toBeChecked();
    await readOnly.click();
    await expect(readOnly).toBeChecked();
    await expect(page.getByText("Application access updated", { exact: true }).first()).toBeVisible();
    await expect(runner).toContainText("0 live tokens");
    await enabled.click();
    await expect(enabled).not.toBeChecked();
    await expect(runner).toContainText("Disabled by an administrator");
    // The application's level is read-only: the row's own setting cannot widen it, so it is not a control.
    const notes = paths.getByRole("row", { name: /^Example Notes/ });
    await expect(notes).toContainText("Application · Level: read-only · 1 live token");
    await expect(notes).toContainText("Fixed by the application’s level");
    await expect(notes.getByRole("switch")).toHaveCount(1);
    await expect(notes.getByRole("switch", { name: "Application Example Notes enabled", exact: true })).toBeChecked();
    // A disconnected row kept for its restriction: its settings stay editable.
    const kept = paths.getByRole("row", { name: /^Example Reports/ });
    await expect(kept).toContainText("Not connected");
    await expect(kept).toContainText("0 live tokens");
    await expect(kept.getByRole("switch", { name: "Application Example Reports enabled", exact: true })).toBeChecked();
    await expect(kept.getByRole("switch", { name: "Application Example Reports read-only", exact: true })).toBeChecked();
    const retired = paths.getByRole("row", { name: /^retired-runner/ });
    await expect(retired).toContainText("Application unavailable");
    await expect(retired).toContainText("Application · Level: not available · 0 live tokens");
    await expect(retired.getByRole("switch")).toHaveCount(2);
    // Removing a connected application says its access ends at once.
    await runner.getByRole("button", { name: "Remove application Example Runner", exact: true }).click();
    const confirm = page.getByRole("alertdialog", { name: "Remove application access?", exact: true });
    await expect(confirm).toContainText("Remove Example Runner for this person? This ends its access at once: every token it holds for them stops working. They can connect it again later.");
    await confirm.getByRole("button", { name: "Remove access", exact: true }).click();
    await expect(runner).toHaveCount(0);
    // Removing a disconnected row clears the kept restriction.
    await kept.getByRole("button", { name: "Remove application Example Reports", exact: true }).click();
    await expect(confirm).toContainText("Remove Example Reports for this person? It is not connected; this clears the settings kept for it, so a later connection starts afresh.");
    await confirm.getByRole("button", { name: "Remove access", exact: true }).click();
    await expect(kept).toHaveCount(0);
    await expect(paths.getByRole("row")).toHaveCount(4);
    expect(model.writes).toEqual([
      { method: "PATCH", path: "/v1/admin/principals/alex/application-access/access-runner", query: "", body: { readOnly: true, expectedVersion: 1 } },
      { method: "PATCH", path: "/v1/admin/principals/alex/application-access/access-runner", query: "", body: { enabled: false, expectedVersion: 2 } },
      { method: "DELETE", path: "/v1/admin/principals/alex/application-access/access-runner", query: "?expectedVersion=3", body: null },
      { method: "DELETE", path: "/v1/admin/principals/alex/application-access/access-kept", query: "?expectedVersion=4", body: null }
    ]);
    expect(model.errors).toEqual([]);
  });

  test("a stale version refreshes the row and asks for a fresh change or removal", async ({ page }) => {
    const model = await fixture(page, (m) => { m.role = "admin"; m.adminAccess = [access()]; m.adminConflict = true; });
    await page.goto(`${assets.baseUrl}/ui/admin/principals/alex`);
    const identity = page.getByRole("region", { name: "Identity access", exact: true });
    const runner = identity.getByRole("table", { name: "Access paths", exact: true }).getByRole("row", { name: /^Example Runner/ });
    const enabled = runner.getByRole("switch", { name: "Application Example Runner enabled", exact: true });
    const readOnly = runner.getByRole("switch", { name: "Application Example Runner read-only", exact: true });
    await enabled.click();
    const conflict = identity.getByText("Application access changed. Review the refreshed state before trying again.", { exact: true });
    await expect(conflict).toBeVisible();
    // Nothing is replayed: the row shows the other administrator's change and the new version.
    await expect(enabled).toBeChecked();
    await expect(readOnly).toBeChecked();
    await expect(runner).toContainText(/Connected\s*2\s*Remove$/);
    expect(model.writes).toHaveLength(1);
    await enabled.click();
    await expect(enabled).not.toBeChecked();
    await expect(conflict).toHaveCount(0);
    // A stale removal closes its confirmation; removing takes a fresh one.
    model.adminConflict = true;
    await runner.getByRole("button", { name: "Remove application Example Runner", exact: true }).click();
    const confirm = page.getByRole("alertdialog", { name: "Remove application access?", exact: true });
    await confirm.getByRole("button", { name: "Remove access", exact: true }).click();
    await expect(page.getByRole("alertdialog")).toHaveCount(0);
    await expect(conflict).toBeVisible();
    await expect(runner).toHaveCount(1);
    await runner.getByRole("button", { name: "Remove application Example Runner", exact: true }).click();
    await confirm.getByRole("button", { name: "Remove access", exact: true }).click();
    await expect(runner).toHaveCount(0);
    expect(model.writes).toEqual([
      { method: "PATCH", path: "/v1/admin/principals/alex/application-access/access-runner", query: "", body: { enabled: false, expectedVersion: 1 } },
      { method: "PATCH", path: "/v1/admin/principals/alex/application-access/access-runner", query: "", body: { enabled: false, expectedVersion: 2 } },
      { method: "DELETE", path: "/v1/admin/principals/alex/application-access/access-runner", query: "?expectedVersion=3", body: null },
      { method: "DELETE", path: "/v1/admin/principals/alex/application-access/access-runner", query: "?expectedVersion=4", body: null }
    ]);
    expect(model.errors).toEqual([]);
  });

  test("an auditor reads the rows without controls", async ({ page }) => {
    const model = await fixture(page, (m) => { m.role = "auditor"; m.adminAccess = rows().map((row, index) => index === 0 ? { ...row, enabled: false } : row); });
    await page.goto(`${assets.baseUrl}/ui/admin/principals/alex`);
    const paths = page.getByRole("region", { name: "Identity access", exact: true }).getByRole("table", { name: "Access paths", exact: true });
    await expect(paths.getByRole("row")).toHaveCount(6);
    await expect(paths.getByRole("switch")).toHaveCount(0);
    await expect(paths.getByRole("button")).toHaveCount(0);
    const runner = paths.getByRole("row", { name: /^Example Runner/ });
    await expect(runner.getByRole("cell")).toHaveText(["Disabled by an administrator", "Disabled", "Full access", "1", ""]);
    await expect(paths.getByRole("row", { name: /^Example Notes/ }).getByRole("cell")).toHaveText(["Connected", "Enabled", /^Read-only\s*Fixed by the application’s level$/, "1", ""]);
    await expect(paths.getByRole("row", { name: /^Example Reports/ }).getByRole("cell")).toHaveText(["Not connected", "Enabled", "Read-only", "4", ""]);
    expect(model.writes).toEqual([]);
    expect(model.errors).toEqual([]);
  });
});

test.describe("configuration reload", () => {
  async function reload(page: Page) {
    await page.getByRole("button", { name: "Reload config", exact: true }).click();
    await page.getByRole("alertdialog", { name: "Reload broker configuration?", exact: true }).getByRole("button", { name: "Reload config", exact: true }).click();
  }

  test("reports the application tokens it ended, and a failed token step", async ({ page }) => {
    const model = await fixture(page, (m) => { m.role = "admin"; m.reloadTokens = { status: "reconciled", applications: [] }; });
    await page.goto(`${assets.baseUrl}/ui/admin/system`);
    await reload(page);
    await expect(page.getByText("Config reloaded · generation 2", { exact: true })).toBeVisible();
    model.reloadTokens = { status: "reconciled", applications: [
      { applicationId: "example-runner", reason: "registration_narrowed", revokedTokens: 3 },
      { applicationId: "retired-runner", reason: "registration_removed", revokedTokens: 1 }
    ] };
    await reload(page);
    await expect(page.getByText("Config reloaded · generation 2. Ended application tokens: example-runner 3 (registration narrowed), retired-runner 1 (no longer registered)", { exact: true })).toBeVisible();
    // The configuration is active even when the token step failed; the notice says so and what happens next.
    model.reloadTokens = { status: "failed" };
    await reload(page);
    await expect(page.getByText("Config reloaded · generation 2. Application tokens the new configuration no longer allows were not ended; the next reload or restart tries again.", { exact: true })).toBeVisible();
    expect(model.errors).toEqual([]);
  });
});
