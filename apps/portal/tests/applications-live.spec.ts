// Real Broker + SQLite acceptance of application access in the portal: no API
// routing. Only the application's own redirect address is answered by the
// test, standing in for the client application. The application's side of
// the OAuth flow (authorization request, code exchange, refresh) is driven
// over HTTP with its client secret. The last test rewrites the Broker's
// configuration file and reloads it from the System page.
import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { once } from "node:events";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { ApplicationAccess } from "../src/types";
import { brokerBinary, portalDist, repoRoot } from "./support/binaries";
import { startBroker } from "./support/broker-process";
import { releaseTestRoot } from "./support/test-root";

test.describe.configure({ mode: "serial" });

const ADMIN_PASSWORD = "admin-password";
const ADMIN_UPDATED = "admin-password-updated";
const USER = "alex";
const USER_PASSWORD = "alex-password-value";
const RUNNER = { id: "example-runner", name: "Example Runner", callback: "https://runner.example.test/auth/broker/callback" };
const NOTES = { id: "example-notes", name: "Example Notes", callback: "https://notes.example.test/auth/broker/callback" };
type Application = typeof RUNNER;

let broker: ChildProcessWithoutNullStreams | undefined;
let root = "";
let baseUrl = "";
const logs: string[] = [];
const secrets = new Map<string, string>();
/** The person's and the administrator's browsers, kept signed in across the tests. */
let person: BrowserContext;
let administrator: BrowserContext;
/** What the first application holds after the person approved it. */
let runnerRefreshToken = "";
/** The person's access for the first application, which later approvals reuse. */
let runnerAccessId = "";

test.beforeAll(async ({ browser }) => {
  await fs.access(path.join(portalDist, "index.html"));
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-applications-"));
  for (const [index, name] of ["encryption", "hash", "csrf", "pepper"].entries()) {
    await fs.writeFile(path.join(root, name), Buffer.alloc(32, index + 1).toString("base64url"));
  }
  for (const application of [RUNNER, NOTES]) {
    secrets.set(application.id, `client-${randomBytes(24).toString("hex")}`);
    await fs.writeFile(path.join(root, `${application.id}-secret`), secrets.get(application.id)!);
  }
  const configure = async (_port: number, url: string) => {
    baseUrl = url;
    return writeConfig({ runnerCallback: RUNNER.callback, runnerConnect: "read_write" });
  };
  ({ child: broker } = await startBroker({
    binary: brokerBinary,
    configure,
    cwd: repoRoot,
    env: { ...process.env, RUST_LOG: "agent_access_broker=warn,agent_access_core=warn" },
    readinessHeaders: () => ({ "X-Agent-Access-Request-Id": randomUUID() }),
    timeoutMs: 60_000,
    onOutput: (text) => logs.push(text)
  }));
  administrator = await newContext(browser);
  person = await newContext(browser);
  // The administrator creates a person whose self-service is off.
  const page = await administrator.newPage();
  await signInAsAdmin(page);
  await page.goto(`${baseUrl}/ui/admin/principals`);
  await manage(page, "/v1/admin/principals", { method: "POST", body: { principalId: USER, kind: "user", displayName: "Alex Example" } });
  await manage(page, `/v1/admin/principals/${USER}/login-methods/local-password/enable`, { method: "POST", body: { password: USER_PASSWORD, mustChangePassword: false, acknowledgeSeparateSignIn: true } });
  await manage(page, `/v1/admin/principals/${USER}/access`, { method: "PATCH", body: { selfServiceEnabled: false } });
  await page.close();
});

test.afterEach(async ({}, testInfo) => {
  if (testInfo.status !== testInfo.expectedStatus) {
    await testInfo.attach("broker.log", { body: logs.join(""), contentType: "text/plain" });
  }
});

test.afterAll(async ({}, testInfo) => {
  await person?.close();
  await administrator?.close();
  if (broker && broker.exitCode === null) {
    const exited = once(broker, "exit");
    broker.kill("SIGTERM");
    const timer = setTimeout(() => broker?.kill("SIGKILL"), 5000);
    await exited;
    clearTimeout(timer);
  }
  await releaseTestRoot(root, testInfo, logs.join(""));
});

/** Writes the Broker's configuration with the given registration of the first application and returns its path. */
async function writeConfig(runner: { runnerCallback: string; runnerConnect: "read_write" | "read_only" }) {
  const quoted = (relative: string) => JSON.stringify(path.join(root, relative));
  const file = path.join(root, "broker.toml");
  await fs.writeFile(file, `
[deployment]
environment = "development"
[identity]
mode = "required"
authority = "managed"
[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"
[managed_store]
type = "sqlite"
path = ${quoted("store.sqlite")}
auto_migrate = true
[execution_context]
allowed_values = ["default"]
default_context = "default"
[credential_encryption]
active_key = "k1"
[[credential_encryption.keys]]
id = "k1"
provider = "file"
path = ${quoted("encryption")}
[broker_tokens]
hash_key_ref = "file:${root}/hash"
[browser_auth]
enabled = true
public_origin = "${baseUrl}"
csrf_key_ref = "file:${root}/csrf"
[browser_auth.local_password]
enabled = true
pepper_ref = "file:${root}/pepper"
[portal]
enabled = true
mount_path = "/ui"
static_dir = ${JSON.stringify(portalDist)}
[management]
enabled = true
[management.initial_admin]
mode = "create_if_empty"
principal_id = "admin"
initial_password = "${ADMIN_PASSWORD}"
[applications.${RUNNER.id}]
display_name = "${RUNNER.name}"
client_secret_ref = "file:${root}/${RUNNER.id}-secret"
redirect_uris = ["${runner.runnerCallback}"]
connect = "${runner.runnerConnect}"
allowed_execution_contexts = ["default"]
access_token_ttl = "1h"
[applications.${NOTES.id}]
display_name = "${NOTES.name}"
client_secret_ref = "file:${root}/${NOTES.id}-secret"
redirect_uris = ["${NOTES.callback}"]
connect = "read_only"
allowed_execution_contexts = ["default"]
access_token_ttl = "1h"
[policy]
authority = "managed"
default_decision = "deny"
[audit]
type = "sqlite"
path = ${quoted("audit.sqlite")}
[limits]
upload_spool_dir = ${quoted("spool")}
`);
  return file;
}

/** A browser whose only non-Broker destination is the applications' redirect addresses. */
async function newContext(browser: Browser) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  await context.route(/^https:\/\/(runner|notes)\.example\.test\//, (route) =>
    route.fulfill({ contentType: "text/html", body: "<!doctype html><title>Application</title><h1>Back in the application</h1>" }));
  return context;
}

async function signIn(page: Page, principalId: string, password: string) {
  const response = await page.request.post(`${baseUrl}/v1/auth/local/login`, {
    headers: { Origin: baseUrl, "X-Agent-Access-Request-Id": randomUUID() },
    data: { principalId, password, returnTo: "/ui" }
  });
  const body = await response.json();
  return response.ok() && body.ok ? (body.result as { passwordChangeRequired?: boolean; csrfHeader: string; csrfToken: string }) : null;
}

async function signInAsAdmin(page: Page) {
  const session = await signIn(page, "admin", ADMIN_PASSWORD);
  expect(session?.passwordChangeRequired).toBe(true);
  const change = await page.request.post(`${baseUrl}/v1/auth/local/password/change`, {
    headers: { Origin: baseUrl, "X-Agent-Access-Request-Id": randomUUID(), [session!.csrfHeader]: session!.csrfToken },
    data: { currentPassword: ADMIN_PASSWORD, newPassword: ADMIN_UPDATED }
  });
  expect(change.ok()).toBe(true);
}

/** A management call from the signed-in browser session (same origin, CSRF header). */
async function manage<T>(page: Page, apiPath: string, init: { method?: string; body?: unknown } = {}) {
  return page.evaluate(
    async ({ apiPath, init }) => {
      const session = await (await fetch("/v1/auth/session", { credentials: "same-origin" })).json();
      const headers: Record<string, string> = { Accept: "application/json", "X-Agent-Access-Request-Id": crypto.randomUUID() };
      if (init.body !== undefined) headers["Content-Type"] = "application/json";
      headers[session.result.csrfHeader] = session.result.csrfToken;
      const response = await fetch(apiPath, { method: init.method ?? "GET", credentials: "same-origin", headers, body: init.body === undefined ? undefined : JSON.stringify(init.body) });
      const envelope = await response.json();
      if (!response.ok || !envelope.ok) throw new Error(envelope.error?.message ?? `Management request failed: ${apiPath}`);
      return envelope.result;
    },
    { apiPath, init }
  ) as Promise<T>;
}

/** What the application keeps for one authorization request. */
type Attempt = { application: Application; state: string; verifier: string; url: string };

/** The authorization request an application sends the person's browser with. */
function authorizationRequest(application: Application): Attempt {
  const verifier = randomBytes(32).toString("base64url");
  const state = `state-${randomBytes(8).toString("hex")}`;
  const query = new URLSearchParams({
    response_type: "code",
    client_id: application.id,
    redirect_uri: application.callback,
    state,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256"
  });
  return { application, state, verifier, url: `${baseUrl}/v1/applications/authorize?${query}` };
}

/** The application's token endpoint call, authenticated with its client secret. */
async function tokenRequest(application: Application, form: Record<string, string>) {
  const response = await fetch(`${baseUrl}/v1/applications/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${Buffer.from(`${application.id}:${secrets.get(application.id)}`).toString("base64")}`,
      "Content-Type": "application/x-www-form-urlencoded",
      "X-Agent-Access-Request-Id": randomUUID()
    },
    body: new URLSearchParams(form)
  });
  return { status: response.status, body: await response.json() as Record<string, unknown> };
}

/** Waits for the top-level navigation that carries a decision back to the application. */
async function returnedTo(page: Page, attempt: Attempt, act: () => Promise<void>) {
  const arrival = page.waitForRequest((request) => request.url().startsWith(attempt.application.callback));
  await act();
  const request = await arrival;
  expect(request.method()).toBe("GET");
  expect(request.isNavigationRequest()).toBe(true);
  expect(request.resourceType()).toBe("document");
  expect(request.frame()).toBe(page.mainFrame());
  await expect(page.getByRole("heading", { name: "Back in the application", exact: true })).toBeVisible();
  const outcome = new URL(page.url());
  expect(`${outcome.origin}${outcome.pathname}`).toBe(attempt.application.callback);
  expect(outcome.searchParams.get("state")).toBe(attempt.state);
  return outcome.searchParams;
}

function consent(page: Page) {
  return page.getByRole("main", { name: "Application request", exact: true });
}

function applicationsSection(page: Page) {
  return page.getByRole("region", { name: "Applications", exact: true });
}

function accessPaths(page: Page) {
  return page.getByRole("region", { name: "Identity access", exact: true }).getByRole("table", { name: "Access paths", exact: true });
}

/** The application's whole connection: request, the person's approval in `page`, and the code exchange. */
async function connect(page: Page, application: Application) {
  const attempt = authorizationRequest(application);
  await page.goto(attempt.url);
  const approve = consent(page).getByRole("button", { name: "Approve", exact: true });
  const outcome = await returnedTo(page, attempt, () => approve.click());
  const exchange = await tokenRequest(application, { grant_type: "authorization_code", code: outcome.get("code")!, redirect_uri: application.callback, code_verifier: attempt.verifier });
  expect(exchange.status).toBe(200);
  return exchange.body;
}

/** The person's stored access for one application, as the administrator reads it. */
async function storedAccess(page: Page, application: Application) {
  const { access } = await manage<{ access: ApplicationAccess[] }>(page, `/v1/admin/principals/${USER}/application-access`);
  return access.find((item) => item.applicationId === application.id);
}

/** Removes an application from the person's own list; the confirmation mentions an administrator's restriction only when there is one. */
async function removeOwn(page: Page, name: string, restricted: boolean) {
  await page.goto(`${baseUrl}/ui/account`);
  const row = applicationsSection(page).getByRole("row", { name: new RegExp(`^${name}`) });
  await row.getByRole("button", { name: `Remove ${name}`, exact: true }).click();
  const confirm = page.getByRole("alertdialog", { name: "Remove application?", exact: true });
  await expect(confirm).toContainText("This ends its access at once");
  await expect(confirm.getByText("The restriction an administrator set stays in place if you connect it again.", { exact: false })).toHaveCount(restricted ? 1 : 0);
  await confirm.getByRole("button", { name: "Remove application", exact: true }).click();
  await expect(row).toHaveCount(0);
}

function guardPage(page: Page) {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error" && /Content Security Policy|Refused to (apply|load|execute)/i.test(message.text())) problems.push(message.text());
  });
  return problems;
}

test("a person without self-service signs in from the request, approves, and sees the application once it has connected", async () => {
  const page = await person.newPage();
  const problems = guardPage(page);
  const attempt = authorizationRequest(RUNNER);
  // The application sends the browser to the Broker, which hands the request to the portal.
  await page.goto(attempt.url);
  await expect(page).toHaveURL(/\/ui\/authorize\/[A-Za-z0-9_-]{43}$/);
  const consentUrl = page.url();
  await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
  await expect(page.getByText("Sign in to review an application’s request to act as you.", { exact: true })).toBeVisible();
  await page.getByLabel("Principal", { exact: true }).fill(USER);
  await page.getByLabel("Password", { exact: true }).fill(USER_PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  // Sign-in returns to the same request.
  await expect(consent(page).getByRole("heading", { name: "Connect Example Runner?", exact: true })).toBeVisible();
  expect(page.url()).toBe(consentUrl);
  await expect(consent(page)).toContainText("Read and write");
  await expect(consent(page)).toContainText("Alex Example · alex");
  await expect(page.getByRole("navigation")).toHaveCount(0);
  await expect(page.getByRole("link")).toHaveCount(0);
  const approve = consent(page).getByRole("button", { name: "Approve", exact: true });
  const outcome = await returnedTo(page, attempt, () => approve.dblclick());
  expect(outcome.get("error")).toBeNull();
  const code = outcome.get("code");
  expect(code).toBeTruthy();
  // The answered request is a plain error page.
  await page.goto(consentUrl);
  await expect(consent(page).getByRole("heading", { name: "This request is no longer valid", exact: true })).toBeVisible();
  await expect(consent(page).getByRole("button")).toHaveCount(0);
  // An approval alone connects nothing: without self-service the portal home is Account, and it lists no application yet.
  await page.goto(`${baseUrl}/ui`);
  await expect(page).toHaveURL(/\/ui\/account$/);
  await expect(page.getByText("Self-service is disabled for your account.", { exact: true })).toBeVisible();
  await expect(applicationsSection(page).getByRole("heading", { name: "No applications connected", exact: true })).toBeVisible();
  // The application exchanges the code; the person never holds the token.
  const exchange = await tokenRequest(RUNNER, { grant_type: "authorization_code", code: code!, redirect_uri: RUNNER.callback, code_verifier: attempt.verifier });
  expect(exchange.status).toBe(200);
  expect(exchange.body).toMatchObject({ token_type: "Bearer", principal_id: USER, principal_name: "Alex Example", read_only: false });
  runnerRefreshToken = String(exchange.body.refresh_token);
  await page.reload();
  const row = applicationsSection(page).getByRole("row", { name: /^Example Runner/ });
  await expect(row.getByRole("cell")).toContainText(["Read and write", "Connected"]);
  await expect(row.getByRole("cell").nth(3)).toHaveText("1");
  expect(problems).toEqual([]);
  await page.close();
});

test("cancelling returns access_denied and creates no access", async () => {
  const page = await person.newPage();
  const attempt = authorizationRequest(NOTES);
  await page.goto(attempt.url);
  // Already signed in: the request opens directly, at the application's read-only level.
  await expect(consent(page).getByRole("heading", { name: "Connect Example Notes?", exact: true })).toBeVisible();
  await expect(consent(page)).toContainText("Read-only");
  await expect(consent(page)).toContainText("It can read what you can read, and cannot make changes.");
  const cancel = consent(page).getByRole("button", { name: "Cancel", exact: true });
  const outcome = await returnedTo(page, attempt, () => cancel.click());
  expect(outcome.get("error")).toBe("access_denied");
  expect(outcome.get("code")).toBeNull();
  await page.goto(`${baseUrl}/ui/account`);
  await expect(applicationsSection(page).getByRole("row", { name: /^Example Runner/ })).toBeVisible();
  await expect(applicationsSection(page).getByRole("row", { name: /^Example Notes/ })).toHaveCount(0);
  await page.close();
});

test("an administrator narrows and disables the access from the person's Access paths", async () => {
  const page = await administrator.newPage();
  const problems = guardPage(page);
  await page.goto(`${baseUrl}/ui/admin/principals/${USER}`);
  const row = accessPaths(page).getByRole("row", { name: /^Example Runner/ });
  await expect(row).toContainText("Application · Level: read and write · 1 live token");
  await expect(row).toContainText("Connected");
  const enabled = row.getByRole("switch", { name: "Application Example Runner enabled", exact: true });
  const readOnly = row.getByRole("switch", { name: "Application Example Runner read-only", exact: true });
  await expect(enabled).toBeChecked();
  await expect(readOnly).not.toBeChecked();
  // Read-only narrows the application's level and ends the tokens it holds.
  await readOnly.click();
  await expect(readOnly).toBeChecked();
  await expect(row).toContainText("0 live tokens");
  const narrowed = await tokenRequest(RUNNER, { grant_type: "refresh_token", refresh_token: runnerRefreshToken });
  expect(narrowed.status).toBe(200);
  expect(narrowed.body).toMatchObject({ principal_id: USER, read_only: true });
  // Disabled stops the application for this person.
  await enabled.click();
  await expect(enabled).not.toBeChecked();
  await expect(row).toContainText("Disabled by an administrator");
  const refused = await tokenRequest(RUNNER, { grant_type: "refresh_token", refresh_token: runnerRefreshToken });
  expect(refused).toEqual({ status: 400, body: { error: "invalid_grant" } });
  const stored = await storedAccess(page, RUNNER);
  expect(stored).toMatchObject({ enabled: false, readOnly: true, effectiveReadOnly: true, connected: true, version: 3, liveTokenCount: 0 });
  runnerAccessId = stored!.accessId;
  expect(problems).toEqual([]);
  await page.close();
});

test("a person whose access is disabled is told why and can only return to the application", async () => {
  const page = await person.newPage();
  const attempt = authorizationRequest(RUNNER);
  await page.goto(attempt.url);
  await expect(consent(page).getByRole("heading", { name: "You can’t connect Example Runner", exact: true })).toBeVisible();
  await expect(consent(page).getByText("An administrator disabled your access for this application.", { exact: true })).toBeVisible();
  await expect(consent(page).getByRole("button")).toHaveText(["Return to Example Runner", "Use a different account"]);
  const back = consent(page).getByRole("button", { name: "Return to Example Runner", exact: true });
  const outcome = await returnedTo(page, attempt, () => back.click());
  expect(outcome.get("error")).toBe("access_denied");
  await page.close();
});

test("a read-only restriction survives the person's Remove and is reused by the next approval", async () => {
  const admin = await administrator.newPage();
  await admin.goto(`${baseUrl}/ui/admin/principals/${USER}`);
  const adminRow = accessPaths(admin).getByRole("row", { name: /^Example Runner/ });
  const enabled = adminRow.getByRole("switch", { name: "Application Example Runner enabled", exact: true });
  const readOnly = adminRow.getByRole("switch", { name: "Application Example Runner read-only", exact: true });
  // Enabled again, still read-only.
  await enabled.click();
  await expect(enabled).toBeChecked();
  await expect(adminRow).toContainText("Connected");
  // The person sees the narrowed level and removes the application.
  const page = await person.newPage();
  await page.goto(`${baseUrl}/ui/account`);
  await expect(applicationsSection(page).getByRole("row", { name: /^Example Runner/ }).getByRole("cell")).toContainText(["Read-only", "Connected"]);
  await removeOwn(page, "Example Runner", true);
  await expect(applicationsSection(page).getByRole("heading", { name: "No applications connected", exact: true })).toBeVisible();
  expect(await tokenRequest(RUNNER, { grant_type: "refresh_token", refresh_token: runnerRefreshToken })).toEqual({ status: 400, body: { error: "invalid_grant" } });
  // The administrator still has the row, not connected, with its settings and version.
  await admin.reload();
  await expect(adminRow).toContainText("Not connected");
  await expect(adminRow).toContainText("Application · Level: read and write · 0 live tokens");
  await expect(enabled).toBeChecked();
  await expect(readOnly).toBeChecked();
  expect(await storedAccess(admin, RUNNER)).toMatchObject({ accessId: runnerAccessId, enabled: true, readOnly: true, connected: false, version: 4 });
  // Approving again offers the restricted level, and connects only when the application redeems the code.
  const attempt = authorizationRequest(RUNNER);
  await page.goto(attempt.url);
  await expect(consent(page).getByRole("heading", { name: "Connect Example Runner?", exact: true })).toBeVisible();
  await expect(consent(page)).toContainText("Read-only");
  await expect(consent(page)).toContainText("It can read what you can read, and cannot make changes.");
  const approve = consent(page).getByRole("button", { name: "Approve", exact: true });
  const outcome = await returnedTo(page, attempt, () => approve.click());
  await page.goto(`${baseUrl}/ui/account`);
  await expect(applicationsSection(page).getByRole("heading", { name: "No applications connected", exact: true })).toBeVisible();
  expect(await storedAccess(admin, RUNNER)).toMatchObject({ accessId: runnerAccessId, connected: false });
  const exchange = await tokenRequest(RUNNER, { grant_type: "authorization_code", code: outcome.get("code")!, redirect_uri: RUNNER.callback, code_verifier: attempt.verifier });
  expect(exchange.status).toBe(200);
  expect(exchange.body).toMatchObject({ principal_id: USER, read_only: true });
  runnerRefreshToken = String(exchange.body.refresh_token);
  await page.reload();
  await expect(applicationsSection(page).getByRole("row", { name: /^Example Runner/ }).getByRole("cell")).toContainText(["Read-only", "Connected"]);
  // The same row, connected again, with the same settings and version.
  await admin.reload();
  await expect(adminRow).toContainText("Connected");
  await expect(adminRow).toContainText("1 live token");
  await expect(readOnly).toBeChecked();
  expect(await storedAccess(admin, RUNNER)).toMatchObject({ accessId: runnerAccessId, enabled: true, readOnly: true, connected: true, version: 4 });
  await page.close();
  await admin.close();
});

test("a disabled access stays disabled after the person's Remove until an administrator removes it", async () => {
  const admin = await administrator.newPage();
  await admin.goto(`${baseUrl}/ui/admin/principals/${USER}`);
  const adminRow = accessPaths(admin).getByRole("row", { name: /^Example Runner/ });
  const enabled = adminRow.getByRole("switch", { name: "Application Example Runner enabled", exact: true });
  await enabled.click();
  await expect(enabled).not.toBeChecked();
  await expect(adminRow).toContainText("Disabled by an administrator");
  // The person can still remove it from their list, which does not lift the restriction.
  const page = await person.newPage();
  await page.goto(`${baseUrl}/ui/account`);
  await expect(applicationsSection(page).getByRole("row", { name: /^Example Runner/ })).toContainText("Disabled by an administrator");
  await removeOwn(page, "Example Runner", true);
  await admin.reload();
  await expect(adminRow).toContainText("Not connected");
  await expect(enabled).not.toBeChecked();
  await expect(adminRow.getByRole("switch", { name: "Application Example Runner read-only", exact: true })).toBeChecked();
  expect(await storedAccess(admin, RUNNER)).toMatchObject({ accessId: runnerAccessId, enabled: false, readOnly: true, connected: false, version: 5 });
  // Connecting is still refused.
  const refused = authorizationRequest(RUNNER);
  await page.goto(refused.url);
  await expect(consent(page).getByRole("heading", { name: "You can’t connect Example Runner", exact: true })).toBeVisible();
  await expect(consent(page).getByText("An administrator disabled your access for this application.", { exact: true })).toBeVisible();
  const back = consent(page).getByRole("button", { name: "Return to Example Runner", exact: true });
  expect((await returnedTo(page, refused, () => back.click())).get("error")).toBe("access_denied");
  // Only the administrator's Remove clears the restriction.
  await adminRow.getByRole("button", { name: "Remove application Example Runner", exact: true }).click();
  const confirm = admin.getByRole("alertdialog", { name: "Remove application access?", exact: true });
  await expect(confirm).toContainText("It is not connected; this clears the settings kept for it, so a later connection starts afresh.");
  await confirm.getByRole("button", { name: "Remove access", exact: true }).click();
  await expect(adminRow).toHaveCount(0);
  // The person connects afresh, unrestricted, as a new access.
  const attempt = authorizationRequest(RUNNER);
  await page.goto(attempt.url);
  await expect(consent(page).getByRole("heading", { name: "Connect Example Runner?", exact: true })).toBeVisible();
  await expect(consent(page)).toContainText("Read and write");
  const approve = consent(page).getByRole("button", { name: "Approve", exact: true });
  const outcome = await returnedTo(page, attempt, () => approve.click());
  const exchange = await tokenRequest(RUNNER, { grant_type: "authorization_code", code: outcome.get("code")!, redirect_uri: RUNNER.callback, code_verifier: attempt.verifier });
  expect(exchange.body).toMatchObject({ principal_id: USER, read_only: false });
  runnerRefreshToken = String(exchange.body.refresh_token);
  const fresh = await storedAccess(admin, RUNNER);
  expect(fresh).toMatchObject({ enabled: true, readOnly: false, connected: true, version: 1 });
  expect(fresh!.accessId).not.toBe(runnerAccessId);
  await page.close();
  await admin.close();
});

test("an application whose level is read-only is shown as fixed, and removing an unrestricted access deletes it", async () => {
  const page = await person.newPage();
  const exchange = await connect(page, NOTES);
  expect(exchange).toMatchObject({ principal_id: USER, read_only: true });
  // The administrator sees the level as fixed, not as a setting.
  const admin = await administrator.newPage();
  await admin.goto(`${baseUrl}/ui/admin/principals/${USER}`);
  const notes = accessPaths(admin).getByRole("row", { name: /^Example Notes/ });
  await expect(notes).toContainText("Application · Level: read-only · 1 live token");
  await expect(notes).toContainText("Fixed by the application’s level");
  await expect(notes.getByRole("switch")).toHaveCount(1);
  // The person removes it; nothing restricted it, so the confirmation says no more and the row is gone for everyone.
  await page.goto(`${baseUrl}/ui/account`);
  await expect(applicationsSection(page).getByRole("row", { name: /^Example Notes/ }).getByRole("cell")).toContainText(["Read-only", "Connected"]);
  await removeOwn(page, "Example Notes", false);
  await expect(applicationsSection(page).getByRole("row", { name: /^Example Runner/ })).toBeVisible();
  expect(await tokenRequest(NOTES, { grant_type: "refresh_token", refresh_token: String(exchange.refresh_token) })).toEqual({ status: 400, body: { error: "invalid_grant" } });
  await admin.reload();
  await expect(accessPaths(admin).getByRole("row", { name: /^Example Runner/ })).toBeVisible();
  await expect(notes).toHaveCount(0);
  await page.close();
  await admin.close();
});

test("an auditor reads a person's application access without controls", async ({ browser }) => {
  const admin = await administrator.newPage();
  await admin.goto(`${baseUrl}/ui/admin/principals`);
  await manage(admin, "/v1/admin/principals", { method: "POST", body: { principalId: "sam", kind: "user", displayName: "Sam Example" } });
  await manage(admin, "/v1/admin/principals/sam/login-methods/local-password/enable", { method: "POST", body: { password: USER_PASSWORD, mustChangePassword: false, acknowledgeSeparateSignIn: true } });
  await manage(admin, "/v1/admin/principals/sam/access", { method: "PATCH", body: { role: "auditor" } });
  await admin.close();
  const context = await newContext(browser);
  const auditor = await context.newPage();
  expect(await signIn(auditor, "sam", USER_PASSWORD)).not.toBeNull();
  await auditor.goto(`${baseUrl}/ui/admin/principals/${USER}`);
  const row = accessPaths(auditor).getByRole("row", { name: /^Example Runner/ });
  await expect(row).toContainText("Application · Level: read and write · 1 live token");
  await expect(row.getByRole("cell")).toHaveText(["Connected", "Enabled", "Full access", "1", ""]);
  await expect(accessPaths(auditor).getByRole("switch")).toHaveCount(0);
  await expect(accessPaths(auditor).getByRole("button")).toHaveCount(0);
  await context.close();
});

test("a reload that narrows the registration ends its tokens, and a request for a removed redirect address is invalid", async () => {
  // Two requests are waiting for the person's answer when the operator changes the registration.
  const approving = await person.newPage();
  await approving.goto(authorizationRequest(RUNNER).url);
  await expect(consent(approving).getByRole("heading", { name: "Connect Example Runner?", exact: true })).toBeVisible();
  const cancelling = await person.newPage();
  await cancelling.goto(authorizationRequest(RUNNER).url);
  await expect(consent(cancelling).getByRole("heading", { name: "Connect Example Runner?", exact: true })).toBeVisible();
  const visited: string[] = [];
  for (const page of [approving, cancelling]) page.on("request", (request) => { if (request.url().startsWith("https://")) visited.push(request.url()); });
  // The level becomes read-only and the redirect address is replaced.
  await writeConfig({ runnerCallback: "https://runner.example.test/auth/broker/moved", runnerConnect: "read_only" });
  const admin = await administrator.newPage();
  const problems = guardPage(admin);
  await admin.goto(`${baseUrl}/ui/admin/system`);
  await admin.getByRole("button", { name: "Reload config", exact: true }).click();
  await admin.getByRole("alertdialog", { name: "Reload broker configuration?", exact: true }).getByRole("button", { name: "Reload config", exact: true }).click();
  // The reload reports the write-capable token it ended.
  await expect(admin.getByText("Config reloaded · generation 2. Ended application tokens: example-runner 1 (registration narrowed)", { exact: true })).toBeVisible();
  await expect(admin.getByRole("region", { name: "Last reload", exact: true })).toContainText("Applied");
  // Neither answer returns the browser to the address the operator removed.
  await consent(approving).getByRole("button", { name: "Approve", exact: true }).click();
  await expect(consent(approving).getByRole("heading", { name: "This request is no longer valid", exact: true })).toBeVisible();
  await consent(cancelling).getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(consent(cancelling).getByRole("heading", { name: "This request is no longer valid", exact: true })).toBeVisible();
  await expect(consent(cancelling).getByRole("button")).toHaveCount(0);
  await cancelling.reload();
  await expect(consent(cancelling).getByRole("heading", { name: "This request is no longer valid", exact: true })).toBeVisible();
  expect(visited).toEqual([]);
  // The access stays connected with no live token, at the new fixed level; its refresh token now mints read-only tokens.
  await admin.goto(`${baseUrl}/ui/admin/principals/${USER}`);
  const row = accessPaths(admin).getByRole("row", { name: /^Example Runner/ });
  await expect(row).toContainText("Application · Level: read-only · 0 live tokens");
  await expect(row).toContainText("Connected");
  await expect(row).toContainText("Fixed by the application’s level");
  const refreshed = await tokenRequest(RUNNER, { grant_type: "refresh_token", refresh_token: runnerRefreshToken });
  expect(refreshed.status).toBe(200);
  expect(refreshed.body).toMatchObject({ principal_id: USER, read_only: true });
  expect(problems).toEqual([]);
  await approving.close();
  await cancelling.close();
  await admin.close();
});
