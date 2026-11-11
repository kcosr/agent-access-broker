// Real Broker + SQLite acceptance of application access in the portal: no API
// routing. Only the application's own redirect address is answered by the
// test, standing in for the client application. The application's side of
// the OAuth flow (authorization request, code exchange, refresh) is driven
// over HTTP with its client secret.
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
/** What the application holds after the person approved it. */
let runnerRefreshToken = "";

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
  const quoted = (relative: string) => JSON.stringify(path.join(root, relative));
  const configure = async (_port: number, url: string) => {
    baseUrl = url;
    await fs.writeFile(path.join(root, "broker.toml"), `
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
redirect_uris = ["${RUNNER.callback}"]
connect = "read_write"
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
    return path.join(root, "broker.toml");
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

function guardPage(page: Page) {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error" && /Content Security Policy|Refused to (apply|load|execute)/i.test(message.text())) problems.push(message.text());
  });
  return problems;
}

test("a person without self-service signs in from the request, approves, and sees the application under Account", async () => {
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
  // The application exchanges the code; the person never holds the token.
  const exchange = await tokenRequest(RUNNER, { grant_type: "authorization_code", code: code!, redirect_uri: RUNNER.callback, code_verifier: attempt.verifier });
  expect(exchange.status).toBe(200);
  expect(exchange.body).toMatchObject({ token_type: "Bearer", principal_id: USER, principal_name: "Alex Example", read_only: false });
  runnerRefreshToken = String(exchange.body.refresh_token);
  // The answered request is a plain error page.
  await page.goto(consentUrl);
  await expect(consent(page).getByRole("heading", { name: "This request is no longer valid", exact: true })).toBeVisible();
  await expect(consent(page).getByRole("button")).toHaveCount(0);
  // Without self-service the portal home is Account, which lists the application.
  await page.goto(`${baseUrl}/ui`);
  await expect(page).toHaveURL(/\/ui\/account$/);
  await expect(page.getByText("Self-service is disabled for your account.", { exact: true })).toBeVisible();
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
  const [stored] = await manage<{ access: ApplicationAccess[] }>(page, `/v1/admin/principals/${USER}/application-access`).then((result) => result.access);
  expect(stored).toMatchObject({ applicationId: RUNNER.id, enabled: false, readOnly: true, effectiveReadOnly: true, version: 3, liveTokenCount: 0 });
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

test("an administrator removes the access, and the person connects and removes another application", async () => {
  const admin = await administrator.newPage();
  await admin.goto(`${baseUrl}/ui/admin/principals/${USER}`);
  const runner = accessPaths(admin).getByRole("row", { name: /^Example Runner/ });
  await runner.getByRole("button", { name: "Remove application Example Runner", exact: true }).click();
  await admin.getByRole("alertdialog", { name: "Remove application access?", exact: true }).getByRole("button", { name: "Remove access", exact: true }).click();
  await expect(runner).toHaveCount(0);
  // With no approval left the person's section stays, empty, while applications are registered.
  const page = await person.newPage();
  await page.goto(`${baseUrl}/ui/account`);
  await expect(applicationsSection(page).getByRole("heading", { name: "No applications connected", exact: true })).toBeVisible();
  // An application whose level is read-only.
  const attempt = authorizationRequest(NOTES);
  await page.goto(attempt.url);
  const approve = consent(page).getByRole("button", { name: "Approve", exact: true });
  const outcome = await returnedTo(page, attempt, () => approve.click());
  const exchange = await tokenRequest(NOTES, { grant_type: "authorization_code", code: outcome.get("code")!, redirect_uri: NOTES.callback, code_verifier: attempt.verifier });
  expect(exchange.status).toBe(200);
  expect(exchange.body).toMatchObject({ principal_id: USER, read_only: true });
  // The administrator sees the level as fixed, not as a setting.
  await admin.reload();
  const notes = accessPaths(admin).getByRole("row", { name: /^Example Notes/ });
  await expect(notes).toContainText("Application · Level: read-only · 1 live token");
  await expect(notes).toContainText("Fixed by the application’s level");
  await expect(notes.getByRole("switch")).toHaveCount(1);
  await admin.close();
  // The person removes it; the application's refresh token stops working at once.
  await page.goto(`${baseUrl}/ui/account`);
  const row = applicationsSection(page).getByRole("row", { name: /^Example Notes/ });
  await expect(row.getByRole("cell")).toContainText(["Read-only", "Connected"]);
  await row.getByRole("button", { name: "Remove Example Notes", exact: true }).click();
  const confirm = page.getByRole("alertdialog", { name: "Remove application?", exact: true });
  await expect(confirm).toContainText("This ends its access at once");
  await confirm.getByRole("button", { name: "Remove application", exact: true }).click();
  await expect(row).toHaveCount(0);
  await expect(applicationsSection(page).getByRole("heading", { name: "No applications connected", exact: true })).toBeVisible();
  const refused = await tokenRequest(NOTES, { grant_type: "refresh_token", refresh_token: String(exchange.body.refresh_token) });
  expect(refused).toEqual({ status: 400, body: { error: "invalid_grant" } });
  await page.close();
});

test("an auditor reads a person's application access without controls", async ({ browser }) => {
  // Reconnect so there is a row to read, then give a second person the auditor role.
  const page = await person.newPage();
  const attempt = authorizationRequest(RUNNER);
  await page.goto(attempt.url);
  const approve = consent(page).getByRole("button", { name: "Approve", exact: true });
  await returnedTo(page, attempt, () => approve.click());
  await page.close();
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
  await expect(row).toContainText("Application · Level: read and write");
  await expect(row.getByRole("cell").nth(1)).toHaveText("Enabled");
  await expect(row.getByRole("cell").nth(2)).toHaveText("Full access");
  await expect(accessPaths(auditor).getByRole("switch")).toHaveCount(0);
  await expect(accessPaths(auditor).getByRole("button")).toHaveCount(0);
  await context.close();
});
