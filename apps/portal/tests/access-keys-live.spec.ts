// Real Broker + SQLite acceptance of access keys in the portal: no API
// routing. A person issues, lists and revokes their own key; an administrator
// changes the person's access key type setting, which changes what the person
// may issue, and issues keys for the person and for a service account. The
// person's username is derived from their email by the Broker itself. An
// account without a username shows the Broker's reason and offers no issuing.
import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AccessKeyView } from "../src/types";
import { brokerBinary, portalDist, repoRoot } from "./support/binaries";
import { startBroker } from "./support/broker-process";
import { releaseTestRoot } from "./support/test-root";

test.describe.configure({ mode: "serial" });

const ADMIN_PASSWORD = "admin-password";
const ADMIN_UPDATED = "admin-password-updated";
const PERSON = "usr-alice";
const PERSON_PASSWORD = "alice-password-value";
const SERVICE = "svc-build-runner";

let broker: ChildProcessWithoutNullStreams | undefined;
let root = "";
let baseUrl = "";
const logs: string[] = [];
let person: BrowserContext;
let administrator: BrowserContext;

test.beforeAll(async ({ browser }) => {
  await fs.access(path.join(portalDist, "index.html"));
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-access-keys-"));
  for (const [index, name] of ["encryption", "hash", "csrf", "pepper"].entries()) {
    await fs.writeFile(path.join(root, name), Buffer.alloc(32, index + 1).toString("base64url"));
  }
  ({ child: broker } = await startBroker({
    binary: brokerBinary,
    configure: async (_port, url) => {
      baseUrl = url;
      return writeConfig();
    },
    cwd: repoRoot,
    env: { ...process.env, RUST_LOG: "agent_access_broker=warn,agent_access_core=warn" },
    readinessHeaders: () => ({ "X-Agent-Access-Request-Id": randomUUID() }),
    timeoutMs: 60_000,
    onOutput: (text) => logs.push(text)
  }));
  administrator = await newContext(browser);
  person = await newContext(browser);
  // The administrator creates a group that allows Model inference, a person in
  // it whose email gives the username "alice", and a service account allowed
  // Package downloads, which people cannot issue themselves.
  const page = await administrator.newPage();
  await signInAsAdmin(page);
  await page.goto(`${baseUrl}/ui/admin/principals`);
  await manage(page, "/v1/admin/groups", { method: "POST", body: { groupId: "ml-team", displayName: "ML team", accessKeyTypes: { allow: ["inference"] } } });
  await manage(page, "/v1/admin/principals", { method: "POST", body: { principalId: PERSON, kind: "user", displayName: "Alice Example", email: "alice@example.com" } });
  await manage(page, `/v1/admin/principals/${PERSON}/login-methods/local-password/enable`, { method: "POST", body: { password: PERSON_PASSWORD, mustChangePassword: false, acknowledgeSeparateSignIn: true } });
  await manage(page, `/v1/admin/principals/${PERSON}/groups/ml-team`, { method: "PUT" });
  await manage(page, "/v1/admin/principals", { method: "POST", body: { principalId: SERVICE, kind: "service_account", displayName: "Build runner" } });
  await manage(page, `/v1/admin/principals/${SERVICE}/access`, { method: "PATCH", body: { accessKeyTypes: { allow: ["package-downloads"], deny: [] } } });
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

async function writeConfig() {
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
[access_key_types.inference]
display_name = "Model inference"
description = "Call the hosted models through the gateway."
lifetime_options = ["1d", "7d", "14d", "30d", "never"]
default_lifetime = "7d"
self_service = true
[access_key_types.web-search]
display_name = "Web search"
lifetime_options = ["1d", "7d", "14d"]
default_lifetime = "7d"
self_service = true
[access_key_types.package-downloads]
display_name = "Package downloads"
lifetime_options = ["1d", "7d", "never"]
default_lifetime = "7d"
[usernames]
email_domains = ["example.com"]
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

async function newContext(browser: Browser) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: baseUrl });
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

const editor = (page: Page) => page.getByRole("main", { name: "Issue access key", exact: true });
const issueButton = (page: Page) => editor(page).getByRole("region", { name: "Issue access key", exact: true }).getByRole("button", { name: "Issue access key", exact: true });
const keyRow = (page: Page, name: string) => page.getByRole("row").filter({ has: page.getByRole("cell", { name, exact: true }).or(page.getByRole("rowheader", { name, exact: true })) });

/** Issues a key on the open issue page and returns the secret the dialog shows once. */
async function issueFromForm(page: Page, name: string, types: string[], lifetime?: string) {
  for (const type of types) await editor(page).getByRole("checkbox", { name: type }).check();
  await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill(name);
  if (lifetime) await editor(page).getByRole("combobox", { name: "Lifetime", exact: true }).selectOption(lifetime);
  await issueButton(page).click();
  const dialog = page.getByRole("dialog", { name: "Access key created" });
  await expect(dialog).toContainText("It cannot be shown again after you close this dialog.");
  if (lifetime === "never") await expect(dialog).toContainText("ExpiresNever");
  const secret = (await dialog.getByLabel("Access key", { exact: true }).textContent()) ?? "";
  expect(secret).toMatch(/^aab_ak_[A-Za-z0-9_-]{43}$/);
  await dialog.getByRole("button", { name: "Done", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  // Once dismissed, the key is nowhere on the page.
  await expect(page.getByText(secret)).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.outerHTML)).not.toContain(secret);
  return secret;
}

test("a person issues an access key from Keys, sees it once, finds it listed and revokes it", async () => {
  const page = await person.newPage();
  await signIn(page, PERSON, PERSON_PASSWORD);
  await page.goto(`${baseUrl}/ui/access`);
  const nav = page.getByRole("navigation", { name: "My access", exact: true });
  await nav.getByRole("link", { name: "Keys", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Access keys", level: 1 })).toBeVisible();
  // The page header's button; the empty list offers the same link.
  await page.getByRole("link", { name: "Issue access key", exact: true }).first().click();
  // The one type the person may issue is offered, and not chosen for them.
  await expect(editor(page).getByRole("checkbox")).toHaveCount(1);
  await expect(editor(page).getByRole("checkbox", { name: "Model inference" })).not.toBeChecked();
  await expect(editor(page).getByRole("complementary", { name: "Access key summary" })).toContainText("alice");
  await expect(issueButton(page)).toBeDisabled();
  const secret = await issueFromForm(page, "laptop-models", ["Model inference"]);
  await expect(page.getByText(secret)).toHaveCount(0);
  await expect(keyRow(page, "laptop-models")).toContainText("Model inference");
  await expect(keyRow(page, "laptop-models").getByText("Active", { exact: true })).toBeAttached();
  await keyRow(page, "laptop-models").getByRole("button", { name: "Revoke laptop-models" }).click();
  await page.getByRole("button", { name: "Revoke access key", exact: true }).click();
  await expect(keyRow(page, "laptop-models")).toContainText("Revoked");
  const keys = await manage<{ keys: AccessKeyView[] }>(page, "/v1/access-keys?includeRevoked=true");
  expect(keys.keys.map((key) => [key.name, key.status, key.origin])).toEqual([["laptop-models", "revoked", "portal"]]);
  await page.close();
});

test("the administrator's per-type setting changes what the person may issue", async () => {
  const admin = await administrator.newPage();
  await admin.goto(`${baseUrl}/ui/admin/principals/${PERSON}`);
  const username = admin.getByRole("region", { name: "Username", exact: true });
  await expect(username).toContainText("Working");
  await expect(username).toContainText("Given by the saved email, alice@example.com.");
  const table = admin.getByRole("table", { name: "Access key types" });
  await expect(table.getByRole("row", { name: /Model inference/ })).toContainText("Allowed · from group ml-team");
  await expect(table.getByRole("row", { name: /Web search/ })).toContainText("Not allowed");
  await table.getByRole("combobox", { name: "Web search setting" }).selectOption("allow");
  await table.getByRole("combobox", { name: "Model inference setting" }).selectOption("deny");
  await admin.getByRole("button", { name: "Save access", exact: true }).click();
  await admin.getByRole("button", { name: "Update access", exact: true }).click();
  await expect(table.getByRole("row", { name: /Web search/ })).toContainText("Allowed · set on this account");
  await expect(table.getByRole("row", { name: /Model inference/ })).toContainText("Denied · set on this account");
  await admin.close();

  const page = await person.newPage();
  await page.goto(`${baseUrl}/ui/keys/new`);
  await expect(editor(page).getByRole("checkbox")).toHaveCount(1);
  await expect(editor(page).getByRole("checkbox", { name: "Web search" })).not.toBeChecked();
  await expect(editor(page).getByRole("checkbox", { name: "Model inference" })).toHaveCount(0);
  await expect(editor(page).getByRole("combobox", { name: "Lifetime", exact: true })).toBeDisabled();
  await editor(page).getByRole("checkbox", { name: "Web search" }).check();
  await expect(editor(page).getByRole("combobox", { name: "Lifetime", exact: true }).locator("option")).toHaveText(["1 day", "7 days", "14 days"]);
  await page.close();
});

test("an administrator issues keys for the person and for a service account from their Keys tabs", async () => {
  const admin = await administrator.newPage();
  await admin.goto(`${baseUrl}/ui/admin/principals/${PERSON}/keys`);
  // The person may hold Package downloads only once the administrator allows it.
  await manage(admin, `/v1/admin/principals/${PERSON}/access`, { method: "PATCH", body: { accessKeyTypes: { allow: ["package-downloads", "web-search"], deny: ["inference"] } } });
  await admin.goto(`${baseUrl}/ui/admin/principals/${PERSON}/keys`);
  await expect(keyRow(admin, "laptop-models")).toHaveCount(0);
  await admin.getByRole("radio", { name: /All/ }).or(admin.getByRole("button", { name: /^All/ })).click();
  await expect(keyRow(admin, "laptop-models")).toContainText("Revoked");
  await admin.getByRole("link", { name: "Issue access key", exact: true }).click();
  await expect(editor(admin)).toContainText("People cannot issue it themselves.");
  await expect(editor(admin)).toContainText("Not offered, because Alice Example is not allowed them: Model inference.");
  await issueFromForm(admin, "ci-cache", ["Package downloads"]);
  await expect(keyRow(admin, "ci-cache")).toContainText("Package downloads");
  await expect(keyRow(admin, "ci-cache")).toContainText("admin");

  await admin.goto(`${baseUrl}/ui/admin/principals/${SERVICE}/keys`);
  await admin.getByRole("link", { name: "Issue access key", exact: true }).click();
  await expect(editor(admin)).toContainText(`For ${SERVICE}`);
  await expect(editor(admin)).toContainText(`services will know it as ${SERVICE}.`);
  await issueFromForm(admin, "nightly-packages", ["Package downloads"]);
  await expect(keyRow(admin, "nightly-packages")).toContainText("Package downloads");
  await admin.close();

  // The person finds the administrator's key in their own list.
  const page = await person.newPage();
  await page.goto(`${baseUrl}/ui/keys`);
  await expect(keyRow(page, "ci-cache")).toContainText("Package downloads");
  await page.close();
});

test("an email change tells the administrator what happened to the username and the keys", async () => {
  const admin = await administrator.newPage();
  await admin.goto(`${baseUrl}/ui/admin/principals/${PERSON}`);
  await admin.getByRole("textbox", { name: "Email" }).fill("alice.example@example.com");
  await admin.getByRole("button", { name: "Save profile", exact: true }).click();
  const dialog = admin.getByRole("alertdialog").or(admin.getByRole("dialog"));
  await expect(dialog).toContainText("may change it. If it changes, their 1 active access key stops working");
  await dialog.getByRole("button", { name: "Save email", exact: true }).click();
  // The result is reported where the email was saved.
  await expect(admin.getByRole("region", { name: "Profile", exact: true })).toContainText("The username changed from alice to alice.example. 1 access key ended.");
  await admin.goto(`${baseUrl}/ui/admin/principals/${PERSON}/keys`);
  await expect(keyRow(admin, "ci-cache")).toContainText("Username changed");
  await admin.close();
});

test("an administrator is told why no key of an account can work, and is offered issuing once it is fixed", async () => {
  // Erin's email is in a domain the configuration does not list, so the
  // Broker gives her no username and no key of hers can work.
  const erin = "usr-erin";
  const reason = "This account has no username. Set one on the Overview tab first.";
  const admin = await administrator.newPage();
  await admin.goto(`${baseUrl}/ui/admin/principals`);
  await manage(admin, "/v1/admin/principals", { method: "POST", body: { principalId: erin, kind: "user", displayName: "Erin Sample", email: "erin@example.org" } });
  await manage(admin, `/v1/admin/principals/${erin}/groups/ml-team`, { method: "PUT" });
  expect((await manage<{ accessKeyProblem: unknown }>(admin, `/v1/admin/principals/${erin}`)).accessKeyProblem).toBe("no_account_username");
  await admin.goto(`${baseUrl}/ui/admin/principals/${erin}/keys`);
  await expect(admin.getByText(reason, { exact: true })).toBeVisible();
  await expect(admin.getByRole("link", { name: "Issue access key", exact: true })).toHaveCount(0);
  await expect(admin.getByRole("button", { name: "Issue access key", exact: true })).toHaveCount(0);
  await admin.goto(`${baseUrl}/ui/admin/principals/${erin}/keys/new`);
  await expect(editor(admin).getByText(reason, { exact: true })).toBeVisible();
  await expect(editor(admin).getByRole("checkbox")).toHaveCount(0);
  // A name set by hand removes the cause.
  await manage(admin, `/v1/admin/principals/${erin}/account-username`, { method: "PUT", body: { mode: "manual", accountUsername: "erin" } });
  expect((await manage<{ accessKeyProblem: unknown }>(admin, `/v1/admin/principals/${erin}`)).accessKeyProblem).toBeNull();
  await admin.goto(`${baseUrl}/ui/admin/principals/${erin}/keys`);
  await expect(admin.getByText(reason, { exact: true })).toHaveCount(0);
  await admin.getByRole("link", { name: "Issue access key", exact: true }).click();
  await expect(editor(admin).getByRole("checkbox", { name: "Model inference" })).not.toBeChecked();
  await admin.close();
});


test("personal and administrator forms issue non-expiring keys that the real Broker lists as active", async () => {
  const admin = await administrator.newPage();
  await admin.goto(`${baseUrl}/ui/admin/principals/${PERSON}`);
  await manage(admin, `/v1/admin/principals/${PERSON}/access`, { method: "PATCH", body: { accessKeyTypes: { allow: ["inference", "web-search", "package-downloads"], deny: [] } } });
  const page = await person.newPage();
  await signIn(page, PERSON, PERSON_PASSWORD);
  await page.goto(`${baseUrl}/ui/keys/new`);
  await issueFromForm(page, "continuous-models", ["Model inference"], "never");
  const personal = (await manage<{ keys: AccessKeyView[] }>(page, "/v1/access-keys")).keys.find((key) => key.name === "continuous-models");
  expect(personal).toMatchObject({ status: "active", expiresAt: null, usableAccessKeyTypes: [{ name: "inference", validUntil: null }] });
  await expect(keyRow(page, "continuous-models").getByRole("cell", { name: "Never", exact: true })).toHaveCount(2);
  await expect(page.getByRole("complementary", { name: "Access key continuous-models" })).toContainText("ExpiresNever");
  await page.close();

  await admin.goto(`${baseUrl}/ui/admin/principals/${SERVICE}/keys/new`);
  await issueFromForm(admin, "continuous-packages", ["Package downloads"], "never");
  const administrative = (await manage<{ keys: AccessKeyView[] }>(admin, `/v1/admin/access-keys?principal=${SERVICE}`)).keys.find((key) => key.name === "continuous-packages");
  expect(administrative).toMatchObject({ status: "active", expiresAt: null, usableAccessKeyTypes: [{ name: "package-downloads", validUntil: null }] });
  await expect(keyRow(admin, "continuous-packages").getByRole("cell", { name: "Never", exact: true })).toHaveCount(2);
  await expect(admin.getByRole("complementary", { name: "Access key continuous-packages" })).toContainText("ExpiresNever");
  await admin.close();
});
