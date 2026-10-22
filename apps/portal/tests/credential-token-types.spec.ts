// Token types against a real Broker and store: a Git gateway connection
// accepting two token types of different kinds. A user chooses a type for a
// first save, replaces the token with the other type, sees it become a Not
// used row when the configuration stops accepting its type and active again,
// without re-entry, when the type is accepted again; an administrator chooses
// a service account's type. The mocked browser contract is in
// credentials.spec.ts.
import { test, expect, type Browser, type Locator, type Page } from "@playwright/test";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { promises as fs } from "node:fs";
import { once } from "node:events";
import os from "node:os";
import path from "node:path";
import { brokerBinary, portalDist, repoRoot } from "./support/binaries";
import { startBroker } from "./support/broker-process";
import { releaseTestRoot } from "./support/test-root";

test.use({ actionTimeout: 15_000 });

let broker: ChildProcessWithoutNullStreams | undefined;
let root = "";
let baseUrl = "";
const logs: string[] = [];
let requestCounter = 0;
const ADMIN_PASSWORD = "admin-password";
const ADMIN_UPDATED = "admin-password-updated";
const USER = "casey";
const USER_PASSWORD = "casey-password";
const BOT = "build-bot";
const BOTH = ["git-bearer-token", "git-basic-api-token"];

/** Writes the Broker configuration, with the token types the Git connection accepts from people. */
async function writeConfig(userTokenProfiles: string[]) {
  const quoted = (relative: string) => JSON.stringify(path.join(root, relative));
  const configPath = path.join(root, "broker.toml");
  await fs.writeFile(
    configPath,
    `
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
[credentials.connections.gitlab_git]
display_name = "GitLab Git"
user_token_profiles = ${JSON.stringify(userTokenProfiles)}
service_account_token_profiles = ${JSON.stringify(BOTH)}
[credentials.per_user.gitlab_git]
type = "connection"
connection = "gitlab_git"
[gateways.gitlab_git]
kind = "git_http"
display_name = "GitLab Git"
broker_hosts = ["git.local.test"]
upstream_base_url = "https://gitlab.example.invalid"
allowed_upstream_hosts = ["https://gitlab.example.invalid/**"]
auth_modes = ["basic_broker_token"]
credential_modes = ["per_user"]
[gateways.gitlab_git.git]
allow_fetch = true
allow_push = false
[policy]
authority = "managed"
default_decision = "deny"
[limits]
upload_spool_dir = ${quoted("spool")}
[audit]
type = "jsonl"
path = ${quoted("audit.jsonl")}
`
  );
  return configPath;
}

test.beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-token-types-"));
  for (const [index, name] of ["encryption", "hash", "csrf", "pepper"].entries()) {
    await fs.writeFile(path.join(root, name), Buffer.alloc(32, index + 21).toString("base64url"));
  }
  ({ child: broker } = await startBroker({
    binary: brokerBinary,
    configure: async (_port, url) => {
      baseUrl = url;
      return writeConfig(BOTH);
    },
    cwd: repoRoot,
    env: { ...process.env, RUST_LOG: "agent_access_broker=warn,agent_access_core=warn" },
    readinessHeaders: () => ({ "X-Agent-Access-Request-Id": "token-types-health" }),
    timeoutMs: 60_000,
    onOutput: (text) => logs.push(text)
  }));
});

test.afterAll(async ({}, testInfo) => {
  if (broker && broker.exitCode === null) {
    const stopped = once(broker, "exit");
    broker.kill("SIGTERM");
    const timer = setTimeout(() => broker?.kill("SIGKILL"), 5000);
    await stopped;
    clearTimeout(timer);
  }
  await releaseTestRoot(root, testInfo, logs.join(""));
});

async function signIn(page: Page, principalId: string, password: string) {
  const response = await page.request.post(`${baseUrl}/v1/auth/local/login`, {
    headers: { Origin: baseUrl, "X-Agent-Access-Request-Id": `token-types-login-${++requestCounter}` },
    data: { principalId, password, returnTo: "/ui" }
  });
  const body = await response.json();
  return response.ok() && body.ok ? (body.result as { passwordChangeRequired?: boolean; csrfHeader: string; csrfToken: string }) : null;
}

/** A page signed in as the administrator, in its own browser context. */
async function adminPage(browser: Browser) {
  const page = await (await browser.newContext()).newPage();
  const session = await signIn(page, "admin", ADMIN_PASSWORD);
  expect(session?.passwordChangeRequired).toBe(true);
  const change = await page.request.post(`${baseUrl}/v1/auth/local/password/change`, {
    headers: { Origin: baseUrl, "X-Agent-Access-Request-Id": `token-types-password-${++requestCounter}`, [session!.csrfHeader]: session!.csrfToken },
    data: { currentPassword: ADMIN_PASSWORD, newPassword: ADMIN_UPDATED }
  });
  expect(change.ok()).toBe(true);
  await page.context().clearCookies();
  expect(await signIn(page, "admin", ADMIN_UPDATED)).not.toBeNull();
  await page.goto(`${baseUrl}/ui`);
  return page;
}

/** A management call from the page's browser session (same origin, CSRF header). */
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

type StoredCredential = { credentialId: string; profile: string; label: string | null; credentialKind: string };
type CredentialList = { connections: Array<{ connection: string; credential: StoredCredential | null }>; retained: Array<StoredCredential & { service: string; name: string }> };

/** The Git connection's stored token in a credential list. */
function gitToken(list: CredentialList) {
  return list.connections.find((connection) => connection.connection === "gitlab_git")?.credential ?? null;
}

/** A DataTable row by its row header (the primary cell's link). */
function tableRow(scope: Page | Locator, name: string) {
  const page = "page" in scope && typeof scope.page === "function" ? scope.page() : (scope as Page);
  return scope.getByRole("row").filter({ has: page.getByRole("rowheader", { name, exact: true }) });
}

/** Reloads the configuration with the token types the Git connection accepts from people. */
async function acceptFromPeople(admin: Page, profiles: string[]) {
  await writeConfig(profiles);
  await manage(admin, "/v1/admin/config/reload", { method: "POST" });
}

test("people and administrators choose among a connection's token types, and an unaccepted type's token is kept but not used", async ({ browser, page }) => {
  const admin = await adminPage(browser);
  await manage(admin, "/v1/admin/principals", { method: "POST", body: { principalId: USER, kind: "user", displayName: "Casey" } });
  await manage(admin, `/v1/admin/principals/${USER}/login-methods/local-password/enable`, { method: "POST", body: { password: USER_PASSWORD, mustChangePassword: false, acknowledgeSeparateSignIn: true } });
  await manage(admin, "/v1/admin/principals", { method: "POST", body: { principalId: BOT, kind: "service_account", displayName: "Build bot" } });
  await manage(admin, "/v1/admin/policy/resources", {
    method: "POST",
    body: { id: "app-repo", displayName: "App repository", resourceType: "git_repository", selector: { kind: "exact", value: "team/app" }, allowedExecutionContexts: ["default"], enabled: true }
  });
  await manage(admin, "/v1/admin/policy/grants", {
    method: "POST",
    body: {
      grantId: "git-fetch",
      subjects: [`user:${USER}`, `user:${BOT}`],
      service: "gitlab_git",
      actions: ["repo.fetch"],
      executionContexts: ["default"],
      resources: { resourceIds: ["app-repo"], resourceGroupIds: [] },
      credentialMode: "per_user",
      status: "active"
    }
  });

  // A first save: the user chooses the Basic type, which asks for a username and token.
  expect(await signIn(page, USER, USER_PASSWORD)).not.toBeNull();
  await page.goto(`${baseUrl}/ui/credentials`);
  const credentials = page.getByRole("table", { name: "Credentials", exact: true });
  const gitRow = tableRow(credentials, "GitLab Git");
  await expect(gitRow).toContainText("Not saved");
  await expect(gitRow).toContainText("2 token types");
  await gitRow.getByRole("link", { name: "GitLab Git", exact: true }).click();
  const drawer = page.getByRole("complementary", { name: "GitLab Git credential", exact: true });
  const type = drawer.getByRole("combobox", { name: "Token type", exact: true });
  await expect(type).toHaveValue("");
  await expect(type.locator("option")).toHaveText(["Choose a token type", ...BOTH]);
  await expect(drawer.getByRole("button", { name: "Save credential", exact: true })).toBeDisabled();
  await type.selectOption("git-basic-api-token");
  await drawer.getByLabel("GitLab Git username", { exact: true }).fill("casey@example.test");
  await drawer.getByLabel("GitLab Git API token", { exact: true }).fill("synthetic-basic-token");
  await drawer.getByRole("button", { name: "Save credential", exact: true }).click();
  await expect(gitRow).toContainText("git-basic-api-token");
  await expect(gitRow).toContainText("Not verified");
  const basic = gitToken(await manage<CredentialList>(page, "/v1/credentials"));
  expect(basic).toMatchObject({ profile: "git-basic-api-token", label: null, credentialKind: "basic_api_token" });

  // Replacing preselects the stored type; the bearer type replaces the token in place.
  await expect(type).toHaveValue("git-basic-api-token");
  await type.selectOption("git-bearer-token");
  await expect(drawer.getByLabel("GitLab Git username", { exact: true })).toHaveCount(0);
  await drawer.getByLabel("GitLab Git bearer token", { exact: true }).fill("synthetic-bearer-token");
  await drawer.getByRole("button", { name: "Replace credential", exact: true }).click();
  await expect(gitRow).toContainText("git-bearer-token");
  const bearer = gitToken(await manage<CredentialList>(page, "/v1/credentials"));
  expect(bearer).toMatchObject({ credentialId: basic!.credentialId, profile: "git-bearer-token", credentialKind: "bearer_token" });

  // People stop being accepted with bearer tokens: the stored token is kept as a Not used row.
  await acceptFromPeople(admin, ["git-basic-api-token"]);
  await page.goto(`${baseUrl}/ui/credentials`);
  await expect(gitRow).toContainText("Not saved");
  await expect(gitRow).toContainText("git-basic-api-token");
  const notUsed = tableRow(credentials, "gitlab_git/default");
  await expect(notUsed).toContainText("Not used");
  await expect(notUsed).toContainText("git-bearer-token");
  const list = await manage<CredentialList>(page, "/v1/credentials");
  expect(gitToken(list)).toBeNull();
  expect(list.retained).toEqual([expect.objectContaining({ credentialId: basic!.credentialId, service: "gitlab_git", name: "default", profile: "git-bearer-token", label: null })]);
  await notUsed.getByRole("link", { name: "gitlab_git/default", exact: true }).click();
  const retainedDrawer = page.getByRole("complementary", { name: "gitlab_git/default credential", exact: true });
  await expect(retainedDrawer).toContainText("its connection no longer accepts its token type from this account");
  await expect(retainedDrawer.getByRole("definition").filter({ hasText: "git-bearer-token" })).toHaveText("git-bearer-token");
  // With one accepted type, the form has nothing to choose.
  await gitRow.getByRole("link", { name: "GitLab Git", exact: true }).click();
  await expect(drawer.getByRole("combobox", { name: "Token type" })).toHaveCount(0);
  await expect(drawer.getByLabel("GitLab Git username", { exact: true })).toBeVisible();
  await expect(drawer.getByLabel("GitLab Git API token", { exact: true })).toBeVisible();

  // Accepting the type again uses the kept token without re-entry.
  await acceptFromPeople(admin, BOTH);
  await page.goto(`${baseUrl}/ui/credentials`);
  await expect(gitRow).toContainText("git-bearer-token");
  await expect(gitRow).toContainText("Not verified");
  await expect(tableRow(credentials, "gitlab_git/default")).toHaveCount(0);

  // An administrator chooses the service account's type.
  await admin.goto(`${baseUrl}/ui/admin/principals/${BOT}/credentials`);
  const botRow = tableRow(admin.getByRole("table", { name: "Credentials", exact: true }), "GitLab Git");
  await expect(botRow).toContainText("2 token types");
  await botRow.getByRole("link", { name: "GitLab Git", exact: true }).click();
  const botDrawer = admin.getByRole("complementary", { name: "GitLab Git credential", exact: true });
  const botType = botDrawer.getByRole("combobox", { name: "Token type", exact: true });
  await expect(botType).toHaveValue("");
  await botType.selectOption("git-bearer-token");
  await botDrawer.getByLabel("GitLab Git bearer token", { exact: true }).fill("synthetic-service-token");
  await botDrawer.getByRole("button", { name: "Save credential", exact: true }).click();
  await expect(botRow).toContainText("git-bearer-token");
  expect(gitToken(await manage<CredentialList>(admin, `/v1/admin/principals/${BOT}/credentials`))).toMatchObject({ profile: "git-bearer-token", credentialKind: "bearer_token" });
  await admin.context().close();
});
