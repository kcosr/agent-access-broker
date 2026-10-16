// My access shows service names, action effects, and credential verification
// inputs even when the browser session's execution context (the configured
// default) has no grants: they come from the token options and credential
// targets, which don't depend on the request's context, not from agent
// discovery (`/v1/services`).
import { test, expect, type Locator, type Page } from "@playwright/test";
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

test.beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-my-access-"));
  for (const [index, name] of ["encryption", "hash", "csrf", "pepper"].entries()) {
    await fs.writeFile(path.join(root, name), Buffer.alloc(32, index + 11).toString("base64url"));
  }
  const quoted = (relative: string) => JSON.stringify(path.join(root, relative));
  // Jira grants live in `internal`; Git is also available in `external`.
  // Jira also grants `sandbox`, where its resource is ineligible, leaving no effective access.
  // Browser sessions resolve to `default`, where the user has no grants.
  const configure = async (_port: number, url: string) => {
    baseUrl = url;
    await fs.writeFile(
      path.join(root, "broker.toml"),
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
[execution_context]
allowed_values = ["default", "internal", "external", "sandbox"]
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
[credentials.per_user.jira]
type = "managed_store"
credential_name = "default"
profile = "jira-cloud-api-token"
[credentials.per_user.gitlab_git]
type = "managed_store"
credential_name = "default"
profile = "git-bearer-token"
[providers.jira]
tenant_host = "jira.example.invalid"
allowed_upstream_hosts = ["https://jira.example.invalid/**"]
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
    return path.join(root, "broker.toml");
  };
  ({ child: broker } = await startBroker({
    binary: brokerBinary,
    configure,
    cwd: repoRoot,
    env: { ...process.env, RUST_LOG: "agent_access_broker=warn,agent_access_core=warn" },
    readinessHeaders: () => ({ "X-Agent-Access-Request-Id": "my-access-health" }),
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
    headers: { Origin: baseUrl, "X-Agent-Access-Request-Id": `my-access-login-${++requestCounter}` },
    data: { principalId, password, returnTo: "/ui" }
  });
  const body = await response.json();
  return response.ok() && body.ok ? (body.result as { passwordChangeRequired?: boolean; csrfHeader: string; csrfToken: string }) : null;
}

async function signInAsAdmin(page: Page) {
  await page.context().clearCookies();
  if (await signIn(page, "admin", ADMIN_UPDATED)) return;
  const session = await signIn(page, "admin", ADMIN_PASSWORD);
  expect(session?.passwordChangeRequired).toBe(true);
  const change = await page.request.post(`${baseUrl}/v1/auth/local/password/change`, {
    headers: { Origin: baseUrl, "X-Agent-Access-Request-Id": `my-access-password-${++requestCounter}`, [session!.csrfHeader]: session!.csrfToken },
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
      const response = await fetch(apiPath, {
        method: init.method ?? "GET",
        credentials: "same-origin",
        headers,
        body: init.body === undefined ? undefined : JSON.stringify(init.body)
      });
      const envelope = await response.json();
      if (!response.ok || !envelope.ok) throw new Error(envelope.error?.message ?? `Management request failed: ${apiPath}`);
      return envelope.result;
    },
    { apiPath, init }
  ) as Promise<T>;
}

/** A DataTable row by its row header (the primary cell's link). */
function tableRow(scope: Page | Locator, name: string) {
  const page = "page" in scope && typeof scope.page === "function" ? scope.page() : (scope as Page);
  return scope.getByRole("row").filter({ has: page.getByRole("rowheader", { name, exact: true }) });
}

async function columnCell(row: Locator, header: string) {
  await expect(row).toBeAttached();
  const headers = (await row.locator("xpath=ancestor::table[1]").getByRole("columnheader", { includeHidden: true }).allTextContents()).map((text) => text.trim());
  const index = headers.indexOf(header);
  expect(index, `column ${header} in ${headers.join(", ")}`).toBeGreaterThanOrEqual(0);
  return row.locator(":scope > th, :scope > td").nth(index);
}

/**
 * Saves a GitLab Git token in the open credential drawer, then verifies it
 * against a repository: the request carries the repository and fails upstream
 * (the host doesn't resolve), not with "requires repository".
 */
async function saveAndVerifyGitCredential(page: Page, drawer: Locator, verifyPath: RegExp) {
  await expect(drawer.getByRole("heading", { name: "GitLab Git" })).toBeVisible();
  await drawer.getByLabel("GitLab Git bearer token", { exact: true }).fill("synthetic-git-token");
  await drawer.getByRole("button", { name: "Save credential", exact: true }).click();
  await expect(page.getByText("Credential saved")).toBeVisible();
  const repository = drawer.getByRole("textbox", { name: "Repository" });
  await expect(repository).toBeVisible();
  const verifyButton = drawer.getByRole("button", { name: "Verify", exact: true });
  await expect(verifyButton).toBeDisabled();
  await repository.fill("team/app");
  const request = page.waitForRequest((candidate) => candidate.method() === "POST" && verifyPath.test(new URL(candidate.url()).pathname));
  const response = page.waitForResponse((candidate) => candidate.request().method() === "POST" && verifyPath.test(new URL(candidate.url()).pathname));
  await verifyButton.click();
  expect((await request).postDataJSON()).toEqual({ repository: "team/app" });
  const body = await (await response).json();
  expect(body.reasonCode).not.toBe("input_invalid");
  expect(JSON.stringify(body)).not.toContain("requires repository");
  await expect(drawer.getByText("Verification failed").first()).toBeVisible();
}

test("My access shows names, effects and the repository input when the default context has no grants", async ({ page }) => {
  await signInAsAdmin(page);
  await page.goto(`${baseUrl}/ui/admin/policies`);
  await manage(page, "/v1/admin/principals", { method: "POST", body: { principalId: USER, kind: "user", displayName: "Casey" } });
  await manage(page, `/v1/admin/principals/${USER}/login-methods/local-password/enable`, { method: "POST", body: { password: USER_PASSWORD, mustChangePassword: false, acknowledgeSeparateSignIn: true } });
  await manage(page, "/v1/admin/policy/resources", {
    method: "POST",
    body: { id: "eng", displayName: "Engineering", resourceType: "jira_project", selector: { kind: "exact", value: "ENG" }, allowedExecutionContexts: ["internal"], enabled: true }
  });
  await manage(page, "/v1/admin/policy/resources", {
    method: "POST",
    body: { id: "app-repo", displayName: "App repository", resourceType: "git_repository", selector: { kind: "exact", value: "team/app" }, allowedExecutionContexts: ["internal", "external"], enabled: true }
  });
  for (const [service, actions, resource] of [
    ["jira", ["issue.view", "issue.create"], "eng"],
    ["gitlab_git", ["repo.fetch"], "app-repo"]
  ] as const) {
    await manage(page, "/v1/admin/policy/grants", {
      method: "POST",
      body: {
        grantId: `${service}-internal`,
        subjects: [`user:${USER}`],
        service,
        actions,
        executionContexts: service === "gitlab_git" ? ["internal", "external"] : ["internal", "sandbox"],
        resources: { resourceIds: [resource], resourceGroupIds: [] },
        credentialMode: "per_user",
        status: "active"
      }
    });
  }

  // The user: Access classifies actions and names services without grants in the session's context.
  await page.context().clearCookies();
  expect(await signIn(page, USER, USER_PASSWORD)).not.toBeNull();
  const services = new Set<string>();
  page.on("request", (request) => {
    const pathname = new URL(request.url()).pathname;
    if (pathname.startsWith("/v1/services") || pathname === "/v1/capabilities") services.add(pathname);
  });
  await page.goto(`${baseUrl}/ui/access`);
  const access = page.getByRole("table", { name: "Access", exact: true });
  await expect(await columnCell(tableRow(access, "issue.view"), "Effect")).toHaveText("Read-only");
  await expect(await columnCell(tableRow(access, "issue.create"), "Effect")).toHaveText("Write-capable");
  await expect(await columnCell(tableRow(access, "repo.fetch"), "Effect")).toHaveText("Read-only");
  await expect(await columnCell(tableRow(access, "issue.view"), "Service")).toHaveText("Jira");
  await expect(await columnCell(tableRow(access, "repo.fetch"), "Service")).toHaveText("GitLab Git");
  const sidebar = page.getByRole("complementary", { name: "Access filters", exact: true });
  await expect(sidebar.getByRole("button", { name: /^GitLab Git/ })).toBeVisible();
  await expect(sidebar.getByRole("button", { name: /^Jira/ })).toBeVisible();
  const contexts = sidebar.getByRole("radiogroup", { name: "Execution context" });
  await expect(contexts.getByRole("radio", { name: "All contexts", exact: true })).toBeChecked();
  await expect(page.getByRole("button", { name: "All contexts", exact: true })).toHaveCount(0);
  const effects = sidebar.getByRole("region", { name: /^Action effects/ });
  const read = effects.getByRole("checkbox", { name: "Read-only", exact: true });
  const write = effects.getByRole("checkbox", { name: "Write-capable", exact: true });
  await expect(read).toHaveAccessibleDescription("2");
  await expect(write).toHaveAccessibleDescription("1");
  await write.check();
  await expect(tableRow(access, "issue.create")).toBeVisible();
  await expect(tableRow(access, "issue.view")).toHaveCount(0);
  await expect(tableRow(access, "repo.fetch")).toHaveCount(0);
  await expect(page).toHaveURL(/effect=write/);
  // Counts ignore their own effect selection; selecting both restores all actions.
  await expect(read).toHaveAccessibleDescription("2");
  await read.check();
  await expect(tableRow(access, "repo.fetch")).toBeVisible();
  await page.reload();
  await expect(read).toBeChecked();
  await expect(write).toBeChecked();
  await sidebar.getByRole("button", { name: /^Jira/ }).click();
  await expect(read).toHaveAccessibleDescription("1");
  await expect(write).toHaveAccessibleDescription("1");
  const search = page.getByPlaceholder("Filter actions, resources…");
  await search.fill("issue.view");
  await expect(write).toHaveAccessibleDescription("0");
  await expect(read).toHaveAccessibleDescription("1");
  await contexts.getByRole("radio", { name: "external", exact: true }).check();
  await expect(page).toHaveURL(/context=external/);
  await expect(read).toHaveAccessibleDescription("0");
  await expect(page.getByText("No matching access", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expect(contexts.getByRole("radio", { name: "All contexts", exact: true })).toBeChecked();
  await expect(read).not.toBeChecked();
  await expect(write).not.toBeChecked();
  await expect(search).toHaveValue("");
  await expect(page).not.toHaveURL(/[?&](effect|context|service|q)=/);
  await contexts.getByRole("radio", { name: "sandbox", exact: true }).check();
  await expect(page.getByText("No services or actions are available in sandbox.", { exact: true })).toBeVisible();
  await expect(page.getByText("No matching access", { exact: true })).toHaveCount(0);
  await expect(read).toHaveAccessibleDescription("0");
  await expect(write).toHaveAccessibleDescription("0");
  await contexts.getByRole("radio", { name: "internal", exact: true }).check();
  await expect(read).toHaveAccessibleDescription("2");
  await expect(tableRow(access, "repo.fetch")).toBeVisible();
  // The drawer shows the gateway's broker hosts.
  await tableRow(access, "repo.fetch").getByRole("link", { name: "repo.fetch", exact: true }).click();
  const actionDrawer = page.getByRole("complementary", { name: "repo.fetch on GitLab Git", exact: true });
  await expect(actionDrawer.getByText("git.local.test", { exact: true })).toBeVisible();
  await expect(actionDrawer.getByText("Read-only", { exact: true })).toBeVisible();

  // Credentials are named, and GitLab Git verification asks for a repository.
  await page.goto(`${baseUrl}/ui/credentials`);
  const credentials = page.getByRole("table", { name: "Service credentials", exact: true });
  await expect(tableRow(credentials, "Jira")).toBeVisible();
  await tableRow(credentials, "GitLab Git").getByRole("link", { name: "GitLab Git", exact: true }).click();
  await saveAndVerifyGitCredential(page, page.getByRole("complementary", { name: "GitLab Git credential", exact: true }), /^\/v1\/credentials\/gitlab_git\/default\/verify$/);
  expect([...services]).toEqual([]);

  // An administrator managing the user's credentials sees the same repository input.
  await signInAsAdmin(page);
  await page.goto(`${baseUrl}/ui/admin/principals/${USER}/credentials`);
  const managed = page.getByRole("table", { name: "Service credentials", exact: true });
  await expect(tableRow(managed, "Jira")).toBeVisible();
  await tableRow(managed, "GitLab Git").getByRole("link", { name: "GitLab Git", exact: true }).click();
  const drawer = page.getByRole("complementary", { name: "GitLab Git credential", exact: true });
  await expect(drawer.getByRole("heading", { name: "GitLab Git" })).toBeVisible();
  // The user's saved credential: the admin verifies it against a repository.
  const repository = drawer.getByRole("textbox", { name: "Repository" });
  await expect(repository).toBeVisible();
  await repository.fill("team/app");
  const verifyPath = new RegExp(`^/v1/admin/principals/${USER}/credentials/gitlab_git/default/verify$`);
  const request = page.waitForRequest((candidate) => candidate.method() === "POST" && verifyPath.test(new URL(candidate.url()).pathname));
  const response = page.waitForResponse((candidate) => candidate.request().method() === "POST" && verifyPath.test(new URL(candidate.url()).pathname));
  await drawer.getByRole("button", { name: "Verify", exact: true }).click();
  expect((await request).postDataJSON()).toEqual({ repository: "team/app" });
  const body = await (await response).json();
  expect(body.reasonCode).not.toBe("input_invalid");
  expect(JSON.stringify(body)).not.toContain("requires repository");
  // The user's Access tab (the admin view) uses the same classifications.
  await page.goto(`${baseUrl}/ui/admin/principals/${USER}/access`);
  const managedAccess = page.getByRole("table", { name: "Access", exact: true });
  await expect(await columnCell(tableRow(managedAccess, "issue.view"), "Effect")).toHaveText("Read-only");
  await expect(await columnCell(tableRow(managedAccess, "issue.create"), "Effect")).toHaveText("Write-capable");
  await expect(await columnCell(tableRow(managedAccess, "issue.view"), "Service")).toHaveText("Jira");
  // Embedded Access retains both filters because it has no Access sidebar.
  const embeddedEffects = page.getByRole("group", { name: "Action effects", exact: true });
  await embeddedEffects.getByRole("checkbox", { name: "Write-capable", exact: true }).check();
  await expect(tableRow(managedAccess, "issue.create")).toBeVisible();
  await expect(tableRow(managedAccess, "issue.view")).toHaveCount(0);
  await page.getByRole("button", { name: "external", exact: true }).click();
  await expect(page.getByText("No matching access", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expect(tableRow(managedAccess, "issue.view")).toBeVisible();
  await expect(embeddedEffects.getByRole("checkbox", { name: "Write-capable", exact: true })).not.toBeChecked();
});
