import { test, expect, type Page, type TestInfo } from "@playwright/test";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { promises as fs } from "node:fs";
import { createServer, type AddressInfo } from "node:net";
import { createServer as createHttpServer, type Server } from "node:http";
import { once } from "node:events";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { brokerBinary, portalDist } from "./support/binaries";

test.use({ actionTimeout: 15_000 });

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
let broker: ChildProcessWithoutNullStreams | undefined;
let root = "";
let baseUrl = "";
const logs: string[] = [];
let upstream: Server;
let endpoint = "";
let changed = false;
let titleChanged = false;
const upstreamTokens: (string | undefined)[] = [];

test.beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-imports-portal-"));
  upstream = createHttpServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const rpc = JSON.parse(Buffer.concat(chunks).toString());
    upstreamTokens.push(request.headers.authorization);
    const result = rpc.method === "server/discover" ? { supportedVersions: ["2026-07-28"], capabilities: { tools: {} }, ttlMs: 0, cacheScope: "private" } : rpc.method === "tools/list" ? { tools: [
      { name: "query", description: "Read metrics", inputSchema: { type: "object", ...(changed ? { properties: { filter: { type: "string" } } } : {}) }, annotations: { readOnlyHint: true, title: titleChanged ? "Updated metric title" : "Metric title" } },
      { name: "update", description: "Update upstream", inputSchema: { type: "object" } },
      { name: "unsupported", description: "Unsupported remote reference", inputSchema: { type: "object", properties: { item: { $ref: "https://schema.example.test/remote" } } } },
      ...(changed ? [{ name: "new_tool", description: "Newly discovered tool", inputSchema: { type: "object" } }] : [])
    ] } : { content: [] };
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result }));
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  endpoint = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/mcp`;
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = (server.address() as AddressInfo).port;
  await new Promise<void>(resolve => server.close(() => resolve()));
  baseUrl = `http://127.0.0.1:${port}`;
  for (const [index, name] of ["encryption", "hash", "csrf", "pepper"].entries()) {
    await fs.writeFile(path.join(root, name), Buffer.alloc(32, index + 1).toString("base64url"));
  }
  const quoted = (relative: string) => JSON.stringify(path.join(root, relative));
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
allowed_values = ["default", "internal"]
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
initial_password = "admin-password"
[policy]
authority = "managed"
default_decision = "deny"
[imports]
enabled = true
allowed_kinds = ["mcp_http"]
allowed_endpoints = ["${endpoint}"]
[audit]
type = "jsonl"
path = ${quoted("audit.jsonl")}
[limits]
upload_spool_dir = ${quoted("spool")}
[limits.invocations]
default = { requests = 1000, window = "1m" }
`);
  broker = spawn(brokerBinary, ["--config", path.join(root, "broker.toml"), "serve", "--listen", `127.0.0.1:${port}`], { cwd: repoRoot });
  broker.stdout.on("data", chunk => logs.push(String(chunk)));
  broker.stderr.on("data", chunk => logs.push(String(chunk)));
  await expect.poll(async () => {
    if (broker?.exitCode !== null) throw new Error(logs.join(""));
    try { return (await fetch(`${baseUrl}/v1/healthz`)).ok; } catch { return false; }
  }, { timeout: 30_000 }).toBe(true);
});

test.afterAll(async () => {
  if (broker && broker.exitCode === null) {
    const stopped = once(broker, "exit");
    broker.kill("SIGTERM");
    const timer = setTimeout(() => broker?.kill("SIGKILL"), 5000);
    await stopped;
    clearTimeout(timer);
  }
  await fs.writeFile(path.join(root, "broker.log"), logs.join(""));
  await new Promise<void>((resolve) => upstream.close(() => resolve()));
  // Preserve test database, logs and artifacts for this implementation review.
});

async function signInAndChangePassword(page: Page) {
  await page.getByLabel("Principal").fill("admin");
  await page.getByLabel("Password", { exact: true }).fill("admin-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByLabel("Current password").fill("admin-password");
  await page.getByLabel("New password", { exact: true }).fill("admin-password-updated");
  await page.getByLabel("Confirm new password").fill("admin-password-updated");
  await page.getByRole("button", { name: "Update password" }).click();
}

/** A DataTable row whose row header (the primary cell, holding the row link) has this name. */
function tableRow(page: Page, name: string) {
  return page.getByRole("row").filter({ has: page.getByRole("rowheader", { name, exact: true }) });
}

/** Opens a service page tab through the page's own tab links. */
async function openTab(page: Page, tab: "Actions" | "Import") {
  await page.getByRole("navigation", { name: /sections$/ }).getByRole("link", { name: new RegExp(`^${tab}`) }).click();
}

test("administrator imports, classifies, refreshes and retires an HTTP MCP service", async ({ page }, testInfo) => {
  await page.goto(`${baseUrl}/ui/admin/catalog`);
  await signInAndChangePassword(page);
  const main = page.getByRole("main", { name: "Services" });
  await expect(main).toBeVisible();
  // The toolbar and the empty catalog both offer the primary action.
  await main.getByRole("button", { name: "Import service", exact: true }).first().click();
  let dialog = page.getByRole("dialog", { name: "Import service", exact: true });
  await dialog.getByLabel("Service ID").fill("metrics");
  await dialog.getByLabel("Display name").fill("Metrics");
  await dialog.getByLabel("HTTP MCP endpoint").fill(endpoint);
  await expect(dialog.locator('option[value="per_user"]')).toHaveJSProperty("disabled", true);
  await dialog.getByLabel("Personal credentials for each user").check();
  await dialog.getByLabel("Discovery credential").selectOption("per_user");
  await expect(dialog.getByLabel("Discovery principal ID")).toHaveValue("admin");
  await expect(dialog.getByLabel("Discovery principal ID")).toHaveAttribute("readonly", "");
  await dialog.getByRole("button", { name: "Create draft" }).click();
  await expect(dialog).not.toBeVisible();
  // A new import lands on its service page's Import tab, listed in the Catalog sidebar.
  await expect(page).toHaveURL(/\/ui\/admin\/catalog\/services\/metrics\/import$/);
  await expect(page.getByRole("complementary", { name: "Catalog" }).getByRole("link", { name: /^Metrics/ })).toHaveAttribute("aria-current", "page");
  await page.getByRole("button", { name: "Set execution token" }).click();
  dialog = page.getByRole("dialog", { name: "Set execution token" });
  await dialog.getByLabel("Token", { exact: true }).fill("synthetic-execution-token");
  await dialog.getByRole("button", { name: "Save token" }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.getByRole("button", { name: "Rotate execution token" })).toBeVisible();
  // A base admin can provision their own discovery credential before the draft has actions or grants.
  await page.getByRole("button", { name: "Set personal token", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Set personal token" });
  await dialog.getByLabel("Token", { exact: true }).fill("synthetic-personal-token");
  await dialog.getByRole("button", { name: "Save token" }).click();
  await expect(dialog).not.toBeVisible();
  await page.getByRole("button", { name: "Discover tools", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered tools" });
  await expect(dialog.getByLabel("Accept query", { exact: true })).not.toBeChecked();
  await expect(dialog.getByText("Upstream suggests read-only.")).toBeVisible();
  await expect(dialog.getByText("unsupported · Unsupported", { exact: true })).toBeVisible();
  expect(upstreamTokens.length).toBeGreaterThan(0);
  expect(upstreamTokens.every((token) => token === "Bearer synthetic-personal-token")).toBe(true);
  await dialog.getByLabel("Effects for query", { exact: true }).selectOption("read");
  const allReads = dialog.getByRole("button", { name: "Select all matching read-only tools" });
  await allReads.focus(); await page.keyboard.press("Enter");
  await expect(dialog.getByLabel("Accept query", { exact: true })).toBeChecked();
  await dialog.getByRole("button", { name: "Select none matching read-only tools" }).focus();
  await page.keyboard.press("Space");
  await expect(dialog.getByLabel("Accept query", { exact: true })).not.toBeChecked();
  await allReads.click();
  await dialog.getByLabel("Action name for update", { exact: true }).fill("update.item");
  await dialog.getByLabel("Accept update.item", { exact: true }).check();
  await dialog.getByRole("button", { name: "Accept selected tools" }).click();
  await expect(dialog).not.toBeVisible();
  await page.getByRole("button", { name: "Enable", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Enable metrics?", exact: true }).getByRole("button", { name: "Enable service" }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await browserManagementRequest(page, "/v1/admin/policy/grants", { method: "POST", body: { grantId: "metrics-grant", service: "metrics", subjects: ["user:admin"], actions: ["query", "update.item"], credentialMode: "service", executionContexts: ["internal"], resources: { resourceIds: [], resourceGroupIds: [] }, status: "active" } });
  await browserManagementRequest(page, "/v1/admin/principals", { method: "POST", body: { principalId: "writer", kind: "user" } });
  await browserManagementRequest(page, "/v1/admin/policy/grants", { method: "POST", body: { grantId: "metrics-write-grant", service: "metrics", subjects: ["user:writer"], actions: ["update.item"], credentialMode: "service", executionContexts: ["internal"], resources: { resourceIds: [], resourceGroupIds: [] }, status: "active" } });
  titleChanged = true;
  await page.getByRole("button", { name: "Refresh discovery", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered tools" });
  await expect(dialog.getByText("query · Metadata changed", { exact: true })).toBeVisible();
  await expect(dialog.getByLabel("Accept query", { exact: true })).toBeChecked();
  await expect(dialog.getByLabel("Effects for query", { exact: true })).toHaveValue("read");
  await expect(dialog.getByText(/Existing grants to review:/)).toHaveCount(0);
  await expect(dialog.getByRole("button", { name: "Accept selected tools" })).toBeEnabled();
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.getByRole("button", { name: "Edit configuration", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Edit imported service" });
  await dialog.getByLabel("Display name").fill("Metrics renamed");
  await expect(dialog.getByLabel(/I reviewed the .* existing grant/)).toHaveCount(0);
  await dialog.getByRole("button", { name: "Save configuration" }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: "Metrics renamed" })).toBeVisible();
  changed = true;
  await page.getByRole("button", { name: "Refresh discovery", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered tools" });
  await expect(dialog.getByLabel("Accept query", { exact: true })).not.toBeChecked();
  await expect(dialog.getByText("query · Changed", { exact: true })).toBeVisible();
  await expect(dialog.getByLabel("Effects for query", { exact: true })).toHaveValue("write");
  await expect(dialog.getByLabel("Action name for query", { exact: true })).toBeDisabled();
  await expect(dialog.getByLabel("Accept new_tool", { exact: true })).not.toBeChecked();
  await expect(dialog.getByLabel("Accept update.item", { exact: true })).toBeChecked();
  await expect(dialog.getByLabel("Action name for update.item", { exact: true })).toHaveValue("update.item");
  await expect(dialog.getByText(/Existing grants to review:/)).toHaveCount(0);
  await expect(dialog.getByRole("button", { name: "Accept selected tools" })).toBeEnabled();
  await dialog.getByLabel("Accept query", { exact: true }).check();
  await expect(dialog.getByText("Existing grants to review: metrics-grant", { exact: true })).toBeVisible();
  await expect(dialog.getByText(/Existing grants to review:.*metrics-write-grant/)).toHaveCount(0);
  await expect(dialog.getByRole("button", { name: "Accept selected tools" })).toBeDisabled();
  await dialog.getByLabel("I reviewed the affected grants and approve these action changes.").check();
  await expect(dialog.getByRole("button", { name: "Accept selected tools" })).toBeEnabled();
  await page.screenshot({ path: testInfo.outputPath("imports-review.png"), fullPage: true });
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  // Complete discovery quarantined the changed accepted tool.
  await expect(page.getByText("Quarantined actions require a new discovery review before they can be enabled.")).toBeVisible();
  await openTab(page, "Actions");
  const actions = page.getByRole("table", { name: "Metrics renamed actions" });
  await expect(tableRow(page, "query")).toContainText("Quarantined");
  // Grouping by status is optional and kept in the URL.
  await page.getByRole("button", { name: "Group", exact: true }).click();
  await page.getByRole("menuitemradio", { name: "Status", exact: true }).click();
  await expect(page).toHaveURL(/group=status/);
  await expect(actions.getByRole("rowgroup").filter({ hasText: /^Quarantined/ }).getByRole("rowheader", { name: "query", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "update.item", exact: true }).click();
  const drawer = page.getByRole("complementary", { name: "Action update.item" });
  await expect(drawer.getByText("Write-capable").first()).toBeVisible();
  await drawer.getByRole("button", { name: "Retire", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Retire update.item?", exact: true }).getByRole("button", { name: "Retire action" }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(tableRow(page, "update.item")).toContainText("Retired");
  await openTab(page, "Import");
  await page.getByRole("button", { name: "Refresh discovery", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered tools" });
  await expect(dialog.getByText(/Retired – new identity required/)).toBeVisible();
  const replacementName = dialog.getByLabel(/^Action name for update/);
  await expect(replacementName).toBeEnabled();
  await replacementName.fill("update.replacement");
  await dialog.getByLabel("Accept update.replacement", { exact: true }).check();
  await expect(dialog.getByText(/Existing grants to review:/)).toHaveCount(0);
  await dialog.getByRole("button", { name: "Accept selected tools" }).click();
  await expect(dialog).not.toBeVisible();
  await openTab(page, "Actions");
  await expect(tableRow(page, "update.item")).toContainText("Retired");
  await expect(tableRow(page, "update.replacement")).toContainText("Enabled");
  const retainedGrant = await browserManagementRequest<{ actions: string[] }>(page, "/v1/admin/policy/grants/metrics-grant");
  expect(retainedGrant.actions).toEqual(["query", "update.item"]);
  await openTab(page, "Import");
  await page.getByRole("button", { name: "Retire", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Retire metrics?", exact: true }).getByRole("button", { name: "Retire service" }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(page.getByRole("button", { name: "Refresh discovery", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Delete execution token", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Delete execution token?" }).getByRole("button", { name: "Delete token" }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(page.getByRole("button", { name: "Delete execution token", exact: true })).toBeDisabled();
  await expect(page.locator("body")).not.toContainText("synthetic-execution-token");
  await expect(page.locator("body")).not.toContainText("synthetic-personal-token");
  await page.screenshot({ path: testInfo.outputPath("imports-retired.png"), fullPage: true });
  await assertNoHorizontalOverflow(page, testInfo);
  // The grant editor keeps a selected quarantined action but cannot add it back once removed.
  await page.goto(`${baseUrl}/ui/admin/policies/metrics-grant/edit`);
  const query = page.getByLabel("query", { exact: true });
  await expect(query).toBeEnabled();
  await expect(query).toBeChecked();
  await expect(page.getByLabel("Credential mode")).toHaveValue("service");
  await query.uncheck();
  await expect(query).toBeDisabled();
  await expect(page.getByLabel("Credential mode")).toHaveValue("service");
  const save = page.getByRole("button", { name: "Save grant", exact: true });
  await expect(save).toBeEnabled();
  await save.click();
  await expect.poll(async () => (await browserManagementRequest<{ actions: string[] }>(page, "/v1/admin/policy/grants/metrics-grant")).actions).toEqual(["update.item"]);
  // Saving leaves the editor for the saved grant.
  await expect(page).toHaveURL(/\/ui\/admin\/policies\?grant=metrics-grant$/);
});
async function assertNoHorizontalOverflow(page: Page, _testInfo: TestInfo) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
}

async function browserManagementRequest<T>(page: Page, path: string, init: { method?: string; body?: unknown } = {}) {
  return page.evaluate(
    async ({ path, init }) => {
      const sessionResponse = await fetch("/v1/auth/session", {
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      });
      const sessionEnvelope = await sessionResponse.json();
      if (!sessionResponse.ok || !sessionEnvelope.ok || !sessionEnvelope.result?.csrfHeader || !sessionEnvelope.result?.csrfToken) {
        throw new Error("Failed to load browser session for management request");
      }
      const headers: Record<string, string> = {
        Accept: "application/json",
        "X-Agent-Access-Request-Id": crypto.randomUUID()
      };
      if (init.body !== undefined) {
        headers["Content-Type"] = "application/json";
      }
      headers[sessionEnvelope.result.csrfHeader] = sessionEnvelope.result.csrfToken;
      const response = await fetch(path, {
        method: init.method ?? "GET",
        credentials: "same-origin",
        headers,
        body: init.body === undefined ? undefined : JSON.stringify(init.body)
      });
      const envelope = await response.json();
      if (!response.ok || !envelope.ok) {
        throw new Error(envelope.error?.message ?? "Management request failed");
      }
      return envelope.result;
    },
    { path, init }
  ) as Promise<T>;
}
