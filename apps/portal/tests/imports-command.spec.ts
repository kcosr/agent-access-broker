import { test, expect, type Page } from "@playwright/test";
import { execFileSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { brokerBinary, portalDist } from "./support/binaries";
import { startBroker } from "./support/broker-process";
import { releaseTestRoot } from "./support/test-root";

// A real Broker imports the reference command,
// crates/agent-access/tests/fixtures/command-imports/ticketing.py, and runs it
// for discovery, invocation and verification. The command needs Python 3: a
// missing interpreter fails this spec instead of skipping it.
test.use({ actionTimeout: 15_000 });

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const ticketing = path.join(repoRoot, "crates/agent-access/tests/fixtures/command-imports/ticketing.py");
const SERVICE_TOKEN = "svc-example-service";
const PERSONAL_TOKEN = "pat-example-avery";
const WEBHOOK_SECRET = "s3cr3t-example-webhook";
let broker: ChildProcessWithoutNullStreams | undefined;
let root = "";
let baseUrl = "";
let interpreter = "";
const logs: string[] = [];

/** The Python 3 interpreter the command's `#!/usr/bin/env python3` finds; throws when there is none. */
function python3(): string {
  return execFileSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).trim();
}

/** Writes the Broker configuration, with the command's manifest profile in its environment. */
async function writeConfig(profile: "default" | "v2") {
  const quoted = (relative: string) => JSON.stringify(path.join(root, relative));
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
allowed_values = ["internal"]
default_context = "internal"
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
allowed_kinds = ["command"]
[command_imports.ticketing]
path = ${JSON.stringify(ticketing)}
timeout = "30s"
network = "none"
[command_imports.ticketing.env]
PATH = ${JSON.stringify(`${path.dirname(interpreter)}:/usr/bin:/bin`)}
LANG = "C.UTF-8"
TICKETING_PROFILE = "${profile}"
[mcp]
enabled = true
public_url = "${baseUrl}/mcp"
[audit]
type = "sqlite"
path = ${quoted("audit.sqlite")}
[limits]
upload_spool_dir = ${quoted("spool")}
[limits.invocations]
default = { requests = 1000, window = "1m" }
`
  );
  return path.join(root, "broker.toml");
}

test.beforeAll(async () => {
  interpreter = python3();
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-command-portal-"));
  for (const [index, name] of ["encryption", "hash", "csrf", "pepper"].entries()) {
    await fs.writeFile(path.join(root, name), Buffer.alloc(32, index + 1).toString("base64url"));
  }
  ({ child: broker } = await startBroker({
    binary: brokerBinary,
    configure: async (_port, url) => {
      baseUrl = url;
      return writeConfig("default");
    },
    cwd: repoRoot,
    timeoutMs: 30_000,
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

async function signInAndChangePassword(page: Page) {
  await page.getByLabel("Principal").fill("admin");
  await page.getByLabel("Password", { exact: true }).fill("admin-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByLabel("Current password").fill("admin-password");
  await page.getByLabel("New password", { exact: true }).fill("admin-password-updated");
  await page.getByLabel("Confirm new password").fill("admin-password-updated");
  await page.getByRole("button", { name: "Update password" }).click();
}

const invoke = (token: string, action: string, inputs: unknown) =>
  fetch(`${baseUrl}/v1/invoke/ticketing/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, "X-Agent-Access-Request-Id": randomUUID() },
    body: JSON.stringify({ inputs })
  });

async function invokeOk(token: string, action: string, inputs: unknown) {
  const response = await invoke(token, action, inputs);
  const text = await response.text();
  expect(response.ok, text).toBe(true);
  return JSON.parse(text) as { result: Record<string, unknown> & { upstreamCommand: Record<string, unknown> } };
}

/** One JSON-RPC message from an HTTP MCP response, JSON or event stream. */
async function rpcResult(response: Response) {
  const text = await response.text();
  if ((response.headers.get("content-type") ?? "").startsWith("application/json")) return JSON.parse(text);
  return text
    .split("\n")
    .filter((line) => line.startsWith("data:"))
    .map((line) => JSON.parse(line.slice(5)))
    .find((message) => message.id !== undefined);
}

async function mcpToolNames(token: string) {
  const headers = { Authorization: `Bearer ${token}`, Accept: "application/json, text/event-stream", "Content-Type": "application/json" };
  const initialized = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "command-portal", version: "1" } } })
  });
  const session = initialized.headers.get("mcp-session-id") ?? "";
  expect((await rpcResult(initialized)).result.protocolVersion).toBe("2025-11-25");
  const sessionHeaders = { ...headers, "mcp-session-id": session, "mcp-protocol-version": "2025-11-25" };
  await (await fetch(`${baseUrl}/mcp`, { method: "POST", headers: sessionHeaders, body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) })).text();
  const listed = await rpcResult(await fetch(`${baseUrl}/mcp`, { method: "POST", headers: sessionHeaders, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) }));
  return (listed.result.tools as Array<{ name: string }>).map((tool) => tool.name).filter((name) => name.startsWith("ticketing_")).sort();
}

test("administrator imports the reference command, grants it, and agents invoke it in both authorization modes", async ({ page }, testInfo) => {
  test.setTimeout(240_000);
  await page.goto(`${baseUrl}/ui/admin/catalog`);
  await signInAndChangePassword(page);
  await expect(page.getByRole("main", { name: "Services" })).toBeVisible();

  await test.step("import a draft by its approved name", async () => {
    await page.getByRole("main", { name: "Services" }).getByRole("button", { name: "Import service", exact: true }).first().click();
    const dialog = page.getByRole("dialog", { name: "Import service", exact: true });
    // `command` is the only allowed kind, and `ticketing` the only approved command.
    await expect(dialog.getByLabel("Import type", { exact: true })).toHaveValue("command");
    await expect(dialog.getByLabel("Command", { exact: true })).toHaveValue("ticketing");
    await expect(dialog).not.toContainText(ticketing);
    await expect(dialog.getByLabel("Service ID", { exact: true })).toHaveValue("ticketing");
    await dialog.getByLabel("Display name", { exact: true }).fill("Ticketing");
    await dialog.getByLabel("Shared service credential", { exact: true }).check();
    await dialog.getByLabel("Personal credentials for each user", { exact: true }).check();
    await dialog.getByRole("button", { name: "Create draft", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/catalog\/services\/ticketing\/import$/);
    await expect(page.getByRole("button", { name: "Set execution credential", exact: true })).toBeDisabled();
  });

  await test.step("discover, preview and accept the manifest", async () => {
    await page.getByRole("button", { name: "Discover actions", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Review discovered actions", exact: true });
    const manifest = dialog.getByRole("region", { name: "Command manifest", exact: true });
    await expect(manifest).toContainText("1.4.0");
    await expect(manifest).toContainText("Username and token · shared or personal");
    await expect(dialog.getByLabel("Broker type ID for project", { exact: true })).toHaveValue("ticketing_project");
    const row = (action: string) => dialog.locator(".pt-catalog-review-item").filter({ has: page.getByRole("checkbox", { name: `Accept ${action}`, exact: true }) });
    await expect(row("issue.view")).toContainText("Resources checked by: Broker · Project, from project");
    await expect(row("issue.search")).toContainText("Resources checked by: Command · Projects");
    await expect(row("issue.close")).toContainText("Resources checked by: Command · Projects");
    await expect(row("whoami")).toContainText("Resources checked by: Command · no resource type");
    for (const action of ["issue.view", "issue.search", "whoami"]) await dialog.getByLabel(`Effects for ${action}`, { exact: true }).selectOption("read");
    for (const action of ["issue.view", "issue.search", "issue.create", "issue.close", "whoami"]) await dialog.getByRole("checkbox", { name: `Accept ${action}`, exact: true }).check();
    await page.screenshot({ path: testInfo.outputPath("command-preview.png") });
    await dialog.getByRole("button", { name: "Accept selected actions", exact: true }).click();
    await expect(dialog).not.toBeVisible();
    await expect(page.getByRole("main", { name: "Ticketing" })).toContainText("Imported at version");
  });

  await test.step("set the service credential with its username and enable the service", async () => {
    await page.getByRole("button", { name: "Set execution credential", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Set execution credential", exact: true });
    await dialog.getByLabel("Username", { exact: true }).fill("svc-tickets");
    await dialog.getByLabel("Token", { exact: true }).fill(SERVICE_TOKEN);
    await dialog.getByRole("button", { name: "Save credential", exact: true }).click();
    await expect(dialog).not.toBeVisible();
    await page.getByRole("button", { name: "Enable", exact: true }).click();
    await page.getByRole("alertdialog", { name: "Enable ticketing?", exact: true }).getByRole("button", { name: "Enable service" }).click();
    await expect(page.getByRole("dialog")).not.toBeVisible();
    await expect(page.locator("body")).not.toContainText(SERVICE_TOKEN);
  });

  // Resources of the imported type, the reader principal and grants in both credential modes.
  await browserManagementRequest(page, "/v1/admin/principals", { method: "POST", body: { principalId: "avery", kind: "user", displayName: "Avery Example" } });
  await browserManagementRequest(page, "/v1/admin/policy/resources", {
    method: "POST",
    body: { id: "ops", resourceType: "ticketing_project", selector: { kind: "exact", value: "OPS" }, displayName: "Operations", allowedExecutionContexts: ["internal"], enabled: true, attributes: { region: "eu-1", webhookSecret: WEBHOOK_SECRET } }
  });
  await browserManagementRequest(page, "/v1/admin/policy/resources", {
    method: "POST",
    body: { id: "web", resourceType: "ticketing_project", selector: { kind: "exact", value: "WEB" }, allowedExecutionContexts: ["internal"], enabled: true }
  });
  const grant = (grantId: string, actions: string[], credentialMode: string, resourceIds: string[]) =>
    browserManagementRequest(page, "/v1/admin/policy/grants", {
      method: "POST",
      body: { grantId, service: "ticketing", subjects: ["user:avery"], actions, credentialMode, executionContexts: ["internal"], resources: { resourceIds, resourceGroupIds: [] }, status: "active" }
    });
  await grant("ticketing-service", ["issue.view", "issue.create"], "service", ["ops"]);
  await grant("ticketing-personal", ["issue.search", "issue.close"], "per_user", ["ops", "web"]);
  await grant("ticketing-whoami", ["whoami"], "per_user", []);

  await test.step("the grant editor shows who checks each action's resources", async () => {
    await page.goto(`${baseUrl}/ui/admin/policies/ticketing-personal/edit`);
    const search = page.getByRole("checkbox", { name: "issue.search", exact: true });
    await expect(search).toBeChecked();
    await expect(search).toHaveAccessibleDescription(/Resources checked by: Command\..*the Broker cannot check that/);
    await expect(page.getByRole("checkbox", { name: "issue.view", exact: true })).toHaveAccessibleDescription(/^Resources checked by: Broker\./);
    await expect(page.getByText("The Broker checks the action grant and passes the caller's grants with their credentials.", { exact: false })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("command-grant-editor.png") });
  });

  await test.step("set and verify the personal username-and-token credential", async () => {
    await page.goto(`${baseUrl}/ui/admin/principals/avery/credentials?credential=ticketing%2Fdefault`);
    const drawer = page.getByRole("complementary", { name: "Ticketing credential", exact: true });
    await expect(drawer).toContainText("username-token");
    // The form follows the Broker's schema for the `username-token` profile.
    await drawer.getByLabel("Ticketing username", { exact: true }).fill("avery");
    await drawer.getByLabel("Ticketing API token", { exact: true }).fill(PERSONAL_TOKEN);
    await drawer.getByRole("button", { name: "Save credential", exact: true }).click();
    await expect(drawer).toContainText("Not verified");
    await drawer.getByRole("button", { name: "Verify", exact: true }).click();
    await expect(drawer.getByText("Upstream verified").first()).toBeVisible();
    await expect(page.locator("body")).not.toContainText(PERSONAL_TOKEN);
    await page.screenshot({ path: testInfo.outputPath("command-personal-verified.png") });
  });

  const deniedRequests: string[] = [];
  const spawnedRequests: string[] = [];
  const token = (await browserManagementRequest<{ token: string }>(page, "/v1/admin/principals/avery/agent-tokens", {
    method: "POST",
    body: { name: "ticketing-agent", ttl: "8h", allowedServices: ["ticketing"], allowedExecutionContexts: ["internal"] }
  })).token;

  await test.step("Broker-checked actions get the named resources and the service credential", async () => {
    const view = await invokeOk(token, "issue.view", { project: "OPS", issue: 42 });
    expect(view.result.upstreamCommand).toMatchObject({ issue: { key: "OPS-42" }, access: { credential: "service", account: "svc-tickets", attributes: ["region", "webhookSecret"] } });
    const create = await invokeOk(token, "issue.create", { project: "OPS", summary: "Rotate the build keys" });
    expect(create.result.upstreamCommand).toMatchObject({ key: "OPS-43", webhookSigned: true });
    expect(JSON.stringify(create)).toContain("OPS-43");
    expect(create.result).toMatchObject({ mutationStatus: "applied_unverified", retrySafe: false, safeLocators: { issue: "OPS-43" } });
    expect(JSON.stringify(create)).not.toContain(WEBHOOK_SECRET);
    // The Broker denies an uncovered project itself; its audit below shows
    // that no process started.
    const denied = await invoke(token, "issue.view", { project: "SEC", issue: 7 });
    const denial = await denied.json();
    expect(denied.status).toBe(403);
    expect(denial).toMatchObject({ reasonCode: "service_action_denied", error: { message: "policy denied service action for resolved scopes" } });
    deniedRequests.push(denial.brokerRequestId);
  });

  await test.step("command-checked actions get the caller's grants with the personal credential", async () => {
    const search = await invokeOk(token, "issue.search", { query: "" });
    expect(search.result.upstreamCommand).toMatchObject({ total: 4, access: { accounts: { user: "avery" } } });
    expect((search.result.upstreamCommand.issues as Array<{ key: string }>).map((issue) => issue.key)).toEqual(["OPS-41", "OPS-42", "WEB-12", "WEB-13"]);
    const close = await invokeOk(token, "issue.close", { key: "WEB-12" });
    expect(close.result.upstreamCommand).toMatchObject({ key: "WEB-12", status: "closed", access: { credential: "user", account: "avery" } });
    expect(close.result).toMatchObject({ mutationStatus: "applied_unverified", retrySafe: false, safeLocators: { issue: "WEB-12" } });
    const refused = await invoke(token, "issue.close", { key: "SEC-7" });
    const refusal = await refused.json();
    expect(refused.status, JSON.stringify(refusal)).toBe(403);
    // The command started and refused the write: nothing was applied.
    expect(refusal).toMatchObject({ reasonCode: "service_action_denied", result: { mutationStatus: "not_applied", operationDispatched: true }, error: { message: "Project SEC is outside your access." } });
    spawnedRequests.push(refusal.brokerRequestId);
    const whoami = await invokeOk(token, "whoami", {});
    expect(whoami.result.upstreamCommand).toMatchObject({ caller: { principal: "avery", kind: "user", displayName: "Avery Example", token: { label: "ticketing-agent" } }, context: "internal", access: { credential: "user", account: "avery" } });
  });

  await test.step("MCP lists the granted command actions", async () => {
    expect(await mcpToolNames(token)).toEqual(["ticketing_issue_close", "ticketing_issue_create", "ticketing_issue_search", "ticketing_issue_view", "ticketing_whoami"]);
  });

  await test.step("the Actions tab and audit show the command's actions and calls", async () => {
    await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing`);
    const table = page.getByRole("table", { name: "Ticketing actions", exact: true });
    await expect(table.getByRole("row", { name: /issue\.view/ })).toContainText("Broker · Project");
    await expect(table.getByRole("row", { name: /issue\.close/ })).toContainText("Command · Projects");
    await page.screenshot({ path: testInfo.outputPath("command-actions.png") });
    await page.goto(`${baseUrl}/ui/admin/audit`);
    await expect(page.getByRole("main")).toContainText("issue.create");
    await page.screenshot({ path: testInfo.outputPath("command-audit.png") });
    await page.getByRole("row", { name: /issue\.create/ }).first().click();
    await expect(page.getByRole("complementary").filter({ hasText: "issue.create" }).first()).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("command-audit-record.png") });
    await page.getByRole("tab", { name: "Raw", exact: true }).click();
    await page.getByText("Provider details", { exact: true }).click();
    await expect(page.getByText('"contractViolation": false').first()).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("command-audit-raw.png") });
    const audit = await browserManagementRequest<{ items: Array<{ action?: string; brokerRequestId?: string; providerAudit?: { command?: { spawned?: boolean }; commandAuthorization?: unknown; verification?: { command?: unknown } } }> }>(page, "/v1/admin/audit/events?service=ticketing");
    // The Broker's denial started no process; the command's refusal did.
    for (const id of deniedRequests) {
      const record = audit.items.find((item) => item.brokerRequestId === id);
      expect(record, id).toBeTruthy();
      expect(record?.providerAudit?.command?.spawned ?? false).toBe(false);
    }
    for (const id of spawnedRequests) expect(audit.items.find((item) => item.brokerRequestId === id)?.providerAudit?.command?.spawned).toBe(true);
    for (const secret of [SERVICE_TOKEN, PERSONAL_TOKEN, WEBHOOK_SECRET]) expect(JSON.stringify(audit)).not.toContain(secret);
    const created = audit.items.find((record) => record.action === "issue.create" && record.providerAudit?.command);
    expect(created?.providerAudit?.command).toMatchObject({ name: "ticketing", spawned: true, exitCode: 0, contractViolation: false, operationDispatched: true });
    const closed = audit.items.find((record) => record.action === "issue.close" && record.providerAudit?.commandAuthorization);
    expect(closed?.providerAudit?.commandAuthorization).toBeTruthy();
  });

  await test.step("an upgraded command refreshes with a resource type change", async () => {
    await writeConfig("v2");
    await browserManagementRequest(page, "/v1/admin/config/reload", { method: "POST" });
    await page.goto(`${baseUrl}/ui/admin/catalog/services/ticketing/import`);
    await page.getByRole("button", { name: "Refresh discovery", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Review discovered actions", exact: true });
    const manifest = dialog.getByRole("region", { name: "Command manifest", exact: true });
    await expect(manifest).toContainText("1.5.0 · imported at version 1.4.0");
    const project = manifest.getByRole("group", { name: "Resource type project", exact: true });
    await expect(project).toContainText("Changed: new optional attribute.");
    await expect(project).toContainText("Applied on acceptance.");
    await expect(dialog.getByText("issue.search · Changed", { exact: true })).toBeVisible();
    await expect(dialog.getByText("issue.comment · New", { exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("command-refresh-types.png") });
    await expect(dialog.getByRole("region", { name: "Unavailable actions and retained identities", exact: true })).toContainText("whoami · Removed");
    const comment = dialog.locator(".pt-catalog-review-item").filter({ has: page.getByRole("checkbox", { name: "Accept issue.comment", exact: true }) });
    await expect(comment).toContainText("Resources checked by: Broker · Project, from project");
    await dialog.getByRole("checkbox", { name: "Accept issue.search", exact: true }).check();
    await dialog.getByLabel("Effects for issue.search", { exact: true }).selectOption("read");
    await expect(dialog.getByText("Existing grants to review: ticketing-personal", { exact: true })).toBeVisible();
    await dialog.getByLabel("I reviewed the affected grants and approve these action changes.").check();
    await page.screenshot({ path: testInfo.outputPath("command-refresh.png") });
    await dialog.getByRole("button", { name: "Accept selected actions", exact: true }).click();
    await expect(dialog).not.toBeVisible();
    const types = await page.evaluate(async () => (await (await fetch("/v1/resource-types", { credentials: "same-origin", headers: { "X-Agent-Access-Request-Id": crypto.randomUUID() } })).json()) as { resourceTypes: Array<{ id: string; importedService?: string; attributes?: Array<{ name: string }> }> });
    const accepted = types.resourceTypes.find((type) => type.id === "ticketing_project");
    expect(accepted?.importedService).toBe("ticketing");
    expect(accepted?.attributes?.map((attribute) => attribute.name)).toEqual(["region", "webhookSecret", "owner"]);
    const limited = await invokeOk(token, "issue.search", { query: "", limit: 1 });
    expect(limited.result.upstreamCommand).toMatchObject({ total: 4 });
  });

  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  await assertNoSecrets(page);
});

async function assertNoSecrets(page: Page) {
  const text = await page.locator("body").innerText();
  for (const secret of [SERVICE_TOKEN, PERSONAL_TOKEN, WEBHOOK_SECRET]) expect(text).not.toContain(secret);
}

async function browserManagementRequest<T>(page: Page, path: string, init: { method?: string; body?: unknown } = {}) {
  return page.evaluate(
    async ({ path, init }) => {
      const sessionResponse = await fetch("/v1/auth/session", { credentials: "same-origin", headers: { Accept: "application/json" } });
      const sessionEnvelope = await sessionResponse.json();
      if (!sessionResponse.ok || !sessionEnvelope.ok || !sessionEnvelope.result?.csrfHeader || !sessionEnvelope.result?.csrfToken) {
        throw new Error("Failed to load browser session for management request");
      }
      const headers: Record<string, string> = { Accept: "application/json", "X-Agent-Access-Request-Id": crypto.randomUUID() };
      if (init.body !== undefined) headers["Content-Type"] = "application/json";
      headers[sessionEnvelope.result.csrfHeader] = sessionEnvelope.result.csrfToken;
      const response = await fetch(path, { method: init.method ?? "GET", credentials: "same-origin", headers, body: init.body === undefined ? undefined : JSON.stringify(init.body) });
      const envelope = await response.json();
      if (!response.ok || !envelope.ok) throw new Error(envelope.error?.message ?? "Management request failed");
      return envelope.result;
    },
    { path, init }
  ) as Promise<T>;
}
