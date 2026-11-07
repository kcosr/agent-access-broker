import { test, expect, type Page } from "@playwright/test";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { promises as fs } from "node:fs";
import { createServer, request as httpRequest, type IncomingHttpHeaders, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import { createHash, randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import type { ImportPreviewResult } from "../src/import-types";
import { brokerBinary, portalDist, repoRoot } from "./support/binaries";
import { startBroker } from "./support/broker-process";
import { releaseTestRoot } from "./support/test-root";

// A real Broker, managed store, portal and native HTTP gateway. No API route
// mocks: the synthetic upstream records every dispatch, including any leak of
// Broker ingress authentication or fallthrough from an unaccepted concrete path.
test.use({ actionTimeout: 15_000 });
let broker: ChildProcessWithoutNullStreams | undefined;
let upstream: Server | undefined;
let root = "", baseUrl = "", gatewayBaseUrl = "", endpoint = "";
const logs: string[] = [];
const calls: Array<{ method: string; path: string; headers: IncomingHttpHeaders }> = [];
const gatewayHost = "inventory.gateway.test";
const upstreamCredential = { username: "inventory-reader", token: "synthetic-upstream-password" };
const upstreamAuthorization = `Basic ${Buffer.from(`${upstreamCredential.username}:${upstreamCredential.token}`).toString("base64")}`;

function document() {
  return {
    openapi: "3.1.1", info: { title: "Synthetic gateway inventory", version: "1" },
    servers: [{ url: endpoint }],
    components: { securitySchemes: { inventoryBasic: { type: "http", scheme: "basic" } } },
    security: [{ inventoryBasic: [] }],
    paths: {
      "/items/{id}": {
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        get: {
          operationId: "get_item", summary: "Read an inventory item",
          responses: { "200": { description: "Item", content: { "application/json": { schema: { type: "object" } } } } }
        }
      },
      "/items/admin": {
        get: {
          operationId: "admin_items", summary: "Administrative inventory; leave unaccepted",
          responses: { "200": { description: "Administrative data", content: { "application/json": { schema: { type: "object" } } } } }
        }
      }
    }
  };
}

test.beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-gateway-portal-"));
  upstream = createServer((request, response) => {
    calls.push({ method: request.method!, path: request.url!, headers: request.headers });
    if (request.headers.authorization !== upstreamAuthorization) {
      response.writeHead(401).end();
      return;
    }
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ id: request.url!.split("/").at(-1), name: "Synthetic widget" }));
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  endpoint = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/api`;
  for (const [index, name] of ["encryption", "hash", "csrf", "pepper"].entries()) {
    await fs.writeFile(path.join(root, name), Buffer.alloc(32, index + 31).toString("base64url"));
  }
  const quoted = (relative: string) => JSON.stringify(path.join(root, relative));
  const started = await startBroker({
    binary: brokerBinary, cwd: repoRoot, gatewayListener: true, timeoutMs: 60_000,
    onOutput: (text) => logs.push(text),
    configure: async (_port, url) => {
      baseUrl = url;
      const config = path.join(root, "broker.toml");
      await fs.writeFile(config, `
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
allowed_kinds = ["openapi_http", "openapi_gateway"]
allowed_endpoints = ["${endpoint}"]
[imports.gateway_bindings.inventory]
endpoint = "${endpoint}"
broker_hosts = ["${gatewayHost}"]
auth_modes = ["bearer_broker_token"]
allow_forwarded_identity = false
[audit]
type = "jsonl"
path = ${quoted("audit.jsonl")}
[limits]
upload_spool_dir = ${quoted("spool")}
[limits.invocations]
default = { requests = 1000, window = "1m" }
`);
      return config;
    }
  });
  broker = started.child;
  gatewayBaseUrl = started.gatewayBaseUrl!;
});

test.afterAll(async ({}, testInfo) => {
  if (broker && broker.exitCode === null) {
    const stopped = once(broker, "exit");
    broker.kill("SIGTERM");
    const timer = setTimeout(() => broker?.kill("SIGKILL"), 5_000);
    await stopped;
    clearTimeout(timer);
  }
  if (upstream) await new Promise<void>((resolve) => upstream!.close(() => resolve()));
  await releaseTestRoot(root, testInfo, logs.join(""));
});

async function management<T>(page: Page, apiPath: string, init: { method?: string; body?: unknown } = {}) {
  return page.evaluate(async ({ apiPath, init }) => {
    const session = await (await fetch("/v1/auth/session", { credentials: "same-origin" })).json();
    const headers: Record<string, string> = { Accept: "application/json", "X-Agent-Access-Request-Id": crypto.randomUUID() };
    headers[session.result.csrfHeader] = session.result.csrfToken;
    if (init.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetch(apiPath, {
      method: init.method ?? "GET", credentials: "same-origin", headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body)
    });
    const envelope = await response.json();
    if (!response.ok || !envelope.ok) throw new Error(envelope.error?.message ?? "Management request failed");
    return envelope.result;
  }, { apiPath, init }) as Promise<T>;
}

/** Native HTTP uses the dedicated listener and the operator-bound Host. */
function gatewayGet(resource: string, token: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(`${gatewayBaseUrl}${resource}`, {
      method: "GET", headers: { Host: gatewayHost, Authorization: `Bearer ${token}`, "X-Agent-Access-Request-Id": randomUUID() }
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("error", reject);
      response.on("end", () => resolve({ status: response.statusCode!, body: Buffer.concat(chunks).toString("utf8") }));
    });
    request.setTimeout(10_000, () => request.destroy(new Error("Gateway fixture request timed out")));
    request.on("error", reject);
    request.end();
  });
}

test("a reviewed portal gateway forwards native HTTP with separate credentials and denies an unaccepted shadow route", async ({ page }, testInfo) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => { if (message.type() === "error" && /content security policy/i.test(message.text())) errors.push(message.text()); });
  await page.goto(`${baseUrl}/ui/admin/catalog`);
  await page.getByLabel("Principal").fill("admin");
  await page.getByLabel("Password", { exact: true }).fill("admin-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByLabel("Current password").fill("admin-password");
  await page.getByLabel("New password", { exact: true }).fill("admin-password-updated");
  await page.getByLabel("Confirm new password").fill("admin-password-updated");
  await page.getByRole("button", { name: "Update password" }).click();
  await page.getByRole("complementary", { name: "Catalog" }).getByRole("button", { name: "Import service", exact: true }).click();
  let dialog = page.getByRole("dialog", { name: "Import service", exact: true });
  await dialog.getByLabel("Import type", { exact: true }).selectOption("openapi");
  await dialog.getByLabel("Exposure", { exact: true }).selectOption("openapi_gateway");
  await dialog.getByLabel("Approved gateway binding", { exact: true }).selectOption("inventory");
  await expect(dialog.getByLabel("Service ID", { exact: true })).toHaveValue("inventory");
  await expect(dialog.getByLabel("Service ID", { exact: true })).toBeDisabled();
  await expect(dialog.getByLabel("API base URL", { exact: true })).toHaveValue(endpoint);
  await expect(dialog.getByLabel("API base URL", { exact: true })).toBeDisabled();
  await dialog.getByLabel("Display name", { exact: true }).fill("Inventory HTTP gateway");
  await expect(dialog.getByLabel("Upstream authentication", { exact: true })).toHaveValue("static");
  await expect(dialog).toContainText("Broker ingress: Broker Bearer token");
  await dialog.getByRole("button", { name: "Upload file", exact: true }).click();
  const bytes = Buffer.from(`${JSON.stringify(document(), null, 2)}\n`);
  await dialog.getByLabel("Choose specification JSON file").setInputFiles({ name: "inventory-gateway.json", mimeType: "application/json", buffer: bytes });
  await dialog.getByRole("button", { name: "Create draft", exact: true }).click();
  await expect(page).toHaveURL(/\/services\/inventory\/import$/);
  const initial = await management<ImportPreviewResult>(page, "/v1/admin/imports/inventory/preview");
  expect(initial.service.definition).toMatchObject({ adapterKind: "openapi_gateway", endpoint, connectionSettings: { definitionSource: "upload", executionAuthentication: "static" } });
  expect(initial.service.document).toEqual({ filename: "inventory-gateway.json", byteLength: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") });
  expect(initial.scopedMcp).toBeNull();
  expect(calls).toHaveLength(0);

  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered operations", exact: true });
  await expect(dialog).toContainText("Whole-action access");
  await expect(dialog).toContainText("Body schema not validated by gateway");
  await dialog.getByRole("button", { name: "Configure API authentication", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Edit imported service", exact: true });
  await dialog.getByLabel("API security scheme", { exact: true }).selectOption("inventoryBasic");
  await expect(dialog).toContainText("Credential delivery: Authorization: Basic");
  await expect(dialog.getByLabel("Exposure", { exact: true })).toBeDisabled();
  await dialog.getByRole("button", { name: "Save configuration", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await page.getByRole("button", { name: "Set execution credential", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Set execution credential", exact: true });
  await dialog.getByLabel("Username", { exact: true }).fill(upstreamCredential.username);
  await dialog.getByLabel("Password or API token", { exact: true }).fill(upstreamCredential.token);
  await dialog.getByRole("button", { name: "Save credential", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await page.reload();
  await page.getByRole("button", { name: "Load saved definition", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered operations", exact: true });
  await expect(dialog).toContainText("GET /items/{id}");
  await expect(dialog).toContainText("GET /items/admin");
  await dialog.getByLabel("Effects for get_item", { exact: true }).selectOption("read");
  await dialog.getByLabel("Accept get_item", { exact: true }).check();
  await expect(dialog.getByLabel("Accept admin_items", { exact: true })).not.toBeChecked();
  await dialog.getByRole("button", { name: "Accept selected operations", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await page.getByRole("button", { name: "Enable", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Enable inventory?", exact: true }).getByRole("button", { name: "Enable service", exact: true }).click();
  await expect(page.getByRole("alertdialog")).not.toBeVisible();
  expect(calls).toHaveLength(0);

  // Use the real grant editor so gateway metadata cannot depend on the ordinary
  // agent catalog, which deliberately omits gateway services.
  await page.goto(`${baseUrl}/ui/admin/policies/new`);
  await page.getByLabel("Grant ID").fill("inventory-reader");
  const subjects = page.locator("#grant-subjects");
  await subjects.getByRole("group", { name: "Subject type", exact: true }).getByRole("button", { name: "User", exact: true }).click();
  const user = subjects.getByRole("combobox", { name: "User", exact: true });
  await user.fill("admin");
  await page.getByRole("listbox").getByRole("option", { name: /^admin/ }).click();
  await page.getByRole("combobox", { name: "Service", exact: true }).selectOption("inventory");
  await page.getByRole("checkbox", { name: "get_item", exact: true }).check();
  await expect(page.getByLabel("Credential mode", { exact: true })).toHaveValue("service");
  await page.getByRole("group", { name: "Execution contexts", exact: true }).getByLabel("internal", { exact: true }).check();
  await page.getByRole("region", { name: "Save grant", exact: true }).getByRole("button", { name: "Create grant", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/policies\?grant=inventory-reader$/);
  expect(await management(page, "/v1/admin/policy/grants/inventory-reader")).toMatchObject({ service: "inventory", subjects: ["user:admin"], actions: ["get_item"], credentialMode: "service", executionContexts: ["internal"] });

  // Token issuance uses the real session API; token-editor behavior has its own
  // browser suite. No policy, credential or request response is mocked here.
  await management(page, "/v1/admin/principals/admin/access", { method: "PATCH", body: { agentTokenIssuance: { mode: "read_only", allowedExecutionContexts: ["internal"] } } });
  const issued = await management<{ token: string }>(page, "/v1/tokens", { method: "POST", body: { name: "gateway-reader", ttl: "8h", readOnly: true, allowedServices: ["inventory"], allowedExecutionContexts: ["internal"] } });
  const read = await gatewayGet("/items/widget", issued.token);
  expect(read.status).toBe(200);
  expect(JSON.parse(read.body)).toEqual({ id: "widget", name: "Synthetic widget" });
  expect(calls).toHaveLength(1);
  expect(calls[0]).toMatchObject({ method: "GET", path: "/api/items/widget" });
  expect(calls[0].headers.authorization).toBe(upstreamAuthorization);
  expect(calls[0].headers.authorization).not.toContain(issued.token);
  expect(calls[0].headers.cookie).toBeUndefined();
  expect(calls[0].headers["x-agent-access-execution-context"]).toBeUndefined();
  expect(calls[0].headers["x-aw-identity-token-sha256"]).toBeUndefined();
  const denied = await gatewayGet("/items/admin", issued.token);
  expect(denied.status).toBe(404);
  expect(calls).toHaveLength(1);
  const accepted = await management<ImportPreviewResult>(page, "/v1/admin/imports/inventory/preview");
  expect(accepted.service.actions.map((record) => [record.definition.action, record.status, record.definition.readOnly])).toEqual([["get_item", "enabled", true]]);
  await page.goto(`${baseUrl}/ui/admin/catalog/services/inventory/import`);
  await expect(page.getByText("inventory-gateway.json", { exact: false })).toBeVisible();
  await expect(page.getByText("Gateway address example:", { exact: false })).toContainText(gatewayHost);
  await page.screenshot({ path: testInfo.outputPath("gateway-import-ready.png"), fullPage: true });
  expect(errors).toEqual([]);
});
