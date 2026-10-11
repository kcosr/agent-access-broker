import { test, expect, type Page } from "@playwright/test";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { promises as fs } from "node:fs";
import { createServer, type AddressInfo } from "node:net";
import { createServer as createHttpServer, type Server, type IncomingHttpHeaders } from "node:http";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { brokerBinary, portalDist } from "./support/binaries";
import type { ImportPreviewResult } from "../src/import-types";

test.use({ actionTimeout: 15_000 });
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
let broker: ChildProcessWithoutNullStreams | undefined;
let root = "", baseUrl = "", endpoint = "", privateEndpoint = "", definitionUrl = "", privateDefinitionUrl = "";
const logs: string[] = [];
let apiServer: Server, documentServer: Server;
let changed = false, denyWrite = false;
const documentRequests: Array<{ path: string; headers: IncomingHttpHeaders }> = [];
const apiRequests: Array<{ method: string; path: string; headers: IncomingHttpHeaders; body: string }> = [];

function document() {
  const response = { description: "Item", content: { "application/json": { schema: { type: "object", properties: { id: { type: "string" }, name: { type: "string" } } } } } };
  return { openapi: "3.1.0", info: { title: "Synthetic inventory", version: "1" }, security: [{ HeaderKey: [] }, { Bearer: [] }], components: { securitySchemes: { HeaderKey: { type: "apiKey", in: "header", name: "X-Api-Key" }, Bearer: { type: "http", scheme: "bearer" }, UnsupportedCookie: { type: "apiKey", in: "cookie", name: "session" } } }, paths: {
    "/items/{id}": { get: { operationId: "get_item", description: "Read an inventory item", parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }, { name: "limit", in: "query", schema: { type: "integer" } }, ...(changed ? [{ name: "filter", in: "query", schema: { type: "string" } }] : [])], responses: { "200": response } } },
    "/items": { post: { operationId: "create_item", description: "Create an inventory item", requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["name"], properties: { name: { type: "string" } }, additionalProperties: false } } } }, responses: { "200": response } } },
    ...(changed ? { "/new-items": { get: { operationId: "list_items", responses: { "200": response } } } } : {}),
  } };
}

test.beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-openapi-portal-"));
  apiServer = createHttpServer(async (request, response) => {
    const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks).toString();
    apiRequests.push({ method: request.method!, path: request.url!, headers: request.headers, body });
    const privateApi = request.url!.startsWith("/private-api/");
    const authorized = privateApi ? request.headers.authorization === "Bearer synthetic-private-api-token" : ["synthetic-api-token", "synthetic-personal-token"].includes(String(request.headers["x-api-key"]));
    response.writeHead(!authorized ? 401 : denyWrite && request.method === "POST" ? 403 : 200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ id: "one", name: body ? JSON.parse(body).name : "item" }));
  });
  apiServer.listen(0, "127.0.0.1"); await once(apiServer, "listening");
  const origin = `http://127.0.0.1:${(apiServer.address() as AddressInfo).port}`;
  endpoint = `${origin}/api`; privateEndpoint = `${origin}/private-api`;
  documentServer = createHttpServer((request, response) => {
    documentRequests.push({ path: request.url!, headers: request.headers });
    const authorized = request.url !== "/private.json" || request.headers["x-definition-key"] === "synthetic-document-token";
    response.writeHead(authorized ? 200 : 401, { "Content-Type": "application/json" });
    response.end(JSON.stringify(authorized ? document() : { error: "unauthorized" }));
  });
  documentServer.listen(0, "127.0.0.1"); await once(documentServer, "listening");
  const documents = `http://127.0.0.1:${(documentServer.address() as AddressInfo).port}`;
  definitionUrl = `${documents}/public.json`; privateDefinitionUrl = `${documents}/private.json`;
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
allowed_kinds = ["mcp_http", "openapi_http"]
allowed_endpoints = ["${endpoint}", "${privateEndpoint}", "${definitionUrl}", "${privateDefinitionUrl}"]
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
  await new Promise<void>((resolve) => apiServer.close(() => resolve()));
  await new Promise<void>((resolve) => documentServer.close(() => resolve()));
  // Preserve test database, logs and artifacts for this implementation review.
});


async function setToken(page: Page, purpose: "execution" | "discovery", value: string) {
  await page.getByRole("button", { name: `Set ${purpose} token`, exact: true }).click();
  const dialog = page.getByRole("dialog", { name: `Set ${purpose} token` });
  await dialog.getByLabel("Token", { exact: true }).fill(value);
  await dialog.getByRole("button", { name: "Save token" }).click();
  await expect(dialog).not.toBeVisible();
}
async function signInAndChangePassword(page: Page) {
  await page.getByLabel("Principal").fill("admin");
  await page.getByLabel("Password", { exact: true }).fill("admin-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByLabel("Current password").fill("admin-password");
  await page.getByLabel("New password", { exact: true }).fill("admin-password-updated");
  await page.getByLabel("Confirm new password").fill("admin-password-updated");
  await page.getByRole("button", { name: "Update password" }).click();
}
/** Import service from the Catalog sidebar, available on every Catalog page; the draft opens on its Import tab. */
async function createDraft(page: Page, privateDocument = false) {
  await page.getByRole("complementary", { name: "Catalog" }).getByRole("button", { name: "Import service", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Import service", exact: true });
  await dialog.getByLabel("Import type").selectOption("openapi_http");
  await dialog.getByLabel("Service ID").fill(privateDocument ? "private_inventory" : "inventory");
  await dialog.getByLabel("Display name").fill(privateDocument ? "Private inventory" : "Inventory");
  await dialog.getByLabel("API base URL").fill(privateDocument ? privateEndpoint : endpoint);
  await dialog.getByLabel("OpenAPI definition URL").fill(privateDocument ? privateDefinitionUrl : definitionUrl);
  await expect(dialog.getByLabel("Personal authentication")).toHaveCount(0);
  await expect(dialog.getByLabel("Separate transport bearer token")).toHaveCount(0);
  if (privateDocument) {
    await dialog.getByLabel("Definition authentication").selectOption("raw_header");
    await dialog.getByLabel("Definition token header").fill("X-Definition-Key");
  } else await dialog.getByLabel("Personal credentials for each user").check();
  await dialog.getByRole("button", { name: "Create draft" }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page).toHaveURL(new RegExp(`/ui/admin/catalog/services/${privateDocument ? "private_inventory" : "inventory"}/import$`));
}
async function loadDefinition(page: Page) {
  await page.getByRole("button", { name: /^(Load|Refresh) definition$/ }).click();
  const dialog = page.getByRole("dialog", { name: "Review discovered operations" });
  await expect(dialog).toBeVisible();
  return dialog;
}
async function enable(page: Page, service: string) {
  await page.getByRole("button", { name: "Enable", exact: true }).click();
  await page.getByRole("alertdialog", { name: `Enable ${service}?`, exact: true }).getByRole("button", { name: "Enable service" }).click();
  await expect(page.getByRole("alertdialog")).not.toBeVisible();
}
async function grant(page: Page, service: string, principal: string, mode: "service" | "per_user", actions: string[]) {
  await browserManagementRequest(page, "/v1/admin/policy/grants", { method: "POST", body: { grantId: `${service}-${principal}`, service, subjects: [`user:${principal}`], actions, credentialMode: mode, executionContexts: ["internal"], resources: { resourceIds: [], resourceGroupIds: [] }, status: "active" } });
}
const invoke = (token: string, service: string, action: string, inputs: unknown) => fetch(`${baseUrl}/v1/invoke/${service}/${action}`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, "X-Agent-Access-Request-Id": randomUUID() }, body: JSON.stringify({ inputs }) });

test("administrator imports public and private OpenAPI definitions with separated credentials and reviewed actions", async ({ page }, testInfo) => {
  await page.goto(`${baseUrl}/ui/admin/catalog`);
  await signInAndChangePassword(page);
  await expect(page.getByRole("main", { name: "Services" })).toBeVisible();
  await createDraft(page);
  await setToken(page, "execution", "synthetic-api-token");
  let dialog = await loadDefinition(page);
  await expect(dialog.getByText("get_item · Unsupported", { exact: true })).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Accept selected operations" })).toBeDisabled();
  expect(documentRequests).toHaveLength(1);
  expect(documentRequests[0].headers.authorization).toBeUndefined();
  expect(documentRequests[0].headers["x-api-key"]).toBeUndefined();
  await dialog.getByRole("button", { name: "Configure API authentication" }).click();
  dialog = page.getByRole("dialog", { name: "Edit imported service" });
  await expect(dialog.getByLabel("OpenAPI definition URL")).toBeEnabled();
  await expect(dialog.locator('option[value="UnsupportedCookie"]')).toHaveCount(0);
  await dialog.getByLabel("API security scheme").selectOption("HeaderKey");
  await expect(dialog.getByText("Token delivery: X-Api-Key.", { exact: false })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("openapi-scheme.png"), fullPage: true });
  await dialog.getByRole("button", { name: "Save configuration" }).click(); await expect(dialog).not.toBeVisible();
  const selectedScheme = await browserManagementRequest<ImportPreviewResult>(page, "/v1/admin/imports/inventory/preview");
  expect(selectedScheme.service.slotVersions).toEqual({});
  await setToken(page, "execution", "synthetic-api-token");
  dialog = await loadDefinition(page);
  await expect(dialog.getByLabel("Effects for get_item", { exact: true })).toHaveValue("write");
  await expect(dialog.getByText("GET /items/{id}", { exact: false })).toBeVisible();
  await dialog.getByLabel("Effects for get_item", { exact: true }).selectOption("read");
  await dialog.getByRole("button", { name: "Select all matching read-only operations" }).focus();
  await page.keyboard.press("Enter");
  await dialog.getByLabel("Accept create_item", { exact: true }).check();
  await dialog.getByRole("button", { name: "Accept selected operations" }).click(); await expect(dialog).not.toBeVisible();
  await enable(page, "inventory");
  await grant(page, "inventory", "admin", "service", ["get_item", "create_item"]);
  const admin = await browserManagementRequest<{ token: string }>(page, "/v1/tokens", { method: "POST", body: { name: "openapi-admin", ttl: "8h", allowedServices: ["inventory"], allowedExecutionContexts: ["internal"] } });
  const read = await invoke(admin.token, "inventory", "get_item", { path: { id: "one" }, query: { limit: 2 } });
  expect(read.ok, await read.text()).toBe(true);
  expect(apiRequests.at(-1)?.path).toBe("/api/items/one?limit=2");
  const write = await invoke(admin.token, "inventory", "create_item", { body: { name: "created" } });
  expect(write.ok, await write.text()).toBe(true);
  expect(apiRequests.at(-1)?.body).toBe('{"name":"created"}');
  denyWrite = true;
  const writesBefore = apiRequests.filter((request) => request.method === "POST").length;
  expect((await invoke(admin.token, "inventory", "create_item", { body: { name: "denied" } })).ok).toBe(false);
  expect(apiRequests.filter((request) => request.method === "POST")).toHaveLength(writesBefore + 1);
  // A second user's personal mode cannot use the configured shared API token.
  await browserManagementRequest(page, "/v1/admin/principals", { method: "POST", body: { principalId: "reader", kind: "user" } });
  await grant(page, "inventory", "reader", "per_user", ["get_item"]);
  const reader = await browserManagementRequest<{ token: string }>(page, "/v1/admin/principals/reader/agent-tokens", { method: "POST", body: { name: "openapi-reader", ttl: "8h", allowedServices: ["inventory"], allowedExecutionContexts: ["internal"] } });
  const callsBeforeMissing = apiRequests.length;
  expect((await invoke(reader.token, "inventory", "get_item", { path: { id: "one" } })).ok).toBe(false);
  expect(apiRequests).toHaveLength(callsBeforeMissing);
  await browserManagementRequest(page, "/v1/admin/principals/reader/credentials/inventory/default", { method: "PUT", body: { profile: "token", secret: { token: "synthetic-personal-token" }, metadata: {} } });
  const personalRead = await invoke(reader.token, "inventory", "get_item", { path: { id: "one" } });
  expect(personalRead.ok, await personalRead.text()).toBe(true);
  expect(apiRequests.at(-1)?.headers["x-api-key"]).toBe("synthetic-personal-token");
  expect((await invoke(reader.token, "inventory", "create_item", { body: { name: "forbidden-by-grant" } })).ok).toBe(false);
  expect(apiRequests).toHaveLength(callsBeforeMissing + 1);
  await page.getByRole("button", { name: "Edit configuration", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Edit imported service" });
  await expect(dialog.getByLabel("API security scheme")).toBeDisabled();
  await expect(dialog.getByLabel("Definition authentication")).toBeDisabled();
  await expect(dialog.getByLabel("OpenAPI definition URL")).toBeDisabled();
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  changed = true;
  dialog = await loadDefinition(page);
  await expect(dialog.getByText("get_item · Changed", { exact: true })).toBeVisible();
  await expect(dialog.getByLabel("Accept get_item", { exact: true })).not.toBeChecked();
  await expect(dialog.getByLabel("Accept list_items", { exact: true })).not.toBeChecked();
  const beforeQuarantine = apiRequests.length;
  expect((await invoke(admin.token, "inventory", "get_item", { path: { id: "one" } })).ok).toBe(false);
  expect(apiRequests).toHaveLength(beforeQuarantine);
  await dialog.getByLabel("Accept get_item", { exact: true }).check();
  await dialog.getByLabel("Effects for get_item", { exact: true }).selectOption("read");
  await expect(dialog.getByText(/Existing grants to review:.*inventory-admin.*inventory-reader/)).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Accept selected operations" })).toBeDisabled();
  await dialog.getByLabel("I reviewed the affected grants and approve these action changes.").check();
  await page.screenshot({ path: testInfo.outputPath("openapi-review.png"), fullPage: true });
  await dialog.getByRole("button", { name: "Accept selected operations" }).click(); await expect(dialog).not.toBeVisible();
  const retained = await browserManagementRequest<{ actions: string[] }>(page, "/v1/admin/policy/grants/inventory-admin");
  expect(retained.actions).toEqual(["get_item", "create_item"]);
  const resumed = await invoke(admin.token, "inventory", "get_item", { path: { id: "one" }, query: { filter: "active" } });
  expect(resumed.ok, await resumed.text()).toBe(true);
  // A private definition has its own token and header, independent of API Bearer delivery.
  await createDraft(page, true);
  await setToken(page, "execution", "synthetic-private-api-token");
  await setToken(page, "discovery", "synthetic-document-token");
  dialog = await loadDefinition(page);
  await dialog.getByRole("button", { name: "Configure API authentication" }).click();
  dialog = page.getByRole("dialog", { name: "Edit imported service" });
  await dialog.getByLabel("API security scheme").selectOption("Bearer");
  await dialog.getByRole("button", { name: "Save configuration" }).click(); await expect(dialog).not.toBeVisible();
  const selectedPrivateScheme = await browserManagementRequest<ImportPreviewResult>(page, "/v1/admin/imports/private_inventory/preview");
  expect(selectedPrivateScheme.service.slotVersions).toEqual({});
  await setToken(page, "execution", "synthetic-private-api-token");
  await setToken(page, "discovery", "synthetic-document-token");
  dialog = await loadDefinition(page);
  await dialog.getByLabel("Effects for get_item", { exact: true }).selectOption("read");
  await dialog.getByLabel("Accept get_item", { exact: true }).check();
  await dialog.getByRole("button", { name: "Accept selected operations" }).click(); await expect(dialog).not.toBeVisible();
  await enable(page, "private_inventory");
  await grant(page, "private_inventory", "admin", "service", ["get_item"]);
  const privateToken = await browserManagementRequest<{ token: string }>(page, "/v1/tokens", { method: "POST", body: { name: "openapi-private", ttl: "8h", allowedServices: ["private_inventory"], allowedExecutionContexts: ["internal"] } });
  const privateRead = await invoke(privateToken.token, "private_inventory", "get_item", { path: { id: "one" } });
  expect(privateRead.ok, await privateRead.text()).toBe(true);
  expect(apiRequests.at(-1)?.path).toBe("/private-api/items/one");
  expect(apiRequests.at(-1)?.headers.authorization).toBe("Bearer synthetic-private-api-token");
  expect(apiRequests.every((request) => request.headers["x-definition-key"] === undefined)).toBe(true);
  expect(documentRequests.filter((request) => request.path === "/private.json").every((request) => request.headers["x-definition-key"] === "synthetic-document-token")).toBe(true);
  expect(documentRequests.every((request) => request.headers.authorization === undefined && request.headers["x-api-key"] === undefined)).toBe(true);
  const privateRecord = await browserManagementRequest<ImportPreviewResult>(page, "/v1/admin/imports/private_inventory/preview");
  expect(privateRecord.service.definition.executionBindings[0].delivery).toEqual({ kind: "bearer" });
  expect(privateRecord.service.definition.connectionSettings.definitionAuthHeader).toBe("X-Definition-Key");
  await page.screenshot({ path: testInfo.outputPath("openapi-private.png"), fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  expect(await page.locator("body").innerText()).not.toContain("synthetic-document-token");
  await fs.writeFile(path.join(root, `result-${testInfo.project.name}.json`), JSON.stringify({ documentRequests: documentRequests.length, apiRequests: apiRequests.length }));
});

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
