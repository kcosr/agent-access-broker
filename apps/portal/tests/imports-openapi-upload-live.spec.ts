import { test, expect, type Page } from "@playwright/test";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { promises as fs } from "node:fs";
import type { AddressInfo } from "node:net";
import { createServer as createHttpServer, type Server, type IncomingHttpHeaders } from "node:http";
import { once } from "node:events";
import { randomUUID, createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { brokerBinary, portalDist } from "./support/binaries";
import { startBroker } from "./support/broker-process";
import { releaseTestRoot } from "./support/test-root";
import type { ImportPreviewResult } from "../src/import-types";

test.use({ actionTimeout: 15_000 });
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
let broker: ChildProcessWithoutNullStreams | undefined;
let root = "", baseUrl = "", endpoint = "";
const logs: string[] = [];
let apiServer: Server;
const shared = { username: " opérateur ", token: " päss word: " };
const authorization = (value: { username: string; token: string }) => `Basic ${Buffer.from(`${value.username}:${value.token}`).toString("base64")}`;
const apiRequests: Array<{ method: string; path: string; headers: IncomingHttpHeaders; body: string }> = [];

function document(replacement = false) {
  const url = new URL(endpoint);
  const value = {
    swagger: "2.0", info: { title: "Synthetic inventory", version: "1" }, host: url.host, basePath: "/api", schemes: ["http"],
    consumes: ["application/x-www-form-urlencoded"], produces: ["application/json"],
    securityDefinitions: { basicAuth: { type: "basic" } }, security: [{ basicAuth: [] }],
    paths: {
      "/search": { post: { operationId: "search", description: "Search items", parameters: [
        { name: "query", in: "formData", type: "string", required: true },
        { name: "ids", in: "formData", type: "string" },
        { name: "page", in: "formData", type: "integer" }
      ], responses: { "200": { description: "Results", schema: { type: "object", properties: { ok: { type: "boolean" } }, required: ["ok"] } } } } },
      "/items": { delete: { operationId: "erase", description: "Erase selected items", parameters: [{ name: "ids", in: "formData", type: "string", required: true }], responses: { "200": { description: "No content" } } } }
    }
  };
  if (replacement) {
    value.paths["/search"].post.parameters.push({ name: "sort", in: "formData", type: "string" });
    delete (value.paths as Record<string, unknown>)["/items"];
    (value.paths as Record<string, unknown>)["/export"] = {
      get: { operationId: "export", responses: { "200": { description: "Export", schema: { type: "object", properties: { ok: { type: "boolean" } }, required: ["ok"] } } } }
    };
  }
  return value;
}

test.beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-upload-portal-"));
  apiServer = createHttpServer(async (request, response) => {
    const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks).toString();
    apiRequests.push({ method: request.method!, path: request.url!, headers: request.headers, body });
    if (request.headers.authorization !== authorization(shared)) {
      response.writeHead(401); response.end(); return;
    }
    if (request.method === "DELETE") { response.writeHead(200); response.end(); return; }
    response.writeHead(200, { "Content-Type": "application/json; charset=UTF-8" });
    response.end(JSON.stringify({ ok: true }));
  });
  apiServer.listen(0, "127.0.0.1"); await once(apiServer, "listening");
  const origin = `http://127.0.0.1:${(apiServer.address() as AddressInfo).port}`;
  endpoint = `${origin}/api`;
  for (const [index, name] of ["encryption", "hash", "csrf", "pepper"].entries()) {
    await fs.writeFile(path.join(root, name), Buffer.alloc(32, index + 1).toString("base64url"));
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
allowed_kinds = ["openapi_http"]
allowed_endpoints = ["${endpoint}"]
[audit]
type = "jsonl"
path = ${quoted("audit.jsonl")}
[limits]
upload_spool_dir = ${quoted("spool")}
[limits.invocations]
default = { requests = 1000, window = "1m" }
`);
    return path.join(root, "broker.toml");
  };
  ({ child: broker } = await startBroker({
    binary: brokerBinary,
    configure,
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
  if (apiServer) await new Promise<void>((resolve) => apiServer.close(() => resolve()));
  await releaseTestRoot(root, testInfo, logs.join(""));
});


test("uploaded Swagger source persists through authentication setup, offline reload and reviewed replacement without expanding grants", async ({ page }, testInfo) => {
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
  await dialog.getByLabel("Service ID").fill("inventory");
  await dialog.getByLabel("Display name").fill("Inventory");
  await dialog.getByLabel("API base URL").fill(endpoint);
  await dialog.getByRole("button", { name: "Upload file", exact: true }).click();
  const original = Buffer.from(`\n${JSON.stringify(document(), null, 2)}\n`);
  await dialog.getByLabel("Choose specification JSON file").setInputFiles({ name: "inventory.json", mimeType: "application/json", buffer: original });
  await expect(dialog).toContainText("Swagger 2.0");
  await page.screenshot({ path: testInfo.outputPath("upload-selected.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(dialog.getByRole("button", { name: "Upload file", exact: true })).toHaveAttribute("aria-pressed", "true");
  await dialog.getByRole("button", { name: "Replace file", exact: true }).focus();
  await expect(dialog.getByRole("button", { name: "Replace file", exact: true })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(dialog.getByRole("button", { name: "Remove", exact: true })).toBeFocused();
  const layout = await dialog.getByRole("group", { name: "Specification file", exact: true }).evaluate((element) => {
    const bounds = element.getBoundingClientRect();
    return { left: bounds.left, right: bounds.right, width: window.innerWidth, scrollWidth: document.documentElement.scrollWidth };
  });
  expect(layout.left).toBeGreaterThanOrEqual(0);
  expect(layout.right).toBeLessThanOrEqual(layout.width);
  expect(layout.scrollWidth).toBeLessThanOrEqual(layout.width);
  await page.screenshot({ path: testInfo.outputPath("upload-selected-narrow.png"), fullPage: true });
  await page.setViewportSize({ width: 1280, height: 900 });
  await dialog.getByRole("button", { name: "Create draft" }).click();
  await expect(page).toHaveURL(/\/services\/inventory\/import$/);
  await expect(page.getByText("inventory.json", { exact: false })).toBeVisible();
  const initial = await browserManagementRequest<ImportPreviewResult>(page, "/v1/admin/imports/inventory/preview");
  expect(initial.service.definition.connectionSettings).toEqual({ definitionSource: "upload" });
  expect(initial.service.document).toEqual({ filename: "inventory.json", byteLength: original.length, sha256: createHash("sha256").update(original).digest("hex") });
  expect(initial.preview?.manifest.protocolVersion).toBe("2.0");
  expect(initial.service.actions).toEqual([]);
  expect(apiRequests).toHaveLength(0);
  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered operations" });
  await dialog.getByRole("button", { name: "Configure API authentication" }).click();
  dialog = page.getByRole("dialog", { name: "Edit imported service" });
  await expect(dialog.getByLabel("Definition authentication")).toHaveCount(0);
  await dialog.getByLabel("API security scheme").selectOption("basicAuth");
  await dialog.getByRole("button", { name: "Save configuration" }).click();
  await expect(dialog).not.toBeVisible();
  let current = await browserManagementRequest<ImportPreviewResult>(page, "/v1/admin/imports/inventory/preview");
  expect(current.service.document).toEqual(initial.service.document);
  expect(current.service.credentialInputs.execution).toMatchObject({ state: "ready", credentialKind: "basic_api_token", inputPolicy: "http_basic" });
  expect(current.service.credentialInputs).not.toHaveProperty("discovery");
  await page.getByRole("button", { name: "Set execution credential", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Set execution credential", exact: true });
  await dialog.getByLabel("Username", { exact: true }).fill(shared.username);
  await dialog.getByLabel("Password or API token", { exact: true }).fill(shared.token);
  await dialog.getByRole("button", { name: "Save credential", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  // Reload discards every browser File object. Rediscovery must use the Broker's retained bytes.
  await page.reload();
  await page.getByRole("button", { name: "Load saved definition", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered operations" });
  await expect(dialog).toContainText("Source: Swagger 2.0");
  await expect(dialog).toContainText("application/x-www-form-urlencoded");
  await dialog.getByLabel("Effects for search", { exact: true }).selectOption("read");
  await dialog.getByLabel("Accept search", { exact: true }).check();
  await dialog.getByLabel("Accept erase", { exact: true }).check();
  await dialog.getByRole("button", { name: "Accept selected operations" }).click();
  await expect(dialog).not.toBeVisible();
  expect(apiRequests).toHaveLength(0);
  await page.getByRole("button", { name: "Enable", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Enable inventory?", exact: true }).getByRole("button", { name: "Enable service" }).click();
  await expect(page.getByRole("alertdialog")).not.toBeVisible();
  await browserManagementRequest(page, "/v1/admin/policy/grants", { method: "POST", body: { grantId: "inventory-admin", service: "inventory", subjects: ["user:admin"], actions: ["search", "erase"], credentialMode: "service", executionContexts: ["internal"], resources: { resourceIds: [], resourceGroupIds: [] }, status: "active" } });
  const token = await browserManagementRequest<{ token: string }>(page, "/v1/tokens", { method: "POST", body: { name: "uploaded-source", ttl: "8h", allowedServices: ["inventory"], allowedExecutionContexts: ["internal"] } });
  const invoke = (action: string, inputs: unknown) => fetch(`${baseUrl}/v1/invoke/inventory/${action}`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token.token}`, "X-Agent-Access-Request-Id": randomUUID() }, body: JSON.stringify({ inputs }) });
  const response = await invoke("search", { body: { query: "open items", ids: "123,456" } });
  expect(response.ok, await response.text()).toBe(true);
  expect(apiRequests).toHaveLength(1);
  expect(apiRequests[0]).toMatchObject({ method: "POST", path: "/api/search", body: "ids=123%2C456&query=open+items" });
  expect(apiRequests[0].headers.authorization).toBe(authorization(shared));
  await page.getByRole("button", { name: "Edit configuration", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Edit imported service", exact: true });
  await expect(dialog.getByRole("button", { name: "From URL", exact: true })).toBeDisabled();
  await expect(dialog.getByRole("button", { name: "Upload file", exact: true })).toBeDisabled();
  await expect(dialog.getByLabel("API security scheme")).toBeDisabled();
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();

  current = await browserManagementRequest<ImportPreviewResult>(page, "/v1/admin/imports/inventory/preview");
  const grants = await browserManagementRequest<unknown>(page, "/v1/admin/policy/grants");
  await page.getByRole("button", { name: "Upload replacement", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Upload replacement definition", exact: true });
  // Local syntax checks leave duplicate-member rejection to the Broker and preserve its exact bytes.
  const duplicate = Buffer.from('{"swagger":"2.0",' + JSON.stringify(document()).slice(1));
  await dialog.getByLabel("Choose specification JSON file").setInputFiles({ name: "invalid.json", mimeType: "application/json", buffer: duplicate });
  const refused = page.waitForResponse((response) => response.url().includes("/imports/inventory/document?") && response.request().method() === "PUT");
  await dialog.getByRole("button", { name: "Upload and review" }).click();
  expect((await refused).status()).toBe(400);
  await expect(dialog.getByRole("alert")).toBeVisible();
  const unchanged = await browserManagementRequest<ImportPreviewResult>(page, "/v1/admin/imports/inventory/preview");
  expect(unchanged.service).toEqual(current.service);
  expect(unchanged.preview).toEqual(current.preview);
  expect(unchanged.catalogRevision).toBe(current.catalogRevision);
  expect(await browserManagementRequest(page, "/v1/admin/policy/grants")).toEqual(grants);
  expect(apiRequests).toHaveLength(1);
  const replacement = Buffer.from(JSON.stringify(document(true)));
  await dialog.getByLabel("Choose specification JSON file").setInputFiles({ name: "inventory-v2.json", mimeType: "application/json", buffer: replacement });
  await expect(dialog.getByRole("button", { name: "Upload and review" })).toBeDisabled();
  await dialog.getByRole("button", { name: "Reload current state" }).click();
  await expect(dialog.getByLabel("Stored definition document")).toContainText("inventory.json");
  await expect(dialog.getByRole("group", { name: "Specification file", exact: true })).toContainText("inventory-v2.json");
  await dialog.getByRole("button", { name: "Upload and review" }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered operations", exact: true });
  await expect(dialog).toBeVisible();
  const refreshed = await browserManagementRequest<ImportPreviewResult>(page, "/v1/admin/imports/inventory/preview");
  expect(refreshed.service.document).toEqual({ filename: "inventory-v2.json", byteLength: replacement.length, sha256: createHash("sha256").update(replacement).digest("hex") });
  expect(refreshed.service.actions.map((action) => [action.definition.action, action.status]).sort()).toEqual([["erase", "quarantined"], ["search", "quarantined"]]);
  expect(refreshed.service.slotVersions).toEqual(current.service.slotVersions);
  expect(await browserManagementRequest(page, "/v1/admin/policy/grants")).toEqual(grants);
  expect((await invoke("search", { body: { query: "blocked" } })).ok).toBe(false);
  expect(apiRequests).toHaveLength(1);
  await dialog.getByLabel("Effects for search", { exact: true }).selectOption("read");
  await dialog.getByLabel("Accept search", { exact: true }).check();
  await dialog.getByLabel("Accept export", { exact: true }).check();
  await dialog.getByLabel("I reviewed the affected grants and approve these action changes.", { exact: true }).check();
  await page.screenshot({ path: testInfo.outputPath("upload-replacement-review.png"), fullPage: true });
  await dialog.getByRole("button", { name: "Accept selected operations" }).click();
  await expect(dialog).not.toBeVisible();
  expect(await browserManagementRequest(page, "/v1/admin/policy/grants")).toEqual(grants);
  expect((await invoke("export", {})).ok).toBe(false);
  expect((await invoke("erase", { body: { ids: "123" } })).ok).toBe(false);
  expect(apiRequests).toHaveLength(1);
  const updated = await invoke("search", { body: { query: "open", sort: "recent" } });
  expect(updated.ok, await updated.text()).toBe(true);
  expect(apiRequests).toHaveLength(2);
  expect(apiRequests.at(-1)?.body).toBe("query=open&sort=recent");
  await page.reload();
  await expect(page.getByText("inventory-v2.json", { exact: false })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("upload-retained-source.png"), fullPage: true });
  const audit = await fs.readFile(path.join(root, "audit.jsonl"), "utf8");
  expect(audit).not.toContain(shared.token);
  expect(audit).not.toContain(authorization(shared));
  expect(audit).not.toContain(original.toString());
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
