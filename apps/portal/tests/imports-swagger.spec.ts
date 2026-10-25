import { test, expect, type Page } from "@playwright/test";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { promises as fs } from "node:fs";
import type { AddressInfo } from "node:net";
import { createServer as createHttpServer, type Server, type IncomingHttpHeaders } from "node:http";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
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
let root = "", baseUrl = "", endpoint = "", definitionUrl = "";
const logs: string[] = [];
let apiServer: Server, documentServer: Server;
const shared = { username: " opérateur ", token: " päss word: " };
const personal = { username: " lecteur ", token: " personal päss: " };
const reader = { username: " reader ", token: " reader päss: " };
const discovery = { username: " définition ", token: " document päss: " };
const authorization = (value: { username: string; token: string }) => `Basic ${Buffer.from(`${value.username}:${value.token}`).toString("base64")}`;
const documentRequests: Array<{ path: string; headers: IncomingHttpHeaders }> = [];
const apiRequests: Array<{ method: string; path: string; headers: IncomingHttpHeaders; body: string }> = [];

function document() {
  const url = new URL(endpoint);
  return {
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
}

test.beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-swagger-portal-"));
  apiServer = createHttpServer(async (request, response) => {
    const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks).toString();
    apiRequests.push({ method: request.method!, path: request.url!, headers: request.headers, body });
    if (![shared, personal, reader].some((value) => request.headers.authorization === authorization(value))) {
      response.writeHead(401); response.end(); return;
    }
    if (request.method === "DELETE") { response.writeHead(200); response.end(); return; }
    response.writeHead(200, { "Content-Type": "application/json; charset=UTF-8" });
    response.end(JSON.stringify({ ok: true }));
  });
  apiServer.listen(0, "127.0.0.1"); await once(apiServer, "listening");
  const origin = `http://127.0.0.1:${(apiServer.address() as AddressInfo).port}`;
  endpoint = `${origin}/api`;
  documentServer = createHttpServer((request, response) => {
    documentRequests.push({ path: request.url!, headers: request.headers });
    const authorized = request.headers.authorization === authorization(discovery);
    response.writeHead(authorized ? 200 : 401, { "Content-Type": "application/json" });
    response.end(JSON.stringify(authorized ? document() : { error: "unauthorized" }));
  });
  documentServer.listen(0, "127.0.0.1"); await once(documentServer, "listening");
  const documents = `http://127.0.0.1:${(documentServer.address() as AddressInfo).port}`;
  definitionUrl = `${documents}/swagger.json`;
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
allowed_kinds = ["mcp_http", "openapi_http"]
allowed_endpoints = ["${endpoint}", "${definitionUrl}"]
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
  if (documentServer) await new Promise<void>((resolve) => documentServer.close(() => resolve()));
  await releaseTestRoot(root, testInfo, logs.join(""));
});


async function setCredential(page: Page, purpose: "execution" | "discovery", value: { username: string; token: string }) {
  await page.getByRole("button", { name: `Set ${purpose} credential`, exact: true }).click();
  const dialog = page.getByRole("dialog", { name: `Set ${purpose} credential`, exact: true });
  await dialog.getByLabel("Username", { exact: true }).fill(value.username);
  await dialog.getByLabel("Password or API token", { exact: true }).fill(value.token);
  await expect(dialog.getByText("Enter the username and password or API token exactly, including spaces.", { exact: false })).toBeVisible();
  await dialog.getByRole("button", { name: "Save credential", exact: true }).click();
  await expect(dialog).not.toBeVisible();
}

async function grant(page: Page, principal: string, mode: "service" | "per_user", actions: string[]) {
  await browserManagementRequest(page, "/v1/admin/policy/grants", { method: "POST", body: { grantId: `inventory-${principal}-${mode}`, service: "inventory", subjects: [`user:${principal}`], actions, credentialMode: mode, executionContexts: ["internal"], resources: { resourceIds: [], resourceGroupIds: [] }, status: "active" } });
}
const invoke = (token: string, action: string, inputs: unknown) => fetch(`${baseUrl}/v1/invoke/inventory/${action}`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, "X-Agent-Access-Request-Id": randomUUID() }, body: JSON.stringify({ inputs }) });

test("Swagger Basic onboarding and form calls preserve separate discovery, shared and personal credentials", async ({ page }, testInfo) => {
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
  await dialog.getByLabel("Import type").selectOption({ label: "OpenAPI / Swagger" });
  await dialog.getByLabel("Service ID").fill("inventory");
  await dialog.getByLabel("Display name").fill("Inventory");
  await dialog.getByLabel("API base URL").fill(endpoint);
  await dialog.getByLabel("OpenAPI / Swagger definition URL").fill(definitionUrl);
  await dialog.getByLabel("Definition authentication").selectOption("basic");
  await dialog.getByLabel("Personal credentials for each user").check();
  await dialog.getByRole("button", { name: "Create draft" }).click();
  await expect(dialog).not.toBeVisible();
  await setCredential(page, "discovery", discovery);
  await page.getByRole("button", { name: "Load definition", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered operations" });
  await expect(dialog.getByText("Source: Swagger 2.0", { exact: true })).toBeVisible();
  await dialog.getByRole("button", { name: "Configure API authentication" }).click();
  dialog = page.getByRole("dialog", { name: "Edit imported service" });
  await dialog.getByLabel("API security scheme").selectOption("basicAuth");
  await expect(dialog.getByText("Credential delivery: Authorization: Basic.", { exact: false })).toBeVisible();
  await dialog.getByRole("button", { name: "Save configuration" }).click();
  await expect(dialog).not.toBeVisible();
  const draft = await browserManagementRequest<ImportPreviewResult>(page, "/v1/admin/imports/inventory/preview");
  expect(draft.service.slotVersions).toEqual({});
  expect(draft.service.credentialInputs.execution).toMatchObject({ state: "ready", credentialKind: "basic_api_token", inputPolicy: "http_basic" });
  expect(draft.service.credentialInputs.discovery).toMatchObject({ state: "ready", credentialKind: "basic_api_token", inputPolicy: "http_basic" });
  await setCredential(page, "execution", shared);
  await setCredential(page, "discovery", discovery);
  await page.getByRole("button", { name: /^(Load|Refresh) definition$/ }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered operations" });
  await expect(dialog.getByText("POST /search", { exact: false })).toBeVisible();
  await expect(dialog.getByText("application/x-www-form-urlencoded", { exact: false }).first()).toBeVisible();
  await expect(dialog.getByText("Declares no response content (200)", { exact: false })).toBeVisible();
  await expect(dialog.getByLabel("Effects for search", { exact: true })).toHaveValue("write");
  await dialog.getByLabel("Effects for search", { exact: true }).selectOption("read");
  await dialog.getByLabel("Accept search", { exact: true }).check();
  await dialog.getByLabel("Accept erase", { exact: true }).check();
  await page.screenshot({ path: testInfo.outputPath("swagger-form-review.png"), fullPage: true });
  await dialog.getByRole("button", { name: "Accept selected operations" }).click();
  await expect(dialog).not.toBeVisible();
  await page.getByRole("button", { name: "Enable", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Enable inventory?", exact: true }).getByRole("button", { name: "Enable service" }).click();
  await expect(page.getByRole("alertdialog")).not.toBeVisible();
  await grant(page, "admin", "service", ["search"]);
  await grant(page, "admin", "per_user", ["erase"]);
  const admin = await browserManagementRequest<{ token: string }>(page, "/v1/tokens", { method: "POST", body: { name: "swagger-admin", ttl: "8h", allowedServices: ["inventory"], allowedExecutionContexts: ["internal"] } });
  const beforeSearch = apiRequests.length;
  const response = await invoke(admin.token, "search", { body: { query: "open items", ids: "123,456", page: 2 } });
  expect(response.ok, await response.text()).toBe(true);
  expect(apiRequests).toHaveLength(beforeSearch + 1);
  expect(apiRequests.at(-1)).toMatchObject({ method: "POST", path: "/api/search", body: "ids=123%2C456&page=2&query=open+items" });
  expect(apiRequests.at(-1)?.headers["content-type"]).toBe("application/x-www-form-urlencoded");
  expect(apiRequests.at(-1)?.headers.authorization).toBe(authorization(shared));
  const beforeMissing = apiRequests.length;
  expect((await invoke(admin.token, "erase", { body: { ids: "123" } })).ok).toBe(false);
  expect(apiRequests).toHaveLength(beforeMissing);

  // Personal and administered forms consume the same policy and preserve exact input.
  await page.goto(`${baseUrl}/ui/credentials?credential=inventory`);
  let drawer = page.getByRole("complementary", { name: "Inventory credential", exact: true });
  await drawer.getByLabel("Username", { exact: true }).fill(personal.username);
  await drawer.getByLabel("Password or API token", { exact: true }).fill(personal.token);
  await drawer.getByRole("button", { name: "Save credential", exact: true }).click();
  await expect(drawer.getByRole("button", { name: "Replace credential", exact: true })).toBeVisible();
  const erased = await invoke(admin.token, "erase", { body: { ids: "123" } });
  expect(erased.ok, await erased.text()).toBe(true);
  expect(apiRequests).toHaveLength(beforeMissing + 1);
  expect(apiRequests.at(-1)).toMatchObject({ method: "DELETE", path: "/api/items", body: "ids=123" });
  expect(apiRequests.at(-1)?.headers.authorization).toBe(authorization(personal));

  await browserManagementRequest(page, "/v1/admin/principals", { method: "POST", body: { principalId: "reader", kind: "system" } });
  await grant(page, "reader", "per_user", ["search"]);
  await page.goto(`${baseUrl}/ui/admin/principals/reader/credentials?credential=inventory`);
  drawer = page.getByRole("complementary", { name: "Inventory credential", exact: true });
  await drawer.getByLabel("Username", { exact: true }).fill(reader.username);
  await drawer.getByLabel("Password or API token", { exact: true }).fill(reader.token);
  await drawer.getByRole("button", { name: "Save credential", exact: true }).click();
  await expect(drawer.getByRole("button", { name: "Replace credential", exact: true })).toBeVisible();
  const readerToken = await browserManagementRequest<{ token: string }>(page, "/v1/admin/principals/reader/agent-tokens", { method: "POST", body: { name: "swagger-reader", ttl: "8h", allowedServices: ["inventory"], allowedExecutionContexts: ["internal"] } });
  const beforeReader = apiRequests.length;
  const personalRead = await invoke(readerToken.token, "search", { body: { query: "personal" } });
  expect(personalRead.ok, await personalRead.text()).toBe(true);
  expect(apiRequests).toHaveLength(beforeReader + 1);
  expect(apiRequests.at(-1)?.headers.authorization).toBe(authorization(reader));
  expect(documentRequests.length).toBeGreaterThan(0);
  expect(documentRequests.every((request) => request.headers.authorization === authorization(discovery))).toBe(true);
  expect(apiRequests.every((request) => request.headers.authorization !== authorization(discovery))).toBe(true);
  const audit = await fs.readFile(path.join(root, "audit.jsonl"), "utf8");
  const pageText = await page.locator("body").innerText();
  for (const value of [shared, personal, reader, discovery]) {
    expect(audit).not.toContain(value.token);
    expect(audit).not.toContain(authorization(value));
    expect(pageText).not.toContain(value.token);
  }
  await page.screenshot({ path: testInfo.outputPath("swagger-administered-credential.png"), fullPage: true });
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
