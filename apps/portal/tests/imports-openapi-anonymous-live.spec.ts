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
let root = "", baseUrl = "", endpoint = "";
const logs: string[] = [];
let apiServer: Server;
const apiRequests: Array<{ method: string; path: string; headers: IncomingHttpHeaders; body: string }> = [];

function document() {
  return {
    openapi: "3.1.1", info: { title: "Public inventory", version: "1" },
    servers: [{ url: endpoint }], security: [],
    paths: { "/index.html": { get: {
      operationId: "readIndex", description: "Read matching inventory",
      parameters: [{ name: "customer", in: "query", required: true, schema: { type: "string" } }],
      responses: { "200": { description: "Results", content: { "application/json": { schema: { type: "object", properties: { ok: { type: "boolean" } }, required: ["ok"] } } } } }
    } } }
  };
}

test.beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-anonymous-portal-"));
  apiServer = createHttpServer(async (request, response) => {
    const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks).toString();
    apiRequests.push({ method: request.method!, path: request.url!, headers: request.headers, body });
    if (request.headers.authorization !== undefined) {
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


test("anonymous Actions/tools imports onboard and invoke without an upstream credential", async ({ page }, testInfo) => {
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
  // Wait for the available adapter list before filling fields also present
  // on the provisional MCP form.
  await expect(dialog.getByLabel("API base URL")).toBeVisible();
  await dialog.getByLabel("Service ID").fill("inventory");
  await dialog.getByLabel("Display name").fill("Inventory");
  await dialog.getByLabel("API base URL").fill(endpoint);
  await dialog.getByLabel("Upstream authentication", { exact: true }).selectOption("anonymous");
  await expect(dialog.getByLabel("Shared service credential")).toHaveCount(0);
  await expect(dialog.getByLabel("Personal credentials for each user")).toHaveCount(0);
  await expect(dialog.getByLabel("API security scheme")).toHaveCount(0);
  await dialog.getByRole("button", { name: "Upload file", exact: true }).click();
  await dialog.getByLabel("Choose specification JSON file").setInputFiles({ name: "public.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(document())) });
  await dialog.getByRole("button", { name: "Create draft" }).click();
  await expect(page).toHaveURL(/\/services\/inventory\/import$/);
  let current = await browserManagementRequest<ImportPreviewResult>(page, "/v1/admin/imports/inventory/preview");
  expect(current.service.definition.executionBindings).toEqual([]);
  expect(current.service.definition.connectionSettings).toEqual({ definitionSource: "upload" });
  expect(current.service.credentialInputs).toEqual({});
  expect(current.preview?.manifest.tools[0].unsupportedReason).toBeNull();
  await page.getByRole("button", { name: "Review preview", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered operations" });
  await expect(dialog).toContainText("Anonymous upstream");
  await dialog.getByLabel("Effects for readindex", { exact: true }).selectOption("read");
  await dialog.getByLabel("Accept readindex", { exact: true }).check();
  await dialog.getByRole("button", { name: "Accept selected operations" }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.getByRole("button", { name: "Set execution credential", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Enable", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Enable inventory?", exact: true }).getByRole("button", { name: "Enable service" }).click();
  await expect(page.getByRole("alertdialog")).not.toBeVisible();
  expect(apiRequests).toHaveLength(0);
  await browserManagementRequest(page, "/v1/admin/policy/grants", { method: "POST", body: { grantId: "inventory-admin", service: "inventory", subjects: ["user:admin"], actions: ["readindex"], credentialMode: "service", executionContexts: ["internal"], resources: { resourceIds: [], resourceGroupIds: [] }, status: "active" } });
  await browserManagementRequest(page, "/v1/admin/principals/admin/access", { method: "PATCH", body: { agentTokenIssuance: { mode: "read_only", allowedExecutionContexts: ["internal"] } } });
  const token = await browserManagementRequest<{ token: string }>(page, "/v1/tokens", { method: "POST", body: { readOnly: true, name: "anonymous-upstream", ttl: "8h", allowedServices: ["inventory"], allowedExecutionContexts: ["internal"] } });
  const response = await fetch(`${baseUrl}/v1/invoke/inventory/readindex`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token.token}`, "X-Agent-Access-Request-Id": randomUUID() }, body: JSON.stringify({ inputs: { query: { customer: "a +&b" } } }) });
  expect(response.ok, await response.text()).toBe(true);
  expect(apiRequests).toHaveLength(1);
  expect(apiRequests[0].path).toBe("/api/index.html?customer=a%20%2B%26b");
  expect(apiRequests[0].headers.authorization).toBeUndefined();
  expect(apiRequests[0].headers.cookie).toBeUndefined();
  await page.reload();
  await expect(page.getByText("Upstream access is anonymous.", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Edit configuration", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Edit imported service", exact: true });
  await expect(dialog.getByLabel("Upstream authentication", { exact: true })).toHaveValue("anonymous");
  await expect(dialog.getByLabel("Upstream authentication", { exact: true })).toBeDisabled();
  await expect(dialog.getByLabel("API security scheme")).toHaveCount(0);
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  current = await browserManagementRequest<ImportPreviewResult>(page, "/v1/admin/imports/inventory/preview");
  expect(current.service.slotVersions).toEqual({});
  await page.screenshot({ path: testInfo.outputPath("anonymous-actions.png"), fullPage: true });
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
