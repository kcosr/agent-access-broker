import { test, expect, type Page } from "@playwright/test";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { promises as fs } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { createServer as createTcpServer, type AddressInfo } from "node:net";
import { createServer, type Server } from "node:http";
import { once } from "node:events";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { brokerBinary, portalDist } from "./support/binaries";
import { openOAuthWindow, preservePortalDocument } from "./support/oauth-window";
import type { OAuthConnectionTarget } from "../src/types";

test.use({ actionTimeout: 15_000 });
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
let root = "";
let broker: ChildProcessWithoutNullStreams | undefined;
let issuerServer: Server;
let baseUrl = "";
let issuer = "";
let endpoint = "";
const logs: string[] = [];
const authorizations = new Map<string, URLSearchParams>();
const issuedCodes = new Map<string, URLSearchParams>();
const tokenForms: URLSearchParams[] = [];
const upstreamTokens: (string | undefined)[] = [];
const accessToken = "synthetic-mcp-oauth-access-token";
let writeCalls = 0;
let denyWrite = false;
let rejectNextCodeExchange = false;

test.beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-import-oauth-portal-"));
  issuerServer = createServer(async (request, response) => {
    const url = new URL(request.url!, issuer);
    const json = (value: unknown, status = 200) => { response.writeHead(status, { "Content-Type": "application/json" }); response.end(JSON.stringify(value)); };
    if (url.pathname === "/resource-metadata") return json({ resource: endpoint, authorization_servers: [issuer], bearer_methods_supported: ["header"] });
    if (url.pathname === "/issuer-metadata") return json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, response_types_supported: ["code"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"], authorization_response_iss_parameter_supported: true });
    if (url.pathname === "/authorize") {
      if (url.searchParams.get("resource") !== endpoint || url.searchParams.get("code_challenge_method") !== "S256") return json({ error: "invalid_request" }, 400);
      const flow = randomUUID();
      authorizations.set(flow, url.searchParams);
      response.writeHead(200, { "Content-Type": "text/html" });
      response.end(`<html><body><h1>Synthetic MCP consent</h1><p>Requested scope: ${url.searchParams.get("scope")}</p><a href="/consent?flow=${flow}&amp;allow=yes">Allow metrics access</a><a href="/consent?flow=${flow}&amp;allow=no">Deny access</a></body></html>`);
      return;
    }
    if (url.pathname === "/consent") {
      const params = authorizations.get(url.searchParams.get("flow")!);
      if (!params) return json({ error: "invalid_flow" }, 400);
      const callback = new URL(params.get("redirect_uri")!);
      callback.searchParams.set("state", params.get("state")!);
      callback.searchParams.set("iss", issuer);
      if (url.searchParams.get("allow") === "yes") {
        const code = randomUUID(); issuedCodes.set(code, params); callback.searchParams.set("code", code);
      } else callback.searchParams.set("error", "access_denied");
      response.writeHead(302, { Location: callback.toString() }); response.end(); return;
    }
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks).toString();
    if (url.pathname === "/token") {
      const form = new URLSearchParams(body); tokenForms.push(form);
      const authorization = issuedCodes.get(form.get("code")!);
      if (!authorization || form.get("resource") !== endpoint || form.get("scope") !== "metrics.read metrics.write" || createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url") !== authorization.get("code_challenge")) return json({ error: "invalid_grant" }, 400);
      issuedCodes.delete(form.get("code")!);
      if (rejectNextCodeExchange) {
        rejectNextCodeExchange = false;
        return json({ error: "invalid_grant" }, 400);
      }
      // MCP permits access-only authorization; no refresh token is issued.
      return json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, scope: "metrics.read metrics.write" });
    }
    if (url.pathname === "/mcp") {
      upstreamTokens.push(request.headers.authorization);
      if (request.headers.authorization !== `Bearer ${accessToken}`) return json({ error: "unauthorized" }, 401);
      const rpc = JSON.parse(body);
      if (rpc.method === "tools/call" && rpc.params.name === "update") {
        writeCalls += 1;
        if (denyWrite) return json({ error: "forbidden" }, 403);
      }
      const result = rpc.method === "server/discover" ? { supportedVersions: ["2026-07-28"], capabilities: { tools: {} }, ttlMs: 0, cacheScope: "private" } : rpc.method === "tools/list" ? { tools: [{ name: "query", description: "Read metrics with delegated authority", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } }, { name: "update", description: "Change a disposable synthetic metric", inputSchema: { type: "object" } }] } : { content: [{ type: "text", text: "synthetic metric" }] };
      return json({ jsonrpc: "2.0", id: rpc.id, result });
    }
    json({ error: "not_found" }, 404);
  });
  issuerServer.listen(0, "127.0.0.1"); await once(issuerServer, "listening");
  issuer = `http://127.0.0.1:${(issuerServer.address() as AddressInfo).port}`;
  endpoint = `${issuer}/mcp`;
  const listener = createTcpServer(); listener.listen(0, "127.0.0.1"); await once(listener, "listening");
  const port = (listener.address() as AddressInfo).port; await new Promise<void>((resolve) => listener.close(() => resolve()));
  baseUrl = `http://127.0.0.1:${port}`;
  for (const [index, name] of ["encryption", "hash", "csrf", "pepper"].entries()) await fs.writeFile(path.join(root, name), Buffer.alloc(32, index + 1).toString("base64url"));
  const quoted = (name: string) => JSON.stringify(path.join(root, name));
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
allowed_kinds = ["mcp_http"]
allowed_endpoints = ["${endpoint}"]
[oauth.registrations.metrics]
adapter = "mcp_oauth"
base_url = "${issuer}"
redirect_uri = "${baseUrl}/v1/oauth/callback/metrics"
client_id = "synthetic-browser-broker"
client_auth = "none"
encoding = "form"
rotation = "preserve_old"
allow_insecure_loopback = true
[oauth.registrations.metrics.adapter_settings]
resource = "${endpoint}"
protected_resource_metadata_url = "${issuer}/resource-metadata"
authorization_server_metadata_url = "${issuer}/issuer-metadata"
authorization_endpoint = "${issuer}/authorize"
token_endpoint = "${issuer}/token"
[oauth.registrations.metrics.permission_profiles.access]
scopes = ["metrics.read", "metrics.write"]
audience = "${endpoint}"
target = "${endpoint}"
[audit]
type = "jsonl"
path = ${quoted("audit.jsonl")}
[limits]
upload_spool_dir = ${quoted("spool")}
[limits.invocations]
default = { requests = 1000, window = "1m" }
`);
  broker = spawn(brokerBinary, ["--config", path.join(root, "broker.toml"), "serve", "--listen", `127.0.0.1:${port}`], { cwd: repo });
  broker.stdout.on("data", (chunk) => logs.push(String(chunk))); broker.stderr.on("data", (chunk) => logs.push(String(chunk)));
  broker.on("error", (error) => logs.push(error.message));
  await expect.poll(async () => {
    if (broker?.exitCode !== null) throw new Error(logs.join(""));
    try { return (await fetch(`${baseUrl}/v1/healthz`)).ok; } catch { return false; }
  }, { timeout: 30_000 }).toBe(true);
});

test.afterAll(async () => {
  if (broker?.pid && broker.exitCode === null) {
    const stopped = once(broker, "exit"); broker.kill("SIGTERM");
    const timer = setTimeout(() => broker?.kill("SIGKILL"), 5000); await stopped; clearTimeout(timer);
  }
  if (root) await fs.writeFile(path.join(root, "broker.log"), logs.join(""));
  if (issuerServer) await new Promise<void>((resolve) => issuerServer.close(() => resolve()));
  // Retain the DB, logs and fixture for the implementation review.
});

const importTab = /\/ui\/admin\/catalog\/services\/metrics\/import$/;

async function selectImport(page: Page) {
  await page.goto(`${baseUrl}/ui/admin/catalog`);
  await page.getByRole("complementary", { name: "Catalog" }).getByRole("link", { name: /^OAuth metrics/ }).click();
  await page.getByRole("navigation", { name: /sections$/ }).getByRole("link", { name: /^Import/ }).click();
  await expect(page).toHaveURL(importTab);
}

async function managementRequest(page: Page, route: string, body?: unknown): Promise<unknown> {
  return page.evaluate(async ({ route, body }) => {
    const session = await (await fetch("/v1/auth/session", { credentials: "same-origin" })).json();
    const headers: Record<string, string> = { "Content-Type": "application/json", "X-Agent-Access-Request-Id": crypto.randomUUID(), [session.result.csrfHeader]: session.result.csrfToken };
    const response = await fetch(route, { method: body === undefined ? "GET" : "POST", credentials: "same-origin", headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const envelope = await response.json();
    if (!response.ok || !envelope.ok) throw new Error(envelope.error?.message ?? "Management request failed");
    return envelope.result;
  }, { route, body });
}

// The consent return path (`/ui/admin/catalog/services/metrics/import`) comes
// from the broker: it needs a broker whose OAuth `returnPath` accepts
// `/ui/admin/catalog`.
test("administrator connects an OAuth discovery draft, reviews tools and explicitly replaces unknown identity", async ({ page }, testInfo) => {
  await page.goto(`${baseUrl}/ui/admin/catalog`);
  await page.getByLabel("Principal").fill("admin"); await page.getByLabel("Password", { exact: true }).fill("admin-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByLabel("Current password").fill("admin-password");
  await page.getByLabel("New password", { exact: true }).fill("admin-password-updated");
  await page.getByLabel("Confirm new password").fill("admin-password-updated");
  await page.getByRole("button", { name: "Update password" }).click();
  await page.getByRole("main", { name: "Services" }).getByRole("button", { name: "Import service", exact: true }).first().click();
  let dialog = page.getByRole("dialog", { name: "Import service", exact: true });
  await dialog.getByLabel("Service ID").fill("metrics"); await dialog.getByLabel("Display name").fill("OAuth metrics");
  await dialog.getByLabel("HTTP MCP endpoint").fill(endpoint);
  await dialog.getByLabel("Shared service token").uncheck(); await dialog.getByLabel("Personal credentials for each user").check();
  await dialog.getByLabel("Personal authentication").selectOption("oauth");
  await dialog.getByLabel("Discovery credential").selectOption("per_user");
  await expect(dialog.getByRole("button", { name: "Create draft" })).toBeDisabled();
  await dialog.getByLabel("OAuth registration").selectOption("metrics");
  await dialog.getByLabel("Permission profile").selectOption("access");
  await expect(dialog.getByLabel("Credential delivery")).toBeDisabled();
  await expect(dialog.getByText("Requested scopes: metrics.read, metrics.write")).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("oauth-draft.png"), fullPage: true });
  await dialog.getByRole("button", { name: "Create draft" }).click(); await expect(dialog).not.toBeVisible();
  await expect(page).toHaveURL(importTab);
  await expect(page.getByText("No actions accepted yet.")).toBeVisible();
  expect(await managementRequest(page, "/v1/admin/policy/grants")).toEqual([]);
  await expect(page.getByRole("button", { name: "Set personal token", exact: true })).not.toBeVisible();
  const connection = page.getByRole("region", { name: "Connected account" });
  const connect = connection.getByRole("button", { name: "Connect account", exact: true });
  const starts: Array<{ intent: string }> = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/v1/oauth/connect" && request.method() === "POST") starts.push(request.postDataJSON());
  });
  const assertDraftDocument = await preservePortalDocument(page);
  // Browser-contract failures are simulated here; the following consent and
  // callback journeys use the real Broker and synthetic authorization server.
  await page.evaluate(() => {
    const open = window.open;
    window.open = () => { window.open = open; return null; };
  });
  await connect.click();
  await expect(page.getByText("Allow pop-ups for this site, then try connecting again.", { exact: true })).toBeVisible();
  expect(starts).toHaveLength(0);
  expect(page.context().pages()).toHaveLength(1);
  await assertDraftDocument();
  await expect(connect).toBeEnabled();

  await page.route("**/v1/oauth/connect", (route) => route.fulfill({
    status: 503,
    json: { ok: false, reasonCode: "service_unavailable", error: { message: "Synthetic authorization start failed" } }
  }), { times: 1 });
  const failedWindow = page.context().waitForEvent("page");
  await connect.click();
  const abandoned = await failedWindow;
  await expect.poll(() => abandoned.isClosed()).toBe(true);
  await expect(page.getByText("Synthetic authorization start failed (service_unavailable)", { exact: true })).toBeVisible();
  expect(starts).toHaveLength(1);
  expect(authorizations.size).toBe(0);
  await assertDraftDocument();
  await expect(connect).toBeEnabled();

  // Observe focus calls through a real Window handle. Headless browsers do not
  // reliably expose OS focus changes, and the popup navigates across origins.
  await page.evaluate(() => {
    const open = window.open;
    document.documentElement.dataset.oauthFocusCalls = "0";
    window.open = (...args) => {
      window.open = open;
      const popup = open.apply(window, args);
      if (!popup) return null;
      return new Proxy(popup, {
        get(target, property) {
          if (property === "focus") return () => {
            const documentRoot = document.documentElement;
            documentRoot.dataset.oauthFocusCalls = String(Number(documentRoot.dataset.oauthFocusCalls) + 1);
            target.focus();
          };
          return Reflect.get(target, property, target);
        },
        set: (target, property, value) => Reflect.set(target, property, value, target)
      });
    };
  });
  let flow = await openOAuthWindow(page, connect, "Synthetic MCP consent");
  const beforeFocus = starts.length;
  await page.bringToFront();
  await connection.getByRole("button", { name: "Return to authorization tab", exact: true }).click();
  expect(await page.evaluate(() => document.documentElement.dataset.oauthFocusCalls)).toBe("1");
  expect(starts).toHaveLength(beforeFocus);
  expect(page.context().pages()).toHaveLength(2);
  expect(flow.consent.isClosed()).toBe(false);
  await expect(page.getByText("No actions accepted yet.")).toBeVisible();
  await flow.consent.getByRole("link", { name: "Deny access" }).click();
  await flow.finish("canceled", "disconnected");
  await expect(page.getByText("No actions accepted yet.")).toBeVisible();
  await expect(connect).toBeEnabled();
  const savedDraft = await managementRequest(page, "/v1/admin/imports/metrics") as { service: unknown };
  flow = await openOAuthWindow(page, connect, "Synthetic MCP consent");
  // Keep working on an unsaved edit while consent is open. Completion must
  // refresh connection data without replacing the import page or its local form.
  await page.getByRole("button", { name: "Edit configuration", exact: true }).click();
  const draftEdit = page.getByRole("dialog", { name: "Edit imported service", exact: true });
  await draftEdit.getByLabel("Display name").fill("Unsaved metrics draft");
  await flow.consent.addInitScript(() => {
    window.close = () => {
      const root = document.documentElement;
      root.dataset.oauthCloseAttempts = String(Number(root.dataset.oauthCloseAttempts ?? "0") + 1);
    };
  });
  await flow.consent.getByRole("link", { name: "Allow metrics access" }).click();
  await expect(flow.consent.getByRole("heading", { name: "Authorized", exact: true })).toBeVisible();
  await flow.consent.screenshot({ path: testInfo.outputPath("oauth-authorized-fallback.png"), fullPage: true });
  await flow.finish("authorized", "connected", true);
  await expect(draftEdit.getByLabel("Display name")).toHaveValue("Unsaved metrics draft");
  await draftEdit.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(connection.getByText("Upstream account identity unavailable", { exact: false }).first()).toBeVisible();
  await expect(connection.getByText("Connected", { exact: true })).toBeVisible();
  expect((await managementRequest(page, "/v1/admin/imports/metrics") as { service: unknown }).service).toEqual(savedDraft.service);
  const connectedTargets = await managementRequest(page, "/v1/oauth/connections") as OAuthConnectionTarget[];
  const originalConnectionId = connectedTargets.find((target) => target.service === "metrics")?.connection?.connectionId;
  expect(originalConnectionId).toBeTruthy();
  await assertDraftDocument();
  await page.getByRole("button", { name: "Discover tools", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered tools" });
  await dialog.getByLabel("Effects for query", { exact: true }).selectOption("read");
  await dialog.getByLabel("Accept query", { exact: true }).check();
  await dialog.getByLabel("Accept update", { exact: true }).check();
  await dialog.getByRole("button", { name: "Accept selected tools" }).click(); await expect(dialog).not.toBeVisible();
  await page.getByRole("button", { name: "Enable", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Enable metrics?", exact: true }).getByRole("button", { name: "Enable service" }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await managementRequest(page, "/v1/admin/policy/grants", { grantId: "metrics-user", service: "metrics", subjects: ["user:admin"], actions: ["query", "update"], credentialMode: "per_user", executionContexts: ["internal"], resources: { resourceIds: [], resourceGroupIds: [] }, status: "active" });
  const issued = await managementRequest(page, "/v1/tokens", { name: "oauth-browser-agent", ttl: "8h", allowedServices: ["metrics"], allowedExecutionContexts: ["internal"] }) as { token: string };
  const invoke = (action: string) => fetch(`${baseUrl}/v1/invoke/metrics/${action}`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${issued.token}`, "X-Agent-Access-Request-Id": randomUUID() }, body: JSON.stringify({ inputs: {} }) });
  const read = await invoke("query");
  expect(read.ok, await read.text()).toBe(true);
  const write = await invoke("update");
  expect(write.ok, await write.text()).toBe(true);
  expect(writeCalls).toBe(1);
  denyWrite = true;
  const denied = await invoke("update");
  expect(denied.ok).toBe(false);
  expect(writeCalls).toBe(2);
  expect(tokenForms).toHaveLength(1);
  expect(upstreamTokens.length).toBeGreaterThan(0);
  expect(upstreamTokens.every((token) => token === `Bearer ${accessToken}`)).toBe(true);
  expect(tokenForms[0].get("client_secret")).toBeNull();
  expect(tokenForms[0].get("code_verifier")).toBeTruthy();
  // Without identity evidence, reconnecting asks before replacing the connection.
  await connection.getByRole("button", { name: "Reconnect", exact: true }).click();
  const confirmation = page.getByRole("alertdialog", { name: "Replace this connection?" });
  await expect(confirmation).toBeVisible();
  const beforeReplacement = starts.length;
  expect(page.context().pages()).toHaveLength(1);
  await page.screenshot({ path: testInfo.outputPath("oauth-replacement-confirmation.png"), fullPage: true });
  await confirmation.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(confirmation).not.toBeVisible();
  await expect(page).toHaveURL(importTab);
  expect(starts).toHaveLength(beforeReplacement);
  expect(page.context().pages()).toHaveLength(1);
  await connection.getByRole("button", { name: "Reconnect", exact: true }).click();
  flow = await openOAuthWindow(page, confirmation.getByRole("button", { name: "Replace connection", exact: true }), "Synthetic MCP consent");
  expect(starts.at(-1)?.intent).toBe("replace_account");
  await flow.consent.getByRole("link", { name: "Deny access" }).click();
  await flow.finish("canceled", "connected");
  await expect(connection.getByRole("button", { name: "Reconnect", exact: true })).toBeEnabled();
  const retainedRead = await invoke("query");
  expect(retainedRead.ok, await retainedRead.text()).toBe(true);
  expect(tokenForms).toHaveLength(1);
  const deniedReplacement = await managementRequest(page, "/v1/oauth/connections") as OAuthConnectionTarget[];
  expect(deniedReplacement.find((target) => target.service === "metrics")?.connection?.connectionId).toBe(originalConnectionId);
  await connection.getByRole("button", { name: "Reconnect", exact: true }).click();
  flow = await openOAuthWindow(page, confirmation.getByRole("button", { name: "Replace connection", exact: true }), "Synthetic MCP consent");
  expect(starts.at(-1)?.intent).toBe("replace_account");
  await flow.consent.getByRole("link", { name: "Allow metrics access" }).click();
  await flow.finish("authorized", "connected");
  await expect(connection.getByRole("button", { name: "Reconnect", exact: true })).toBeEnabled();
  expect(tokenForms).toHaveLength(2);
  const replaced = await managementRequest(page, "/v1/oauth/connections") as OAuthConnectionTarget[];
  const replacement = replaced.find((target) => target.service === "metrics")?.connection;
  expect(replacement?.connectionId).toBeTruthy();
  expect(replacement?.connectionId).not.toBe(originalConnectionId);
  expect(replacement?.status).toBe("ready");
  await connection.getByRole("button", { name: "Disconnect", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Disconnect account?" }).getByRole("button", { name: "Disconnect", exact: true }).click();
  await expect(connection.getByText("No account connected", { exact: false })).toBeVisible();
  // Connections started in the ordinary Credentials screen keep that destination.
  await page.goto(`${baseUrl}/ui/credentials`);
  flow = await openOAuthWindow(page, page.getByRole("button", { name: "Connect account", exact: true }), "Synthetic MCP consent");
  await flow.consent.getByRole("link", { name: "Deny access" }).click();
  await flow.finish("canceled", "disconnected");
  await expect(page.getByRole("button", { name: "Connect account", exact: true })).toBeEnabled();
  // Authentication can change after import without changing its action/grant
  // identity. Both changes require an explicit review of the existing grant.
  await selectImport(page);
  await page.getByRole("button", { name: "Edit configuration", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Edit imported service", exact: true });
  await dialog.getByLabel("Personal authentication").selectOption("static_token");
  await expect(dialog.getByRole("button", { name: "Save configuration" })).toBeDisabled();
  await dialog.getByLabel(/I reviewed the 1 existing grant/).check();
  await dialog.getByRole("button", { name: "Save configuration" }).click(); await expect(dialog).not.toBeVisible();
  await expect(page.getByText("Personal token", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Edit configuration", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Edit imported service", exact: true });
  await dialog.getByLabel("Personal authentication").selectOption("oauth");
  await dialog.getByLabel("OAuth registration").selectOption("metrics");
  await dialog.getByLabel("Permission profile").selectOption("access");
  await expect(dialog.getByRole("button", { name: "Save configuration" })).toBeDisabled();
  await dialog.getByLabel(/I reviewed the 1 existing grant/).check();
  await dialog.getByRole("button", { name: "Save configuration" }).click(); await expect(dialog).not.toBeVisible();
  await expect(page.getByText("Personal OAuth connection", { exact: false })).toBeVisible();

  // Hold the real Connect response while the user leaves Import. Its reserved
  // window must still reach consent so this server-side flow can be completed.
  let releaseConnect!: () => void;
  const connectReleased = new Promise<void>((resolve) => { releaseConnect = resolve; });
  let receivedConnect!: () => void;
  const connectReceived = new Promise<void>((resolve) => { receivedConnect = resolve; });
  await page.route("**/v1/oauth/connect", async (route) => {
    const response = await route.fetch();
    expect(response.ok()).toBe(true);
    receivedConnect();
    await connectReleased;
    await route.fulfill({ response });
  }, { times: 1 });
  const lateWindow = page.context().waitForEvent("page");
  await connect.click();
  const lateConsent = await lateWindow;
  try {
    await connectReceived;
    await expect(lateConsent).toHaveURL("about:blank");
    await page.getByRole("navigation", { name: /sections$/ }).getByRole("link", { name: /^Actions/ }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/catalog\/services\/metrics$/);
    const assertActionsPreserved = await preservePortalDocument(page);
    expect(lateConsent.isClosed()).toBe(false);
    releaseConnect();
    await expect(lateConsent.getByRole("heading", { name: "Synthetic MCP consent", exact: true })).toBeVisible();
    expect(await lateConsent.evaluate(() => window.opener === null)).toBe(true);
    await lateConsent.getByRole("link", { name: "Deny access" }).click();
    await expect(lateConsent.getByRole("heading", { name: "Authorization canceled", exact: true })).toBeVisible();
    await expect(lateConsent).toHaveURL(`${baseUrl}/v1/oauth/callback/metrics`);
    await assertActionsPreserved();
    expect(lateConsent.isClosed()).toBe(false);
  } finally {
    releaseConnect();
    if (!lateConsent.isClosed()) await lateConsent.close();
  }
  await selectImport(page);

  // A failed real token exchange stays on the callback endpoint. The original
  // page must leave its pending state while that error remains open to read.
  rejectNextCodeExchange = true;
  flow = await openOAuthWindow(page, connect, "Synthetic MCP consent");
  const callbackError = flow.consent.waitForResponse((response) => new URL(response.url()).pathname === "/v1/oauth/callback/metrics");
  await flow.consent.getByRole("link", { name: "Allow metrics access" }).click();
  expect((await callbackError).ok()).toBe(false);
  await flow.finish("failed", "disconnected");
  expect(rejectNextCodeExchange).toBe(false);

  // Closing consent is a separate completion signal. Do this last because the
  // provider flow remains pending until Broker expiry when no callback runs.
  flow = await openOAuthWindow(page, connect, "Synthetic MCP consent");
  const exchangesBeforeClose = tokenForms.length;
  await flow.closeWithoutConsent();
  expect(tokenForms).toHaveLength(exchangesBeforeClose);
  await expect(connect).toBeEnabled();
  await page.screenshot({ path: testInfo.outputPath("oauth-configured.png"), fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  expect(await page.locator("body").innerText()).not.toContain(accessToken);
  await fs.writeFile(path.join(root, `result-${testInfo.project.name}.json`), JSON.stringify({ browser: testInfo.project.name, codeExchanges: tokenForms.length, discoveryRequests: upstreamTokens.length }));
});
