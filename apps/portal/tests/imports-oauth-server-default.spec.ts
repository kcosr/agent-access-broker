import { test, expect, type Locator, type Page } from "@playwright/test";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { promises as fs } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import { createServer, type Server } from "node:http";
import { once } from "node:events";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { brokerBinary, portalDist } from "./support/binaries";
import { startBroker } from "./support/broker-process";
import { openOAuthWindow } from "./support/oauth-window";
import { releaseTestRoot } from "./support/test-root";
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
const issuedCodes = new Map<string, { authorization: URLSearchParams; account: string }>();
const tokenForms: URLSearchParams[] = [];
const accessTokens = new Map<string, string>();
const refreshTokens = new Map<string, string>();
const refreshes = new Map<string, number>();
const calls: Array<{ account: string; method: string; action?: string }> = [];

test.beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-mcp-default-portal-"));
  await fs.chmod(root, 0o700);
  issuerServer = createServer(async (request, response) => {
    const url = new URL(request.url!, issuer);
    const json = (value: unknown, status = 200) => { response.writeHead(status, { "Content-Type": "application/json" }); response.end(JSON.stringify(value)); };
    if (url.pathname === "/resource-metadata") return json({ resource: endpoint, authorization_servers: [issuer], bearer_methods_supported: ["header"] });
    if (url.pathname === "/issuer-metadata") return json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, response_types_supported: ["code"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"], authorization_response_iss_parameter_supported: true });
    if (url.pathname === "/authorize") {
      if (url.searchParams.has("scope") || url.searchParams.get("resource") !== endpoint || url.searchParams.get("client_id") !== "synthetic-browser-broker" || url.searchParams.get("redirect_uri") !== `${baseUrl}/v1/oauth/callback/metrics` || url.searchParams.get("code_challenge_method") !== "S256" || !url.searchParams.get("code_challenge")) return json({ error: "invalid_request" }, 400);
      const flow = randomUUID();
      authorizations.set(flow, url.searchParams);
      response.writeHead(200, { "Content-Type": "text/html" });
      response.end(`<html><body><h1>Synthetic MCP consent</h1><p>Server-default permissions</p><a href="/consent?flow=${flow}&amp;account=discovery">Authorize discovery account</a><a href="/consent?flow=${flow}&amp;account=reader">Authorize reader account</a></body></html>`);
      return;
    }
    if (url.pathname === "/consent") {
      const params = authorizations.get(url.searchParams.get("flow")!);
      if (!params) return json({ error: "invalid_flow" }, 400);
      const callback = new URL(params.get("redirect_uri")!);
      callback.searchParams.set("state", params.get("state")!);
      callback.searchParams.set("iss", issuer);
      const account = url.searchParams.get("account");
      if (!account || !["discovery", "reader"].includes(account)) return json({ error: "invalid_account" }, 400);
      const code = randomUUID();
      issuedCodes.set(code, { authorization: params, account });
      callback.searchParams.set("code", code);
      response.writeHead(302, { Location: callback.toString() }); response.end(); return;
    }
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks).toString();
    if (url.pathname === "/token") {
      const form = new URLSearchParams(body); tokenForms.push(form);
      if (form.has("scope") || form.has("client_secret") || form.get("resource") !== endpoint || form.get("client_id") !== "synthetic-browser-broker") return json({ error: "invalid_request" }, 400);
      let account: string;
      let refresh = false;
      if (form.get("grant_type") === "authorization_code") {
        const code = issuedCodes.get(form.get("code")!);
        if (!code || form.get("redirect_uri") !== code.authorization.get("redirect_uri") || createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url") !== code.authorization.get("code_challenge")) return json({ error: "invalid_grant" }, 400);
        issuedCodes.delete(form.get("code")!);
        account = code.account;
      } else if (form.get("grant_type") === "refresh_token") {
        const owner = refreshTokens.get(form.get("refresh_token")!);
        if (!owner) return json({ error: "invalid_grant" }, 400);
        account = owner;
        refresh = true;
        refreshes.set(account, (refreshes.get(account) ?? 0) + 1);
      } else return json({ error: "unsupported_grant_type" }, 400);
      const access = `synthetic-access-${account}-${randomUUID()}`;
      const refreshToken = `synthetic-refresh-${account}`;
      accessTokens.set(access, account);
      refreshTokens.set(refreshToken, account);
      // Code responses omit scope. Only the discovery account's refresh reports it.
      return json({ access_token: access, refresh_token: refreshToken, token_type: "Bearer", expires_in: refresh ? 3600 : 5, ...(refresh && account === "discovery" ? { scope: "metrics.read" } : {}) });
    }
    if (url.pathname === "/mcp") {
      const token = request.headers.authorization?.replace(/^Bearer /, "") ?? "";
      const account = accessTokens.get(token);
      if (!account) return json({ error: "unauthorized" }, 401);
      const rpc = JSON.parse(body);
      calls.push({ account, method: rpc.method, action: rpc.params?.name });
      const result = rpc.method === "server/discover" ? { supportedVersions: ["2026-07-28"], capabilities: { tools: {} }, ttlMs: 0, cacheScope: "private" } : rpc.method === "tools/list" ? { tools: [{ name: "query", description: "Read metrics with delegated authority", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } }, { name: "update", description: "Change a disposable synthetic metric", inputSchema: { type: "object" } }] } : { content: [{ type: "text", text: "synthetic metric" }] };
      return json({ jsonrpc: "2.0", id: rpc.id, result });
    }
    json({ error: "not_found" }, 404);
  });
  issuerServer.listen(0, "127.0.0.1"); await once(issuerServer, "listening");
  issuer = `http://127.0.0.1:${(issuerServer.address() as AddressInfo).port}`;
  endpoint = `${issuer}/mcp`;
  for (const [index, name] of ["encryption", "hash", "csrf", "pepper"].entries()) await fs.writeFile(path.join(root, name), Buffer.alloc(32, index + 1).toString("base64url"));
  const quoted = (name: string) => JSON.stringify(path.join(root, name));
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
scope_mode = "server_default"
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
    return path.join(root, "broker.toml");
  };
  ({ child: broker } = await startBroker({
    binary: brokerBinary,
    configure,
    cwd: repo,
    timeoutMs: 30_000,
    onOutput: (text) => logs.push(text)
  }));
});

test.afterAll(async ({}, testInfo) => {
  if (broker?.pid && broker.exitCode === null) {
    const stopped = once(broker, "exit"); broker.kill("SIGTERM");
    const timer = setTimeout(() => broker?.kill("SIGKILL"), 5000); await stopped; clearTimeout(timer);
  }
  if (issuerServer) await new Promise<void>((resolve) => issuerServer.close(() => resolve()));
  await testInfo.attach("broker-log", { body: logs.join(""), contentType: "text/plain" });
  await releaseTestRoot(root, testInfo, logs.join(""));
});

const importTab = /\/ui\/admin\/catalog\/services\/metrics\/import$/;

async function managementRequest<T = unknown>(page: Page, route: string, body?: unknown, method = body === undefined ? "GET" : "POST"): Promise<T> {
  return page.evaluate(async ({ route, body, method }) => {
    const session = await (await fetch("/v1/auth/session", { credentials: "same-origin" })).json();
    const headers: Record<string, string> = { "Content-Type": "application/json", "X-Agent-Access-Request-Id": crypto.randomUUID(), [session.result.csrfHeader]: session.result.csrfToken };
    const response = await fetch(route, { method, credentials: "same-origin", headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const envelope = await response.json();
    if (!response.ok || !envelope.ok) throw new Error(envelope.error?.message ?? "Management request failed");
    return envelope.result;
  }, { route, body, method });
}

async function signIn(page: Page, principal: string, password: string) {
  await page.getByLabel("Principal").fill(principal);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
}

function invoke(token: string, action = "query") {
  return fetch(`${baseUrl}/v1/invoke/metrics/${action}`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, "X-Agent-Access-Request-Id": randomUUID() }, body: JSON.stringify({ inputs: {} }) });
}

async function refreshThroughRead(token: string, account: string) {
  await expect.poll(async () => {
    const response = await invoke(token);
    expect(response.ok, await response.text()).toBe(true);
    return refreshes.get(account) ?? 0;
  }, { timeout: 15_000, intervals: [250, 500, 1000] }).toBe(1);
}

/**
 * Opens the imported service's row in the Credentials drawer, which shows its
 * permissions and connect availability, runs `check`, then closes the drawer:
 * the OAuth window helper expects the row's actions alone on the page.
 */
async function inConnectionDrawer(page: Page, check: (drawer: Locator) => Promise<void>) {
  await page.getByRole("table", { name: "Credentials" }).getByRole("link", { name: "Default metrics", exact: true }).click();
  const drawer = page.getByRole("complementary", { name: "Default metrics credential", exact: true });
  await expect(drawer).toBeVisible();
  await check(drawer);
  await drawer.getByRole("button", { name: "Close", exact: true }).click();
  await expect(drawer).toHaveCount(0);
}

// The issuer provides no identity claim. Synthetic consent choices make each
// upstream account distinguishable without teaching Broker a provider identity.
test("server-default discovery and group-granted personal connections need no credential rights", async ({ page, browser }, testInfo) => {
  await page.goto(`${baseUrl}/ui/admin/catalog`);
  await signIn(page, "admin", "admin-password");
  await page.getByLabel("Current password").fill("admin-password");
  await page.getByLabel("New password", { exact: true }).fill("admin-password-updated");
  await page.getByLabel("Confirm new password").fill("admin-password-updated");
  await page.getByRole("button", { name: "Update password" }).click();
  await page.getByRole("main", { name: "Services" }).getByRole("button", { name: "Import service", exact: true }).first().click();
  let dialog = page.getByRole("dialog", { name: "Import service", exact: true });
  await dialog.getByLabel("Service ID").fill("metrics");
  await dialog.getByLabel("Display name").fill("Default metrics");
  await dialog.getByLabel("HTTP MCP endpoint").fill(endpoint);
  await dialog.getByLabel("Shared service token").uncheck();
  await dialog.getByLabel("Personal credentials for each user").check();
  await dialog.getByLabel("Personal authentication").selectOption("oauth");
  await dialog.getByLabel("Discovery credential").selectOption("per_user");
  await dialog.getByLabel("OAuth registration").selectOption("metrics");
  await dialog.getByLabel("Permission profile").selectOption("access");
  await expect(dialog.getByText("Server-default permissions", { exact: true })).toBeVisible();
  await expect(dialog.getByText(/Requested scopes:/)).not.toBeVisible();
  await dialog.getByRole("button", { name: "Create draft" }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page).toHaveURL(importTab);
  const connection = page.getByRole("region", { name: "Connected account" });
  await expect(connection.getByText(/Server-default permissions/)).toBeVisible();
  const discoveryFlow = await openOAuthWindow(page, connection.getByRole("button", { name: "Connect account", exact: true }), "Synthetic MCP consent");
  await expect(page.getByText("No actions accepted yet.")).toBeVisible();
  await discoveryFlow.consent.getByRole("link", { name: "Authorize discovery account" }).click();
  await discoveryFlow.finish("authorized", "connected");
  await expect(connection.getByText(/Scope details unavailable/)).toBeVisible();
  await expect(connection.getByText("Connected", { exact: true })).toBeVisible();
  const initial = await managementRequest<OAuthConnectionTarget[]>(page, "/v1/oauth/connections");
  expect(initial[0]).toMatchObject({ scopeMode: "server_default", requestedScopes: [], connection: { subjectId: null, targets: [{ id: endpoint, scopes: [] }] } });
  await page.getByRole("button", { name: "Discover tools", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Review discovered tools" });
  await dialog.getByLabel("Effects for query", { exact: true }).selectOption("read");
  await dialog.getByLabel("Accept query", { exact: true }).check();
  await dialog.getByLabel("Accept update", { exact: true }).check();
  await dialog.getByRole("button", { name: "Accept selected tools" }).click();
  await expect(dialog).not.toBeVisible();
  await page.getByRole("button", { name: "Enable", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Enable metrics?", exact: true }).getByRole("button", { name: "Enable service" }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  expect(calls.some((call) => call.method === "tools/list")).toBe(true);
  expect(calls.every((call) => call.account === "discovery")).toBe(true);

  await managementRequest(page, "/v1/admin/principals", { principalId: "reader", kind: "user", role: "user", selfServiceEnabled: true });
  await managementRequest(page, "/v1/admin/principals/reader/login-methods/local-password/enable", { password: "reader-password", mustChangePassword: false, acknowledgeSeparateSignIn: true });
  await managementRequest(page, "/v1/admin/groups", { groupId: "metric-readers", displayName: "Metric readers" });
  await managementRequest(page, "/v1/admin/groups/metric-readers/members/reader", undefined, "PUT");
  await managementRequest(page, "/v1/admin/policy/grants", { grantId: "metrics-admin", service: "metrics", subjects: ["user:admin"], actions: ["query"], credentialMode: "per_user", executionContexts: ["internal"], resources: { resourceIds: [], resourceGroupIds: [] }, status: "active" });
  await managementRequest(page, "/v1/admin/policy/grants", { grantId: "metrics-readers", service: "metrics", subjects: ["group:metric-readers"], actions: ["query"], credentialMode: "per_user", executionContexts: ["internal"], resources: { resourceIds: [], resourceGroupIds: [] }, status: "active" });
  const tokenRequest = { name: "default-permissions-agent", ttl: "8h", allowedServices: ["metrics"], allowedExecutionContexts: ["internal"] };
  const adminToken = await managementRequest<{ token: string }>(page, "/v1/tokens", tokenRequest);
  await refreshThroughRead(adminToken.token, "discovery");
  await page.reload();
  await expect(connection.getByText(/Server-default permissions/)).toBeVisible();
  await expect(connection.getByText(/Known scopes: metrics.read/)).toBeVisible();
  const refreshed = await managementRequest<OAuthConnectionTarget[]>(page, "/v1/oauth/connections");
  expect(refreshed[0].connection?.targets[0].scopes).toEqual(["metrics.read"]);

  const readerContext = await browser.newContext();
  const reader = await readerContext.newPage();
  try {
    await reader.goto(`${baseUrl}/ui/credentials`);
    await signIn(reader, "reader", "reader-password");
    await inConnectionDrawer(reader, async (drawer) => {
      await expect(drawer.getByText("Server-default permissions", { exact: true })).toBeVisible();
    });
    const session = await managementRequest<{ role: string; selfServiceEnabled: boolean }>(reader, "/v1/auth/session");
    expect(session).toMatchObject({ role: "user", selfServiceEnabled: true });
    const targets = await managementRequest<OAuthConnectionTarget[]>(reader, "/v1/oauth/connections");
    expect(targets[0]).toMatchObject({ canConnect: true, connectUnavailableReason: null, canDisconnect: false, scopeMode: "server_default" });
    expect(targets[0].connection?.connectionId ?? null).toBeNull();
    const readerToken = await managementRequest<{ token: string }>(reader, "/v1/tokens", tokenRequest);
    const beforeConnection = calls.length;
    expect((await invoke(readerToken.token)).ok).toBe(false);
    expect(calls).toHaveLength(beforeConnection);
    const readerFlow = await openOAuthWindow(reader, reader.getByRole("button", { name: "Connect account", exact: true }), "Synthetic MCP consent");
    await readerFlow.consent.getByRole("link", { name: "Authorize reader account" }).click();
    await readerFlow.finish("authorized", "connected");
    await expect(reader.getByText("Connected", { exact: true })).toBeVisible();
    await inConnectionDrawer(reader, async (drawer) => {
      await expect(drawer.getByText("Server-default permissions · Scope details unavailable", { exact: true })).toBeVisible();
    });
    const firstRead = await invoke(readerToken.token);
    expect(firstRead.ok, await firstRead.text()).toBe(true);
    expect(calls.at(-1)?.account).toBe("reader");
    await refreshThroughRead(readerToken.token, "reader");
    expect(calls.slice(beforeConnection).every((call) => call.account === "reader")).toBe(true);
    await reader.reload();
    const readerConnection = await managementRequest<OAuthConnectionTarget[]>(reader, "/v1/oauth/connections");
    expect(readerConnection[0].connection?.connectionId).not.toBe(refreshed[0].connection?.connectionId);
    expect(readerConnection[0].connection?.targets[0].scopes).toEqual([]);
    // Upstream defaults can cover update, but the Broker action grant does not.
    const beforeDenied = calls.length;
    expect((await invoke(readerToken.token, "update")).ok).toBe(false);
    expect(calls).toHaveLength(beforeDenied);
    const adminRead = await invoke(adminToken.token);
    expect(adminRead.ok, await adminRead.text()).toBe(true);
    expect(calls.at(-1)?.account).toBe("discovery");
    const content = await reader.locator("body").innerText();
    for (const token of accessTokens.keys()) expect(content).not.toContain(token);
    await inConnectionDrawer(reader, async (drawer) => {
      await expect(drawer.getByText("Server-default permissions · Scope details unavailable", { exact: true })).toBeVisible();
      await reader.screenshot({ path: testInfo.outputPath("default-permissions-connected-accounts.png"), fullPage: true });
    });

    // Losing setup entitlement retains ownership cleanup, but cannot reconnect
    // or use the account through the now-disabled Broker grant.
    await managementRequest(page, "/v1/admin/policy/grants/metrics-readers/disable", { expectedVersion: 1 });
    await reader.reload();
    const cleanup = await managementRequest<OAuthConnectionTarget[]>(reader, "/v1/oauth/connections");
    expect(cleanup).toHaveLength(1);
    expect(cleanup[0]).toMatchObject({ canConnect: false, connectUnavailableReason: "no_personal_access", canDisconnect: true, connection: { connectionId: readerConnection[0].connection!.connectionId } });
    const unavailable = "Reconnect requires an active grant for your personal account. You can still disconnect this account.";
    const reconnect = reader.getByRole("button", { name: "Reconnect", exact: true });
    await expect(reconnect).toBeDisabled();
    // The disabled button explains why, as does the drawer.
    await expect(reconnect).toHaveAttribute("title", unavailable);
    await inConnectionDrawer(reader, async (drawer) => {
      await expect(drawer.getByText(unavailable, { exact: true })).toBeVisible();
    });
    const beforeRevokedRead = calls.length;
    expect((await invoke(readerToken.token)).ok).toBe(false);
    expect(calls).toHaveLength(beforeRevokedRead);
    await reader.getByRole("button", { name: "Disconnect", exact: true }).click();
    const disconnect = reader.getByRole("alertdialog", { name: "Disconnect account?", exact: true });
    // The reader no longer holds a grant on the import, which is counted rather than named.
    await expect(disconnect.getByText(/1 other service stops using this account/)).toBeVisible();
    await disconnect.getByRole("button", { name: "Disconnect", exact: true }).click();
    await expect(reader.getByRole("table", { name: "Credentials" }).getByRole("link", { name: "Default metrics", exact: true })).toHaveCount(0);
    expect(await managementRequest(reader, "/v1/oauth/connections")).toEqual([]);
  } finally {
    await readerContext.close();
  }
  await page.goto(`${baseUrl}/ui/credentials`);
  await inConnectionDrawer(page, async (drawer) => {
    await expect(drawer.getByText("Server-default permissions · Known scopes: metrics.read", { exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("default-permissions-known-scopes.png"), fullPage: true });
  });
  expect(authorizations.size).toBe(2);
  expect([...authorizations.values()].every((form) => !form.has("scope") && form.get("resource") === endpoint && form.get("code_challenge_method") === "S256")).toBe(true);
  expect(tokenForms.filter((form) => form.get("grant_type") === "authorization_code")).toHaveLength(2);
  expect(tokenForms.filter((form) => form.get("grant_type") === "refresh_token")).toHaveLength(2);
  expect(tokenForms.every((form) => !form.has("scope") && form.get("resource") === endpoint && !form.has("client_secret"))).toBe(true);
});
