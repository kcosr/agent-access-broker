import { test, expect, type Page, type TestInfo } from "@playwright/test";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { promises as fs } from "node:fs";
import { createServer, type AddressInfo } from "node:net";
import { once } from "node:events";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { brokerBinary, portalDist } from "./support/binaries";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
let broker: ChildProcessWithoutNullStreams | undefined;
let root = "";
let baseUrl = "";
const logs: string[] = [];

test.beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-teams-portal-"));
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
[providers.teams]
allowed_upstream_hosts = ["https://portal-fixture.environment.api.powerplatform.com/**"]
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
  if (root) await fs.rm(root, { recursive: true, force: true });
});

test("Teams destinations keep secrets private across creation, reveal and replacement", async ({ page }, testInfo) => {
  await page.goto(`${baseUrl}/ui/admin/catalog/resources`);
  await page.getByLabel("Principal").fill("admin");
  await page.getByLabel("Password").fill("admin-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByLabel("Current password").fill("admin-password");
  await page.getByLabel("New password", { exact: true }).fill("admin-password-updated");
  await page.getByLabel("Confirm new password").fill("admin-password-updated");
  await page.getByRole("button", { name: "Update password" }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/catalog\/resources$/);
  await exercisePrivateResourceAttributes(page, testInfo);
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

// Only broker management is exercised; these signed-looking fixture URLs are never posted.
async function exercisePrivateResourceAttributes(page: Page, testInfo: TestInfo) {
  const endpoint = "https://portal-fixture.environment.api.powerplatform.com/workflows/test?sig=synthetic-first";
  const replacement = endpoint.replace("synthetic-first", "synthetic-second");
  const reveals: string[] = [];
  page.on("request", request => { if (request.url().endsWith("/attributes/webhookUrl/reveal")) reveals.push(request.method()); });
  await page.goto(`${baseUrl}/ui/admin/catalog/resources`);
  await page.getByRole("main").getByRole("button", { name: "Add resource", exact: true }).first().click();
  const add = page.getByRole("complementary", { name: "Add resource", exact: true });
  await add.getByLabel("Resource type").selectOption("teams_notification_destination");
  await expect(add.getByLabel("Webhook URL", { exact: true })).toBeVisible();
  await add.getByLabel("Coverage").selectOption("all");
  await expect(add.getByLabel("Webhook URL", { exact: true })).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("teams-all.png"), fullPage: true });
  await add.getByLabel("Coverage").selectOption("exact");
  await add.getByLabel("Canonical identifier").fill("portal-release-alerts");
  await add.getByLabel("Display name").fill("Release alerts");
  await add.getByLabel("Webhook URL", { exact: true }).fill(endpoint);
  await add.getByRole("group", { name: "Allowed execution contexts" }).getByLabel("default", { exact: true }).check();
  await expect(add.getByRole("button", { name: "Save resource" })).toBeEnabled();
  await page.screenshot({ path: testInfo.outputPath("teams-create.png"), fullPage: true });
  const created = page.waitForResponse(response => response.request().method() === "POST" && new URL(response.url()).pathname === "/v1/admin/policy/resources");
  await add.getByRole("button", { name: "Save resource" }).click();
  const creation = await (await created).json();
  expect(JSON.stringify(creation)).not.toContain(endpoint);
  await expect(add).toHaveCount(0);
  // The new resource opens in its detail drawer; the value stays hidden until revealed.
  let details = page.getByRole("complementary", { name: "Resource Release alerts", exact: true });
  await expect(details.getByLabel("Webhook URL", { exact: true })).not.toHaveValue(endpoint);
  expect(reveals).toEqual([]);
  await details.getByRole("button", { name: "Edit", exact: true }).click();
  const edit = page.getByRole("complementary", { name: /^Edit resource / });
  await expect(edit.getByLabel("Current Webhook URL")).not.toHaveValue(endpoint);
  expect(reveals).toEqual([]);
  await expect(edit.getByLabel("Resource type")).toBeDisabled();
  await expect(edit.getByLabel("Coverage")).toBeDisabled();
  await page.screenshot({ path: testInfo.outputPath("teams-edit.png"), fullPage: true });
  await edit.getByRole("button", { name: "Reveal Webhook URL" }).click();
  await expect(edit.getByLabel("Current Webhook URL")).toHaveValue(endpoint);
  await edit.getByRole("button", { name: "Hide Webhook URL" }).click();
  await expect(edit.getByLabel("Current Webhook URL")).not.toHaveValue(endpoint);
  await edit.getByLabel("Display name").fill("Release notifications");
  const patched = page.waitForRequest(request => request.method() === "PATCH" && new URL(request.url()).pathname.startsWith("/v1/admin/policy/resources/"));
  await edit.getByRole("button", { name: "Save resource" }).click();
  expect((await patched).postDataJSON()).not.toHaveProperty("attributes");
  await expect(edit).toHaveCount(0);
  details = page.getByRole("complementary", { name: "Resource Release notifications", exact: true });
  await details.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(edit.getByLabel("Replacement Webhook URL")).toHaveValue("");
  await edit.getByRole("button", { name: "Reveal Webhook URL" }).click();
  await expect(edit.getByLabel("Current Webhook URL")).toHaveValue(endpoint);
  await edit.getByLabel("Replacement Webhook URL").fill(replacement);
  await edit.getByRole("button", { name: "Save resource" }).click();
  await expect(edit).toHaveCount(0);
  await details.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(edit.getByLabel("Current Webhook URL")).not.toHaveValue(replacement);
  await edit.getByRole("button", { name: "Reveal Webhook URL" }).click();
  await expect(edit.getByLabel("Current Webhook URL")).toHaveValue(replacement);
  await edit.getByRole("button", { name: "Close", exact: true }).click();
  expect(reveals).toEqual(["POST", "POST", "POST"]);
  const catalog = await browserManagementRequest<Array<{id: string; version: number; selector: {value?: string}}>>(page, "/v1/admin/policy/resources");
  expect(JSON.stringify(catalog)).not.toContain("synthetic-");
  const resource = catalog.find(item => item.selector.value === "portal-release-alerts")!;
  await page.goto(`${baseUrl}/ui/admin/policies/new`);
  await page.getByLabel("Grant ID").fill("teams-portal-grant");
  const subjects = page.locator("#grant-subjects");
  await subjects.getByRole("group", { name: "Subject type", exact: true }).getByRole("button", { name: "User", exact: true }).click();
  await subjects.getByRole("combobox", { name: "User", exact: true }).fill("admin");
  await page.getByRole("listbox").getByRole("option", { name: /^admin/ }).first().click();
  await page.getByRole("combobox", { name: "Service", exact: true }).selectOption("teams");
  await page.getByRole("checkbox", { name: "notification.send", exact: true }).check();
  await expect(page.getByLabel("Credential mode")).toHaveValue("service");
  await page.getByRole("group", { name: "Resources", exact: true }).getByRole("checkbox", { name: /Release notifications/ }).check();
  const create = page.getByRole("region", { name: "Save grant", exact: true }).getByRole("button", { name: "Create grant", exact: true });
  await expect(create).toBeEnabled();
  await page.screenshot({ path: testInfo.outputPath("teams-grant.png"), fullPage: true });
  await create.click();
  await expect(page).toHaveURL(/\/ui\/admin\/policies\?grant=teams-portal-grant$/);
  const saved = await browserManagementRequest<{credentialMode: string; resources: {resourceIds: string[]}}>(page, "/v1/admin/policy/grants/teams-portal-grant");
  expect(saved.credentialMode).toBe("service");
  expect(saved.resources.resourceIds).toEqual([resource.id]);
  await browserManagementRequest(page, "/v1/admin/policy/grants/teams-portal-grant?expectedVersion=1", { method: "DELETE" });
  await browserManagementRequest(page, `/v1/admin/policy/resources/${resource.id}?expectedVersion=${resource.version}`, { method: "DELETE" });
}
