// Real Broker + SQLite acceptance: no API routing or seeded audit records.
import { expect, test, type Page, type Response } from "@playwright/test";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { promises as fs } from "node:fs";
import { createServer, type AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import type { AuditRecord, CatalogMutation, ResourceGroupRecord, ResourceRecord } from "../src/types";
import { brokerBinary, portalDist, repoRoot } from "./support/binaries";

let broker: ChildProcessWithoutNullStreams | undefined;
let root = "";
let baseUrl = "";
const logs: string[] = [];
const resourcePath = "/v1/admin/policy/resources";
const groupPath = "/v1/admin/policy/resource-groups";
const resourceName = "Payments API";
const renamedResource = "Payments service";
const groupName = "Engineering repositories";
const selector = "engineering/payments";

test.beforeAll(async () => {
  await fs.access(path.join(portalDist, "index.html"));
  root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-resource-audit-"));
  const listener = createServer();
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  const port = (listener.address() as AddressInfo).port;
  await new Promise<void>((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
  baseUrl = `http://127.0.0.1:${port}`;
  for (const [index, name] of ["encryption", "hash", "csrf", "pepper"].entries()) {
    await fs.writeFile(path.join(root, name), Buffer.alloc(32, index + 1).toString("base64url"));
  }
  await fs.writeFile(path.join(root, "git-token"), "synthetic-unused-git-token");
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
[credentials.service.gitlab_git]
type = "bearer_token"
token_ref = "file:${root}/git-token"
[gateways.gitlab_git]
kind = "git_http"
display_name = "GitLab Git"
broker_hosts = ["git.example.test"]
upstream_base_url = "https://gitlab.example.test"
allowed_upstream_hosts = ["https://gitlab.example.test/**"]
auth_modes = ["basic_broker_token"]
credential_modes = ["service"]
[gateways.gitlab_git.git]
allow_fetch = true
allow_push = false
[policy]
authority = "managed"
default_decision = "deny"
[audit]
type = "sqlite"
path = ${quoted("audit.sqlite")}
[limits]
upload_spool_dir = ${quoted("spool")}
[limits.invocations]
default = { requests = 1000, window = "1m" }
`);
  broker = spawn(brokerBinary, ["--config", path.join(root, "broker.toml"), "serve", "--listen", `127.0.0.1:${port}`], {
    cwd: repoRoot,
    env: { ...process.env, RUST_LOG: "agent_access_broker=warn,agent_access_core=warn" },
  });
  broker.stdout.on("data", chunk => logs.push(String(chunk)));
  broker.stderr.on("data", chunk => logs.push(String(chunk)));
  await expect.poll(async () => {
    if (broker?.exitCode !== null) throw new Error(`Broker exited before readiness\n${logs.join("")}`);
    try {
      return (await fetch(`${baseUrl}/v1/healthz`, { headers: { "X-Agent-Access-Request-Id": randomUUID() } })).ok;
    } catch { return false; }
  }, { timeout: 60_000 }).toBe(true);
});

test.afterEach(async ({}, testInfo) => {
  if (testInfo.status !== testInfo.expectedStatus) {
    await testInfo.attach("broker.log", { body: logs.join(""), contentType: "text/plain" });
  }
});

test.afterAll(async () => {
  if (broker && broker.exitCode === null) {
    const exited = once(broker, "exit");
    broker.kill("SIGTERM");
    const timer = setTimeout(() => broker?.kill("SIGKILL"), 5000);
    await exited;
    clearTimeout(timer);
  }
  if (root) await fs.rm(root, { recursive: true, force: true });
});

function mutation(page: Page, method: string, pathname: string) {
  return page.waitForResponse(response => response.request().method() === method && new URL(response.url()).pathname === pathname);
}

async function saved<T>(response: Promise<Response>) {
  const completed = await response;
  const envelope = await completed.json();
  expect(envelope, `mutation returned HTTP ${completed.status()}`).toMatchObject({ ok: true });
  return envelope as { brokerRequestId: string; result: CatalogMutation<T> };
}

async function browserRead<T>(page: Page, pathname: string, headers: Record<string, string> = {}) {
  const response = await page.request.get(`${baseUrl}${pathname}`, {
    headers: { "X-Agent-Access-Request-Id": randomUUID(), ...headers },
  });
  const envelope = await response.json();
  expect(envelope, `browser read returned HTTP ${response.status()}`).toMatchObject({ ok: true });
  return envelope.result as T;
}

function management(record: AuditRecord) {
  return record.providerAudit?.management as { phase?: string; target?: Record<string, unknown>; change?: Record<string, unknown> } | undefined;
}

async function completedAudit(page: Page, brokerRequestId: string, operation: string) {
  const timeline = await browserRead<{ items: AuditRecord[] }>(page, `/v1/admin/audit/requests/${encodeURIComponent(brokerRequestId)}`);
  expect(timeline.items.map(record => management(record)?.phase)).toEqual(["preflight", "success"]);
  const completion = timeline.items[1];
  expect(completion).toMatchObject({ action: operation, decision: "allow", brokerRequestId });
  return completion;
}

async function searchAudit(page: Page, query: string) {
  // The search field is debounced. Wait for the applied URL and real query,
  // since the matching row can also be visible in the previous result set.
  const queried = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.pathname === "/v1/admin/audit/events" && url.searchParams.get("q") === query;
  });
  await page.getByRole("searchbox", { name: "Search", exact: true }).fill(query);
  await expect.poll(() => new URL(page.url()).searchParams.get("q")).toBe(query);
  expect((await queried).ok()).toBe(true);
}

test("repository and membership audit shows committed names, historical changes, and current links", async ({ page }, testInfo) => {
  const pageErrors: string[] = [];
  page.on("pageerror", error => pageErrors.push(error.message));
  page.on("console", message => {
    if (message.type() === "error" && /Content Security Policy|Refused to (apply|load|execute)/i.test(message.text())) pageErrors.push(message.text());
  });
  await page.goto(`${baseUrl}/ui/admin/catalog/resources`);
  await page.getByLabel("Principal").fill("admin");
  await page.getByLabel("Password").fill("admin-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByLabel("Current password").fill("admin-password");
  await page.getByLabel("New password", { exact: true }).fill("admin-password-updated");
  await page.getByLabel("Confirm new password").fill("admin-password-updated");
  await page.getByRole("button", { name: "Update password" }).click();
  await expect(page).toHaveURL(/\/ui\/admin\/catalog\/resources$/);

  await page.getByRole("main").getByRole("button", { name: "Add resource", exact: true }).first().click();
  const add = page.getByRole("complementary", { name: "Add resource", exact: true });
  await add.getByLabel("Resource type").selectOption("git_repository");
  await add.getByLabel("Canonical identifier").fill(selector);
  await add.getByLabel("Display name").fill(resourceName);
  await add.getByRole("group", { name: "Allowed execution contexts" }).getByLabel("default", { exact: true }).check();
  const creation = mutation(page, "POST", resourcePath);
  await add.getByRole("button", { name: "Save resource", exact: true }).click();
  const created = await saved<ResourceRecord>(creation);
  const resourceId = created.result.record.id;
  await expect(page.getByRole("complementary", { name: `Resource ${resourceName}`, exact: true })).toBeVisible();
  const createEvent = await completedAudit(page, created.brokerRequestId, "admin.policy.resources.create");
  expect(management(createEvent)).toMatchObject({
    target: { kind: "resource", id: resourceId, displayName: resourceName, resourceType: "git_repository", selector: { kind: "exact", value: selector } },
    change: { before: null, after: { displayName: resourceName }, revision: created.result.revision },
  });

  await page.goto(`${baseUrl}/ui/admin/catalog/resource-groups`);
  await page.getByRole("main").getByRole("button", { name: "Add resource group", exact: true }).first().click();
  const groupAdd = page.getByRole("complementary", { name: "Add resource group", exact: true });
  await groupAdd.getByLabel("Group name").fill(groupName);
  const groupCreation = mutation(page, "POST", groupPath);
  await groupAdd.getByRole("button", { name: "Save resource group", exact: true }).click();
  const groupCreated = await saved<ResourceGroupRecord>(groupCreation);
  const groupId = groupCreated.result.record.id;
  const groupDetails = page.getByRole("complementary", { name: `Resource group ${groupName}`, exact: true });
  await groupDetails.getByRole("button", { name: "Edit", exact: true }).click();
  const groupEdit = page.getByRole("complementary", { name: /^Edit resource group / });
  await groupEdit.getByRole("group", { name: "Included resources", exact: true }).getByRole("checkbox", { name: new RegExp(resourceName) }).check();
  const inclusion = mutation(page, "PATCH", `${groupPath}/${groupId}`);
  await groupEdit.getByRole("button", { name: "Save resource group", exact: true }).click();
  const included = await saved<ResourceGroupRecord>(inclusion);
  await expect(groupDetails.getByRole("region", { name: /^Includes/ })).toContainText(resourceName);
  const inclusionEvent = await completedAudit(page, included.brokerRequestId, "admin.policy.resource_groups.patch");
  expect(management(inclusionEvent)).toMatchObject({
    target: { kind: "resource_group", id: groupId, displayName: groupName },
    change: {
      changedFields: ["includedResourceIds"],
      membership: {
        includedAdded: { count: 1, items: [expect.objectContaining({ id: resourceId, displayName: resourceName })], truncated: false },
        includedRemoved: { count: 0, items: [], truncated: false },
        excludedAdded: { count: 0, items: [], truncated: false },
        excludedRemoved: { count: 0, items: [], truncated: false },
      },
    },
  });

  await page.goto(`${baseUrl}/ui/admin/catalog/resources?item=${encodeURIComponent(resourceId)}`);
  await page.getByRole("complementary", { name: `Resource ${resourceName}`, exact: true }).getByRole("button", { name: "Edit", exact: true }).click();
  const edit = page.getByRole("complementary", { name: /^Edit resource / });
  await edit.getByLabel("Display name").fill(renamedResource);
  const renaming = mutation(page, "PATCH", `${resourcePath}/${resourceId}`);
  await edit.getByRole("button", { name: "Save resource", exact: true }).click();
  const renamed = await saved<ResourceRecord>(renaming);
  await expect(page.getByRole("complementary", { name: `Resource ${renamedResource}`, exact: true })).toBeVisible();
  const renameEvent = await completedAudit(page, renamed.brokerRequestId, "admin.policy.resources.patch");
  expect(management(renameEvent)).toMatchObject({
    change: { before: { displayName: resourceName }, after: { displayName: renamedResource }, changedFields: ["displayName"] },
  });

  // Search indexes event-time labels, including the member of a group change.
  const search = new URLSearchParams({ q: `"${resourceName}"`, action: "admin.policy.*", limit: "100" });
  const matching = await browserRead<{ items: AuditRecord[] }>(page, `/v1/admin/audit/events?${search}`);
  expect(matching.items.map(record => record.auditId)).toEqual(expect.arrayContaining([createEvent.auditId, inclusionEvent.auditId, renameEvent.auditId]));
  expect(management(matching.items.find(record => record.auditId === createEvent.auditId)!)).toMatchObject({ target: { displayName: resourceName } });
  search.set("q", `"${groupName}"`);
  const matchingGroup = await browserRead<{ items: AuditRecord[] }>(page, `/v1/admin/audit/events?${search}`);
  expect(matchingGroup.items.map(record => record.auditId)).toContain(inclusionEvent.auditId);

  await page.goto(`${baseUrl}/ui/admin/audit`);
  await searchAudit(page, `"${resourceName}"`);
  const creationLink = page.getByRole("main").getByRole("rowheader").getByRole("link", { name: new RegExp(`Created.*${resourceName}`) });
  await expect(creationLink).toBeVisible();
  await creationLink.click();
  const auditDrawer = page.getByRole("complementary").filter({ has: page.getByRole("tab", { name: "Summary", exact: true }) });
  await expect(auditDrawer).toContainText("Completed");
  const historicResourceLink = auditDrawer.getByRole("link", { name: resourceName, exact: true });
  await expect(historicResourceLink).toHaveAttribute("href", `/ui/admin/catalog/resources?item=${resourceId}`);
  await historicResourceLink.click();
  await expect(page.getByRole("complementary", { name: `Resource ${renamedResource}`, exact: true })).toBeVisible();
  await page.goBack();
  await expect(page.getByRole("searchbox", { name: "Search", exact: true })).toHaveValue(`"${resourceName}"`);
  await auditDrawer.getByRole("button", { name: "Close", exact: true }).click();
  await searchAudit(page, `"${groupName}"`);
  const membershipLink = page.getByRole("main").getByRole("rowheader").getByRole("link", { name: new RegExp(`Added.*${resourceName}.*to.*${groupName}.*included`) });
  await membershipLink.click();
  await expect(auditDrawer).toContainText("Included resources added");
  await expect(auditDrawer.getByRole("link", { name: resourceName, exact: true })).toHaveAttribute("href", `/ui/admin/catalog/resources?item=${resourceId}`);
  await page.screenshot({ path: testInfo.outputPath("resource-membership-audit.png"), fullPage: true });
  await auditDrawer.getByRole("link", { name: groupName, exact: true }).click();
  await expect(page.getByRole("complementary", { name: `Resource group ${groupName}`, exact: true })).toBeVisible();

  // A conflicting create names the stored entry and navigates to it; it never succeeds.
  await page.goto(`${baseUrl}/ui/admin/catalog/resources`);
  await page.getByRole("main").getByRole("button", { name: "Add resource", exact: true }).first().click();
  await add.getByLabel("Resource type").selectOption("git_repository");
  await add.getByLabel("Canonical identifier").fill(selector);
  await add.getByLabel("Display name").fill("Attempted duplicate name");
  await add.getByRole("group", { name: "Allowed execution contexts" }).getByLabel("internal", { exact: true }).check();
  const conflictResponse = mutation(page, "POST", resourcePath);
  await add.getByRole("button", { name: "Save resource", exact: true }).click();
  const conflict = await (await conflictResponse).json();
  expect(conflict).toMatchObject({ ok: false, reasonCode: "input_invalid", target: { conflict: { kind: "resource", id: resourceId, displayName: renamedResource } } });
  await expect(add).toContainText(renamedResource);
  const existing = add.getByRole("link", { name: "Open existing resource", exact: true });
  await expect(existing).toHaveAttribute("href", `/ui/admin/catalog/resources?item=${resourceId}`);
  await existing.click();
  await expect(page.getByRole("complementary", { name: `Resource ${renamedResource}`, exact: true })).toBeVisible();
  const failedTimeline = await browserRead<{ items: AuditRecord[] }>(page, `/v1/admin/audit/requests/${encodeURIComponent(conflict.brokerRequestId)}`);
  expect(failedTimeline.items.some(record => management(record)?.phase === "success")).toBe(false);
  // The resource management route requires CSRF even for its catalog GET.
  const session = await browserRead<{ csrfHeader: string; csrfToken: string }>(page, "/v1/auth/session");
  const resources = await browserRead<ResourceRecord[]>(page, resourcePath, { [session.csrfHeader]: session.csrfToken });
  expect(resources.map(resource => resource.id)).toEqual([resourceId]);
  expect(pageErrors).toEqual([]);
});
