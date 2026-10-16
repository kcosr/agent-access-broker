import { test, expect, type Page } from "@playwright/test";
import { createServer, type Server } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { RESOURCE_TYPES } from "../unit/resource-types.fixture";
import { portalDist } from "./support/binaries";

// Deterministic browser contract for the one Credentials list: one row per
// credential connection naming the entitled services it serves, one row per
// OAuth registration, and retained stored rows deleted by ID. The real-store
// flows live in portal.spec.ts and my-access-metadata.spec.ts.
let server: Server;
let baseUrl: string;
const envelope = (result: unknown) => ({ ok: true, result });
const stamp = { createdAt: "2026-10-01T00:00:00Z", updatedAt: "2026-10-01T00:00:00Z", createdBy: "viewer", updatedBy: "viewer" };
const rest = { service: "gitlab", displayName: "GitLab REST", credentialVerificationInputs: [] };
const git = { service: "gitlab_git", displayName: "GitLab Git", credentialVerificationInputs: ["repository"] };
const mail = { service: "gmail", displayName: "Gmail", credentialVerificationInputs: [] };
const fields = [{ name: "token", required: true, secret: true, prompt: "GitLab bearer token", inputMethods: ["prompt", "env", "file", "stdin"] }];
const target = {
  connection: "gitlab", displayName: "GitLab", consumers: [rest, git], otherConsumers: 1, profile: "gitlab-access-token", credentialKind: "bearer_token",
  inputSchema: { connection: "gitlab", profile: "gitlab-access-token", credentialKind: "bearer_token", fields }
};
const token = { credentialId: "credential-gitlab", ownerPrincipal: "viewer", ownerKind: "user", connection: "gitlab", profile: "gitlab-access-token", credentialKind: "bearer_token", metadata: {}, status: "active", verificationStatus: "upstream_verified", lastVerifiedAt: stamp.updatedAt, ...stamp };
const retained = { credentialId: "credential-old-git", ownerPrincipal: "viewer", ownerKind: "user", service: "gitlab_git", name: "default", profile: "git-basic-api-token", credentialKind: "basic_api_token", metadata: {}, status: "active", ...stamp };
const credentials = {
  connections: [
    { connection: "gitlab", displayName: "GitLab", method: "token", consumers: [rest, git], otherConsumers: 1, profile: "gitlab-access-token", credentialKind: "bearer_token", registration: null, remoteRevocation: null, credential: token },
    { connection: "gmail", displayName: "Gmail", method: "oauth", consumers: [mail], otherConsumers: 0, profile: null, credentialKind: null, registration: "google", remoteRevocation: "not_requested", credential: null }
  ],
  retained: [retained]
};
const oauthConnections = [{
  registration: "google", displayName: "Gmail", connectionDescription: "Read and manage your mailbox", consumers: [mail], otherConsumers: 1,
  permissionProfile: "mail", scopeMode: "explicit", requestedScopes: ["openid"], target: "me", canConnect: true, connectUnavailableReason: null, canDisconnect: true,
  remoteRevocation: "not_requested",
  connection: { connectionId: "connection-google", subjectId: "subject", displayName: "morgan@example.test", status: "ready", reason: null, targets: [] }
}, {
  // GitLab revokes the tokens of the connections the broker ends; this
  // owner's last one lost the outcome of a token renewal.
  registration: "gitlab", displayName: "GitLab account", connectionDescription: "Lets agents act as your GitLab account.", consumers: [rest, git], otherConsumers: 0,
  permissionProfile: "default", scopeMode: "explicit", requestedScopes: ["api", "write_repository"], target: "https://gitlab.example.test", canConnect: true, connectUnavailableReason: null, canDisconnect: false,
  remoteRevocation: "unconfirmed",
  connection: { connectionId: null, subjectId: null, displayName: null, status: "disconnected", reason: null, targets: [] }
}];

test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    const pathname = new URL(request.url!, "http://localhost").pathname;
    const asset = pathname.startsWith("/ui/assets/") ? pathname.slice(4) : "index.html";
    try {
      const content = await readFile(path.join(portalDist, asset));
      response.setHeader("content-type", asset.endsWith(".js") ? "text/javascript" : asset.endsWith(".css") ? "text/css" : "text/html");
      response.end(content);
    } catch { response.writeHead(404).end(); }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

test.afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

/**
 * A user with self-service, or an administrator managing the service account
 * `bot`; records every broker write as `METHOD path` with its body.
 */
async function fixture(page: Page, role: "user" | "admin" = "user", start = "/ui/credentials") {
  const session = { authenticated: true, principal: "viewer", role, selfServiceEnabled: true, policyManagementServices: [], auditQueryable: false, csrfHeader: "x-csrf-token", csrfToken: "test-csrf", signInMethods: { localPassword: "active", microsoft: "absent" }, loginOptions: { localPassword: { enabled: true } }, tokenIssuancePolicy: { selfAgentInvoke: { defaultTtl: "1h", maxTtl: "8h", options: ["1h"] } } };
  const writes: Array<{ request: string; body: unknown }> = [];
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() !== "GET") writes.push({ request: `${request.method()} ${pathname}`, body: request.postDataJSON() });
    let result: unknown = [];
    if (pathname === "/v1/auth/session") result = session;
    else if (pathname === "/v1/resource-types") result = { resourceTypes: RESOURCE_TYPES };
    else if (pathname === "/v1/me") result = { serviceLimits: [] };
    else if (pathname === "/v1/tokens/options") result = { policyGeneration: 1, executionContexts: ["default"], services: [], resources: [], resourceGroups: [] };
    else if (pathname === "/v1/credentials/targets") result = [target];
    else if (pathname === "/v1/credentials") result = credentials;
    else if (pathname === "/v1/oauth/connections") result = oauthConnections;
    else if (pathname === "/v1/credentials/connections/gitlab/verify") result = { ...token, probeService: "gitlab_git" };
    else if (pathname === `/v1/credentials/retained/${retained.credentialId}`) result = retained;
    else if (pathname === "/v1/oauth/connections/google") result = { disconnected: true, remoteRevocation: "revoked" };
    else if (pathname === "/v1/admin/config/status") result = { identityAuthority: "managed", policyAuthority: "managed", generation: 1, loadedAt: stamp.createdAt, configHash: "fixture" };
    else if (pathname === "/v1/admin/principals/bot") result = bot;
    else if (pathname === "/v1/admin/principals/bot/credentials") result = botCredentials;
    else if (pathname === "/v1/admin/principals/bot/credentials/connections/jira") result = botToken;
    await route.fulfill({ json: envelope(result) });
  });
  await page.goto(`${baseUrl}${start}`);
  return { writes, errors };
}

// A service account that lost every grant on the jira connection still owns its active token.
const bot = { principalId: "bot", kind: "service_account", role: "user", selfServiceEnabled: false, displayName: "Build bot", groups: [], status: "active", ...stamp, signInMethods: { localPassword: "absent", microsoft: "absent" }, groupMemberships: [], policyReferenceSections: [], activePolicyGroupSubjects: [] };
const botToken = { credentialId: "credential-bot-jira", ownerPrincipal: "bot", ownerKind: "user", connection: "jira", profile: "atlassian-api-token", credentialKind: "basic_api_token", metadata: {}, status: "active", verificationStatus: "not_verified", ...stamp };
const botCredentials = {
  connections: [{ connection: "jira", displayName: "Jira", method: "token", consumers: [], otherConsumers: 1, profile: "atlassian-api-token", credentialKind: "basic_api_token", registration: null, credential: botToken }],
  retained: []
};

const list = (page: Page) => page.getByRole("table", { name: "Credentials", exact: true });
const row = (page: Page, name: string) => list(page).getByRole("row").filter({ has: page.getByRole("link", { name, exact: true }) });

test("one row per connection names the services it serves and verifies through a Git service", async ({ page }, testInfo) => {
  const { writes, errors } = await fixture(page);
  await expect(page.getByRole("main", { name: "Credentials" })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("credentials-list.png"), fullPage: true });
  const gitlab = row(page, "GitLab");
  await expect(gitlab).toContainText("GitLab REST, GitLab Git and 1 other service");
  await expect(gitlab).toContainText("Upstream verified");
  await expect(gitlab).toContainText("gitlab-access-token");
  await gitlab.getByRole("link", { name: "GitLab", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/credentials\?credential=gitlab$/);
  const drawer = page.getByRole("complementary", { name: "GitLab credential", exact: true });
  await expect(drawer.getByText("Also used by 1 other service you are not granted.")).toBeVisible();
  // GitLab REST has an identity probe, so plain Verify lets the broker choose; Git needs a repository.
  await expect(drawer.getByRole("button", { name: "Verify", exact: true })).toHaveCount(2);
  await drawer.getByRole("textbox", { name: "Repository" }).fill("team/project");
  await drawer.getByRole("region", { name: "Verify through Git" }).getByRole("button", { name: "Verify", exact: true }).click();
  await expect.poll(() => writes.find((write) => write.request === "POST /v1/credentials/connections/gitlab/verify")?.body).toEqual({ service: "gitlab_git", repository: "team/project" });
  await expect(drawer.getByLabel("GitLab bearer token", { exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("credentials-connection-drawer.png"), fullPage: true });
  expect(errors).toEqual([]);
});

test("OAuth connections are one row per registration and disconnect names every affected service", async ({ page }) => {
  const { writes } = await fixture(page);
  const gmail = row(page, "Gmail");
  await expect(gmail).toHaveCount(1);
  await expect(gmail).toContainText("Connected");
  await expect(gmail).toContainText("morgan@example.test");
  await expect(gmail).toContainText("Read and manage your mailbox");
  await gmail.getByRole("button", { name: "Disconnect", exact: true }).click();
  const confirm = page.getByRole("alertdialog", { name: "Disconnect account?", exact: true });
  await expect(confirm).toContainText("Gmail and 1 other service stop using this account.");
  await expect(confirm).toContainText("Where the provider supports it, the broker also revokes the account's tokens there.");
  await confirm.getByRole("button", { name: "Disconnect", exact: true }).click();
  await expect.poll(() => writes.map((write) => write.request)).toContain("DELETE /v1/oauth/connections/google");
  await expect(page.getByText("Account disconnected. The provider revoked every token the broker held for the account.")).toBeVisible();
});

test("an OAuth connection's remote revocation state and the provider-side action show in its row", async ({ page }) => {
  const { errors } = await fixture(page);
  const gitlab = row(page, "GitLab account");
  await expect(gitlab).toHaveCount(1);
  await expect(gitlab).toContainText("Revocation unconfirmed");
  await expect(gitlab).toContainText("Preferences › Applications › Authorized applications");
  await expect(row(page, "Gmail")).not.toContainText("Revocation");
  expect(errors).toEqual([]);
});

test("a retained stored credential is deleted by its ID", async ({ page }) => {
  const { writes } = await fixture(page);
  const stored = row(page, "gitlab_git/default");
  await expect(stored).toContainText("Not used");
  await page.getByRole("group", { name: "Credential status" }).getByRole("button", { name: /^Not used/ }).click();
  await expect(list(page).getByRole("row").filter({ has: page.getByRole("link") })).toHaveCount(1);
  await stored.getByRole("link", { name: "gitlab_git/default", exact: true }).click();
  const drawer = page.getByRole("complementary", { name: "gitlab_git/default credential", exact: true });
  await expect(drawer).toContainText("git-basic-api-token");
  await drawer.getByRole("button", { name: "Delete", exact: true }).click();
  const confirm = page.getByRole("alertdialog", { name: "Delete stored credential?", exact: true });
  await confirm.getByRole("button", { name: "Delete credential", exact: true }).click();
  await expect.poll(() => writes.map((write) => write.request)).toContain(`DELETE /v1/credentials/retained/${retained.credentialId}`);
});

test("an administrator sees a principal's active token after it lost every grant and can delete it", async ({ page }) => {
  const { writes, errors } = await fixture(page, "admin", "/ui/admin/principals/bot/credentials");
  const jira = row(page, "Jira");
  await expect(jira).toContainText("Not verified");
  await expect(jira).toContainText("No current grants");
  await expect(jira).toContainText("atlassian-api-token");
  await jira.getByRole("link", { name: "Jira", exact: true }).click();
  const drawer = page.getByRole("complementary", { name: "Jira credential", exact: true });
  await expect(drawer.getByText("No service this account is granted uses this connection now.")).toBeVisible();
  await expect(drawer.getByText("Also used by 1 other service this account is not granted.")).toBeVisible();
  // Verification needs a grant on a consuming service; no token form without a target.
  await expect(drawer.getByRole("button", { name: "Verify", exact: true })).toHaveCount(0);
  await expect(drawer.getByRole("button", { name: /credential$/ })).toHaveCount(0);
  await drawer.getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Delete credential?", exact: true }).getByRole("button", { name: "Delete credential", exact: true }).click();
  await expect.poll(() => writes.map((write) => write.request)).toContain("DELETE /v1/admin/principals/bot/credentials/connections/jira");
  expect(errors).toEqual([]);
});
