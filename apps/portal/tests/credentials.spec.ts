import { test, expect, type Page } from "@playwright/test";
import { createServer, type Server } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { RESOURCE_TYPES } from "../unit/resource-types.fixture";
import { portalDist } from "./support/binaries";

// Deterministic browser contract for the one Credentials list: one row per
// credential connection naming the entitled services it serves, one row per
// OAuth registration (read-only for an administered principal) whose status
// flags a remote revocation that needs cleanup, retained stored rows deleted
// by ID, and the token type a connection accepting several asks the saver to
// choose. The real-store flows live in portal.spec.ts and
// my-access-metadata.spec.ts.
let server: Server;
let baseUrl: string;
const envelope = (result: unknown) => ({ ok: true, result });
const stamp = { createdAt: "2026-10-01T00:00:00Z", updatedAt: "2026-10-01T00:00:00Z", createdBy: "viewer", updatedBy: "viewer" };
const rest = { service: "gitlab", displayName: "GitLab REST", credentialVerificationInputs: [] };
const git = { service: "gitlab_git", displayName: "GitLab Git", credentialVerificationInputs: ["repository"] };
const mail = { service: "gmail", displayName: "Gmail", credentialVerificationInputs: [] };
const fields = [{ name: "token", required: true, secret: true, prompt: "GitLab bearer token", inputMethods: ["prompt", "env", "file", "stdin"] }];
const gitlabProfile = {
  profile: "gitlab-access-token", label: null, credentialKind: "bearer_token",
  inputSchema: { connection: "gitlab", profile: "gitlab-access-token", credentialKind: "bearer_token", fields }
};
const target = { connection: "gitlab", displayName: "GitLab", consumers: [rest, git], otherConsumers: 1, tokenProfiles: [gitlabProfile] };
const token = { credentialId: "credential-gitlab", ownerPrincipal: "viewer", ownerKind: "user", connection: "gitlab", profile: "gitlab-access-token", label: null, credentialKind: "bearer_token", metadata: {}, status: "active", verificationStatus: "upstream_verified", lastVerifiedAt: stamp.updatedAt, ...stamp };
const retained = { credentialId: "credential-old-git", ownerPrincipal: "viewer", ownerKind: "user", service: "gitlab_git", name: "default", profile: "git-basic-api-token", label: null, credentialKind: "basic_api_token", metadata: {}, status: "active", ...stamp };
const credentials = {
  connections: [
    { connection: "gitlab", displayName: "GitLab", method: "token", consumers: [rest, git], otherConsumers: 1, tokenProfiles: [gitlabProfile], registration: null, remoteRevocation: null, credential: token },
    { connection: "gmail", displayName: "Gmail", method: "oauth", consumers: [mail], otherConsumers: 0, tokenProfiles: [], registration: "google", remoteRevocation: "not_requested", credential: null }
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
 * What the mocked Broker lists: the signed-in user's credentials and targets,
 * and the service account `bot`'s. `onPut` sees each token save, by path and
 * body, so a fixture can store it.
 */
type Lists = {
  credentials: unknown;
  targets: unknown[];
  botCredentials: unknown;
  botTargets: unknown[];
  onPut?: (pathname: string, body: { profile: string; secret: Record<string, string> }) => void;
};

/**
 * A user with self-service, or an administrator or auditor managing the
 * service account `bot` or the user `morgan`; records every broker read path
 * and every write as `METHOD path` with its body.
 */
async function fixture(page: Page, role: "user" | "admin" | "auditor" = "user", start = "/ui/credentials", lists: Lists = { credentials, targets: [target], botCredentials, botTargets: [] }) {
  const session = { authenticated: true, principal: "viewer", role, selfServiceEnabled: true, policyManagementServices: [], auditQueryable: false, csrfHeader: "x-csrf-token", csrfToken: "test-csrf", signInMethods: { localPassword: "active", microsoft: "absent" }, loginOptions: { localPassword: { enabled: true } }, tokenIssuancePolicy: { selfAgentInvoke: { defaultTtl: "1h", maxTtl: "8h", options: ["1h"] } } };
  const writes: Array<{ request: string; body: unknown }> = [];
  const reads: string[] = [];
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() !== "GET") writes.push({ request: `${request.method()} ${pathname}`, body: request.postDataJSON() });
    else reads.push(pathname);
    if (request.method() === "PUT") lists.onPut?.(pathname, request.postDataJSON());
    let result: unknown = [];
    if (pathname === "/v1/auth/session") result = session;
    else if (pathname === "/v1/resource-types") result = { resourceTypes: RESOURCE_TYPES };
    else if (pathname === "/v1/me") result = { serviceLimits: [] };
    else if (pathname === "/v1/tokens/options") result = { policyGeneration: 1, executionContexts: ["default"], services: [], resources: [], resourceGroups: [] };
    else if (pathname === "/v1/credentials/targets") result = lists.targets;
    else if (pathname === "/v1/credentials") result = lists.credentials;
    else if (pathname === "/v1/oauth/connections") result = oauthConnections;
    else if (pathname === "/v1/credentials/connections/gitlab/verify") result = { ...token, probeService: "gitlab_git" };
    else if (pathname === `/v1/credentials/retained/${retained.credentialId}`) result = retained;
    else if (pathname === "/v1/oauth/connections/google") result = { disconnected: true, remoteRevocation: "revoked" };
    else if (pathname === "/v1/admin/config/status") result = { identityAuthority: "managed", policyAuthority: "managed", generation: 1, loadedAt: stamp.createdAt, configHash: "fixture" };
    else if (pathname === "/v1/admin/principals/bot") result = bot;
    else if (pathname === "/v1/admin/principals/bot/credentials") result = lists.botCredentials;
    else if (pathname === "/v1/admin/principals/bot/credentials/targets") result = lists.botTargets;
    else if (pathname === "/v1/admin/principals/bot/credentials/connections/jira") result = botToken;
    else if (pathname === "/v1/admin/principals/morgan") result = morgan;
    else if (pathname === "/v1/admin/principals/morgan/credentials") result = morganCredentials;
    await route.fulfill({ json: envelope(result) });
  });
  await page.goto(`${baseUrl}${start}`);
  return { writes, reads, errors };
}

// A service account that lost every grant on the jira connection still owns its active token.
const bot = { principalId: "bot", kind: "service_account", role: "user", selfServiceEnabled: false, displayName: "Build bot", groups: [], status: "active", ...stamp, signInMethods: { localPassword: "absent", microsoft: "absent" }, groupMemberships: [], policyReferenceSections: [], activePolicyGroupSubjects: [] };
const botToken = { credentialId: "credential-bot-jira", ownerPrincipal: "bot", ownerKind: "user", connection: "jira", profile: "atlassian-api-token", label: null, credentialKind: "basic_api_token", metadata: {}, status: "active", verificationStatus: "not_verified", ...stamp };
const botCredentials = {
  connections: [{ connection: "jira", displayName: "Jira", method: "token", consumers: [], otherConsumers: 1, tokenProfiles: [{ profile: "atlassian-api-token", label: null, credentialKind: "basic_api_token", inputSchema: { connection: "jira", profile: "atlassian-api-token", credentialKind: "basic_api_token", fields: [] } }], registration: null, credential: botToken }],
  retained: []
};

// A user whose connections use OAuth: GitLab's last ended connection lost a
// renewal's outcome; Morgan lost every grant on GitLab Ops, whose revocation
// failed, so it stays listed for the provider-side cleanup.
const morgan = { ...bot, principalId: "morgan", kind: "user", selfServiceEnabled: true, displayName: "Morgan" };
const oauthRow = (connection: string, displayName: string, registration: string, consumers: (typeof rest)[], otherConsumers: number, remoteRevocation: string) =>
  ({ connection, displayName, method: "oauth", consumers, otherConsumers, tokenProfiles: [], registration, remoteRevocation, credential: null });
const morganCredentials = {
  connections: [
    oauthRow("gitlab", "GitLab", "gitlab", [rest, git], 0, "unconfirmed"),
    oauthRow("gmail", "Gmail", "google", [mail], 0, "not_requested"),
    oauthRow("gitlab_ops", "GitLab Ops", "gitlab-ops", [], 1, "failed")
  ],
  retained: []
};

const list = (page: Page) => page.getByRole("table", { name: "Credentials", exact: true });
const row = (page: Page, name: string) => list(page).getByRole("row").filter({ has: page.getByRole("link", { name, exact: true }) });
/** A row's Status cell, its first data cell (the connection name is the row header). */
const statusCell = (page: Page, name: string) => row(page, name).getByRole("cell").first();

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
  // One accepted token type: nothing to choose, and the replacement names that type.
  await expect(drawer.getByLabel("Token type")).toHaveCount(0);
  await drawer.getByLabel("GitLab bearer token", { exact: true }).fill("synthetic-gitlab-token");
  await drawer.getByRole("button", { name: "Replace credential", exact: true }).click();
  await expect.poll(() => writes.find((write) => write.request === "PUT /v1/credentials/connections/gitlab")?.body).toEqual({ profile: "gitlab-access-token", secret: { token: "synthetic-gitlab-token" }, metadata: {} });
  expect(errors).toEqual([]);
});

test("OAuth connections are one row per registration and disconnect names every affected service", async ({ page }) => {
  const { writes } = await fixture(page);
  const gmail = row(page, "Gmail");
  await expect(gmail).toHaveCount(1);
  await expect(gmail).toContainText("Connected");
  await expect(gmail).toContainText("morgan@example.test");
  // What connecting allows is in the drawer; the list has no Permissions column.
  // Columns hidden by width still count.
  await expect(list(page).getByRole("columnheader", { includeHidden: true })).toHaveText(["Status", "Connection", "Used by", "Method", "Verified", "Row actions"]);
  await expect(gmail).not.toContainText("Read and manage your mailbox");
  await gmail.getByRole("link", { name: "Gmail", exact: true }).click();
  await expect(page.getByRole("complementary", { name: "Gmail credential", exact: true })).toContainText("Read and manage your mailbox");
  await gmail.getByRole("button", { name: "Disconnect", exact: true }).click();
  const confirm = page.getByRole("alertdialog", { name: "Disconnect account?", exact: true });
  await expect(confirm).toContainText("Gmail and 1 other service stop using this account.");
  await expect(confirm).toContainText("Where the provider supports it, the broker also revokes the account's tokens there.");
  await confirm.getByRole("button", { name: "Disconnect", exact: true }).click();
  await expect.poll(() => writes.map((write) => write.request)).toContain("DELETE /v1/oauth/connections/google");
  await expect(page.getByText("Account disconnected. Access through the broker has ended, and the provider revoked every token the broker held for the account.")).toBeVisible();
});

test("an OAuth connection's unconfirmed remote revocation shows in its status, with the provider-side action in its tooltip and drawer", async ({ page }) => {
  const { errors } = await fixture(page);
  const gitlab = row(page, "GitLab account");
  await expect(gitlab).toHaveCount(1);
  // The connection's own status stays beside the revocation problem.
  const status = statusCell(page, "GitLab account");
  await expect(status).toContainText("Not connected");
  const badge = status.getByText("Revocation unconfirmed", { exact: true });
  await expect(badge).toBeVisible();
  // The state concerns the connection the broker ended, not current access.
  await expect(badge).toHaveAttribute("title", /outcome was lost for an ended connection.*Preferences › Applications › Authorized applications/);
  await expect(gitlab).not.toContainText("outcome was lost");
  await expect(row(page, "Gmail")).not.toContainText("Revocation");
  await expect(page.getByRole("group", { name: "Credential status" }).getByRole("button", { name: /^Needs attention/ })).toContainText("1");
  await gitlab.getByRole("link", { name: "GitLab account", exact: true }).click();
  const drawer = page.getByRole("complementary", { name: "GitLab account credential", exact: true });
  await expect(drawer).toContainText("Revocation unconfirmed. A token renewal's outcome was lost for an ended connection");
  await expect(drawer).toContainText("Preferences › Applications › Authorized applications");
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

for (const role of ["admin", "auditor"] as const) {
  test(`an ${role} sees a user's OAuth connections and their remote revocation read-only`, async ({ page }, testInfo) => {
    const { writes, reads, errors } = await fixture(page, role, "/ui/admin/principals/morgan/credentials");
    await expect(page.getByText("OAuth connections are read-only here: only the user can connect, reconnect or disconnect them, from their own Credentials page.")).toBeVisible();
    const gitlab = row(page, "GitLab");
    await expect(gitlab).toContainText("Managed by user");
    await expect(gitlab).toContainText("GitLab REST and GitLab Git");
    await expect(gitlab).toContainText("OAuth · gitlab");
    const status = statusCell(page, "GitLab");
    await expect(status).toContainText("Managed by user");
    const badge = status.getByText("Revocation unconfirmed", { exact: true });
    await expect(badge).toBeVisible();
    // The state concerns the connection the broker ended; the user, or a provider administrator, revokes.
    await expect(badge).toHaveAttribute("title", /outcome was lost for an ended connection.*The user must revoke the broker application's access at the provider.*Preferences › Applications › Authorized applications/);
    await expect(gitlab).not.toContainText("outcome was lost");
    await expect(row(page, "Gmail")).not.toContainText("Revocation");
    const cleanup = row(page, "GitLab Ops");
    await expect(cleanup).toContainText("No current grants");
    await expect(statusCell(page, "GitLab Ops").getByText("Revocation failed", { exact: true })).toBeVisible();
    await expect(list(page).getByRole("button", { name: /^(Connect account|Reconnect|Disconnect|Return to authorization tab|Delete)$/ })).toHaveCount(0);
    await page.screenshot({ path: testInfo.outputPath(`credentials-administered-oauth-${role}.png`), fullPage: true });

    await page.getByRole("group", { name: "Credential status" }).getByRole("button", { name: /^Needs attention/ }).click();
    await expect(list(page).getByRole("row").filter({ has: page.getByRole("link") })).toHaveCount(2);
    await expect(row(page, "Gmail")).toHaveCount(0);

    await gitlab.getByRole("link", { name: "GitLab", exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/principals\/morgan\/credentials\?.*credential=oauth%3Agitlab/);
    const drawer = page.getByRole("complementary", { name: "GitLab credential", exact: true });
    await expect(drawer).toContainText("OAuth registration gitlab");
    await expect(drawer).toContainText("Revocation unconfirmed. A token renewal's outcome was lost for an ended connection");
    await expect(drawer).toContainText("Only the user can connect, reconnect or disconnect this account, from their own Credentials page.");
    await expect(drawer.getByText("GitLab Git", { exact: false })).toBeVisible();
    await expect(drawer.getByRole("button", { name: /^(Connect account|Reconnect|Disconnect|Return to authorization tab|Delete|Verify)$/ })).toHaveCount(0);
    await page.screenshot({ path: testInfo.outputPath(`credentials-administered-oauth-${role}-drawer.png`), fullPage: true });
    // The administered view reads only the principal's list, never the viewer's own OAuth connections.
    expect(reads).not.toContain("/v1/oauth/connections");
    expect(writes).toEqual([]);
    expect(errors).toEqual([]);
  });
}

// Token types. The Git gateway's two unlabelled types differ in kind: Basic
// asks for a username and token, bearer for the token only. The conformance
// provider's two types carry labels.
const inputMethods = ["prompt", "env", "file", "stdin"];
/** A token type with the fields the Broker's input schema gives its kind. */
function tokenType(connection: string, display: string, profile: string, label: string | null, credentialKind: "basic_api_token" | "bearer_token") {
  const tokenField = { name: "token", required: true, secret: true, prompt: `${display} ${credentialKind === "basic_api_token" ? "API" : "bearer"} token`, inputMethods };
  const fields = credentialKind === "basic_api_token" ? [{ name: "username", required: true, secret: false, prompt: `${display} username`, inputMethods }, tokenField] : [tokenField];
  return { profile, label, credentialKind, inputSchema: { connection, profile, credentialKind, fields } };
}
type TokenType = ReturnType<typeof tokenType>;
const gitBearer = tokenType("git", "Git", "git-bearer-token", null, "bearer_token");
const gitBasic = tokenType("git", "Git", "git-basic-api-token", null, "basic_api_token");
const apiToken = tokenType("conformance", "Conformance", "api_token", "API token", "bearer_token");
const routedToken = tokenType("conformance", "Conformance", "routed_token", "Routed token", "bearer_token");
const conformance = { service: "conformance", displayName: "Conformance", credentialVerificationInputs: [] };
const storedToken = (connection: string, type: TokenType, ownerPrincipal = "viewer") =>
  ({ credentialId: `credential-${ownerPrincipal}-${connection}`, ownerPrincipal, ownerKind: "user", connection, profile: type.profile, label: type.label, credentialKind: type.credentialKind, metadata: {}, status: "active", verificationStatus: "not_verified", ...stamp });
const tokenRow = (connection: string, displayName: string, consumers: (typeof rest)[], tokenProfiles: TokenType[], credential: ReturnType<typeof storedToken> | null) =>
  ({ connection, displayName, method: "token", consumers, otherConsumers: 0, tokenProfiles, registration: null, remoteRevocation: null, credential });
const targetOf = (row: ReturnType<typeof tokenRow>) =>
  ({ connection: row.connection, displayName: row.displayName, consumers: row.consumers, otherConsumers: row.otherConsumers, tokenProfiles: row.tokenProfiles });

/**
 * Lists whose `owner` connections are `rows`, with targets, retained rows and
 * a PUT that stores the saved type as the connection's token, as the Broker
 * does.
 */
function tokenTypeLists(owner: "viewer" | "bot", rows: ReturnType<typeof tokenRow>[], retainedRows: unknown[] = []): Lists {
  const list = { connections: rows, retained: retainedRows };
  const lists: Lists = {
    credentials: owner === "viewer" ? list : { connections: [], retained: [] },
    targets: owner === "viewer" ? rows.map(targetOf) : [],
    botCredentials: owner === "bot" ? list : botCredentials,
    botTargets: owner === "bot" ? rows.map(targetOf) : [],
    onPut: (pathname, body) => {
      const row = rows.find((candidate) => pathname.endsWith(`/credentials/connections/${candidate.connection}`));
      const type = row?.tokenProfiles.find((candidate) => candidate.profile === body.profile);
      if (row && type) row.credential = storedToken(row.connection, type, owner);
    }
  };
  return lists;
}

test("a connection accepting several token types asks for one, and its fields and saved type follow the choice", async ({ page }, testInfo) => {
  const gitRow = tokenRow("git", "Git", [git], [gitBearer, gitBasic], null);
  const { writes, errors } = await fixture(page, "user", "/ui/credentials", tokenTypeLists("viewer", [gitRow]));
  const gitConnection = row(page, "Git");
  await expect(gitConnection).toContainText("Not saved");
  await expect(gitConnection).toContainText("2 token types");
  await gitConnection.getByRole("link", { name: "Git", exact: true }).click();
  const drawer = page.getByRole("complementary", { name: "Git credential", exact: true });
  const type = drawer.getByRole("combobox", { name: "Token type", exact: true });
  const save = drawer.getByRole("button", { name: "Save credential", exact: true });

  // A first save chooses explicitly: nothing is preselected, no fields show, and saving waits.
  await expect(type).toHaveValue("");
  await expect(type.locator("option")).toHaveText(["Choose a token type", "git-bearer-token", "git-basic-api-token"]);
  await expect(drawer.getByRole("textbox")).toHaveCount(0);
  await expect(save).toBeDisabled();
  // Leaving the select without a type marks it invalid, keyboard only.
  await type.focus();
  await page.keyboard.press("Tab");
  await expect(type).toHaveAttribute("aria-invalid", "true");
  await expect(drawer.getByText("Choose a token type.", { exact: true })).toBeVisible();
  await expect(type).toHaveAccessibleDescription(/Choose a token type\./);
  await page.screenshot({ path: testInfo.outputPath("credentials-token-type-required.png"), fullPage: true });

  // The keyboard chooses a type; the Basic type asks for a username and token.
  await type.focus();
  await page.keyboard.press("ArrowDown");
  await expect(type).toHaveValue("git-bearer-token");
  await expect(type).not.toHaveAttribute("aria-invalid", "true");
  await expect(drawer.getByLabel("Git bearer token", { exact: true })).toBeVisible();
  await expect(drawer.getByLabel("Git username", { exact: true })).toHaveCount(0);
  await drawer.getByLabel("Git bearer token", { exact: true }).fill("synthetic-git-token");
  await type.selectOption("git-basic-api-token");
  await expect(drawer.getByLabel("Git username", { exact: true })).toHaveValue("");
  // The token both types share keeps its value.
  await expect(drawer.getByLabel("Git API token", { exact: true })).toHaveValue("synthetic-git-token");
  await expect(save).toBeDisabled();
  await drawer.getByLabel("Git username", { exact: true }).fill("casey@example.test");
  await save.click();
  await expect.poll(() => writes.filter((write) => write.request === "PUT /v1/credentials/connections/git").map((write) => write.body)).toEqual([
    { profile: "git-basic-api-token", secret: { username: "casey@example.test", token: "synthetic-git-token" }, metadata: {} }
  ]);
  await expect(gitConnection).toContainText("Not verified");
  await expect(gitConnection).toContainText("git-basic-api-token");

  // Replacing preselects the stored type; another type replaces it, sending only that type's fields.
  const replace = drawer.getByRole("button", { name: "Replace credential", exact: true });
  await expect(type).toHaveValue("git-basic-api-token");
  await expect(type.locator("option")).toHaveText(["git-bearer-token", "git-basic-api-token"]);
  await expect(drawer.getByText("The fields to fill in follow the token type.", { exact: true })).toBeVisible();
  await type.selectOption("git-bearer-token");
  await expect(type).toHaveAccessibleDescription("Saving replaces the stored token, of type git-basic-api-token, with a token of this type.");
  await expect(drawer.getByLabel("Git username", { exact: true })).toHaveCount(0);
  await drawer.getByLabel("Git bearer token", { exact: true }).fill("synthetic-bearer-token");
  await page.screenshot({ path: testInfo.outputPath("credentials-token-type-replace.png"), fullPage: true });
  await replace.click();
  await expect.poll(() => writes.filter((write) => write.request === "PUT /v1/credentials/connections/git").map((write) => write.body)).toHaveLength(2);
  expect(writes.filter((write) => write.request === "PUT /v1/credentials/connections/git")[1].body).toEqual({ profile: "git-bearer-token", secret: { token: "synthetic-bearer-token" }, metadata: {} });
  await expect(gitConnection).toContainText("git-bearer-token");
  await expect(type).toHaveValue("git-bearer-token");
  await expect(drawer.getByRole("definition").filter({ hasText: "git-bearer-token" })).toHaveText("git-bearer-token");
  expect(errors).toEqual([]);
});

test("stored tokens show their type's label, and a token of a type no longer accepted is a Not used row", async ({ page }, testInfo) => {
  const alerts = { service: "alerts", displayName: "Alerts", credentialVerificationInputs: [] };
  // The conformance connection stores a routed token; the alerts connection
  // now accepts only routed tokens, so its stored API token is kept but not used.
  const rows = [
    tokenRow("conformance", "Conformance", [conformance], [apiToken, routedToken], storedToken("conformance", routedToken)),
    tokenRow("alerts", "Alerts", [alerts], [routedToken], null)
  ];
  const kept = { credentialId: "credential-old-alerts", ownerPrincipal: "viewer", ownerKind: "user", service: "alerts", name: "default", profile: "api_token", label: "API token", credentialKind: "bearer_token", metadata: {}, status: "active", ...stamp };
  const { writes, errors } = await fixture(page, "user", "/ui/credentials", tokenTypeLists("viewer", rows, [kept]));
  await expect(row(page, "Conformance")).toContainText("Routed token");
  await expect(row(page, "Conformance")).not.toContainText("routed_token");
  await expect(row(page, "Alerts")).toContainText("Not saved");
  await expect(row(page, "Alerts")).toContainText("Routed token");
  const notUsed = row(page, "alerts/default");
  await expect(notUsed).toContainText("Not used");
  await expect(notUsed).toContainText("API token");
  // The filter matches a type's label and profile.
  await page.getByPlaceholder("Filter credentials…").fill("api_token");
  await expect(list(page).getByRole("row").filter({ has: page.getByRole("link") })).toHaveCount(2);
  await page.getByPlaceholder("Filter credentials…").fill("");

  await row(page, "Conformance").getByRole("link", { name: "Conformance", exact: true }).click();
  const drawer = page.getByRole("complementary", { name: "Conformance credential", exact: true });
  await expect(drawer.getByRole("definition").filter({ hasText: "Routed token" })).toHaveText("Routed token routed_token");
  const type = drawer.getByRole("combobox", { name: "Token type", exact: true });
  await expect(type).toHaveValue("routed_token");
  await expect(type.locator("option")).toHaveText(["API token", "Routed token"]);
  await page.screenshot({ path: testInfo.outputPath("credentials-token-type-label.png"), fullPage: true });

  await notUsed.getByRole("link", { name: "alerts/default", exact: true }).click();
  const retainedDrawer = page.getByRole("complementary", { name: "alerts/default credential", exact: true });
  await expect(retainedDrawer).toContainText("its connection no longer accepts its token type from this account");
  await expect(retainedDrawer.getByRole("definition").filter({ hasText: "API token" })).toHaveText("API token api_token");
  await expect(retainedDrawer.getByRole("combobox")).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("credentials-token-type-not-used.png"), fullPage: true });
  await retainedDrawer.getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("alertdialog", { name: "Delete stored credential?", exact: true }).getByRole("button", { name: "Delete credential", exact: true }).click();
  await expect.poll(() => writes.map((write) => write.request)).toContain("DELETE /v1/credentials/retained/credential-old-alerts");
  expect(errors).toEqual([]);
});

test("an administrator chooses a service account's token type", async ({ page }) => {
  const rows = [tokenRow("conformance", "Conformance", [conformance], [apiToken, routedToken], null)];
  const { writes, errors } = await fixture(page, "admin", "/ui/admin/principals/bot/credentials", tokenTypeLists("bot", rows));
  const connection = row(page, "Conformance");
  await expect(connection).toContainText("2 token types");
  await connection.getByRole("link", { name: "Conformance", exact: true }).click();
  const drawer = page.getByRole("complementary", { name: "Conformance credential", exact: true });
  const type = drawer.getByRole("combobox", { name: "Token type", exact: true });
  await expect(type).toHaveValue("");
  await expect(drawer.getByRole("button", { name: "Save credential", exact: true })).toBeDisabled();
  await type.selectOption({ label: "API token" });
  await drawer.getByLabel("Conformance bearer token", { exact: true }).fill("synthetic-service-token");
  await drawer.getByRole("button", { name: "Save credential", exact: true }).click();
  await expect.poll(() => writes.find((write) => write.request === "PUT /v1/admin/principals/bot/credentials/connections/conformance")?.body).toEqual({
    profile: "api_token",
    secret: { token: "synthetic-service-token" },
    metadata: {}
  });
  await expect(connection).toContainText("API token");
  await expect(type).toHaveValue("api_token");
  expect(errors).toEqual([]);
});
