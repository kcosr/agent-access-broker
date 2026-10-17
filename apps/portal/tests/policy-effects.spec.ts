// Focused browser checks exercise effect facets against catalog metadata,
// including retained grants whose actions are no longer in the catalog.
import { expect, test, type Page } from "@playwright/test";
import { createServer, type Server } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { PolicyGrantRecord } from "../src/types";
import { portalDist } from "./support/binaries";

test.use({ actionTimeout: 15_000 });

let server: Server;
let baseUrl: string;

test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    const pathname = new URL(request.url!, "http://localhost").pathname;
    const asset = pathname.startsWith("/ui/assets/") ? path.join(portalDist, pathname.slice(4)) : path.join(portalDist, "index.html");
    try {
      response.setHeader("content-type", asset.endsWith(".js") ? "application/javascript" : asset.endsWith(".css") ? "text/css" : "text/html");
      response.end(await readFile(asset));
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture address");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

test.afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

function grant(grantRef: string, overrides: Partial<PolicyGrantRecord> = {}): PolicyGrantRecord {
  return {
    grantRef, service: "jira", actions: ["issue.view"], subjects: ["user:alice"], executionContexts: ["development"],
    resources: { resourceIds: [], resourceGroupIds: [] }, credentialMode: "per_user", status: "active", writable: true, ...overrides
  };
}

const grants = [
  grant("read-jira", { writable: false }),
  grant("mixed-jira", { actions: ["issue.view", "issue.update"], executionContexts: ["development", "production"] }),
  grant("unknown-jira", { actions: ["removed.read"], subjects: ["user:bob"], executionContexts: ["production"] }),
  grant("unreviewed-jira", { actions: ["unreviewed.read"], subjects: ["user:bob"] }),
  grant("read-git", { service: "git", actions: ["repository.read"] }),
  grant("disabled-jira", { status: "disabled" }),
  grant("deleted-jira", { status: "deleted", actions: ["issue.update"] })
];

// Fields the grant editor needs beyond the Policies list's effect classification.
const editable = { description: "Fixture action", credentialModes: ["service"], lookupRequired: false, inputSchema: {} };

async function fixture(page: Page, search = "", catalogUnavailable = () => false) {
  await page.route("**/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const envelope = (result: unknown) => ({ ok: true, decision: "allow", requestId: "fixture", brokerRequestId: "fixture", operation: "fixture", principal: "alice", result });
    let body: unknown;
    if (url.pathname === "/v1/auth/session") {
      body = envelope({ role: "admin", selfServiceEnabled: true, authenticated: true, principal: "alice",  policyManagementServices: [], auditQueryable: false });
    } else if (url.pathname === "/v1/admin/policy/status") {
      body = envelope({ writable: true, policyAuthority: "managed", policyGeneration: 1, counts: { active: 5, disabled: 1, deleted: 1 } });
    } else if (url.pathname === "/v1/admin/policy/catalog") {
      if (catalogUnavailable()) {
        await route.fulfill({ status: 503, json: { ok: false, error: { message: "Catalog temporarily unavailable" } } });
        return;
      }
      body = envelope({
        services: [
          { service: "jira", displayName: "Jira", surface: "rest", configuredCredentialModes: ["service"], lookupCredentialConfigured: false, actions: [{ action: "issue.view", readOnly: true, requiredScopes: {}, ...editable }, { action: "issue.update", readOnly: false, requiredScopes: {}, ...editable }, { action: "unreviewed.read", requiredScopes: {}, ...editable }], resourceScopes: {} },
          { service: "git", displayName: "Git", surface: "rest", configuredCredentialModes: ["service"], lookupCredentialConfigured: false, actions: [{ action: "repository.read", readOnly: true, requiredScopes: {}, ...editable }], resourceScopes: {} }
        ],
        subjects: { users: [{ principalId: "alice", displayName: "Alice" }, { principalId: "bob", displayName: "Bob" }], groups: [], anonymous: false },
        resources: [], resourceGroups: [], executionContexts: { allowedValues: ["development", "production"], contextRequired: false }
      });
    } else if (url.pathname === "/v1/admin/policy/grants") {
      body = envelope(grants.filter((item) => url.searchParams.get("status") === "deleted" ? item.status === "deleted" : item.status !== "deleted"));
    } else if (url.pathname === "/v1/resource-types") {
      body = { resourceTypes: [] };
    } else if (url.pathname === "/v1/credentials") {
      body = envelope({ connections: [], retained: [] });
    } else {
      body = envelope([]);
    }
    await route.fulfill({ json: body });
  });
  await page.goto(`${baseUrl}/ui/admin/policies${search}`);
  await expect(page.getByRole("main", { name: "Policies", exact: true })).toBeVisible();
}

test("grant action columns fit beside the editor's section sidebar and preview", async ({ page }) => {
  await page.setViewportSize({ width: 1200, height: 900 });
  await fixture(page);
  await page.getByRole("main", { name: "Policies", exact: true }).getByRole("link", { name: "Create grant", exact: true }).first().click();
  await page.getByLabel("Service", { exact: true }).selectOption("jira");
  const columns = page.getByRole("group", { name: /^(Read-only|Write-capable)$/ });
  await expect(columns).toHaveCount(2);
  for (const column of await columns.all()) {
    expect(await column.evaluate((element) => [element, ...element.querySelectorAll(".pt-action-list")].every((item) => item.scrollWidth <= item.clientWidth + 1))).toBe(true);
  }
});

function rows(page: Page) {
  return page.getByRole("main", { name: "Policies", exact: true }).getByRole("rowheader").getByRole("link");
}

function effects(page: Page) {
  return page.getByRole("region", { name: "Action effects", exact: true });
}

async function counts(page: Page, read: number, write: number) {
  await expect(effects(page).getByRole("checkbox", { name: "Read-only", exact: true })).toHaveAccessibleDescription(String(read));
  await expect(effects(page).getByRole("checkbox", { name: "Write-capable", exact: true })).toHaveAccessibleDescription(String(write));
}

test("Policies filters whole grants by effects, retaining mixed and unknown actions as write-capable", async ({ page }) => {
  await fixture(page);
  await expect(rows(page)).toHaveCount(6);
  await counts(page, 3, 3);
  const read = effects(page).getByRole("checkbox", { name: "Read-only", exact: true });
  const write = effects(page).getByRole("checkbox", { name: "Write-capable", exact: true });
  await read.check();
  await expect(rows(page)).toHaveText(["read-git", "disabled-jira", "read-jira"]);
  await counts(page, 3, 3);
  await expect(page).toHaveURL(/effect=read/);
  await write.check();
  await expect(rows(page)).toHaveCount(6);
  await read.uncheck();
  await expect(rows(page)).toHaveText(["mixed-jira", "unknown-jira", "unreviewed-jira"]);
  await page.reload();
  await expect(write).toBeChecked();
  await expect(read).not.toBeChecked();
  await expect(rows(page)).toHaveText(["mixed-jira", "unknown-jira", "unreviewed-jira"]);
  await effects(page).getByRole("button", { name: "Clear action effects filter" }).click();
  await expect(rows(page)).toHaveCount(6);
  expect(new URL(page.url()).searchParams.has("effect")).toBe(false);
});

test("effect counts honor status, service, context, subject, action and search while clear filters restores the list", async ({ page }) => {
  await fixture(page, "?effect=write&service=jira&context=development&subject=user%3Aalice&action=issue.view");
  await expect(rows(page)).toHaveText(["mixed-jira"]);
  await counts(page, 2, 1);
  await page.getByRole("group", { name: "Grant status" }).getByRole("button", { name: /^Active/ }).click();
  await counts(page, 1, 1);
  const search = page.getByPlaceholder("Filter grants by subject, action, scope…");
  await search.fill("read-jira");
  await expect(page.getByText("No matching grants", { exact: true })).toBeVisible();
  await counts(page, 1, 0);
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expect(rows(page)).toHaveCount(6);
  await expect(effects(page).getByRole("checkbox", { name: "Write-capable", exact: true })).not.toBeChecked();
  await counts(page, 3, 3);
  await expect(page).toHaveURL(`${baseUrl}/ui/admin/policies`);
});

test("deleted grant effects are counted after loading and survive direct URL selection", async ({ page }) => {
  await fixture(page, "?status=deleted&effect=read");
  await expect(page.getByText("No matching grants", { exact: true })).toBeVisible();
  await counts(page, 0, 1);
  await effects(page).getByRole("checkbox", { name: "Write-capable", exact: true }).check();
  await expect(rows(page)).toHaveText(["deleted-jira"]);
  await counts(page, 0, 1);
});

test("a failed policy catalog shows a retryable error instead of an empty read-only result", async ({ page }) => {
  let unavailable = true;
  await fixture(page, "?effect=read", () => unavailable);
  const error = page.getByRole("alert").filter({ hasText: "Couldn’t load policy catalog" });
  await expect(error).toBeVisible();
  await expect(page.getByText("No matching grants", { exact: true })).toHaveCount(0);
  unavailable = false;
  await error.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(error).toHaveCount(0);
  await expect(rows(page)).toHaveText(["read-git", "disabled-jira", "read-jira"]);
  await counts(page, 3, 3);
  await expect(effects(page).getByRole("checkbox", { name: "Read-only", exact: true })).toBeChecked();
});
