import { expect, test } from "@playwright/test";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { brokerBinary, cliBinary, portalDist } from "./support/binaries";
import { openOAuthWindow } from "./support/oauth-window";
import { releaseTestRoot } from "./support/test-root";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const stub = process.env.OAUTH_STUB_REPO;
let fixture: ChildProcessWithoutNullStreams | undefined;
let root = "";
let connection: { portal_url: string; principal_id: string; password: string };

test.describe("delegated OAuth browser connection", () => {
  test.skip(!stub, "Set OAUTH_STUB_REPO to the independent provider stub checkout.");
  test.beforeAll(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "aab-oauth-browser-"));
    const state = path.join(root, "state");
    fixture = spawn("python3", [path.join(stub!, "scripts/broker_e2e.py"),
      "--broker", brokerBinary,
      "--cli", cliBinary,
      "--portal-dir", portalDist,
      "--demo", "--state-dir", state], { cwd: repo });
    fixture.stdout.resume();
    fixture.stderr.resume();
    const deadline = Date.now() + 45_000;
    while (Date.now() < deadline) {
      if (fixture.exitCode !== null) throw new Error("OAuth fixture exited before readiness");
      try {
        connection = JSON.parse(await fs.readFile(path.join(state, "connection-info.json"), "utf8"));
        return;
      } catch { await new Promise((resolve) => setTimeout(resolve, 100)); }
    }
    throw new Error("OAuth fixture readiness timed out");
  });
  test.afterAll(async ({}, testInfo) => {
    if (fixture && fixture.exitCode === null) {
      const stopped = new Promise<void>((resolve) => fixture!.once("exit", () => resolve()));
      fixture.kill("SIGINT");
      await stopped;
    }
    await releaseTestRoot(root, testInfo);
  });

  test("consent denial, account selection, reconnect and local disconnect", async ({ page }) => {
    await page.goto(connection.portal_url + "/credentials");
    await page.getByLabel("Principal").fill(connection.principal_id);
    await page.getByLabel("Password", { exact: true }).fill(connection.password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Sign in", exact: true })).not.toBeVisible();
    await page.goto(connection.portal_url + "/credentials");
    const accounts = page.getByRole("region", { name: /^Connected accounts/ });
    await expect(accounts).toBeVisible();
    let flow = await openOAuthWindow(page, accounts.getByRole("button", { name: "Connect account", exact: true }), "Development OAuth consent");
    await flow.consent.getByRole("button", { name: "Deny", exact: true }).click();
    await flow.finish("canceled", "disconnected");
    await expect(accounts.getByText("No account connected", { exact: true })).toBeVisible();
    await expect(accounts.getByRole("button", { name: "Connect account", exact: true })).toBeEnabled();

    flow = await openOAuthWindow(page, accounts.getByRole("button", { name: "Connect account", exact: true }), "Development OAuth consent");
    await flow.consent.getByRole("combobox", { name: "Account", exact: false }).selectOption("alice");
    await expect(flow.consent.getByLabel("records.read", { exact: true })).toBeChecked();
    await expect(flow.consent.getByLabel("offline_access", { exact: true })).toBeChecked();
    await flow.consent.getByRole("button", { name: "Allow selected scopes" }).click();
    await flow.finish("authorized", "connected");
    await expect(accounts.getByText("Alice", { exact: true })).toBeVisible();
    await expect(accounts.getByText("Connected", { exact: true })).toBeVisible();
    await page.reload();
    await expect(accounts.getByText("Alice", { exact: true })).toBeVisible();

    flow = await openOAuthWindow(page, accounts.getByRole("button", { name: "Reconnect", exact: true }), "Development OAuth consent");
    await flow.consent.getByRole("button", { name: "Allow selected scopes" }).click();
    await flow.finish("authorized", "connected");
    await expect(accounts.getByText("Connected", { exact: true })).toBeVisible();
    await expect(accounts.getByRole("button", { name: "Reconnect", exact: true })).toBeEnabled();
    await accounts.getByRole("button", { name: "Disconnect", exact: true }).click();
    const confirm = page.getByRole("alertdialog", { name: "Disconnect account?", exact: true });
    await confirm.getByRole("button", { name: "Disconnect", exact: true }).click();
    await expect(accounts.getByText("No account connected", { exact: true })).toBeVisible();
    await expect(accounts.getByRole("button", { name: "Connect account", exact: true })).toBeEnabled();
  });
});
