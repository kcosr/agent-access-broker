import { test, expect, type Page } from "@playwright/test";
import { createServer, type Server } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { portalDist } from "./support/binaries";

let server: Server;
let baseUrl: string;
const acknowledgment = "I authorize local password sign-in for this user independently of Microsoft sign-in.";
const envelope = (result: unknown) => ({ ok: true, result });
const methods = (localPassword: string, microsoft = "active") => ({ localPassword, microsoft });
const principal = (id: string, localPassword: string, microsoft = "active") => ({ role: "user", selfServiceEnabled: true,
  principalId: id, kind: "user", displayName: id, status: "active", groups: [],
  createdAt: "2026-09-29T00:00:00Z", updatedAt: "2026-09-29T00:00:00Z", createdBy: "admin",
  signInMethods: methods(localPassword, microsoft), groupMemberships: [], activePolicyGroupSubjects: [], policyReferenceSections: []
});

// These tests exercise the browser against explicit API contracts; no provider or broker process is required.
test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    const pathname = new URL(request.url!, "http://localhost").pathname;
    const asset = pathname.startsWith("/ui/assets/") ? pathname.slice(4) : "index.html";
    try {
      const content = await readFile(path.join(portalDist, asset));
      response.setHeader("Content-Type", asset.endsWith(".js") ? "text/javascript" : asset.endsWith(".css") ? "text/css" : asset.endsWith(".woff2") ? "font/woff2" : "text/html");
      response.end(content);
    } catch { response.writeHead(404).end(); }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
test.afterAll(async () => { await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); });

async function mockSession(page: Page, localPassword: string, loginMethod = "oidc", isAdmin = false) {
  await page.route("**/v1/**", (route) => route.fulfill({ status: 404, json: { ok: false, reasonCode: "not_found", error: { message: "Not mocked" } } }));
  const session = { role: isAdmin ? "admin" : "user", selfServiceEnabled: true, authenticated: true, principal: "viewer",   groups: [], loginMethod,
    signInMethods: methods(localPassword), csrfHeader: "x-csrf-token", csrfToken: "test-csrf", loginOptions: { localPassword: { enabled: true }, microsoft: { enabled: true, available: true } } };
  await page.route("**/v1/auth/session", (route) => route.fulfill({ json: envelope(session) }));
  await page.route("**/v1/me", (route) => route.fulfill({ json: envelope({ serviceLimits: [] }) }));
  return session;
}

for (const localPassword of ["absent", "disabled", "active"]) {
  test(`OIDC settings use ${localPassword} local enrollment despite globally enabled passwords`, async ({ page }) => {
    const session = await mockSession(page, localPassword);
    let changed = false;
    await page.route("**/v1/auth/local/password/change", async (route) => {
      changed = true;
      expect(route.request().postDataJSON()).toMatchObject({ currentPassword: "old-password", newPassword: "new-password-value" });
      await route.fulfill({ json: envelope(session) });
    });
    await page.goto(`${baseUrl}/ui/account`);
    await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
    const current = page.getByLabel("Current password", { exact: true });
    if (localPassword !== "active") {
      await expect(current).toHaveCount(0);
      await expect(page.getByRole("heading", { name: "Local password", exact: true })).toHaveCount(0);
    } else {
      await current.fill("old-password");
      await page.getByLabel("New password", { exact: true }).fill("new-password-value");
      await page.getByLabel("Confirm new password", { exact: true }).fill("new-password-value");
      await page.getByRole("button", { name: "Update password" }).click();
      await expect.poll(() => changed).toBe(true);
      await expect(page.getByText("oidc", { exact: true })).toBeVisible();
    }
  });
}

test("local session with active enrollment retains the password form", async ({ page }) => {
  await mockSession(page, "active", "local_password");
  await page.goto(`${baseUrl}/ui/account`);
  await expect(page.getByLabel("Current password", { exact: true })).toBeVisible();
});

async function mockAdmin(page: Page, rows: ReturnType<typeof principal>[]) {
  await mockSession(page, "active", "oidc", true);
  await page.route("**/v1/admin/principals", (route) => route.fulfill({ json: envelope(rows) }));
  await page.route("**/v1/admin/groups", (route) => route.fulfill({ json: envelope([]) }));
  await page.route("**/v1/admin/config/status", (route) => route.fulfill({ json: envelope({ identityAuthority: "managed" }) }));
  for (const row of rows) {
    await page.route(`**/v1/admin/principals/${row.principalId}`, (route) => route.fulfill({ json: envelope(row) }));
  }
}

for (const state of ["absent", "disabled"]) {
  test(`${state} local method requires explicit enrollment consent; unrelated read failures do not hide methods`, async ({ page }) => {
    const row = principal("target", state);
    await mockAdmin(page, [row]);
    await page.route("**/v1/admin/principals/target/login-methods", (route) => route.fulfill({ json: envelope(state === "absent" ? [] : [{ method: "local_password", status: "disabled" }]) }));
    let enabled = false;
    await page.route("**/v1/admin/principals/target/login-methods/local-password/enable", async (route) => {
      enabled = true;
      expect(route.request().method()).toBe("POST");
      expect(route.request().postDataJSON()).toMatchObject({ acknowledgeSeparateSignIn: true, mustChangePassword: true });
      await route.fulfill({ json: envelope({ method: "local_password", status: "active" }) });
    });
    await page.goto(`${baseUrl}/ui/admin/principals/target`);
    const label = state === "absent" ? "Enable local password sign-in" : "Re-enable local password sign-in";
    await expect(page.getByRole("button", { name: "Reset local password", exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: label, exact: true }).click();
    const dialog = page.getByRole("dialog", { name: label, exact: true });
    await expect(dialog.getByLabel(acknowledgment, { exact: true })).not.toBeChecked();
    await expect(dialog.getByRole("button", { name: label, exact: true })).toBeDisabled();
    await expect(dialog).toContainText("Microsoft MFA and Conditional Access");
    await dialog.getByLabel(acknowledgment, { exact: true }).focus();
    await page.keyboard.press("Enter");
    expect(enabled).toBe(false);
    await page.keyboard.press("Space");
    await expect(dialog.getByLabel(acknowledgment, { exact: true })).toBeChecked();
    await dialog.getByRole("button", { name: label, exact: true }).press("Enter");
    await expect.poll(() => enabled).toBe(true);
    await expect(page.getByRole("dialog", { name: "Local password sign-in enabled", exact: true })).toBeVisible();
  });
}

test("failed login-method read is never treated as absent enrollment", async ({ page }) => {
  await mockAdmin(page, [principal("target", "absent")]);
  await page.route("**/v1/admin/principals/target/login-methods", (route) => route.fulfill({ status: 500, json: { ok: false, error: { message: "Methods unavailable" } } }));
  await page.goto(`${baseUrl}/ui/admin/principals/target`);
  await expect(page.getByText("Methods unavailable", { exact: false })).toBeVisible();
  await expect(page.getByRole("button", { name: "Enable local password sign-in", exact: true })).toHaveCount(0);
});

test("enrollment filters distinguish Microsoft, local, both and no active methods", async ({ page }) => {
  await mockAdmin(page, [principal("ms-only", "absent"), principal("local-only", "active", "absent"), principal("dual-user", "active"), principal("no-methods", "disabled", "absent")]);
  await page.goto(`${baseUrl}/ui/admin/principals`);
  for (const [label, id] of [["Microsoft only", "ms-only"], ["Local password only", "local-only"], ["Both", "dual-user"], ["No active methods", "no-methods"]]) {
    await page.getByRole("button", { name: new RegExp(`^${label}`) }).click();
    const rows = page.getByRole("table", { name: "Users" }).getByRole("row");
    await expect(rows).toHaveCount(2);
    await expect(rows.last()).toContainText(id);
  }
});

test("create user defaults to no local method and directs the administrator to linking", async ({ page }) => {
  const row = principal("new-user", "absent", "absent");
  await mockAdmin(page, [row]);
  await page.route("**/v1/admin/principals/new-user/login-methods", (route) => route.fulfill({ json: envelope([]) }));
  let created = false;
  let passwordRequests = 0;
  await page.route("**/v1/admin/principals/new-user/login-methods/local-password/**", (route) => { passwordRequests++; return route.fulfill({ status: 500 }); });
  await page.route("**/v1/admin/principals", (route) => {
    if (route.request().method() === "POST") created = true;
    return route.fulfill({ json: envelope(route.request().method() === "POST" ? row : []) });
  });
  await page.goto(`${baseUrl}/ui/admin/principals`);
  await page.getByRole("button", { name: "Create user", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Create user", exact: true });
  await dialog.getByLabel("Principal ID", { exact: true }).fill("new-user");
  await expect(dialog.getByLabel("Enable local password sign-in", { exact: true })).not.toBeChecked();
  await dialog.getByRole("button", { name: "Create user", exact: true }).click();
  await expect.poll(() => created).toBe(true);
  await expect(page).toHaveURL(/principals\/new-user$/);
  await expect(page.getByRole("button", { name: "Enable local password sign-in", exact: true })).toBeVisible();
  await expect(page.getByText("User has no sign-in methods.", { exact: false })).toBeVisible();
  expect(passwordRequests).toBe(0);
});

test("active local reset is separate from enrollment and source lockout does not remove its badge", async ({ page }) => {
  const row = principal("target", "active");
  row.status = "disabled";
  await mockAdmin(page, [row]);
  await page.route("**/v1/admin/principals/target/login-methods", (route) => route.fulfill({ json: envelope([{ method: "local_password", status: "active", locked: true, lockedUntil: "2026-09-29T22:00:00Z" }]) }));
  await page.goto(`${baseUrl}/ui/admin/principals/target`);
  await expect(page.getByRole("button", { name: "Reset local password", exact: true })).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Enable user", exact: true })).toBeVisible();
  await expect(page.getByText("Local password (independent)", { exact: true })).toBeVisible();
  await expect(page.getByText("Some sources locked until", { exact: false })).toBeVisible();
  await expect(page.getByRole("button", { name: "Unlock local password", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Enable local password sign-in", exact: true })).toHaveCount(0);
  await expect(page.getByText("Linking Microsoft keeps this user’s independent local password sign-in enabled.", { exact: true })).toBeVisible();
});

test("pending method reads do not offer enrollment", async ({ page }) => {
  await mockAdmin(page, [principal("target", "absent")]);
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/v1/admin/principals/target/login-methods", async (route) => { await pending; await route.fulfill({ json: envelope([]) }); });
  await page.goto(`${baseUrl}/ui/admin/principals/target`);
  await expect(page.getByRole("heading", { name: "target", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Enable local password sign-in", exact: true })).toHaveCount(0);
  release();
  await expect(page.getByRole("button", { name: "Enable local password sign-in", exact: true })).toBeVisible();
});

test("create local user requires fresh consent and reveals the generated password", async ({ page }) => {
  const row = principal("new-user", "active", "absent");
  await mockAdmin(page, [row]);
  await page.route("**/v1/admin/principals/new-user/login-methods", (route) => route.fulfill({ json: envelope([{ method: "local_password", status: "active" }]) }));
  await page.route("**/v1/admin/principals", (route) => route.fulfill({ json: envelope(route.request().method() === "POST" ? row : []) }));
  let generated = "";
  await page.route("**/v1/admin/principals/new-user/login-methods/local-password/enable", (route) => {
    const body = route.request().postDataJSON();
    expect(body.acknowledgeSeparateSignIn).toBe(true);
    generated = body.password;
    return route.fulfill({ json: envelope({ method: "local_password", status: "active" }) });
  });
  await page.goto(`${baseUrl}/ui/admin/principals`);
  await page.getByRole("button", { name: "Create user", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Create user", exact: true });
  await dialog.getByLabel("Principal ID", { exact: true }).fill("new-user");
  const optIn = dialog.getByLabel("Enable local password sign-in", { exact: true });
  await optIn.check();
  await expect(dialog.getByRole("button", { name: "Create user", exact: true })).toBeDisabled();
  await dialog.getByLabel(acknowledgment, { exact: true }).check();
  await optIn.uncheck();
  await optIn.check();
  await expect(dialog.getByLabel(acknowledgment, { exact: true })).not.toBeChecked();
  await dialog.getByLabel(acknowledgment, { exact: true }).check();
  await dialog.getByRole("button", { name: "Create user", exact: true }).click();
  const reveal = page.getByRole("dialog", { name: "User created", exact: true });
  await expect(reveal.getByLabel("Temporary password")).toBeVisible();
  expect(generated.length).toBeGreaterThanOrEqual(24);
  await expect(reveal.getByLabel("Temporary password")).toHaveText(generated);
});

test("stale enrollment rejection shows an error without revealing an unused password", async ({ page }) => {
  await mockAdmin(page, [principal("target", "absent")]);
  await page.route("**/v1/admin/principals/target/login-methods", (route) => route.fulfill({ json: envelope([]) }));
  await page.route("**/v1/admin/principals/target/login-methods/local-password/enable", (route) => route.fulfill({ status: 409, json: { ok: false, error: { message: "Local password is already active" } } }));
  await page.goto(`${baseUrl}/ui/admin/principals/target`);
  await page.getByRole("button", { name: "Enable local password sign-in", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Enable local password sign-in", exact: true });
  await dialog.getByLabel(acknowledgment, { exact: true }).check();
  await dialog.getByRole("button", { name: "Enable local password sign-in", exact: true }).click();
  await expect(dialog.getByText("Local password is already active", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Temporary password", { exact: true })).toHaveCount(0);
});

test("partial user creation with enrollment failure preserves the user and does not reveal an unset password", async ({ page }) => {
  const row = principal("new-user", "absent", "absent");
  await mockAdmin(page, [row]);
  await page.route("**/v1/admin/principals/new-user/login-methods", (route) => route.fulfill({ json: envelope([]) }));
  await page.route("**/v1/admin/principals", (route) => route.fulfill({ json: envelope(route.request().method() === "POST" ? row : []) }));
  await page.route("**/v1/admin/principals/new-user/login-methods/local-password/enable", (route) => route.fulfill({ status: 503, json: { ok: false, error: { message: "Hasher unavailable" } } }));
  await page.goto(`${baseUrl}/ui/admin/principals`);
  await page.getByRole("button", { name: "Create user", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Create user", exact: true });
  await dialog.getByLabel("Principal ID", { exact: true }).fill("new-user");
  await dialog.getByLabel("Enable local password sign-in", { exact: true }).check();
  await dialog.getByLabel(acknowledgment, { exact: true }).check();
  await dialog.getByRole("button", { name: "Create user", exact: true }).click();
  await expect(page).toHaveURL(/principals\/new-user$/);
  await expect(page.getByText("User created, but setup did not complete. Finish setup on Overview.", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Temporary password", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Enable local password sign-in", exact: true })).toBeVisible();
});

test("globally disabled local sign-in keeps enrollment visible but disables password changes", async ({ page }) => {
  const session = await mockSession(page, "active");
  session.loginOptions.localPassword.enabled = false;
  await page.route("**/v1/auth/session", (route) => route.fulfill({ json: envelope(session) }));
  await page.goto(`${baseUrl}/ui/account`);
  await expect(page.getByText("Local password (independent)", { exact: true })).toBeVisible();
  await expect(page.getByText("Your local password is still enrolled, but local password sign-in and password changes are disabled for this broker.", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Current password", { exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Update password", exact: true })).toBeDisabled();
});

test("an administrator resetting their own local password can copy it before expired-session refresh", async ({ page }) => {
  await mockAdmin(page, [principal("viewer", "active", "absent")]);
  const session = { role: "admin", selfServiceEnabled: true, authenticated: true, principal: "viewer",   loginMethod: "local_password", signInMethods: methods("active", "absent"), csrfHeader: "x-csrf-token", csrfToken: "test-csrf", loginOptions: { localPassword: { enabled: true } } };
  let reset = false;
  let sessionRefreshesAfterReset = 0;
  await page.route("**/v1/auth/session", (route) => {
    if (reset) sessionRefreshesAfterReset++;
    return route.fulfill({ json: envelope(reset ? { authenticated: false, loginOptions: session.loginOptions } : session) });
  });
  await page.route("**/v1/admin/principals/viewer/login-methods", (route) => route.fulfill({ json: envelope([{ method: "local_password", status: "active" }]) }));
  await page.route("**/v1/admin/principals/viewer/login-methods/local-password", (route) => {
    expect(route.request().method()).toBe("PUT");
    reset = true;
    return route.fulfill({ json: envelope({ method: "local_password", status: "active" }) });
  });
  await page.goto(`${baseUrl}/ui/admin/principals/viewer`);
  await page.getByRole("button", { name: "Reset local password", exact: true }).click();
  const confirm = page.getByRole("alertdialog", { name: "Reset local password?", exact: true });
  await expect(confirm).toContainText("next local sign-in. Microsoft sessions remain active.");
  await confirm.getByRole("button", { name: "Reset local password", exact: true }).click();
  const reveal = page.getByRole("dialog", { name: "Local password reset", exact: true });
  await expect(reveal.getByLabel("Temporary password", { exact: true })).toBeVisible();
  await expect(reveal).toContainText("Next local sign-in");
  expect(sessionRefreshesAfterReset).toBe(0);
  await reveal.getByRole("button", { name: "Done", exact: true }).click();
  await expect.poll(() => sessionRefreshesAfterReset).toBeGreaterThan(0);
  await expect(page.getByLabel("Password", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Temporary password", { exact: true })).toHaveCount(0);
});

for (const loginMethod of ["oidc", "local_password"]) {
  for (const reasonCode of ["local_login_failed", "local_login_locked"]) {
    test(`${loginMethod} password change keeps the session after ${reasonCode}`, async ({ page }) => {
      const session = await mockSession(page, "active", loginMethod);
      let attempts = 0;
      await page.route("**/v1/auth/local/password/change", async (route) => {
        attempts++;
        if (attempts === 1) {
          await route.fulfill({ status: 401, json: { ok: false, reasonCode, error: { message: "Current local password could not be verified" } } });
        } else {
          expect(route.request().postDataJSON().currentPassword).toBe("correct-password");
          await route.fulfill({ json: envelope(session) });
        }
      });
      await page.goto(`${baseUrl}/ui/account`);
      await page.getByLabel("Current password", { exact: true }).fill("wrong-password");
      await page.getByLabel("New password", { exact: true }).fill("new-password-value");
      await page.getByLabel("Confirm new password", { exact: true }).fill("new-password-value");
      await page.getByRole("button", { name: "Update password", exact: true }).click();
      await expect(page.getByRole("alert").filter({ hasText: "Current local password could not be verified" })).toBeVisible();
      await expect(page.getByText(loginMethod, { exact: true })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toHaveCount(0);
      await page.getByLabel("Current password", { exact: true }).fill("correct-password");
      await page.getByRole("button", { name: "Update password", exact: true }).click();
      await expect.poll(() => attempts).toBe(2);
      await expect(page.getByLabel("Current password", { exact: true })).toHaveValue("");
      await expect(page.getByText(loginMethod, { exact: true })).toBeVisible();
    });
  }
  test(`${loginMethod} password change still signs out an expired browser session`, async ({ page }) => {
    await mockSession(page, "active", loginMethod);
    await page.route("**/v1/auth/local/password/change", (route) => route.fulfill({ status: 401, json: { ok: false, reasonCode: "broker_token_expired", error: { message: "Browser session expired" } } }));
    await page.goto(`${baseUrl}/ui/account`);
    await page.getByLabel("Current password", { exact: true }).fill("correct-password");
    await page.getByLabel("New password", { exact: true }).fill("new-password-value");
    await page.getByLabel("Confirm new password", { exact: true }).fill("new-password-value");
    await page.getByRole("button", { name: "Update password", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
    await expect(page.getByLabel("Current password", { exact: true })).toHaveCount(0);
    await expect(page.getByRole("alert").filter({ hasText: "Browser session expired" })).toBeVisible();
  });
}

test("CSRF retry still leaves a wrong-current-password error inline", async ({ page }) => {
  await mockSession(page, "active", "oidc");
  let attempts = 0;
  await page.route("**/v1/auth/local/password/change", (route) => {
    attempts++;
    return route.fulfill({ status: attempts === 1 ? 403 : 401, json: { ok: false, reasonCode: attempts === 1 ? "csrf_invalid" : "local_login_failed", error: { message: attempts === 1 ? "CSRF rotated" : "Current local password could not be verified" } } });
  });
  await page.goto(`${baseUrl}/ui/account`);
  await page.getByLabel("Current password", { exact: true }).fill("wrong-password");
  await page.getByLabel("New password", { exact: true }).fill("new-password-value");
  await page.getByLabel("Confirm new password", { exact: true }).fill("new-password-value");
  await page.getByRole("button", { name: "Update password", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Current local password could not be verified" })).toBeVisible();
  expect(attempts).toBe(2);
  await expect(page.getByText("oidc", { exact: true })).toBeVisible();
});
