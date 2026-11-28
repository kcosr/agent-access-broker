// Access keys, usernames and access key types in the portal, against explicit
// API fixtures (tests/support/access-key-api.ts): every screen and state of
// the person's Keys page and issue form, an administrator's Keys tab and
// issue form, the Username section, and both access key type settings. The
// real-Broker journeys are in access-keys-live.spec.ts.
import { expect, test, type Page } from "@playwright/test";
import { ADMIN, ALICE, BOB, CAROL, DANA, INFERENCE, KEY_SECRET, PACKAGES, PERSON, PREMIUM, SERVICE, allocation, key, latestAccessKeyModel, routeAccessKeyApi, type AccessKeyModel } from "./support/access-key-api";
import type { AccessKeyAccountProblem } from "../src/types";
import { servePortalAssets, type PortalAssets } from "./support/portal-assets";

let assets: PortalAssets;
let baseUrl: string;

test.beforeAll(async () => {
  assets = await servePortalAssets();
  baseUrl = assets.baseUrl;
});
test.afterAll(async () => { await assets.close(); });
// Every test: no page error, and every write carried the session's CSRF header.
test.afterEach(() => {
  const model = latestAccessKeyModel();
  if (model) noErrors(model);
});

const nav = (page: Page) => page.getByRole("navigation", { name: "My access", exact: true });
const main = (page: Page, name: string) => page.getByRole("main", { name, exact: true });
const row = (page: Page, name: string) => page.getByRole("row").filter({ has: page.getByRole("rowheader", { name, exact: true }).or(page.getByRole("cell", { name, exact: true })) });
const editor = (page: Page) => main(page, "Issue access key");
const issueButton = (page: Page) => editor(page).getByRole("region", { name: "Issue access key", exact: true }).getByRole("button", { name: "Issue access key", exact: true });

function noErrors(model: AccessKeyModel) {
  expect(model.errors).toEqual([]);
}

/** Opens the command palette over whatever is showing and goes to a page by name. */
async function leaveThroughPalette(page: Page, name: string) {
  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog", { name: "Command palette", exact: true });
  await expect(palette).toBeVisible();
  await palette.getByRole("combobox").fill(name);
  await palette.getByRole("option", { name: new RegExp(`^${name}`) }).first().click();
}

/** The key is in the page's text while its dialog shows, and in no URL, history entry or storage. */
async function expectKeyHeldOnlyOnScreen(page: Page) {
  const places = await page.evaluate(() => ({ href: location.href, history: JSON.stringify(history.state), local: JSON.stringify({ ...localStorage }), session: JSON.stringify({ ...sessionStorage }) }));
  for (const value of Object.values(places)) expect(value).not.toContain(KEY_SECRET);
}

async function expectKeyNowhere(page: Page) {
  await expectKeyHeldOnlyOnScreen(page);
  expect(await page.evaluate(() => document.documentElement.outerHTML)).not.toContain(KEY_SECRET);
}

test.describe("a person's access keys", () => {
  test("the Keys page lists what each key gives access to, with partial and no-access labels from the server", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON());
    await page.goto(`${baseUrl}/ui/keys`);
    await expect(nav(page).getByRole("link", { name: "Keys", exact: true })).toHaveAttribute("aria-current", "page");
    // Keys comes right after Tokens.
    await expect(nav(page).getByRole("link")).toHaveText(["Access", "Tokens", "Keys", "Credentials"]);
    const list = main(page, "Access keys");
    await expect(list.getByRole("heading", { name: "Access keys", level: 1 })).toBeVisible();
    await expect(list.getByText("For tools that reach services through the gateway in front of them, such as models and web search.")).toBeVisible();
    await expect(list.getByRole("link", { name: "Issue access key", exact: true })).toBeVisible();
    await expect(row(page, "research-notebook")).toContainText("Model inference");
    await expect(row(page, "research-notebook")).toContainText("Web search · no longer available");
    await expect(row(page, "research-notebook")).toContainText("Partial access");
    await expect(row(page, "search-helper")).toContainText("No access left");
    await expect(row(page, "old-desktop")).toContainText("Expired");
    await expect(row(page, "laptop-models").getByText("Active", { exact: true })).toBeAttached();
    expect(model.requests).toContain("GET /v1/access-keys");
    noErrors(model);
  });

  test("revoking asks first and sends the key's DELETE", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON());
    await page.goto(`${baseUrl}/ui/keys`);
    await row(page, "laptop-models").getByRole("button", { name: "Revoke laptop-models", exact: true }).click();
    const dialog = page.getByRole("alertdialog").or(page.getByRole("dialog"));
    await expect(dialog).toContainText("Revoke laptop-models? Tools using this access key lose access immediately. This cannot be undone.");
    expect(model.revoked).toEqual([]);
    await dialog.getByRole("button", { name: "Revoke access key", exact: true }).click();
    await expect.poll(() => model.revoked).toEqual([`/v1/access-keys/${model.keys.find((key) => key.name === "laptop-models")!.keyId}`]);
    await expect(row(page, "laptop-models")).toContainText("Revoked");
    await expect(row(page, "laptop-models").getByRole("button", { name: "Revoke laptop-models" })).toHaveCount(0);
  });

  test("the page and its navigation item are hidden from a person with no available type and no keys", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON(), (model) => {
      model.options = { ...model.options, accessKeyTypes: [], hasSelfServiceType: false, hasKeys: false, problem: null };
      model.keys = [];
    });
    await page.goto(`${baseUrl}/ui/tokens`);
    await expect(nav(page).getByRole("link", { name: "Tokens", exact: true })).toBeVisible();
    await expect.poll(() => model.requests.filter((request) => request === "GET /v1/access-keys/options").length).toBeGreaterThan(0);
    await expect(nav(page).getByRole("link", { name: "Keys", exact: true })).toHaveCount(0);
    await page.goto(`${baseUrl}/ui/keys`);
    await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
    expect(model.requests).not.toContain("GET /v1/access-keys");
  });

  test("while no type is configured the catalog does not list the routes and the portal never asks for options", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON(), (model) => { model.offered = false; });
    await page.goto(`${baseUrl}/ui/keys`);
    await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
    await expect(nav(page).getByRole("link", { name: "Keys", exact: true })).toHaveCount(0);
    expect(model.requests.filter((request) => request.startsWith("GET /v1/access-keys"))).toEqual([]);
  });

  test("a person without self-service who holds keys sees Keys alone, and no issue button without a self-service type", async ({ page }) => {
    await routeAccessKeyApi(page, PERSON(false), (model) => {
      model.options = { ...model.options, accessKeyTypes: [PACKAGES], hasSelfServiceType: false, hasKeys: true };
    });
    await page.goto(`${baseUrl}/ui/keys`);
    await expect(nav(page).getByRole("link")).toHaveText(["Keys"]);
    await expect(row(page, "laptop-models")).toBeVisible();
    await expect(main(page, "Access keys").getByRole("link", { name: "Issue access key" })).toHaveCount(0);
  });

  // As the broker reports them: `refusal` carries every code, and `problem` too for the four it reports
  // (it is null for a paused or missing identity access, which a resolution finds first).
  for (const [code, isProblem, reason] of [
    ["no_account_username", true, "You have no username yet. Ask an administrator to set one."],
    ["group_limit_exceeded", true, "You are in too many groups for access keys to work. Ask an administrator for help."],
    ["account_username_awaiting_confirmation", true, "Your username is waiting for an administrator to confirm it. Ask an administrator for help."],
    ["account_username_reserved", true, "Your username is one the operator reserved. Ask an administrator to set another."],
    ["identity_access_paused", false, "Your access is paused. Ask an administrator for help."],
    ["identity_access_missing", false, "Your access cannot be confirmed. Ask an administrator for help."]
  ] as const) {
    test(`blocked by ${code}: the page shows the server's reason and no issue button`, async ({ page }) => {
      await routeAccessKeyApi(page, PERSON(), (model) => {
        model.options = { ...model.options, hasKeys: false, refusal: code, problem: isProblem ? code : null };
        model.keys = [];
      });
      await page.goto(`${baseUrl}/ui/keys`);
      const list = main(page, "Access keys");
      await expect(list.getByText(reason, { exact: true })).toBeVisible();
      await expect(list.getByRole("link", { name: "Issue access key" })).toHaveCount(0);
      await expect(list.getByRole("button", { name: "Issue access key" })).toHaveCount(0);
      await expect(list.getByText("No access keys", { exact: true })).toBeVisible();
      await expect(nav(page).getByRole("link", { name: "Keys", exact: true })).toBeVisible();
      await page.goto(`${baseUrl}/ui/keys/new`);
      await expect(editor(page).getByText(reason, { exact: true })).toBeVisible();
      await expect(editor(page).getByRole("checkbox")).toHaveCount(0);
    });
  }
});

test.describe("a person whose identity access is paused", () => {
  test("still sees and revokes the keys they hold, and is told why they cannot issue", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON(), (model) => {
      model.options = { ...model.options, refusal: "identity_access_paused", problem: null };
      model.keys = model.keys.map((item) => (item.status === "active" ? { ...item, status: "identity_access_paused" as const, usableAccessKeyTypes: [], access: "none" as const } : item));
    });
    await page.goto(`${baseUrl}/ui/keys`);
    const list = main(page, "Access keys");
    await expect(list.getByText("Your access is paused. Ask an administrator for help.", { exact: true })).toBeVisible();
    await expect(list.getByRole("link", { name: "Issue access key" })).toHaveCount(0);
    await expect(row(page, "laptop-models")).toContainText("Access paused");
    await row(page, "laptop-models").getByRole("button", { name: "Revoke laptop-models", exact: true }).click();
    await page.getByRole("button", { name: "Revoke access key", exact: true }).click();
    await expect.poll(() => model.revoked).toEqual([`/v1/access-keys/${model.keys.find((item) => item.name === "laptop-models")!.keyId}`]);
    await expect(row(page, "laptop-models")).toContainText("Revoked");
    await page.goto(`${baseUrl}/ui/keys/new`);
    await expect(editor(page).getByText("Your access is paused. Ask an administrator for help.", { exact: true })).toBeVisible();
    await expect(editor(page).getByRole("checkbox")).toHaveCount(0);
    expect(model.issued).toEqual([]);
  });

  test("with nothing to issue and no key has no Keys page", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON(), (model) => {
      model.options = { ...model.options, accessKeyTypes: [PACKAGES], hasSelfServiceType: false, hasKeys: false, refusal: "identity_access_paused", problem: null };
      model.keys = [];
    });
    await page.goto(`${baseUrl}/ui/tokens`);
    await expect.poll(() => model.requests.includes("GET /v1/access-keys/options")).toBe(true);
    await expect(nav(page).getByRole("link", { name: "Keys", exact: true })).toHaveCount(0);
    await page.goto(`${baseUrl}/ui/keys`);
    await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
  });
});

test.describe("an issue refused because no key of the account could work", () => {
  for (const [code, own, administered, fix] of [
    ["group_limit_exceeded", "You are in too many groups for access keys to work. Ask an administrator for help.", "This account is in too many groups for access keys to work. Remove it from some groups on the Groups tab first.", "Open Groups"],
    ["identity_access_missing", "Your access cannot be confirmed. Ask an administrator for help.", "This person’s identity access record is missing, so their access keys cannot work. Ask the operator to check the managed store.", null]
  ] as const) {
    test(`${code}: a person's form says why and keeps the draft, then the page is blocked once the options are read`, async ({ page }) => {
      const model = await routeAccessKeyApi(page, PERSON());
      await page.goto(`${baseUrl}/ui/keys/new`);
      await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
      await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("laptop-models-2");
      // The account changed after the form was read; the refresh that follows the refusal fails at first.
      model.refuseNextIssue = { refusal: code, options: { refusal: code, problem: code === "group_limit_exceeded" ? code : null }, then: () => { model.fail.options = true; } };
      await issueButton(page).click();
      // The refusal's sentence, beside the alert that the refresh failed.
      await expect(editor(page).getByRole("alert").filter({ hasText: own })).toHaveText(own);
      await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("laptop-models-2");
      await expect(issueButton(page)).toBeDisabled();
      model.fail.options = false;
      await editor(page).getByRole("button", { name: "Retry" }).click();
      await expect(editor(page).getByText("You cannot issue an access key now", { exact: true })).toBeVisible();
      await expect(editor(page).getByText(own, { exact: true })).toBeVisible();
      await expect(editor(page).getByRole("checkbox")).toHaveCount(0);
      expect(model.issued).toHaveLength(1);
    });

    test(`${code}: an administrator's form says why and keeps the draft, then the page is blocked with the fix`, async ({ page }) => {
      const model = await routeAccessKeyApi(page, ADMIN());
      await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}/keys/new`);
      await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
      await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("ci-cache");
      model.refuseNextIssue = { refusal: code, then: () => { model.accounts[ALICE]!.accessKeyProblem = code; model.fail.principal = ALICE; } };
      await issueButton(page).click();
      // The refusal's sentence, beside the alert that the refresh failed.
      await expect(editor(page).getByRole("alert").filter({ hasText: administered })).toHaveText(administered);
      await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("ci-cache");
      await expect(issueButton(page)).toBeDisabled();
      model.fail.principal = "";
      await editor(page).getByRole("button", { name: "Retry" }).click();
      await expect(editor(page).getByText("An access key cannot be issued for this account now", { exact: true })).toBeVisible();
      await expect(editor(page).getByText(administered, { exact: true })).toBeVisible();
      await expect(editor(page).getByRole("link", { name: "Open Groups", exact: true })).toHaveCount(fix === "Open Groups" ? 1 : 0);
      await expect(editor(page).getByRole("checkbox")).toHaveCount(0);
      expect(model.issued).toHaveLength(1);
    });
  }
});

test.describe("failing closed when what decides issuing cannot be read", () => {
  test("the Keys page offers no issue button while its options fail to refresh", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON());
    await page.goto(`${baseUrl}/ui/keys`);
    await expect(main(page, "Access keys").getByRole("link", { name: "Issue access key" }).first()).toBeVisible();
    model.fail.options = true;
    await nav(page).getByRole("link", { name: "Tokens", exact: true }).click();
    await nav(page).getByRole("link", { name: "Keys", exact: true }).click();
    const list = main(page, "Access keys");
    await expect(list.getByText("Couldn’t refresh your access key options")).toBeVisible();
    await expect(list.getByRole("link", { name: "Issue access key" })).toHaveCount(0);
    await expect(row(page, "laptop-models")).toBeVisible();
  });

  test("a fresh issue form waits for a successful read of the options, even with cached ones", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON());
    await page.goto(`${baseUrl}/ui/keys`);
    await expect(row(page, "laptop-models")).toBeVisible();
    model.fail.options = true;
    await main(page, "Access keys").getByRole("link", { name: "Issue access key" }).first().click();
    await expect(editor(page).getByText("Couldn’t load your access key options")).toBeVisible();
    await expect(editor(page).getByRole("checkbox")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Issue access key" })).toHaveCount(0);
    model.fail.options = false;
    await editor(page).getByRole("button", { name: "Retry" }).click();
    await expect(editor(page).getByRole("checkbox", { name: "Model inference" })).toBeVisible();
  });

  test("a failed refresh after a refused issue keeps the draft and blocks issuing until a refresh succeeds", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON());
    await page.goto(`${baseUrl}/ui/keys/new`);
    await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("laptop-models-2");
    model.refuseNextIssue = { refusal: "lifetime_not_offered" };
    model.fail.options = true;
    await issueButton(page).click();
    await expect(editor(page).getByText("Couldn’t refresh your access key options")).toBeVisible();
    await expect(issueButton(page)).toBeDisabled();
    await expect(editor(page).getByRole("status")).toContainText("could not be refreshed");
    await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("laptop-models-2");
    await expect(editor(page).getByRole("checkbox", { name: "Model inference" })).toBeChecked();
    model.fail.options = false;
    await editor(page).getByRole("button", { name: "Retry" }).click();
    await expect(issueButton(page)).toBeEnabled();
    await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("laptop-models-2");
  });

  for (const failing of ["types", "principal"] as const) {
    test(`an administrator's issue form and Keys tab fail closed when the ${failing === "types" ? "type list" : "account"} fails to refresh`, async ({ page }) => {
      const model = await routeAccessKeyApi(page, ADMIN());
      await page.goto(`${baseUrl}/ui/admin/principals/${DANA}/keys`);
      await expect(page.getByRole("link", { name: "Issue access key", exact: true })).toBeVisible();
      if (failing === "types") model.fail.types = true;
      else model.fail.principal = DANA;
      await page.getByRole("link", { name: "Issue access key", exact: true }).click();
      await expect(editor(page).getByText("Couldn’t load the account’s access key types")).toBeVisible();
      await expect(editor(page).getByRole("checkbox")).toHaveCount(0);
      await expect(page.getByRole("button", { name: "Issue access key" })).toHaveCount(0);
      await editor(page).getByRole("link", { name: "Keys" }).click();
      if (failing === "types") {
        // The Keys tab says why it cannot offer issuing instead of using the cached list.
        await expect(page.getByRole("button", { name: "Issue access key", exact: true })).toBeDisabled();
        await expect(page.getByText("The access key types could not be loaded.")).toBeVisible();
      } else {
        // Without a current read of the account the tab shows the error, and nothing to issue from.
        await expect(page.getByRole("button", { name: "Retry" })).toBeVisible();
        await expect(page.getByRole("link", { name: "Issue access key", exact: true })).toHaveCount(0);
        await expect(page.getByRole("button", { name: "Issue access key", exact: true })).toHaveCount(0);
      }
    });
  }
});

for (const administered of [false, true]) {
  test.describe(`${administered ? "Administrator" : "Personal"} configured key lifetimes`, () => {
    const issuePath = administered ? `/ui/admin/principals/${DANA}/keys/new` : "/ui/keys/new";

    for (const changed of [false, true]) {
      test(`a lifetime refusal refresh ${changed ? "preselects a replacement and clears the stale error" : "preserves an offered choice and its error"}`, async ({ page }) => {
        const model = await routeAccessKeyApi(page, administered ? ADMIN() : PERSON());
        await page.goto(`${baseUrl}${issuePath}`);
        await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
        await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("refreshed-lifetime");
        const lifetime = editor(page).getByRole("combobox", { name: "Lifetime" });
        await lifetime.selectOption("30d");
        model.refuseNextIssue = {
          refusal: "lifetime_not_offered",
          then: () => {
            if (!changed) return;
            const replacement = { ...INFERENCE, lifetimeOptions: ["1d", "7d"], defaultLifetime: "7d" };
            model.options.accessKeyTypes = model.options.accessKeyTypes.map((type) => type.id === INFERENCE.id ? replacement : type);
            model.types = model.types.map((type) => type.id === INFERENCE.id ? replacement : type);
          }
        };
        await issueButton(page).click();
        await expect(issueButton(page)).toBeEnabled();
        await expect(lifetime).toHaveValue(changed ? "7d" : "30d");
        const error = editor(page).getByText("The chosen lifetime is no longer offered by every access type. Choose an available lifetime.");
        if (changed) await expect(error).toHaveCount(0);
        else await expect(error).toBeVisible();
        // Refresh never submits the replacement automatically.
        expect(model.issued).toHaveLength(1);
      });
    }

    test("expiry sorting treats Never as later than every finite expiry in both directions", async ({ page }) => {
      const types = [{ id: INFERENCE.id, displayName: INFERENCE.displayName, held: true }];
      const keys = [
        key("never-alpha", types, { principalId: administered ? DANA : ALICE, expiresInDays: null }),
        key("later", types, { principalId: administered ? DANA : ALICE, expiresInDays: 60 }),
        key("sooner", types, { principalId: administered ? DANA : ALICE, expiresInDays: 1 }),
        key("never-beta", types, { principalId: administered ? DANA : ALICE, expiresInDays: null })
      ];
      await routeAccessKeyApi(page, administered ? ADMIN() : PERSON(), (model) => {
        if (administered) model.adminKeys[DANA] = keys;
        else model.keys = keys;
      });
      const listPath = administered ? `/ui/admin/principals/${DANA}/keys` : "/ui/keys";
      await page.goto(`${baseUrl}${listPath}`);
      const expires = page.getByRole("columnheader", { name: "Expires" }).getByRole("button");
      const names = () => page.getByRole("rowheader").allTextContents();
      await expires.click();
      await expect.poll(names).toEqual(["sooner", "later", "never-alpha", "never-beta"]);
      await expires.click();
      await expect.poll(names).toEqual(["never-alpha", "never-beta", "later", "sooner"]);
    });

    test("a stored key without expiry displays Never even when its type has a finite validity", async ({ page }) => {
      const stored = key("continuous-existing", [{ id: INFERENCE.id, displayName: INFERENCE.displayName, held: true }], {
        principalId: administered ? DANA : ALICE, expiresInDays: null, usedHoursAgo: null,
        usableAccessKeyTypes: [{ name: "inference", validUntil: "2026-12-31T00:00:00Z" }]
      });
      await routeAccessKeyApi(page, administered ? ADMIN() : PERSON(), (model) => {
        if (administered) model.adminKeys[DANA] = [stored];
        else model.keys = [stored];
      });
      const listPath = administered ? `/ui/admin/principals/${DANA}/keys` : "/ui/keys";
      await page.goto(`${baseUrl}${listPath}?key=${stored.keyId}`);
      await expect(row(page, stored.name).getByRole("cell", { name: "Never", exact: true })).toHaveCount(2);
      await expect(row(page, stored.name)).toContainText("Active");
      await expect(page.getByRole("complementary", { name: `Access key ${stored.name}` })).toContainText("ExpiresNever");
    });

    test("common options keep first-selected order and spelling, choose the shortest fallback, and issue never", async ({ page }) => {
      const types = [
        { ...INFERENCE, lifetimeOptions: ["never", "12h", "7d", "1d", "90m"], defaultLifetime: "12h" },
        { ...PREMIUM, lifetimeOptions: ["48h", "1440m", "168h", "never", "5400s"], defaultLifetime: "48h" }
      ];
      const model = await routeAccessKeyApi(page, administered ? ADMIN() : PERSON(), (model) => {
        model.types = types;
        model.options = { ...model.options, accessKeyTypes: types };
      });
      await page.goto(`${baseUrl}${issuePath}`);
      const lifetime = editor(page).getByRole("combobox", { name: "Lifetime", exact: true });
      await expect(lifetime).toBeDisabled();
      await expect(lifetime.locator("option")).toHaveCount(0);
      await expect(editor(page)).toContainText("Choose access to see its lifetime options.");
      // Premium is first even though it is second in the server's type list.
      await editor(page).getByRole("checkbox", { name: "Premium models" }).check();
      await expect(lifetime).toHaveValue("48h");
      await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
      await expect(lifetime.locator("option")).toHaveText(["1 day", "7 days", "Never expires", "90 minutes"]);
      expect(await lifetime.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value))).toEqual(["1440m", "168h", "never", "5400s"]);
      await expect(lifetime).toHaveValue("5400s");
      await lifetime.selectOption("never");
      await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("continuous-tool");
      await expect(editor(page).getByRole("complementary", { name: "Access key summary" })).toContainText("Never expires");
      await issueButton(page).click();
      expect(model.issued).toEqual([{ pathname: administered ? `/v1/admin/principals/${DANA}/access-keys` : "/v1/access-keys", body: { name: "continuous-tool", accessKeyTypes: ["premium-models", "inference"], lifetime: "never" } }]);
      const dialog = page.getByRole("dialog", { name: "Access key created" });
      await expect(dialog).toContainText("ExpiresNever");
      await dialog.getByRole("button", { name: "Done", exact: true }).click();
      await expect(row(page, "continuous-tool").getByRole("cell", { name: "Never", exact: true })).toHaveCount(2);
      const drawer = page.getByRole("complementary", { name: "Access key continuous-tool" });
      await expect(drawer).toContainText("ExpiresNever");
      const records = administered ? model.adminKeys[DANA]! : model.keys;
      expect(records.find((key) => key.name === "continuous-tool")?.expiresAt).toBeNull();
    });

    test("automatic defaults follow type changes while a common manual choice is retained", async ({ page }) => {
      const types = [
        { ...INFERENCE, lifetimeOptions: ["never", "7d", "1d"], defaultLifetime: "7d" },
        { ...PREMIUM, lifetimeOptions: ["never", "24h", "168h"], defaultLifetime: "24h" },
        { ...PACKAGES, selfService: true, lifetimeOptions: ["24h", "7d"], defaultLifetime: "7d" }
      ];
      await routeAccessKeyApi(page, administered ? ADMIN() : PERSON(), (model) => {
        model.types = types;
        model.options = { ...model.options, accessKeyTypes: types };
      });
      await page.goto(`${baseUrl}${issuePath}`);
      const lifetime = editor(page).getByRole("combobox", { name: "Lifetime", exact: true });
      const inference = editor(page).getByRole("checkbox", { name: "Model inference" });
      const premium = editor(page).getByRole("checkbox", { name: "Premium models" });
      await inference.check();
      await expect(lifetime).toHaveValue("7d");
      await premium.check();
      // An untouched default changes even though the previous value remains offered.
      await expect(lifetime).toHaveValue("1d");
      await premium.uncheck();
      await expect(lifetime).toHaveValue("7d");
      await lifetime.selectOption("never");
      await premium.check();
      await expect(lifetime).toHaveValue("never");
      await editor(page).getByRole("checkbox", { name: "Package downloads" }).check();
      // A manual value that is no longer common is removed, and the new default is selected.
      await expect(lifetime.locator("option")).toHaveText(["7 days", "1 day"]);
      await expect(lifetime).toHaveValue("1d");
      await premium.uncheck();
      // The fallback was automatic, so it follows subsequent default changes.
      await expect(lifetime).toHaveValue("7d");
      await inference.uncheck();
      await expect(lifetime.locator("option")).toHaveText(["1 day", "7 days"]);
      await expect(lifetime).toHaveValue("7d");
    });

    test("no shared lifetime explains and blocks issuance, then removing the conflicting type restores its default", async ({ page }) => {
      const types = [
        { ...INFERENCE, lifetimeOptions: ["never", "90m"], defaultLifetime: "never" },
        { ...PREMIUM, lifetimeOptions: ["1d"], defaultLifetime: "1d" }
      ];
      const model = await routeAccessKeyApi(page, administered ? ADMIN() : PERSON(), (model) => {
        model.types = types;
        model.options = { ...model.options, accessKeyTypes: types };
      });
      await page.goto(`${baseUrl}${issuePath}`);
      const lifetime = editor(page).getByRole("combobox", { name: "Lifetime", exact: true });
      await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
      await expect(lifetime).toHaveValue("never");
      await editor(page).getByRole("checkbox", { name: "Premium models" }).check();
      await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("conflicting-types");
      await expect(lifetime).toBeDisabled();
      await expect(lifetime.locator("option")).toHaveCount(0);
      await expect(editor(page).getByRole("status")).toContainText("The chosen access types have no lifetime in common.");
      await expect(issueButton(page)).toBeDisabled();
      expect(model.issued).toEqual([]);
      await editor(page).getByRole("checkbox", { name: "Premium models" }).uncheck();
      await expect(lifetime).toHaveValue("never");
      await expect(issueButton(page)).toBeEnabled();
    });
  });
}

test.describe("issuing a key for yourself", () => {
  test("with one type offered nothing is chosen, and the form waits for a choice", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON(), (model) => {
      model.options = { ...model.options, accessKeyTypes: [INFERENCE, PACKAGES] };
    });
    await page.goto(`${baseUrl}/ui/keys/new`);
    const inference = editor(page).getByRole("checkbox", { name: "Model inference" });
    await expect(inference).not.toBeChecked();
    // A type people cannot issue themselves is not offered to them.
    await expect(editor(page).getByRole("checkbox")).toHaveCount(1);
    await expect(editor(page)).toContainText("Call the hosted models through the gateway.");
    await expect(editor(page)).toContainText("Lifetimes: 1 day, 7 days, 14 days, 30 days. Default: 7 days.");
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("laptop-models");
    await expect(issueButton(page)).toBeDisabled();
    await expect(editor(page).getByRole("status")).toContainText("1 issue · Choose what this key gives access to.");
    // The summary has no "Used at" row.
    const summary = editor(page).getByRole("complementary", { name: "Access key summary" });
    await expect(summary).toContainText("Nothing chosen yet");
    await expect(summary).not.toContainText("Used at");
    await expect(summary).toContainText("alice");
    await inference.check();
    await expect(editor(page).getByRole("status")).toContainText("Ready to issue. An access key cannot be edited after it is issued.");
    await expect(issueButton(page)).toBeEnabled();
    expect(model.issued).toEqual([]);
    noErrors(model);
  });

  test("the issued key is shown once, with a copy control and a statement that it cannot be shown again", async ({ page, context }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: baseUrl });
    const model = await routeAccessKeyApi(page, PERSON());
    await page.goto(`${baseUrl}/ui/keys`);
    await main(page, "Access keys").getByRole("link", { name: "Issue access key" }).first().click();
    await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
    await editor(page).getByRole("checkbox", { name: "Premium models" }).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("desk-workstation");
    await editor(page).getByRole("combobox", { name: "Lifetime", exact: true }).selectOption({ label: "14 days" });
    await issueButton(page).click();
    const dialog = page.getByRole("dialog", { name: "Access key created" });
    await expect(dialog).toContainText("Copy this access key now. It cannot be shown again after you close this dialog.");
    await expect(dialog.getByLabel("Access key", { exact: true })).toHaveText(KEY_SECRET);
    await expect(dialog).toContainText("Model inference");
    await expect(dialog).toContainText("Premium models");
    await expect(dialog).toContainText("alice");
    expect(model.issued).toEqual([{ pathname: "/v1/access-keys", body: { name: "desk-workstation", accessKeyTypes: ["inference", "premium-models"], lifetime: "14d" } }]);
    await dialog.getByRole("button", { name: "Copy access key", exact: true }).click();
    await expect(dialog.getByRole("button", { name: "Copied", exact: true })).toBeVisible();
    // Assistive technology hears it too.
    await expect(dialog.getByRole("status")).toHaveText("Copied");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(KEY_SECRET);
    // The list opens on the new key behind the dialog.
    await expect(page).toHaveURL(/\/ui\/keys\?key=ak_/);
    // Escape does not close it; only Done does, and then the key is gone.
    await page.keyboard.press("Escape");
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: "Done", exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expect(row(page, "desk-workstation")).toBeVisible();
    await expect(page.getByText(KEY_SECRET)).toHaveCount(0);
    // Back stays in the portal, on the list the key was issued from.
    await page.goBack();
    await expect(page).toHaveURL(/\/ui\/keys$/);
    await expect(row(page, "desk-workstation")).toBeVisible();
    await expectKeyNowhere(page);
  });

  test("a key still open in its dialog cannot be replaced through the palette; Back clears it and Forward cannot reveal it", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON());
    await page.goto(`${baseUrl}/ui/keys`);
    await main(page, "Access keys").getByRole("link", { name: "Issue access key" }).first().click();
    await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("laptop-models-2");
    await issueButton(page).click();
    const dialog = page.getByRole("dialog", { name: "Access key created" });
    await expect(dialog.getByLabel("Access key", { exact: true })).toHaveText(KEY_SECRET);
    // The issue-to-list transition keeps it; any later departure clears it.
    await expect(page).toHaveURL(/\/ui\/keys\?key=ak_/);
    await expectKeyHeldOnlyOnScreen(page);
    // The palette does not open over it, so none of its actions can replace it.
    await page.keyboard.press("Control+k");
    await expect(page.getByRole("dialog", { name: "Command palette", exact: true })).toHaveCount(0);
    await expect(dialog.getByLabel("Access key", { exact: true })).toHaveText(KEY_SECRET);
    // Back returns to the list it was issued from (the form's entry was
    // replaced): the same page, without the key, and the dialog ends.
    await page.goBack();
    await expect(page).toHaveURL(/\/ui\/keys$/);
    await expect(dialog).toHaveCount(0);
    await expect(page.getByText(KEY_SECRET)).toHaveCount(0);
    await page.goForward();
    await expect(page).toHaveURL(/\/ui\/keys\?key=ak_/);
    await expect(row(page, "laptop-models-2")).toBeVisible();
    await expect(page.getByRole("dialog", { name: "Access key created" })).toHaveCount(0);
    await expectKeyNowhere(page);
    noErrors(model);
  });

  test("a key still open in its dialog is cleared when a session refresh requires a password change", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON());
    await page.goto(`${baseUrl}/ui/keys/new`);
    await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("laptop-models-2");
    // After the issue, the list's refresh is refused and the session read again
    // says a password change is required; nothing else about the person changed.
    await page.route((url) => url.pathname === "/v1/access-keys", (route) => route.request().method() === "GET"
      ? route.fulfill({ status: 403, json: { ok: false, reasonCode: "broker_access_key_denied", error: { message: "access key refused" } } })
      : route.fallback());
    let release!: () => void;
    const sessionResponse = new Promise<void>((resolve) => { release = resolve; });
    await page.route((url) => url.pathname === "/v1/auth/session", async (route) => {
      await sessionResponse;
      await route.fulfill({ json: { ok: true, result: { ...PERSON(), passwordChangeRequired: true } } });
    });
    try {
      await issueButton(page).click();
      await expect.poll(() => model.issued.length).toBe(1);
      const dialog = page.getByRole("dialog", { name: "Access key created" });
      await expect(dialog).toBeVisible();
      await expect(dialog.getByText(KEY_SECRET)).toBeVisible();
    } finally {
      release();
    }
    await expect(page.getByText("Change your password to continue", { exact: true })).toBeVisible();
    await expect(page.getByRole("dialog", { name: "Access key created" })).toHaveCount(0);
    await expect(page.getByText(KEY_SECRET)).toHaveCount(0);
    await expectKeyNowhere(page);
  });

  for (const administered of [false, true]) {
    test(`${administered ? "an administrator's" : "a person's"} new key's details wait behind its dialog, which keeps focus and Escape`, async ({ page }) => {
      const model = await routeAccessKeyApi(page, administered ? ADMIN() : PERSON());
      await page.goto(administered ? `${baseUrl}/ui/admin/principals/${ALICE}/keys/new` : `${baseUrl}/ui/keys/new`);
      await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
      await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("laptop-models-2");
      await issueButton(page).click();
      const dialog = page.getByRole("dialog", { name: "Access key created" });
      await expect(dialog.getByLabel("Access key", { exact: true })).toHaveText(KEY_SECRET);
      // The list's refresh has brought the new key in behind the dialog.
      await expect(row(page, "laptop-models-2")).toBeAttached();
      await expect(page).toHaveURL(/\/keys\?key=ak_/);
      await expect.poll(() => page.evaluate(() => Boolean(document.activeElement?.closest("[role=dialog]")?.textContent?.includes("Access key created")))).toBe(true);
      await page.keyboard.press("Escape");
      await expect(dialog).toBeVisible();
      await expect(page).toHaveURL(/\/keys\?key=ak_/);
      await expect.poll(() => page.evaluate(() => Boolean(document.activeElement?.closest("[role=dialog]")?.textContent?.includes("Access key created")))).toBe(true);
      // Done ends the dialog, and the key's details open.
      await dialog.getByRole("button", { name: "Done", exact: true }).click();
      await expect(dialog).toHaveCount(0);
      await expect(page).toHaveURL(/\/keys\?key=ak_/);
      await expect(page.getByRole("heading", { name: "laptop-models-2" })).toBeVisible();
      noErrors(model);
    });
  }

  test("when the clipboard refuses, the key is selected for copying by hand and the dialog says how", async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: () => Promise.reject(new Error("refused")) } });
    });
    await routeAccessKeyApi(page, PERSON());
    await page.goto(`${baseUrl}/ui/keys/new`);
    await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("laptop-models-2");
    await issueButton(page).click();
    const dialog = page.getByRole("dialog", { name: "Access key created" });
    const secret = dialog.getByLabel("Access key", { exact: true });
    await expect(secret).toHaveText(KEY_SECRET);
    await dialog.getByRole("button", { name: "Copy access key", exact: true }).click();
    await expect(dialog.getByRole("status")).toHaveText(/^Press (Ctrl\+C|⌘C) to copy$/);
    await expect(secret).toBeFocused();
    expect(await page.evaluate(() => window.getSelection()?.toString())).toBe(KEY_SECRET);
    await expect(dialog.getByRole("button", { name: "Copied", exact: true })).toHaveCount(0);
    // The key can be reached and selected from the keyboard.
    await expect(secret).toHaveAttribute("tabindex", "0");
  });

  for (const [label, displayName, shown] of [["a blank display name", "   ", null], ["a display name with direction controls", "Alice\u202e Example", "Alice Example"]] as const) {
    test(`the key's dialog names its owner as the rest of the portal does, for ${label}`, async ({ page }) => {
      await routeAccessKeyApi(page, { ...PERSON(), displayName });
      await page.goto(`${baseUrl}/ui/keys/new`);
      await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
      await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("laptop-models-2");
      await issueButton(page).click();
      const dialog = page.getByRole("dialog", { name: "Access key created" });
      await expect(dialog.getByLabel("Access key", { exact: true })).toHaveText(KEY_SECRET);
      expect(await dialog.textContent()).not.toContain("\u202e");
      if (shown) await expect(dialog).toContainText(`${shown} ${ALICE}`);
      // Without a usable name the owner is the principal ID itself, not a blank name beside it.
      else await expect(dialog.locator(".wb-num", { hasText: ALICE })).not.toHaveClass(/wb-muted/);
    });
  }

  test("a double activation of Issue sends one request", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON());
    await page.goto(`${baseUrl}/ui/keys/new`);
    await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("laptop-models-2");
    // Two activations in one task, before the page can show that issuing began.
    await issueButton(page).evaluate((button: HTMLButtonElement) => { button.click(); button.click(); });
    await expect(page.getByRole("dialog", { name: "Access key created" })).toBeVisible();
    expect(model.issued).toHaveLength(1);
    noErrors(model);
  });

  test("leaving the browser page while a key is being issued asks first", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON());
    let release = () => {};
    const held = new Promise<void>((resolve) => { release = resolve; });
    await page.route((url) => url.pathname === "/v1/access-keys", async (route) => {
      if (route.request().method() !== "POST") return route.fallback();
      await held;
      return route.fallback();
    });
    const leaving = () => page.evaluate(() => { const event = new Event("beforeunload", { cancelable: true }); window.dispatchEvent(event); return event.defaultPrevented; });
    await page.goto(`${baseUrl}/ui/keys/new`);
    await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("laptop-models-2");
    expect(await leaving()).toBe(false);
    await issueButton(page).click();
    await expect(editor(page).getByRole("status")).toContainText("Issuing the access key.");
    expect(await leaving()).toBe(true);
    release();
    await expect(page.getByRole("dialog", { name: "Access key created" })).toBeVisible();
    expect(await leaving()).toBe(false);
    expect(model.issued).toHaveLength(1);
  });

  test("a dismissed key is nowhere: not in the URL, router state or browser storage", async ({ page }) => {
    await routeAccessKeyApi(page, PERSON());
    await page.goto(`${baseUrl}/ui/keys/new`);
    await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("laptop-models-2");
    await issueButton(page).click();
    const dialog = page.getByRole("dialog", { name: "Access key created" });
    await dialog.getByRole("button", { name: "Done", exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expectKeyNowhere(page);
    await page.reload();
    await expect(row(page, "laptop-models-2")).toBeVisible();
    await expect(page.getByText(KEY_SECRET)).toHaveCount(0);
  });

  test("a chosen type that stops being offered after a refused issue can be removed, keeping the rest of the draft", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON(), (model) => {
      model.options = { ...model.options, accessKeyTypes: [INFERENCE, PACKAGES, PREMIUM] };
    });
    await page.goto(`${baseUrl}/ui/keys/new`);
    await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
    await editor(page).getByRole("checkbox", { name: "Premium models" }).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("desk-workstation");
    model.refuseNextIssue = { refusal: "access_key_type_not_eligible", accessKeyType: "premium-models", options: { accessKeyTypes: [INFERENCE, PACKAGES] } };
    await issueButton(page).click();
    await expect(editor(page).getByRole("alert")).toHaveText("One of the chosen types is no longer allowed. Reload the page and choose again.");
    await expect(editor(page).getByRole("status")).toContainText("Remove access that is no longer offered.");
    await expect(editor(page)).toContainText("Remove access that is no longer offered before choosing a lifetime.");
    await expect(editor(page)).not.toContainText("The chosen access types have no lifetime in common.");
    const gone = editor(page).getByRole("checkbox", { name: "Premium models" });
    await expect(gone).toBeChecked();
    await expect(editor(page)).toContainText("No longer offered to you. Remove it to issue this key.");
    // Unticking removes it from the draft, and with it the row.
    await gone.click();
    await expect(editor(page).getByRole("checkbox", { name: "Premium models" })).toHaveCount(0);
    await expect(editor(page).getByRole("checkbox", { name: "Model inference" })).toBeChecked();
    await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("desk-workstation");
    await expect(issueButton(page)).toBeEnabled();
    await issueButton(page).click();
    await expect(page.getByRole("dialog", { name: "Access key created" })).toBeVisible();
    expect(model.issued.at(-1)).toEqual({ pathname: "/v1/access-keys", body: { name: "desk-workstation", accessKeyTypes: ["inference"], lifetime: "7d" } });
  });

  test("a refused issue shows the server's reason in the form and keeps the draft", async ({ page }) => {
    const model = await routeAccessKeyApi(page, PERSON());
    await page.route("**/v1/access-keys", async (route) => {
      if (route.request().method() !== "POST") return route.fallback();
      model.issued.push({ pathname: "/v1/access-keys", body: route.request().postDataJSON() });
      await route.fulfill({ status: 403, json: { ok: false, reasonCode: "broker_access_key_denied", error: { message: "access key refused" }, details: { refusal: "no_account_username" } } });
    });
    await page.goto(`${baseUrl}/ui/keys/new`);
    await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("laptop-models");
    await issueButton(page).click();
    await expect(editor(page).getByRole("alert")).toHaveText("You have no username yet. Ask an administrator to set one.");
    await expect(editor(page).getByRole("textbox", { name: "Name", exact: true })).toHaveValue("laptop-models");
    await expect(page.getByRole("dialog", { name: "Access key created" })).toHaveCount(0);
  });
});

test.describe("an administrator's Keys tab", () => {
  test("lists the account's keys with who issued them, filters by status, and revokes", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN());
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}/keys`);
    const tabs = page.getByRole("navigation", { name: "User sections" });
    await expect(tabs.getByRole("link", { name: "Keys" })).toHaveAttribute("aria-current", "page");
    await expect(tabs.getByRole("link")).toContainText(["Overview", "Access", "Grants", "Groups", "Tokens", "Keys", "Credentials", "Limits"]);
    const status = page.getByRole("radiogroup", { name: "Access key status" }).or(page.getByRole("group", { name: "Access key status" }));
    await expect(status).toContainText(/Current\s*4/);
    await expect(row(page, "premium-eval")).toContainText("Admin");
    await expect(row(page, "laptop-models")).toContainText("Alice Example");
    await expect(row(page, "old-desktop")).toHaveCount(0);
    await status.getByRole("button", { name: /Expired/ }).or(status.getByRole("radio", { name: /Expired/ })).click();
    await expect(row(page, "old-desktop")).toBeVisible();
    await status.getByRole("button", { name: /Current/ }).or(status.getByRole("radio", { name: /Current/ })).click();
    await row(page, "laptop-models").getByRole("button", { name: "Revoke laptop-models" }).click();
    await page.getByRole("button", { name: "Revoke access key", exact: true }).click();
    await expect.poll(() => model.revoked).toEqual([expect.stringMatching(/^\/v1\/admin\/access-keys\/ak_/)]);
  });

  test("issues a key for a person allowed every type, offering types people cannot issue themselves", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN());
    await page.goto(`${baseUrl}/ui/admin/principals/${DANA}/keys`);
    await page.getByRole("link", { name: "Issue access key", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/principals/${DANA}/keys/new$`));
    await expect(editor(page)).toContainText(`For Dana Example · ${DANA}`);
    for (const name of ["Model inference", "Package downloads", "Premium models", "Web search"]) {
      await expect(editor(page).getByRole("checkbox", { name })).not.toBeChecked();
    }
    await expect(editor(page)).toContainText("Lifetimes: 1 day, 7 days. Default: 7 days. People cannot issue it themselves.");
    // Dana is allowed every type, so none is named as not offered (see the next tests for one that is not).
    await expect(editor(page)).not.toContainText("Not offered");
    await expect(editor(page).getByRole("status")).toContainText("2 issues · Choose what this key gives access to.");
    await editor(page).getByRole("checkbox", { name: "Package downloads" }).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("ci-cache");
    await expect(editor(page)).toContainText("services will know it as dana.");
    await issueButton(page).click();
    const dialog = page.getByRole("dialog", { name: "Access key created" });
    await expect(dialog.getByLabel("Access key", { exact: true })).toHaveText(KEY_SECRET);
    await expect(dialog).toContainText("Dana Example");
    expect(model.issued).toEqual([{ pathname: `/v1/admin/principals/${DANA}/access-keys`, body: { name: "ci-cache", accessKeyTypes: ["package-downloads"], lifetime: "7d" } }]);
    await dialog.getByRole("button", { name: "Done", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/principals/${DANA}/keys\\?key=`));
    await expect(row(page, "ci-cache")).toBeVisible();
  });

  test("an administrator's key still open in its dialog cannot be replaced through the palette, and Back clears it", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN());
    await page.goto(`${baseUrl}/ui/admin/principals/${SERVICE}/keys`);
    await page.getByRole("link", { name: "Issue access key", exact: true }).click();
    await editor(page).getByRole("checkbox", { name: "Package downloads" }).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("ci-cache");
    await issueButton(page).click();
    const dialog = page.getByRole("dialog", { name: "Access key created" });
    await expect(dialog.getByLabel("Access key", { exact: true })).toHaveText(KEY_SECRET);
    await expect(page).toHaveURL(new RegExp(`/ui/admin/principals/${SERVICE}/keys\\?key=ak_`));
    // Create user, Create group or Reload would otherwise replace the dialog.
    await page.keyboard.press("Control+k");
    await expect(page.getByRole("dialog", { name: "Command palette", exact: true })).toHaveCount(0);
    await expect(dialog.getByLabel("Access key", { exact: true })).toHaveText(KEY_SECRET);
    await page.goBack();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/principals/${SERVICE}/keys$`));
    await expect(dialog).toHaveCount(0);
    await page.goForward();
    await expect(page).toHaveURL(new RegExp(`/ui/admin/principals/${SERVICE}/keys\\?key=ak_`));
    await expect(page.getByRole("dialog", { name: "Access key created" })).toHaveCount(0);
    await expectKeyNowhere(page);
    noErrors(model);
  });

  test("names the types an account is not allowed, with a way to its setting", async ({ page }) => {
    await routeAccessKeyApi(page, ADMIN());
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}/keys/new`);
    await expect(editor(page).getByRole("checkbox")).toHaveCount(2);
    await expect(editor(page)).toContainText("Not offered, because Alice Example is not allowed them: Package downloads, Premium models.");
    await expect(editor(page).getByRole("link", { name: "Open the Access key types setting on the Overview tab" })).toHaveAttribute("href", `/ui/admin/principals/${ALICE}`);
  });

  test("an account that cannot hold keys is told so, with no fix link; one allowed no type is sent to its Overview", async ({ page }) => {
    const SYSTEM = "sys-config-reloader";
    const model = await routeAccessKeyApi(page, ADMIN(), (model) => {
      model.accounts[SYSTEM] = { ...model.accounts[SERVICE]!, principalId: SYSTEM, kind: "system", displayName: SYSTEM, accessKeyTypes: { allow: [], deny: [] } };
      model.accounts[DANA]!.policy = { accessKeyTypes: model.accounts[DANA]!.policy.accessKeyTypes.map((row) => ({ ...row, allowed: false, source: "none", groupIds: [] })) };
    });
    await page.goto(`${baseUrl}/ui/admin/principals/${SYSTEM}/keys/new`);
    await expect(editor(page).getByText("This account cannot hold access keys.", { exact: true })).toBeVisible();
    await expect(editor(page).getByRole("link", { name: "Back to keys", exact: true })).toBeVisible();
    for (const name of ["Open Overview", "Open Groups"]) await expect(editor(page).getByRole("link", { name, exact: true })).toHaveCount(0);
    await page.goto(`${baseUrl}/ui/admin/principals/${DANA}/keys/new`);
    await expect(editor(page).getByText("This account is not allowed any access key type. Allow one in Access key types on the Overview tab.", { exact: true })).toBeVisible();
    await expect(editor(page).getByRole("link", { name: "Open Overview", exact: true })).toHaveAttribute("href", `/ui/admin/principals/${DANA}`);
    noErrors(model);
  });

  test("issues a key for a service account, with nothing chosen although one type is allowed", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN());
    await page.goto(`${baseUrl}/ui/admin/principals/${SERVICE}/keys/new`);
    await expect(editor(page)).toContainText(`For ${SERVICE}`);
    const packages = editor(page).getByRole("checkbox", { name: "Package downloads" });
    await expect(packages).not.toBeChecked();
    await expect(editor(page).getByRole("checkbox")).toHaveCount(1);
    await packages.check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("ci-cache");
    await expect(editor(page)).toContainText(`services will know it as ${SERVICE}.`);
    await issueButton(page).click();
    await expect(page.getByRole("dialog", { name: "Access key created" })).toContainText(SERVICE);
    expect(model.issued).toEqual([{ pathname: `/v1/admin/principals/${SERVICE}/access-keys`, body: { name: "ci-cache", accessKeyTypes: ["package-downloads"], lifetime: "7d" } }]);
  });

  test("an account whose username does not work cannot be issued a key, and says why", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN());
    expect(model.accounts[CAROL]!.accessKeyProblem).toBe("no_account_username");
    await page.goto(`${baseUrl}/ui/admin/principals/${CAROL}/keys`);
    await expect(page.getByText("This account has no username: the one its email gives belongs to someone else. Set one by hand on the Overview tab.", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Issue access key", exact: true })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Issue access key", exact: true })).toHaveCount(0);
    await page.goto(`${baseUrl}/ui/admin/principals/${CAROL}/keys/new`);
    await expect(editor(page).getByRole("checkbox")).toHaveCount(0);
    await expect(editor(page)).toContainText("belongs to someone else");
  });
});

test.describe("why no key of an account can work (accessKeyProblem)", () => {
  // Every code the account detail can carry, as an administrator reads it on the
  // Keys tab and the issue page, with the tab where it is fixed, if any. The
  // account's status and username are set as the broker reports them with the
  // code, and each listed key's status is the code.
  const cases: { problem: AccessKeyAccountProblem; principal: string; reason: string; fix: "Open Overview" | "Open Groups" | null; setup?: (model: AccessKeyModel) => void }[] = [
    { problem: "principal_disabled", principal: ALICE, reason: "This account is disabled. Enable it before issuing access keys.", fix: null, setup: (model) => { model.accounts[ALICE]!.status = "disabled"; } },
    { problem: "identity_access_paused", principal: ALICE, reason: "This person’s identity access is paused. Resume it under Identity access on the Overview tab first.", fix: "Open Overview" },
    { problem: "identity_access_missing", principal: ALICE, reason: "This person’s identity access record is missing, so their access keys cannot work. Ask the operator to check the managed store.", fix: null },
    { problem: "no_account_username", principal: ALICE, reason: "This account has no username. Set one on the Overview tab first.", fix: "Open Overview", setup: (model) => {
      model.accounts[ALICE]!.accountUsername = { ...model.accounts[ALICE]!.accountUsername, state: "none", reason: "domain_not_listed", name: null, liveKeys: 0, fromEmail: { accountUsername: null, reason: "domain_not_listed", conflict: null } };
    } },
    { problem: "account_username_awaiting_confirmation", principal: ALICE, reason: "This account’s username is waiting for confirmation. Confirm it on the Overview tab first.", fix: "Open Overview", setup: (model) => {
      model.accounts[ALICE]!.accountUsername = { ...model.accounts[ALICE]!.accountUsername, state: "awaiting_confirmation", name: allocation(ALICE, "alice", { state: "awaiting_confirmation" }) };
    } },
    { problem: "account_username_reserved", principal: ALICE, reason: "This account’s username is one the operator reserved. Set another on the Overview tab first.", fix: "Open Overview", setup: (model) => {
      model.accounts[ALICE]!.accountUsername = { ...model.accounts[ALICE]!.accountUsername, state: "reserved", name: allocation(ALICE, "alice", { state: "reserved" }) };
    } },
    { problem: "group_limit_exceeded", principal: ALICE, reason: "This account is in too many groups for access keys to work. Remove it from some groups on the Groups tab first.", fix: "Open Groups" },
    { problem: "account_username_reserved", principal: SERVICE, reason: "This service account’s ID is a username the operator reserved. Ask the operator to change the username settings.", fix: null, setup: (model) => {
      model.accounts[SERVICE]!.accountUsername = { ...model.accounts[SERVICE]!.accountUsername, state: "reserved", name: allocation(SERVICE, SERVICE, { holderKind: "service_account", origin: "service_account", state: "reserved" }) };
    } },
    { problem: "no_account_username", principal: SERVICE, reason: "This service account’s ID cannot be used as a username. Issue keys for a service account whose ID can be.", fix: null, setup: (model) => {
      model.accounts[SERVICE]!.accountUsername = { ...model.accounts[SERVICE]!.accountUsername, state: "none", reason: "id_unusable", name: null };
    } }
  ];

  for (const { problem, principal, reason, fix, setup } of cases) {
    test(`${problem} for a ${principal === SERVICE ? "service account" : "person"}: the reason, no issuing, and the keys still listed and revocable`, async ({ page }) => {
      const model = await routeAccessKeyApi(page, ADMIN(), (model) => {
        setup?.(model);
        model.accounts[principal]!.accessKeyProblem = problem;
        model.adminKeys[principal] = [key("nightly-models", [{ id: INFERENCE.id, displayName: INFERENCE.displayName, held: true }], { principalId: principal, status: problem, access: "none", usableAccessKeyTypes: [] })];
      });
      await page.goto(`${baseUrl}/ui/admin/principals/${principal}/keys`);
      await expect(page.getByText(reason, { exact: true })).toBeVisible();
      await expect(page.getByRole("link", { name: "Issue access key", exact: true })).toHaveCount(0);
      await expect(page.getByRole("button", { name: "Issue access key", exact: true })).toHaveCount(0);
      await expect(row(page, "nightly-models")).toContainText("Model inference");
      await row(page, "nightly-models").getByRole("button", { name: "Revoke nightly-models", exact: true }).click();
      await page.getByRole("button", { name: "Revoke access key", exact: true }).click();
      await expect.poll(() => model.revoked).toEqual([`/v1/admin/access-keys/${model.adminKeys[principal]![0]!.keyId}`]);
      await page.goto(`${baseUrl}/ui/admin/principals/${principal}/keys/new`);
      await expect(editor(page).getByText(reason, { exact: true })).toBeVisible();
      await expect(editor(page).getByRole("checkbox")).toHaveCount(0);
      await expect(editor(page).getByRole("button", { name: "Issue access key", exact: true })).toHaveCount(0);
      for (const name of ["Open Overview", "Open Groups"] as const) {
        await expect(editor(page).getByRole("link", { name, exact: true })).toHaveCount(name === fix ? 1 : 0);
      }
      if (fix === "Open Groups") await expect(editor(page).getByRole("link", { name: fix, exact: true })).toHaveAttribute("href", `/ui/admin/principals/${principal}/groups`);
      expect(model.issued).toEqual([]);
      noErrors(model);
    });
  }

  test("null: nothing in the account stands in the way, so issuing is offered and no reason is shown", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN());
    expect(model.accounts[ALICE]!.accessKeyProblem).toBeNull();
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}/keys`);
    await expect(row(page, "laptop-models")).toBeVisible();
    await expect(page.getByRole("link", { name: "Issue access key", exact: true })).toBeVisible();
    for (const { reason } of cases) await expect(page.getByText(reason, { exact: true })).toHaveCount(0);
    await page.getByRole("link", { name: "Issue access key", exact: true }).click();
    await expect(editor(page).getByRole("checkbox")).toHaveCount(2);
    await expect(editor(page).getByText("An access key cannot be issued for this account now")).toHaveCount(0);
    noErrors(model);
  });
});

test.describe("staying current after changes elsewhere", () => {
  test("pausing a person's identity access shows on their Keys tab without a reload", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN());
    const tabs = page.getByRole("navigation", { name: "User sections" });
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}/keys`);
    await expect(row(page, "laptop-models").getByText("Active", { exact: true })).toBeAttached();
    await expect(page.getByRole("link", { name: "Issue access key", exact: true })).toBeVisible();
    await tabs.getByRole("link", { name: "Overview" }).click();
    await page.getByRole("button", { name: "Pause identity access", exact: true }).click();
    await expect(page.getByRole("button", { name: "Resume identity access", exact: true })).toBeVisible();
    await tabs.getByRole("link", { name: "Keys" }).click();
    await expect(page.getByText("This person’s identity access is paused. Resume it under Identity access on the Overview tab first.", { exact: true })).toBeVisible();
    await expect(row(page, "laptop-models")).toContainText("Access paused");
    await expect(page.getByRole("link", { name: "Issue access key", exact: true })).toHaveCount(0);
    // Resuming brings both back.
    await tabs.getByRole("link", { name: "Overview" }).click();
    await page.getByRole("button", { name: "Resume identity access", exact: true }).click();
    await expect(page.getByRole("button", { name: "Pause identity access", exact: true })).toBeVisible();
    await tabs.getByRole("link", { name: "Keys" }).click();
    await expect(row(page, "laptop-models").getByText("Active", { exact: true })).toBeAttached();
    await expect(page.getByRole("link", { name: "Issue access key", exact: true })).toBeVisible();
    noErrors(model);
  });

  test("a configuration reload that adds the first access key type shows Keys in My access without a reload", async ({ page }) => {
    const model = await routeAccessKeyApi(page, { ...ADMIN(), principal: ALICE, displayName: "Alice Example" }, (model) => { model.offered = false; });
    await page.goto(`${baseUrl}/ui/access`);
    await expect(nav(page).getByRole("link", { name: "Tokens", exact: true })).toBeVisible();
    await expect(nav(page).getByRole("link", { name: "Keys", exact: true })).toHaveCount(0);
    // The operator configures a type; an administrator reloads, without leaving the page.
    model.offered = true;
    await leaveThroughPalette(page, "Reload runtime configuration");
    await page.getByRole("alertdialog").or(page.getByRole("dialog")).getByRole("button", { name: "Reload config", exact: true }).click();
    await expect.poll(() => model.reloads).toBe(1);
    await page.getByRole("navigation", { name: "Space" }).getByRole("link", { name: "My access" }).click();
    await expect(nav(page).getByRole("link", { name: "Keys", exact: true })).toBeVisible();
    noErrors(model);
  });
});

test.describe("one account seen from both sides", () => {
  // An administrator who also uses My access: their own account's administrative views follow their personal changes.
  const SELF_ADMIN = () => ({ ...ADMIN(), principal: ALICE, displayName: "Alice Example" });

  async function openThroughPalette(page: Page, option: RegExp) {
    await page.keyboard.press("Control+k");
    const palette = page.getByRole("dialog", { name: "Command palette", exact: true });
    await palette.getByRole("combobox").fill("Alice Example");
    await palette.getByRole("option", { name: option }).first().click();
  }

  test("issuing and revoking in My access refresh the administrator's Keys tab and live key count", async ({ page }) => {
    await routeAccessKeyApi(page, SELF_ADMIN());
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}`);
    const username = page.getByRole("region", { name: "Username", exact: true });
    await expect(username).toContainText("3 active");
    await page.getByRole("navigation", { name: "User sections" }).getByRole("link", { name: "Keys" }).click();
    await expect(row(page, "laptop-models")).toBeVisible();
    // Issue in My access, then come back without a reload.
    await page.getByRole("navigation", { name: "Space" }).getByRole("link", { name: "My access" }).click();
    await nav(page).getByRole("link", { name: "Keys", exact: true }).click();
    await main(page, "Access keys").getByRole("link", { name: "Issue access key" }).first().click();
    await editor(page).getByRole("checkbox", { name: "Model inference" }).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("desk-workstation");
    await issueButton(page).click();
    await page.getByRole("dialog", { name: "Access key created" }).getByRole("button", { name: "Done" }).click();
    await openThroughPalette(page, /Alice Example/);
    await expect(username).toContainText("4 active");
    await page.getByRole("navigation", { name: "User sections" }).getByRole("link", { name: "Keys" }).click();
    await expect(row(page, "desk-workstation")).toBeVisible();
    // Revoke in My access; the administrator's tab shows it revoked.
    await page.getByRole("navigation", { name: "Space" }).getByRole("link", { name: "My access" }).click();
    await nav(page).getByRole("link", { name: "Keys", exact: true }).click();
    await row(page, "desk-workstation").getByRole("button", { name: "Revoke desk-workstation" }).click();
    await page.getByRole("button", { name: "Revoke access key", exact: true }).click();
    await expect(row(page, "desk-workstation")).toContainText("Revoked");
    await openThroughPalette(page, /Alice Example/);
    await expect(username).toContainText("3 active");
    await page.getByRole("navigation", { name: "User sections" }).getByRole("link", { name: "Keys" }).click();
    await expect(row(page, "desk-workstation")).toHaveCount(0);
    await page.getByRole("radio", { name: /^All/ }).or(page.getByRole("button", { name: /^All/ })).click();
    await expect(row(page, "desk-workstation")).toContainText("Revoked");
  });

  test("changing the administrator's own membership shows and hides Keys without a reload", async ({ page }) => {
    const model = await routeAccessKeyApi(page, SELF_ADMIN(), (model) => {
      model.keys = [];
      const hidden = { ...model.options, accessKeyTypes: [], hasSelfServiceType: false, hasKeys: false, problem: null };
      const shown = { ...model.options, accessKeyTypes: [INFERENCE], hasSelfServiceType: true, hasKeys: false, problem: null };
      model.options = hidden;
      model.onMembership = (member) => { model.options = member ? shown : hidden; };
    });
    await page.goto(`${baseUrl}/ui/access`);
    await expect(nav(page).getByRole("link", { name: "Tokens", exact: true })).toBeVisible();
    await expect.poll(() => model.requests.includes("GET /v1/access-keys/options")).toBe(true);
    await expect(nav(page).getByRole("link", { name: "Keys", exact: true })).toHaveCount(0);
    // Join a group that allows a type, from the group's Members tab.
    await page.goto(`${baseUrl}/ui/access`);
    await page.getByRole("navigation", { name: "Space" }).getByRole("link", { name: "Admin" }).click();
    await page.keyboard.press("Control+k");
    const palette = page.getByRole("dialog", { name: "Command palette", exact: true });
    await palette.getByRole("combobox").fill("ML team");
    await palette.getByRole("option", { name: /ML team/ }).first().click();
    await page.getByRole("navigation", { name: "Group sections" }).getByRole("link", { name: /Members/ }).click();
    await page.getByRole("combobox", { name: "Principal to add" }).fill("Alice Example");
    await page.getByRole("option", { name: /Alice Example/ }).first().click();
    await page.getByRole("button", { name: "Add member", exact: true }).click();
    await expect(page.getByText("Member added")).toBeVisible();
    await page.getByRole("navigation", { name: "Space" }).getByRole("link", { name: "My access" }).click();
    await expect(nav(page).getByRole("link", { name: "Keys", exact: true })).toBeVisible();
    // Leave it from the account's Groups tab.
    await openThroughPalette(page, /Alice Example/);
    await page.getByRole("navigation", { name: "User sections" }).getByRole("link", { name: /Groups/ }).click();
    await page.getByRole("button", { name: "Remove ml-team", exact: true }).click();
    await page.getByRole("button", { name: "Remove group", exact: true }).click();
    await expect(page.getByText("Group removed")).toBeVisible();
    await page.getByRole("navigation", { name: "Space" }).getByRole("link", { name: "My access" }).click();
    await expect(nav(page).getByRole("link", { name: "Tokens", exact: true })).toBeVisible();
    await expect(nav(page).getByRole("link", { name: "Keys", exact: true })).toHaveCount(0);
  });
});

test.describe("usernames", () => {
  const section = (page: Page) => page.getByRole("region", { name: "Username", exact: true });

  test("From email shows the server's value for the saved email and what an email change may do", async ({ page }) => {
    await routeAccessKeyApi(page, ADMIN());
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}`);
    await expect(section(page)).toContainText("Working");
    await expect(section(page)).toContainText("Given by the saved email, alice@example.com.");
    await expect(section(page)).toContainText("Changing the email may change this person’s username; if it does, their access keys end and their usage starts under the new username.");
    await expect(section(page)).toContainText("3 active");
    await expect(section(page)).toContainText("Not required");
    await expect(section(page).getByRole("button", { name: "Save username" })).toBeDisabled();
  });

  test("a username state this portal does not know shows a neutral Unknown badge, and the page still works", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), (model) => {
      const alice = model.accounts[ALICE]!;
      alice.accountUsername = { ...alice.accountUsername, state: "held_elsewhere" as never };
    });
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}`);
    const badge = section(page).locator(".wb-badge");
    await expect(badge).toHaveText("Unknown");
    await expect(badge).toHaveClass(/wb-tone-neutral/);
    await expect(section(page)).toContainText("Given by the saved email, alice@example.com.");
    await expect(page.getByRole("region", { name: "Profile", exact: true })).toBeVisible();
    noErrors(model);
  });

  test("an email change asks first, says the username may change, and then reports what happened", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), (model) => {
      model.nextChange = { previousMode: "from_email", mode: "from_email", before: allocation(ALICE, "alice"), after: allocation(ALICE, "alice.example", { incarnation: "alice.example-1" }), renamed: true, endedKeys: 3, reason: null, conflict: null };
    });
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}`);
    await page.getByRole("textbox", { name: "Email" }).fill("alice.example@example.com");
    await page.getByRole("button", { name: "Save profile", exact: true }).click();
    const dialog = page.getByRole("alertdialog").or(page.getByRole("dialog"));
    await expect(dialog).toContainText("Change the email?");
    await expect(dialog).toContainText("Alice Example’s username, alice, is set from email, so saving alice.example@example.com may change it. If it changes, their 3 active access keys stop working and their usage starts under the new username.");
    expect(model.profilePatches).toEqual([]);
    await dialog.getByRole("button", { name: "Save email", exact: true }).click();
    await expect.poll(() => model.profilePatches.length).toBe(1);
    await expect(page.getByRole("region", { name: "Profile", exact: true })).toContainText("The username changed from alice to alice.example. 3 access keys ended.");
  });

  test("the email warning and its result come from the account even when the type list fails to load", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), (model) => {
      model.fail.types = true;
      model.nextChange = { previousMode: "from_email", mode: "from_email", before: allocation(ALICE, "alice"), after: allocation(ALICE, "alice.example", { incarnation: "alice.example-1" }), renamed: true, endedKeys: 3, reason: null, conflict: null };
    });
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}`);
    await expect.poll(() => model.requests.filter((request) => request === "GET /v1/admin/access-key-types").length).toBeGreaterThan(0);
    await page.getByRole("textbox", { name: "Email" }).fill("alice.example@example.com");
    await page.getByRole("button", { name: "Save profile", exact: true }).click();
    const dialog = page.getByRole("alertdialog").or(page.getByRole("dialog"));
    await expect(dialog).toContainText("Alice Example’s username, alice, is set from email, so saving alice.example@example.com may change it. If it changes, their 3 active access keys stop working and their usage starts under the new username.");
    expect(model.profilePatches).toEqual([]);
    await dialog.getByRole("button", { name: "Save email", exact: true }).click();
    await expect(page.getByRole("region", { name: "Profile", exact: true })).toContainText("The username changed from alice to alice.example. 3 access keys ended.");
    // The type list's failure is reported on its own, with a retry.
    await expect(page.getByText("Couldn’t load access key types")).toBeVisible();
  });

  test("an email change for a person who holds no username and no keys saves without a warning or a notice", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), (model) => {
      model.types = [];
      const alice = model.accounts[ALICE]!;
      alice.accountUsername = { ...alice.accountUsername, state: "none", reason: "domain_not_listed", name: null, liveKeys: 0, fromEmail: { accountUsername: null, reason: "domain_not_listed", conflict: null } };
      model.nextChange = { previousMode: "from_email", mode: "from_email", before: null, after: null, renamed: false, endedKeys: 0, reason: "domain_not_listed", conflict: null };
    });
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}`);
    await page.getByRole("textbox", { name: "Email" }).fill("alice@example.org");
    await page.getByRole("button", { name: "Save profile", exact: true }).click();
    await expect.poll(() => model.profilePatches.length).toBe(1);
    await expect(page.getByRole("alertdialog")).toHaveCount(0);
    await expect(page.getByText("Profile saved")).toBeVisible();
    await expect(page.getByText("Username after the change")).toHaveCount(0);
    await expect(page.getByRole("region", { name: "Username", exact: true })).toHaveCount(0);
  });

  test("every later save replaces the username notice: a release, then an email change involving no name, leaves no notice", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), (model) => {
      model.nextChange = { previousMode: "from_email", mode: "from_email", before: allocation(ALICE, "alice"), after: null, renamed: true, endedKeys: 3, reason: "domain_not_listed", conflict: null };
    });
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}`);
    const profile = page.getByRole("region", { name: "Profile", exact: true });
    await page.getByRole("textbox", { name: "Email" }).fill("alice@example.org");
    await page.getByRole("button", { name: "Save profile", exact: true }).click();
    await page.getByRole("button", { name: "Save email", exact: true }).click();
    await expect(profile).toContainText("The username alice was released; the account has no username now.");
    await expect(profile).toContainText("3 access keys ended.");
    // A second email that gives no name either: nothing to report, and the earlier report is gone.
    model.nextChange = { previousMode: "from_email", mode: "from_email", before: null, after: null, renamed: false, endedKeys: 0, reason: "domain_not_listed", conflict: null };
    await page.getByRole("textbox", { name: "Email" }).fill("alice@example.net");
    await page.getByRole("button", { name: "Save profile", exact: true }).click();
    await expect.poll(() => model.profilePatches.length).toBe(2);
    await expect(page.getByRole("button", { name: "Save profile", exact: true })).toBeDisabled();
    await expect(page.getByText("Username after the change")).toHaveCount(0);
    await expect(page.getByText("3 access keys ended.")).toHaveCount(0);
  });

  test("confirming a name replaces an earlier username notice", async ({ page }) => {
    await routeAccessKeyApi(page, ADMIN(), (model) => {
      model.nextChange = { previousMode: "from_email", mode: "from_email", before: allocation(BOB, "bob", { state: "awaiting_confirmation" }), after: allocation(BOB, "bob", { state: "awaiting_confirmation" }), renamed: false, endedKeys: 0, reason: null, conflict: null };
    });
    await page.goto(`${baseUrl}/ui/admin/principals/${BOB}`);
    await page.getByRole("textbox", { name: "Email" }).fill("Bob@example.com");
    await page.getByRole("button", { name: "Save profile", exact: true }).click();
    await page.getByRole("button", { name: "Save email", exact: true }).click();
    await expect(page.getByRole("region", { name: "Profile", exact: true })).toContainText("The username stayed bob. No access keys ended.");
    await page.getByRole("region", { name: "Username", exact: true }).getByRole("button", { name: "Confirm", exact: true }).click();
    await page.getByRole("button", { name: "Confirm username", exact: true }).click();
    await expect(page.getByRole("region", { name: "Username", exact: true })).toContainText("Working");
    await expect(page.getByText("Username after the change")).toHaveCount(0);
  });

  test("an email change that keeps the username says so", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), (model) => {
      model.nextChange = { previousMode: "from_email", mode: "from_email", before: allocation(ALICE, "alice"), after: allocation(ALICE, "alice"), renamed: false, endedKeys: 0, reason: null, conflict: null };
    });
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}`);
    await page.getByRole("textbox", { name: "Email" }).fill("Alice@example.com");
    await page.getByRole("button", { name: "Save profile", exact: true }).click();
    await page.getByRole("button", { name: "Save email", exact: true }).click();
    await expect(page.getByRole("region", { name: "Profile", exact: true })).toContainText("The username stayed alice. No access keys ended.");
    expect(model.profilePatches).toEqual([{ principalId: ALICE, body: { displayName: "Alice Example", email: "Alice@example.com" } }]);
  });

  test("Set by hand: an administrator types the name, is told the change may end keys, and sees the result", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), (model) => {
      model.nextChange = { previousMode: "manual", mode: "manual", before: allocation(DANA, "dana", { origin: "administrator" }), after: allocation(DANA, "dana.e", { origin: "administrator" }), renamed: true, endedKeys: 1, reason: null, conflict: null };
    });
    await page.goto(`${baseUrl}/ui/admin/principals/${DANA}`);
    const name = section(page).getByRole("textbox", { name: "Username set by hand" });
    await expect(name).toHaveValue("dana");
    await expect(section(page)).toContainText("From email would give dana.example, from the saved email.");
    await name.fill("dana.e");
    await section(page).getByRole("button", { name: "Save username", exact: true }).click();
    const dialog = page.getByRole("alertdialog").or(page.getByRole("dialog"));
    await expect(dialog).toContainText("This may change Dana Example’s username. If it changes, their 1 active access key stops working and their usage starts under the new username.");
    await dialog.getByRole("button", { name: "Save username", exact: true }).click();
    await expect.poll(() => model.usernameSets).toEqual([{ principalId: DANA, body: { mode: "manual", accountUsername: "dana.e" } }]);
    await expect(section(page)).toContainText("The username changed from dana to dana.e. 1 access key ended.");
  });

  test("switching to From email sends the mode alone", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), (model) => {
      model.nextChange = { previousMode: "manual", mode: "from_email", before: allocation(DANA, "dana", { origin: "administrator" }), after: allocation(DANA, "dana.example"), renamed: true, endedKeys: 1, reason: null, conflict: null };
    });
    await page.goto(`${baseUrl}/ui/admin/principals/${DANA}`);
    await section(page).getByRole("button", { name: "From email", exact: true }).or(section(page).getByRole("radio", { name: "From email" })).click();
    await expect(section(page)).toContainText("Switching to From email may change this person’s username");
    await section(page).getByRole("button", { name: "Save username", exact: true }).click();
    await page.getByRole("alertdialog").or(page.getByRole("dialog")).getByRole("button", { name: "Save username", exact: true }).click();
    await expect.poll(() => model.usernameSets).toEqual([{ principalId: DANA, body: { mode: "from_email" } }]);
  });

  test("a name awaiting confirmation is confirmed by name", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN());
    await page.goto(`${baseUrl}/ui/admin/principals/${BOB}`);
    await expect(section(page)).toContainText("Awaiting confirmation");
    await expect(section(page)).toContainText("bob is on the operator’s list of usernames that services already use.");
    await expect(section(page)).toContainText("None; issuing is blocked");
    await section(page).getByRole("button", { name: "Confirm", exact: true }).click();
    await page.getByRole("button", { name: "Confirm username", exact: true }).click();
    await expect.poll(() => model.confirms).toEqual([{ principalId: BOB, body: { accountUsername: "bob" } }]);
  });

  test("a conflict names who holds the name and leaves this account without one", async ({ page }) => {
    await routeAccessKeyApi(page, ADMIN());
    await page.goto(`${baseUrl}/ui/admin/principals/${CAROL}`);
    await expect(section(page)).toContainText("Conflict");
    await expect(section(page)).toContainText("carol, from this account’s email, already belongs to Carol Example (carol@example.com), who held it first and keeps it.");
    await expect(section(page)).toContainText("The saved email, carol@example.org, gives carol, which is taken.");
    await expect(section(page)).toContainText("Never set");
    await expect(section(page).getByRole("link", { name: "Carol Example" })).toBeVisible();
  });
});

test.describe("access key type settings", () => {
  test("a person's setting: per type follow the groups, allow or deny, sent whole with Save access", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN());
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}`);
    const table = page.getByRole("table", { name: "Access key types" });
    await expect(table.getByRole("row", { name: /Model inference/ })).toContainText("Allowed · from group ml-team");
    await expect(table.getByRole("row", { name: /Package downloads/ })).toContainText("Not allowed · none of their groups allows it");
    await table.getByRole("combobox", { name: "Premium models setting" }).selectOption("allow");
    await table.getByRole("combobox", { name: "Web search setting" }).selectOption("deny");
    await expect(table.getByRole("row", { name: /Premium models/ })).toContainText("the change applies after saving");
    await page.getByRole("button", { name: "Save access", exact: true }).click();
    const dialog = page.getByRole("alertdialog").or(page.getByRole("dialog"));
    await expect(dialog).toContainText("Access key types change as chosen");
    await dialog.getByRole("button", { name: "Update access", exact: true }).click();
    await expect.poll(() => model.accessPatches).toEqual([{ principalId: ALICE, body: { accessKeyTypes: { allow: ["premium-models"], deny: ["web-search"] } } }]);
  });

  test("a service account's setting is its own section, saved alone", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN());
    await page.goto(`${baseUrl}/ui/admin/principals/${SERVICE}`);
    const settings = page.getByRole("region", { name: "Access key types", exact: true });
    await expect(settings).toContainText("A service account does not issue its own keys: an administrator issues them on its Keys tab, for the types allowed here.");
    await expect(settings.getByRole("row", { name: /Model inference/ })).toContainText("none of its groups allows it");
    await settings.getByRole("combobox", { name: "Model inference setting" }).selectOption("allow");
    await settings.getByRole("button", { name: "Save access", exact: true }).click();
    await expect.poll(() => model.accessPatches).toEqual([{ principalId: SERVICE, body: { accessKeyTypes: { allow: ["inference", "package-downloads"], deny: [] } } }]);
  });

  test("a group's setting: per type allowed or not; a group cannot deny", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN());
    await page.goto(`${baseUrl}/ui/admin/groups/ml-team`);
    const checks = page.getByRole("group", { name: "Access key types this group allows" });
    await expect(checks.getByRole("checkbox", { name: "Model inference" })).toBeChecked();
    await expect(checks.getByRole("checkbox", { name: "Premium models" })).not.toBeChecked();
    await expect(checks).toContainText("issued by administrators only");
    await expect(page.getByRole("combobox", { name: /setting$/ })).toHaveCount(0);
    await checks.getByRole("checkbox", { name: "Premium models" }).check();
    await checks.getByRole("checkbox", { name: "Web search" }).uncheck();
    await page.getByRole("button", { name: "Save token issuance", exact: true }).click();
    await expect.poll(() => model.groupPatches).toEqual([{ accessKeyTypes: { allow: ["inference", "premium-models"] } }]);
  });

  // A type removed from the configuration while an unsaved draft still names it: the broker allows the removal
  // because no saved setting names the type, and refuses any setting that does. Dana's allow is withdrawn so
  // that no saved setting names Premium models.
  const premiumUnnamed = (model: AccessKeyModel) => { model.accounts[DANA]!.accessKeyTypes = { allow: ["package-downloads"], deny: [] }; };
  async function removePremiumAndReload(page: Page, model: AccessKeyModel) {
    model.types = model.types.filter((type) => type.id !== PREMIUM.id);
    await leaveThroughPalette(page, "Reload runtime configuration");
    await page.getByRole("alertdialog").or(page.getByRole("dialog")).getByRole("button", { name: "Reload config", exact: true }).click();
    await expect.poll(() => model.reloads).toBe(1);
  }

  test("a person's setting shows a removed type the draft still allows, blocks Save until it is removed, then saves the other edits", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), premiumUnnamed);
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}`);
    const table = page.getByRole("table", { name: "Access key types" });
    await page.getByRole("checkbox", { name: "Self-service enabled" }).uncheck();
    await table.getByRole("combobox", { name: "Premium models setting" }).selectOption("allow");
    await table.getByRole("combobox", { name: "Web search setting" }).selectOption("deny");
    await removePremiumAndReload(page, model);
    const removed = table.getByRole("row", { name: /Premium models/ });
    await expect(removed).toContainText("premium-models");
    await expect(removed.getByRole("cell").first()).toContainText("Allow");
    await expect(removed).toContainText("No longer configured");
    await expect(table.getByRole("combobox", { name: "Premium models setting" })).toHaveCount(0);
    const save = page.getByRole("button", { name: "Save access", exact: true });
    await expect(save).toBeDisabled();
    await expect(page.getByText("Remove access key types that are no longer configured.", { exact: true })).toBeVisible();
    await removed.getByRole("button", { name: "Remove Premium models setting", exact: true }).click();
    await expect(removed).toHaveCount(0);
    await expect(page.getByText("Remove access key types that are no longer configured.", { exact: true })).toHaveCount(0);
    await expect(table.getByRole("combobox", { name: "Web search setting" })).toHaveValue("deny");
    await save.click();
    await page.getByRole("alertdialog").or(page.getByRole("dialog")).getByRole("button", { name: "Update access", exact: true }).click();
    await expect.poll(() => model.accessPatches).toEqual([{ principalId: ALICE, body: { selfServiceEnabled: false, accessKeyTypes: { allow: [], deny: ["web-search"] } } }]);
  });

  test("a service account's setting shows a removed type the draft still allows, blocks Save until it is removed, then saves the other edit", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), premiumUnnamed);
    await page.goto(`${baseUrl}/ui/admin/principals/${SERVICE}`);
    const settings = page.getByRole("region", { name: "Access key types", exact: true });
    await settings.getByRole("combobox", { name: "Premium models setting" }).selectOption("allow");
    await settings.getByRole("combobox", { name: "Web search setting" }).selectOption("deny");
    await removePremiumAndReload(page, model);
    const removed = settings.getByRole("row", { name: /Premium models/ });
    await expect(removed).toContainText("No longer configured");
    const save = settings.getByRole("button", { name: "Save access", exact: true });
    await expect(save).toBeDisabled();
    await expect(settings.getByText("Remove access key types that are no longer configured.", { exact: true })).toBeVisible();
    await removed.getByRole("button", { name: "Remove Premium models setting", exact: true }).click();
    await expect(removed).toHaveCount(0);
    await save.click();
    await expect.poll(() => model.accessPatches).toEqual([{ principalId: SERVICE, body: { accessKeyTypes: { allow: ["package-downloads"], deny: ["web-search"] } } }]);
  });

  test("a group's setting keeps a removed type the draft still allows, ticked, blocks Save until it is unticked, then saves the other edit", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), premiumUnnamed);
    await page.goto(`${baseUrl}/ui/admin/groups/ml-team`);
    const checks = page.getByRole("group", { name: "Access key types this group allows" });
    await checks.getByRole("checkbox", { name: "Premium models" }).check();
    await checks.getByRole("checkbox", { name: "Web search" }).uncheck();
    await removePremiumAndReload(page, model);
    const removed = checks.getByRole("checkbox", { name: "Premium models" });
    await expect(removed).toBeChecked();
    await expect(removed).toHaveAccessibleDescription("premium-models · no longer configured");
    const save = page.getByRole("button", { name: "Save token issuance", exact: true });
    await expect(save).toBeDisabled();
    await expect(checks.getByText("Remove access key types that are no longer configured.", { exact: true })).toBeVisible();
    // Unticking removes it from the draft, and with it the checkbox.
    await removed.click();
    await expect(removed).toHaveCount(0);
    await expect(checks.getByRole("checkbox", { name: "Web search" })).not.toBeChecked();
    await save.click();
    await expect.poll(() => model.groupPatches).toEqual([{ accessKeyTypes: { allow: ["inference"] } }]);
  });

  // The same removal, reloaded elsewhere (another session or the operator): this page's type list still has
  // Premium models until a refused save makes it read the types again.
  const UNCONFIGURED_REFUSAL = "an access key type setting names an access key type that is not configured";
  const typeReads = (model: AccessKeyModel) => model.requests.filter((request) => request === "GET /v1/admin/access-key-types").length;
  function removePremiumElsewhere(model: AccessKeyModel) {
    model.types = model.types.filter((type) => type.id !== PREMIUM.id);
    return typeReads(model);
  }

  test("a person's save refused for a type removed by a reload elsewhere reads the types again and shows the type for removal", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), premiumUnnamed);
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}`);
    const table = page.getByRole("table", { name: "Access key types" });
    await table.getByRole("combobox", { name: "Premium models setting" }).selectOption("allow");
    await table.getByRole("combobox", { name: "Web search setting" }).selectOption("deny");
    const reads = removePremiumElsewhere(model);
    const save = page.getByRole("button", { name: "Save access", exact: true });
    const dialog = page.getByRole("alertdialog").or(page.getByRole("dialog"));
    await save.click();
    await dialog.getByRole("button", { name: "Update access", exact: true }).click();
    await expect(dialog).toContainText(UNCONFIGURED_REFUSAL);
    await expect.poll(() => typeReads(model)).toBeGreaterThan(reads);
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    const removed = table.getByRole("row", { name: /Premium models/ });
    await expect(removed).toContainText("No longer configured");
    await expect(save).toBeDisabled();
    await removed.getByRole("button", { name: "Remove Premium models setting", exact: true }).click();
    await save.click();
    await dialog.getByRole("button", { name: "Update access", exact: true }).click();
    await expect.poll(() => model.accessPatches).toEqual([
      { principalId: ALICE, body: { accessKeyTypes: { allow: ["premium-models"], deny: ["web-search"] } } },
      { principalId: ALICE, body: { accessKeyTypes: { allow: [], deny: ["web-search"] } } }
    ]);
  });

  test("a service account's save refused for a type removed by a reload elsewhere reads the types again and shows the type for removal", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), premiumUnnamed);
    await page.goto(`${baseUrl}/ui/admin/principals/${SERVICE}`);
    const settings = page.getByRole("region", { name: "Access key types", exact: true });
    await settings.getByRole("combobox", { name: "Premium models setting" }).selectOption("allow");
    const reads = removePremiumElsewhere(model);
    const save = settings.getByRole("button", { name: "Save access", exact: true });
    await save.click();
    await expect(settings).toContainText(UNCONFIGURED_REFUSAL);
    await expect.poll(() => typeReads(model)).toBeGreaterThan(reads);
    const removed = settings.getByRole("row", { name: /Premium models/ });
    await expect(removed).toContainText("No longer configured");
    await expect(save).toBeDisabled();
    await removed.getByRole("button", { name: "Remove Premium models setting", exact: true }).click();
    await settings.getByRole("combobox", { name: "Web search setting" }).selectOption("deny");
    await save.click();
    await expect.poll(() => model.accessPatches).toEqual([
      { principalId: SERVICE, body: { accessKeyTypes: { allow: ["package-downloads", "premium-models"], deny: [] } } },
      { principalId: SERVICE, body: { accessKeyTypes: { allow: ["package-downloads"], deny: ["web-search"] } } }
    ]);
  });

  test("a group's save refused for a type removed by a reload elsewhere reads the types again and shows the type for removal", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), premiumUnnamed);
    await page.goto(`${baseUrl}/ui/admin/groups/ml-team`);
    const checks = page.getByRole("group", { name: "Access key types this group allows" });
    await checks.getByRole("checkbox", { name: "Premium models" }).check();
    await checks.getByRole("checkbox", { name: "Web search" }).uncheck();
    const reads = removePremiumElsewhere(model);
    const save = page.getByRole("button", { name: "Save token issuance", exact: true });
    await save.click();
    await expect(page.getByRole("region", { name: "Token issuance", exact: true })).toContainText(UNCONFIGURED_REFUSAL);
    await expect.poll(() => typeReads(model)).toBeGreaterThan(reads);
    const removed = checks.getByRole("checkbox", { name: "Premium models" });
    await expect(removed).toHaveAccessibleDescription("premium-models · no longer configured");
    await expect(save).toBeDisabled();
    await removed.click();
    await save.click();
    await expect.poll(() => model.groupPatches).toEqual([{ accessKeyTypes: { allow: ["inference", "premium-models"] } }, { accessKeyTypes: { allow: ["inference"] } }]);
  });

  test("a group's setting says when the configured types cannot be read, offers Retry, and shows no stale choices", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN(), (model) => { model.fail.types = true; });
    await page.goto(`${baseUrl}/ui/admin/groups/ml-team`);
    const issuance = page.getByRole("region", { name: "Token issuance", exact: true });
    await expect(issuance.getByText("Couldn’t load access key types")).toBeVisible();
    await expect(page.getByRole("group", { name: "Access key types this group allows" })).toHaveCount(0);
    model.fail.types = false;
    await issuance.getByRole("button", { name: "Retry" }).click();
    await expect(page.getByRole("group", { name: "Access key types this group allows" }).getByRole("checkbox", { name: "Model inference" })).toBeChecked();
    await expect(issuance.getByText("Couldn’t load access key types")).toHaveCount(0);
  });

  test("a person's setting is not editable from a stale type list while the list fails to refresh", async ({ page }) => {
    const model = await routeAccessKeyApi(page, ADMIN());
    const tabs = page.getByRole("navigation", { name: "User sections" });
    await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}`);
    await expect(page.getByRole("table", { name: "Access key types" })).toBeVisible();
    // The issue page reads the types again, and that read fails: the cached list is now stale.
    model.fail.types = true;
    await tabs.getByRole("link", { name: "Keys" }).click();
    await page.getByRole("link", { name: "Issue access key", exact: true }).click();
    await expect(editor(page).getByText("Couldn’t load the account’s access key types")).toBeVisible();
    await editor(page).getByRole("link", { name: "Keys" }).click();
    await tabs.getByRole("link", { name: "Overview" }).click();
    await expect(page.getByText("Couldn’t load access key types")).toBeVisible();
    await expect(page.getByRole("table", { name: "Access key types" })).toHaveCount(0);
    await expect(page.getByRole("combobox", { name: /setting$/ })).toHaveCount(0);
  });

  test("the configured types are listed read-only in the catalog", async ({ page }) => {
    await routeAccessKeyApi(page, ADMIN(), (model) => {
      model.types = model.types.map((type) => type.id === "package-downloads" ? { ...type, lifetimeOptions: ["never", "90m", "1d"], defaultLifetime: "never" } : type);
    });
    await page.goto(`${baseUrl}/ui/admin/catalog`);
    await page.getByRole("link", { name: /Access key types/ }).click();
    await expect(page).toHaveURL(/\/ui\/admin\/catalog\/access-key-types$/);
    const table = page.getByRole("table", { name: "Configured access key types" });
    await expect(table.getByRole("row")).toHaveCount(5);
    await expect(table.getByRole("row", { name: /Package downloads/ })).toContainText("package-downloadsNever expires, 90 minutes, 1 dayNever expiresNo");
    await expect(table.getByRole("row", { name: /Premium models/ })).toContainText("Call the larger hosted models for evaluation work.");
    await expect(page.getByText("4 types", { exact: true })).toBeVisible();
    await expect(page.getByText("Access key types are defined in the broker’s configuration file and are read-only here", { exact: false })).toBeVisible();
    await expect(page.getByRole("main", { name: "Access key types" }).getByRole("button", { name: /Save|Edit|Delete/ })).toHaveCount(0);
  });
});

test("profile submission ignores unchanged and pending saves", async ({ page }) => {
  const model = await routeAccessKeyApi(page, ADMIN());
  await page.goto(`${baseUrl}/ui/admin/principals/${ALICE}`);
  const profile = page.getByRole("region", { name: "Profile", exact: true });
  const form = profile.locator("form");
  await expect(profile.getByRole("button", { name: "Save profile", exact: true })).toBeDisabled();
  // Exercise the handler even when native implicit submission is blocked by the disabled button.
  await form.dispatchEvent("submit");
  await expect.poll(() => model.profilePatches.length).toBe(0);
  let release!: () => void;
  const response = new Promise<void>((resolve) => { release = resolve; });
  let writes = 0;
  await page.route((url) => url.pathname === `/v1/admin/principals/${ALICE}`, async (route) => {
    if (route.request().method() !== "PATCH") return route.fallback();
    writes++;
    await response;
    await route.fallback();
  });
  await page.getByRole("textbox", { name: "Display name" }).fill("Alice Changed");
  await form.dispatchEvent("submit");
  try {
    await expect.poll(() => writes).toBe(1);
    await expect(profile.getByRole("button", { name: "Save profile", exact: true })).toHaveAttribute("aria-busy", "true");
    await form.dispatchEvent("submit");
    // A pending profile write cannot open an email confirmation either.
    await page.getByRole("textbox", { name: "Email" }).fill("alice.example@example.com");
    await form.dispatchEvent("submit");
    await expect(page.getByRole("alertdialog").or(page.getByRole("dialog"))).toHaveCount(0);
  } finally {
    release();
  }
  await expect(profile.getByRole("button", { name: "Save profile", exact: true })).not.toHaveAttribute("aria-busy", "true");
  expect(model.profilePatches).toHaveLength(1);
  expect(writes).toBe(1);
});

test("equal type display names survive selection and the secret dialog", async ({ page }) => {
  // Duplicate-key diagnostics are disabled in React's production build. Exercise
  // the real page in development mode so either chip list using labels as keys
  // fails this regression, even when its first render happens to look correct.
  const { createServer } = await import("vite");
  const { fileURLToPath } = await import("node:url");
  const server = await createServer({
    root: fileURLToPath(new URL("../", import.meta.url)),
    server: { host: "127.0.0.1", port: 0 },
    logLevel: "error"
  });
  const duplicateKeys: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error" && message.text().includes("same key")) duplicateKeys.push(message.text());
  });
  try {
    await server.listen();
    await routeAccessKeyApi(page, PERSON(), (model) => {
      model.options.accessKeyTypes = [INFERENCE, { ...PREMIUM, displayName: INFERENCE.displayName }];
    });
    await page.goto(new URL("keys/new", server.resolvedUrls!.local[0]!).href);
    const choices = editor(page).getByRole("checkbox", { name: INFERENCE.displayName, exact: true });
    await expect(choices).toHaveCount(2);
    await choices.nth(0).check();
    await choices.nth(1).check();
    await editor(page).getByRole("textbox", { name: "Name", exact: true }).fill("shared-labels");
    await expect(editor(page).locator(".pt-key-pills .wb-chip")).toHaveText([INFERENCE.displayName, INFERENCE.displayName]);
    expect(duplicateKeys).toEqual([]);
    await issueButton(page).click();
    const dialog = page.getByRole("dialog", { name: "Access key created" });
    await expect(dialog).toBeVisible();
    await expect(dialog.locator(".pt-key-pills .wb-chip")).toHaveText([INFERENCE.displayName, INFERENCE.displayName]);
    expect(duplicateKeys).toEqual([]);
  } finally {
    await server.close();
  }
});
