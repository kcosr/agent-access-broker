import { expect, type Locator, type Page, type Request, type Response } from "@playwright/test";
import { randomUUID } from "node:crypto";
import type { OAuthConnectionTarget } from "../../src/types";

/** A real close-button click can destroy its page before Playwright acknowledges it. */
async function closeWithButton(consent: Page) {
  const button = consent.getByRole("button", { name: "Close tab", exact: true });
  await expect(button).toBeVisible();
  await expect(button).toBeEnabled();
  const marker = `oauth-close-click:${randomUUID()}`;
  let activated = false;
  let closed = false;
  const observeActivation = (message: { text(): string }) => { if (message.text() === marker) activated = true; };
  const observeClose = () => { closed = true; };
  consent.on("console", observeActivation);
  consent.on("close", observeClose);
  try {
    // Capture the trusted browser event before the application's window.close().
    // Leave its handler and native close behavior unchanged.
    await button.evaluate((element, marker) => {
      element.addEventListener("click", (event) => { if (event.isTrusted) console.info(marker); }, { capture: true, once: true });
    }, marker);
    try {
      await button.click({ noWaitAfter: true });
    } catch (error) {
      if (!(error instanceof Error) || !error.message.includes("Target page, context or browser has been closed") || !activated || !closed) throw error;
    }
    expect(activated).toBe(true);
    await expect.poll(() => closed && consent.isClosed()).toBe(true);
  } finally {
    consent.off("console", observeActivation);
    consent.off("close", observeClose);
  }
}

/** A same-URL reload would still lose unsaved portal state. Track the document too. */
export async function preservePortalDocument(portal: Page) {
  const url = portal.url();
  const marker = await portal.evaluate(() => document.documentElement.dataset.oauthOriginalDocument ??= crypto.randomUUID());
  return async () => {
    await expect(portal).toHaveURL(url);
    expect(await portal.evaluate(() => document.documentElement.dataset.oauthOriginalDocument)).toBe(marker);
  };
}

/** Drive real consent in a separate, isolated window while retaining the portal. */
export async function openOAuthWindow(portal: Page, trigger: Locator, heading: string) {
  const assertPortalPreserved = await preservePortalDocument(portal);
  // An isolated window has no JavaScript opener. Observe it on the context.
  const opened = portal.context().waitForEvent("page");
  await trigger.click();
  const consent = await opened;
  let callback: Response | undefined;
  consent.on("response", (response) => {
    if (new URL(response.url()).pathname.startsWith("/v1/oauth/callback/")) callback = response;
  });
  const reads: Array<{ afterCallback: boolean; response: Promise<Response | null> }> = [];
  const recordRead = (request: Request) => {
    if (request.method() === "GET" && new URL(request.url()).pathname === "/v1/oauth/connections") {
      reads.push({ afterCallback: Boolean(callback), response: request.response() });
    }
  };
  portal.on("request", recordRead);
  expect(consent).not.toBe(portal);
  await expect(consent.getByRole("heading", { name: heading, exact: true })).toBeVisible();
  expect(await consent.evaluate(() => window.opener === null)).toBe(true);
  await assertPortalPreserved();

  async function assertCompleted(state: "connected" | "disconnected", read: (typeof reads)[number]) {
    const response = await read.response;
    expect(response?.ok()).toBe(true);
    const envelope = await response!.json() as { ok: boolean; result: OAuthConnectionTarget[] };
    expect(envelope.ok).toBe(true);
    expect(envelope.result.some((target) => state === "connected"
      ? Boolean(target.connection?.connectionId) && target.connection?.status === "ready"
      : !target.connection?.connectionId)).toBe(true);
    await expect(portal.getByRole("button", { name: "Return to authorization tab", exact: true, includeHidden: true })).toHaveCount(0);
    const action = portal.getByRole("button", { name: state === "connected" ? "Reconnect" : "Connect account", exact: true, includeHidden: true });
    await expect(action).toBeEnabled();
    // Include the rendered state under an unsaved modal, without closing it.
    await expect(portal.getByText(state === "connected" ? "Connected" : "No account connected", { exact: true })).toHaveCount(1);
    await assertPortalPreserved();
  }

  return {
    consent,
    assertPortalPreserved,
    async finish(outcome: "authorized" | "canceled" | "failed", state: "connected" | "disconnected", closeBlocked = false) {
      await expect.poll(() => callback?.status()).toBe(outcome === "failed" ? 400 : 200);
      if (outcome === "authorized" && !closeBlocked) {
        expect(callback!.headers()["content-type"]).toBe("text/html; charset=utf-8");
        await expect.poll(() => consent.isClosed()).toBe(true);
      } else {
        await expect(consent).toHaveURL(/\/v1\/oauth\/callback\/[^/?]+(?:\?.*)?$/);
        expect(await consent.evaluate(() => window.opener === null)).toBe(true);
        if (outcome !== "failed") {
          await expect(consent.getByRole("heading", { name: outcome === "authorized" ? "Authorized" : "Authorization canceled", exact: true })).toBeVisible();
          await expect.poll(() => new URL(consent.url()).search).toBe("");
          const fallback = consent.getByRole("link", { name: "Open Broker in a new tab", exact: true });
          expect(new URL((await fallback.getAttribute("href"))!, portal.url()).href).toBe(portal.url());
          await expect(fallback).toHaveAttribute("target", "_blank");
          await expect(fallback).toHaveAttribute("rel", "noopener noreferrer");
        }
      }
      // Only authoritative reads started after the callback response count.
      // For canceled, failed and blocked-close cases keep consent open and do
      // not focus the portal, so closure/focus cannot mask a broken monitor.
      await expect.poll(() => reads.some((read) => read.afterCallback)).toBe(true);
      await assertCompleted(state, reads.filter((read) => read.afterCallback).at(-1)!);
      portal.off("request", recordRead);
      if (closeBlocked) {
        await expect(consent.getByRole("status")).toHaveText("Your browser kept this tab open. Close it using your browser’s tab controls.");
        await expect.poll(() => consent.evaluate(() => document.documentElement.dataset.oauthCloseAttempts)).toBe("1");
        await consent.getByRole("button", { name: "Close tab", exact: true }).click();
        await expect.poll(() => consent.evaluate(() => document.documentElement.dataset.oauthCloseAttempts)).toBe("2");
        await expect(consent.getByRole("status")).toBeVisible();
      }
      if (outcome === "canceled" || closeBlocked) {
        const reload = await consent.reload();
        expect(reload?.status()).toBe(200);
        await expect(consent.getByRole("heading", { name: "Check connection status", exact: true })).toBeVisible();
        await expect(consent).toHaveURL(/\/v1\/oauth\/callback\/[^/?]+$/);
        expect(consent.isClosed()).toBe(false);
        await assertPortalPreserved();
      }
      if (outcome === "canceled") {
        expect(consent.isClosed()).toBe(false);
        await closeWithButton(consent);
      } else if (outcome === "failed" || closeBlocked) {
        expect(consent.isClosed()).toBe(false);
        await consent.close();
      }
      await portal.bringToFront();
      await assertPortalPreserved();
    },
    async closeWithoutConsent() {
      const beforeClose = reads.length;
      await expect(portal.getByRole("button", { name: "Return to authorization tab", exact: true })).toBeEnabled();
      await consent.close();
      await expect.poll(() => reads.length).toBeGreaterThan(beforeClose);
      await assertCompleted("disconnected", reads.at(-1)!);
      portal.off("request", recordRead);
      await portal.bringToFront();
    }
  };
}
