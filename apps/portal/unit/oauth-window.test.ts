import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { refreshOAuthOnReturn, reserveOAuthWindow, type OAuthAuthorization } from "../src/lib/oauth-window";

const origin = "https://broker.example.test";
const callbackPath = "/v1/oauth/callback/metrics-oauth";
const registration = "metrics-oauth";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function browser() {
  const location = { origin: "null", pathname: "blank", replace: vi.fn() };
  const popup = {
    closed: false,
    opener: {} as unknown,
    document: { title: "", body: { textContent: "" } },
    location,
    close: vi.fn(() => { popup.closed = true; }),
    focus: vi.fn()
  };
  const page = Object.assign(new EventTarget(), {
    open: vi.fn(() => popup),
    location: { origin, assign: vi.fn() },
    setInterval, clearInterval, setTimeout, clearTimeout
  });
  const document = Object.assign(new EventTarget(), { visibilityState: "visible" });
  vi.stubGlobal("window", page);
  vi.stubGlobal("document", document);
  const authorization: OAuthAuthorization = { authorizationUrl: "https://login.example.test/authorize?state=opaque", expiresAt: Date.now() / 1000 + 60 };
  return { page, popup, location, document, authorization };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

test("reserves and isolates the separate window before starting an asynchronous Connect request", async () => {
  const { page, popup, authorization } = browser();
  const response = deferred<OAuthAuthorization>();
  const finished = vi.fn();
  const flow = reserveOAuthWindow(registration, finished);
  expect(page.open).toHaveBeenCalledExactlyOnceWith("about:blank", "_blank");
  const request = vi.fn(() => {
    expect(popup.opener).toBeNull();
    return response.promise;
  });
  const started = flow.authorize(request);
  expect(request).toHaveBeenCalledOnce();
  expect(popup.location.replace).not.toHaveBeenCalled();
  response.resolve(authorization);
  await started;
  expect(popup.location.replace).toHaveBeenCalledExactlyOnceWith(authorization.authorizationUrl);
  expect(page.location.assign).not.toHaveBeenCalled();
  expect(finished).not.toHaveBeenCalled();
  flow.dispose();
});

test("a blocked popup fails before any Connect request or same-tab navigation", () => {
  const { page } = browser();
  page.open.mockReturnValueOnce(null as never);
  expect(() => reserveOAuthWindow(registration, vi.fn())).toThrow("Allow pop-ups for this site, then try connecting again.");
  expect(page.location.assign).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
});

test("failure to isolate the opener closes the window without authorization", () => {
  const { popup } = browser();
  Object.defineProperty(popup, "opener", { set: () => { throw new Error("blocked"); } });
  expect(() => reserveOAuthWindow(registration, vi.fn())).toThrow("could not be prepared");
  expect(popup.close).toHaveBeenCalledOnce();
  expect(popup.location.replace).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
});

test("Connect failure closes the reserved window, clears its monitor and preserves the API error", async () => {
  const { popup } = browser();
  const finished = vi.fn();
  const flow = reserveOAuthWindow(registration, finished);
  const error = new Error("Connection service unavailable");
  await expect(flow.authorize(async () => { throw error; })).rejects.toBe(error);
  expect(popup.close).toHaveBeenCalledOnce();
  expect(popup.location.replace).not.toHaveBeenCalled();
  expect(finished).toHaveBeenCalledOnce();
  expect(vi.getTimerCount()).toBe(0);
});

test("only the expected same-origin callback ends monitoring, without closing the callback page", async () => {
  const { page, popup, location, authorization } = browser();
  const finished = vi.fn();
  const flow = reserveOAuthWindow(registration, finished);
  await flow.authorize(async () => authorization);
  vi.advanceTimersByTime(500); // Initial blank document is not a return.
  location.origin = origin;
  location.pathname = "/ui/credentials";
  vi.advanceTimersByTime(500); // Another portal page is not this flow's return.
  location.pathname = "/v1/oauth/callback/another-registration";
  vi.advanceTimersByTime(500); // Another registration's callback is not this flow.
  location.origin = "https://other.example.test";
  location.pathname = callbackPath;
  vi.advanceTimersByTime(500);
  page.dispatchEvent(new Event("message")); // No message can assert completion.
  expect(finished).not.toHaveBeenCalled();
  Object.defineProperty(popup, "location", { get: () => { throw new Error("cross-origin"); }, configurable: true });
  expect(() => vi.advanceTimersByTime(500)).not.toThrow();
  expect(finished).not.toHaveBeenCalled();
  Object.defineProperty(popup, "location", { value: location, configurable: true });
  location.origin = origin;
  vi.advanceTimersByTime(500);
  expect(finished).toHaveBeenCalledOnce();
  expect(popup.close).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
});

test("a callback error releases the original view while leaving the error window open", async () => {
  const { popup, location, authorization } = browser();
  const finished = vi.fn();
  const flow = reserveOAuthWindow(registration, finished);
  await flow.authorize(async () => authorization);
  location.origin = origin;
  location.pathname = `/v1/oauth/callback/${registration}`;
  vi.advanceTimersByTime(500);
  expect(finished).toHaveBeenCalledOnce();
  expect(popup.close).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
});

test("closing a still-preparing window prevents its late authorization navigation", async () => {
  const { popup, authorization } = browser();
  const finished = vi.fn();
  const response = deferred<OAuthAuthorization>();
  const flow = reserveOAuthWindow(registration, finished);
  const started = flow.authorize(() => response.promise);
  popup.closed = true;
  vi.advanceTimersByTime(500);
  response.resolve(authorization);
  await started;
  expect(popup.location.replace).not.toHaveBeenCalled();
  expect(finished).toHaveBeenCalledOnce();
  expect(vi.getTimerCount()).toBe(0);
});

test("leaving the view during Connect keeps the window and navigates the late response without view updates", async () => {
  const { popup, authorization } = browser();
  const finished = vi.fn();
  const response = deferred<OAuthAuthorization>();
  const flow = reserveOAuthWindow(registration, finished);
  const started = flow.authorize(() => response.promise);
  flow.dispose();
  expect(popup.close).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
  response.resolve(authorization);
  await expect(started).resolves.toBeUndefined();
  expect(popup.location.replace).toHaveBeenCalledExactlyOnceWith(authorization.authorizationUrl);
  expect(popup.close).not.toHaveBeenCalled();
  popup.closed = true;
  vi.advanceTimersByTime(60_000);
  expect(finished).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
});

test("a late Connect failure after leaving the view closes the preparing window without view updates", async () => {
  const { popup } = browser();
  const finished = vi.fn();
  const response = deferred<OAuthAuthorization>();
  const flow = reserveOAuthWindow(registration, finished);
  const started = flow.authorize(() => response.promise);
  flow.dispose();
  response.reject(new Error("late API failure"));
  await expect(started).resolves.toBeUndefined();
  expect(popup.close).toHaveBeenCalledOnce();
  expect(popup.location.replace).not.toHaveBeenCalled();
  expect(finished).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
});

test("a user closing the preparing window after leaving the view prevents late navigation", async () => {
  const { popup, authorization } = browser();
  const finished = vi.fn();
  const response = deferred<OAuthAuthorization>();
  const flow = reserveOAuthWindow(registration, finished);
  const started = flow.authorize(() => response.promise);
  flow.dispose();
  popup.closed = true;
  response.resolve(authorization);
  await started;
  expect(popup.location.replace).not.toHaveBeenCalled();
  expect(finished).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
});

test("leaving the view or reaching flow expiry preserves the user's consent/error window", async () => {
  const { popup, authorization } = browser();
  const finished = vi.fn();
  const flow = reserveOAuthWindow(registration, finished);
  await flow.authorize(async () => authorization);
  vi.advanceTimersByTime(60_000);
  expect(finished).toHaveBeenCalledOnce();
  flow.dispose();
  expect(popup.close).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
});

test("non-HTTP authorization URLs cannot execute in the reserved window", async () => {
  const { popup, authorization } = browser();
  const flow = reserveOAuthWindow(registration, vi.fn());
  await expect(flow.authorize(async () => ({ ...authorization, authorizationUrl: "javascript:private-data" }))).rejects.toThrow("invalid account connection URL");
  expect(popup.location.replace).not.toHaveBeenCalled();
  expect(popup.close).toHaveBeenCalledOnce();
});

test("returning to the original view refreshes from the broker even without a popup handle", () => {
  const { page, document } = browser();
  const refresh = vi.fn();
  const stop = refreshOAuthOnReturn(refresh);
  page.dispatchEvent(new Event("focus"));
  expect(refresh).toHaveBeenCalledTimes(1);
  document.visibilityState = "hidden";
  document.dispatchEvent(new Event("visibilitychange"));
  expect(refresh).toHaveBeenCalledTimes(1);
  document.visibilityState = "visible";
  document.dispatchEvent(new Event("visibilitychange"));
  expect(refresh).toHaveBeenCalledTimes(2);
  stop();
  page.dispatchEvent(new Event("focus"));
  document.dispatchEvent(new Event("visibilitychange"));
  expect(refresh).toHaveBeenCalledTimes(2);
});
