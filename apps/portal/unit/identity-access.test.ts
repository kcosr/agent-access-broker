import { afterEach, expect, test, vi } from "vitest";
import { brokerApi } from "../src/api";
import { validIdentityUsername } from "../src/lib/identity-access";
import { portalQueryKeys } from "../src/lib/portal-queries";

afterEach(() => vi.unstubAllGlobals());

test.each(["Alice", "alice", "00123", "anonymous", "alice.smith_dev+host@example.test", "a".repeat(128)])("accepts the exact identity name %s", (name) => {
  expect(validIdentityUsername(name)).toBe(true);
});

test.each(["", " Alice", "Alice ", "Alice\n", "Alice\r\n", "Alice\t", "alice,bob", "alice%40example.test", "álîce", "a".repeat(129), "a/b", "a\u0000b"])("rejects a name without normalizing it: %j", (name) => {
  expect(validIdentityUsername(name)).toBe(false);
});

test("identity mutations retain exact names, CSRF and current versions on canonical routes", async () => {
  const fetch = vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ ok: true, result: {} }))));
  vi.stubGlobal("fetch", fetch);
  const session = { authenticated: true, role: "admin" as const, csrfHeader: "x-csrf-token", csrfToken: "fixture-csrf" };
  await brokerApi.adminSetIdentityAccess(session, "user/1", { paused: true, expectedVersion: 7 });
  await brokerApi.adminCreateIdentityBinding(session, "user/1", { namespace: "managed_linux", username: "Alice+01@example.test", readOnly: true });
  await brokerApi.adminUpdateIdentityBinding(session, "user/1", "binding/1", { enabled: false, expectedVersion: 3 });
  await brokerApi.adminUpdateIdentityBinding(session, "user/1", "binding/1", { readOnly: true, expectedVersion: 4 });
  await brokerApi.adminDeleteIdentityBinding(session, "user/1", "binding/1", 5);
  await brokerApi.adminUpdateIdentityToken(session, "user/1", { enabled: false, expectedRevision: 2 });
  await brokerApi.adminUpdateIdentityToken(session, "user/1", { readOnly: true, expectedRevision: 3 });
  expect(fetch.mock.calls.map(([url, init]) => [url, init.method, init.body && JSON.parse(init.body)])).toEqual([
    ["/v1/admin/principals/user%2F1/identity-access", "PATCH", { paused: true, expectedVersion: 7 }],
    ["/v1/admin/principals/user%2F1/identity-bindings", "POST", { namespace: "managed_linux", username: "Alice+01@example.test", readOnly: true }],
    ["/v1/admin/principals/user%2F1/identity-bindings/binding%2F1", "PATCH", { enabled: false, expectedVersion: 3 }],
    ["/v1/admin/principals/user%2F1/identity-bindings/binding%2F1", "PATCH", { readOnly: true, expectedVersion: 4 }],
    ["/v1/admin/principals/user%2F1/identity-bindings/binding%2F1?expectedVersion=5", "DELETE", undefined],
    ["/v1/admin/principals/user%2F1/identity-token", "PATCH", { enabled: false, expectedRevision: 2 }],
    ["/v1/admin/principals/user%2F1/identity-token", "PATCH", { readOnly: true, expectedRevision: 3 }]
  ]);
  for (const [, init] of fetch.mock.calls) {
    expect(new Headers(init.headers).get("x-csrf-token")).toBe("fixture-csrf");
    expect(init.credentials).toBe("same-origin");
  }
});

test("a stale identity-token revision surfaces as a version conflict", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: false, reasonCode: "identity_version_conflict", error: { message: "identity token revision changed" } }), { status: 409 })));
  await expect(brokerApi.adminUpdateIdentityToken({ authenticated: true, role: "admin" }, "alice", { enabled: false, expectedRevision: 1 })).rejects.toMatchObject({ status: 409, reasonCode: "identity_version_conflict" });
});

test("identity gate and bindings are isolated by viewer, principal and inventory cache", () => {
  const keys = [
    portalQueryKeys.identityAccess("admin", "alice"),
    portalQueryKeys.identityAccess("auditor", "alice"),
    portalQueryKeys.identityAccess("admin", "bob"),
    portalQueryKeys.identityBindings("admin", "alice"),
    portalQueryKeys.identityToken("admin", "alice")
  ];
  expect(new Set(keys.map((key) => JSON.stringify(key))).size).toBe(keys.length);
});
