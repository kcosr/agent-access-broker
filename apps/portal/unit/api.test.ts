import { afterEach, expect, test, vi } from "vitest";
import { ApiError, brokerApi } from "../src/api";

afterEach(() => vi.unstubAllGlobals());

test("document upload sends the original file once with CSRF and encoded version fences", async () => {
  const file = new File([' {"swagger":"2.0","x":"é","x":"preserved"}\n'], "café & notes.json");
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true, result: {} })));
  vi.stubGlobal("fetch", fetch);
  await brokerApi.uploadImportDocument({ authenticated: true, role: "admin", csrfHeader: "x-csrf", csrfToken: "synthetic" }, "inventory", { expectedVersion: 7, expectedCatalogRevision: 12 }, file);
  expect(fetch).toHaveBeenCalledTimes(1);
  const [path, init] = fetch.mock.calls[0] as [string, RequestInit];
  expect(new URL(path, "https://broker.example.test").searchParams).toEqual(new URLSearchParams({ expectedVersion: "7", expectedCatalogRevision: "12", filename: file.name }));
  expect(init).toMatchObject({ method: "PUT", body: file, credentials: "same-origin" });
  expect(init.body).toBe(file);
  expect(new Headers(init.headers).get("content-type")).toBe("application/json");
  expect(new Headers(init.headers).get("x-csrf")).toBe("synthetic");
  fetch.mockRejectedValueOnce(new TypeError("network connection lost"));
  await expect(brokerApi.uploadImportDocument({ authenticated: true, role: "admin" }, "inventory", { expectedVersion: 7, expectedCatalogRevision: 12 }, file)).rejects.toThrow("network connection lost");
  expect(fetch).toHaveBeenCalledTimes(2);
});

test("proxy HTML errors preserve the HTTP status without exposing their body", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html>private upstream diagnostics</html>", { status: 502 })));
  try {
    await brokerApi.session();
    throw new Error("Expected the session request to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(502);
    expect((error as Error).message).toContain("Check the broker or its reverse proxy");
    expect((error as Error).message).not.toContain("private upstream diagnostics");
  }
});

test("a broken JSON success response is reported as unreadable", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{", { status: 200 })));
  await expect(brokerApi.session()).rejects.toThrow("unreadable response (HTTP 200)");
});

test("refused import changes carry the grants and resources that block them", async () => {
  const affectedGrants = [{ id: "grant-search", reasonCode: "credential_mode_unsupported", reason: "managed policy grant grant-search uses an unsupported credential mode" }];
  const resources = [{ type: "ticketing_project", id: "legacy" }];
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: false, reasonCode: "input_invalid", error: { message: "input is invalid: refused" }, target: { service: "ticketing", affectedGrants, resources } }), { status: 400 })));
  await expect(brokerApi.acceptImport({ authenticated: true, role: "admin" }, "ticketing", { expectedVersion: 1, expectedCatalogRevision: 1, manifestHash: "hash", selections: [], confirmAffectedGrants: false })).rejects.toMatchObject({ status: 400, blocked: { affectedGrants, resources } });
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: false, reasonCode: "input_invalid", error: { message: "select at least one discovered tool" }, target: { service: "ticketing" } }), { status: 400 })));
  const plain = await brokerApi.acceptImport({ authenticated: true, role: "admin" }, "ticketing", { expectedVersion: 1, expectedCatalogRevision: 1, manifestHash: "hash", selections: [], confirmAffectedGrants: false }).catch((error: unknown) => error);
  expect(plain).toMatchObject({ message: "select at least one discovered tool" });
  expect((plain as { blocked?: unknown }).blocked).toBeUndefined();
});

test("an acceptance refused for confirmation carries the broker's classification changes", async () => {
  const classificationChanges = [{ action: "entry.list", from: "write", to: "read" }, { action: "entry.note", from: null, to: "write" }];
  const body = { expectedVersion: 1, expectedCatalogRevision: 1, manifestHash: "hash", selections: [], confirmAffectedGrants: false };
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: false, reasonCode: "input_invalid", error: { message: "accepted changes affect existing grants; confirmAffectedGrants is required" }, target: { service: "ledger", classificationChanges } }), { status: 400 })));
  const refused = await brokerApi.acceptImport({ authenticated: true, role: "admin" }, "ledger", body).catch((error: unknown) => error);
  expect(refused).toMatchObject({ status: 400, reasonCode: "input_invalid", classificationChanges });
  expect((refused as ApiError).blocked).toBeUndefined();
  // An empty list still identifies the confirmation refusal.
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: false, reasonCode: "input_invalid", error: { message: "refused" }, target: { service: "ledger", classificationChanges: [] } }), { status: 400 })));
  await expect(brokerApi.acceptImport({ authenticated: true, role: "admin" }, "ledger", body)).rejects.toMatchObject({ classificationChanges: [] });
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: false, reasonCode: "input_invalid", error: { message: "select at least one discovered tool" }, target: { service: "ledger" } }), { status: 400 })));
  const plain = await brokerApi.acceptImport({ authenticated: true, role: "admin" }, "ledger", body).catch((error: unknown) => error);
  expect((plain as ApiError).classificationChanges).toBeUndefined();
});

test("management errors preserve structured conflict identity independently of message text", async () => {
  const conflict = { kind: "resource", id: "existing", displayName: "Payments API", version: 2 };
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: false, reasonCode: "input_invalid", error: { message: "Already exists" }, target: { conflict } }), { status: 400 })));
  await expect(brokerApi.saveResource({ authenticated: true, role: "admin" }, { resourceType: "git_repository", selector: { kind: "exact", value: "engineering/payments" }, enabled: true, allowedExecutionContexts: ["default"] })).rejects.toMatchObject({ status: 400, reasonCode: "input_invalid", message: "Already exists", conflict });
});


test("a refusal with only group exclusions preserves its structured memberships", async () => {
  const resourceGroups = [{ type: "ticketing_project", id: "engineering", resourceIds: ["ops"] }];
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: false, reasonCode: "input_invalid", error: { message: "refused" }, target: { resourceGroups } }), { status: 400 })));
  await expect(brokerApi.acceptImport({ authenticated: true, role: "admin" }, "ticketing", { expectedVersion: 1, expectedCatalogRevision: 1, manifestHash: "hash", selections: [], confirmAffectedGrants: false })).rejects.toMatchObject({
    status: 400, blocked: { affectedGrants: [], resources: [], resourceGroups }
  });
});
