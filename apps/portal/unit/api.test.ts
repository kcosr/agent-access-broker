import { afterEach, expect, test, vi } from "vitest";
import { ApiError, brokerApi } from "../src/api";

afterEach(() => vi.unstubAllGlobals());

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

test("management errors preserve structured conflict identity independently of message text", async () => {
  const conflict = { kind: "resource", id: "existing", displayName: "Payments API", version: 2 };
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: false, reasonCode: "input_invalid", error: { message: "Already exists" }, target: { conflict } }), { status: 400 })));
  await expect(brokerApi.saveResource({ authenticated: true, role: "admin" }, { resourceType: "git_repository", selector: { kind: "exact", value: "engineering/payments" }, enabled: true, allowedExecutionContexts: ["default"] })).rejects.toMatchObject({ status: 400, reasonCode: "input_invalid", message: "Already exists", conflict });
});
