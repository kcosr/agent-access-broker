import { expect, test } from "vitest";
import { accessDraft, accessDraftPatch, keepAccessDraft, refreshAccessDraft, type AccessFields } from "../src/lib/access-draft";
const base: AccessFields = { role: "user", selfServiceEnabled: true, agentTokenIssuance: { mode: "read_only", allowedExecutionContexts: ["internal"] } };

test("contexts-only edit adopts concurrent role and self-service updates and PATCH omits them", () => {
  const draft = { ...accessDraft(base), value: { ...base, agentTokenIssuance: { ...base.agentTokenIssuance, allowedExecutionContexts: ["internal", "external"] } } };
  const latest: AccessFields = { ...base, role: "auditor", selfServiceEnabled: false };
  const next = refreshAccessDraft(draft, latest);
  expect(next.conflicts).toEqual([]);
  expect(next.value.role).toBe("auditor");
  expect(next.value.selfServiceEnabled).toBe(false);
  expect(accessDraftPatch(next)).toEqual({ agentTokenIssuance: draft.value.agentTokenIssuance });
});

test("a changed edited field blocks until explicit keep or discard; equal saved values become clean", () => {
  const draft = { ...accessDraft(base), value: { ...base, role: "admin" as const, agentTokenIssuance: { ...base.agentTokenIssuance, allowedExecutionContexts: ["external"] } } };
  const latest: AccessFields = { ...base, role: "auditor", selfServiceEnabled: false, agentTokenIssuance: { mode: "disabled", allowedExecutionContexts: [] } };
  const conflicted = refreshAccessDraft(draft, latest);
  expect(conflicted.conflicts).toEqual(["role", "agentTokenIssuance"]);
  const kept = keepAccessDraft(conflicted, latest);
  expect(kept.base.role).toBe("auditor");
  expect(kept.value.selfServiceEnabled).toBe(false);
  expect(accessDraftPatch(kept)).toEqual({ role: "admin", agentTokenIssuance: draft.value.agentTokenIssuance });
  expect(accessDraftPatch(accessDraft(latest))).toEqual({});
  expect(accessDraftPatch(refreshAccessDraft(kept, kept.value))).toEqual({});
});

test("registry order does not conflict or write while an unrelated field stays dirty", () => {
  const value: AccessFields = { ...base, agentTokenIssuance: { mode: "read_only", allowedExecutionContexts: ["external", "internal"] } };
  const draft = { ...accessDraft(value), value: { ...value, role: "admin" as const } };
  const refreshed = refreshAccessDraft(draft, { ...value, agentTokenIssuance: { ...value.agentTokenIssuance, allowedExecutionContexts: ["internal", "external"] } });
  expect(refreshed.conflicts).toEqual([]);
  expect(accessDraftPatch(refreshed)).toEqual({ role: "admin" });
});
