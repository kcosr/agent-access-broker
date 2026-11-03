import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, test } from "vitest";
import type { AgentTokenIssuancePolicy, AgentTokenOptions, Session } from "../src/types";
import { agentTokenIssuanceDescription, eligibleTokenContexts, isAgentTokenIssuancePolicy, selfTokenIssuanceContexts, tokenIssuanceBlocker, issuanceSettingBlocker, issuanceSettingEqual } from "../src/lib/token-issuance-policy";
import { TokenEffect, TokenReadOnlyControl } from "../src/features/tokens/token-effect";

const row = { executionContext: "internal", mode: "write_capable" as const, groupIds: [] };
const policy: AgentTokenIssuancePolicy = { source: "user", contexts: [row] };
const ttl = { defaultTtl: "1h", maxTtl: "8h", options: ["1h"] };
const session: Session = { authenticated: true, tokenIssuancePolicy: { selfAgentInvoke: { ...ttl, access: policy }, administered: { agentInvoke: ttl, admin: ttl, userManage: ttl } } };
const options: AgentTokenOptions = { policyGeneration: 1, agentTokenIssuancePolicy: policy, resources: [], resourceGroups: [], executionContexts: ["internal", "external"], services: [], mcp: null };
const invalidPolicies = [undefined, null, {}, { mode: "write_capable", source: "user", groupIds: [] }, { ...policy, mode: "read_only" }, { ...policy, contexts: null }, { ...policy, contexts: [row, row] }, { ...policy, contexts: [{ ...row, mode: "disabled" }] }, { ...policy, contexts: [{ ...row, executionContext: "Bad name" }] }, { ...policy, contexts: [{ ...row, groupIds: [3] }] }, { ...policy, contexts: [{ ...row, extra: 3 }] }, { ...policy, source: "groups" }, { ...policy, source: "missing" }, { ...policy, source: "default" }, { source: "groups", contexts: [] }, { source: "groups", contexts: [{ ...row, groupIds: ["one", "one"] }] }];

test.each(invalidPolicies)("invalid policy %j never enables personal issuance but does not gate administrative issuance", (invalid) => {
  expect(isAgentTokenIssuancePolicy(invalid)).toBe(false);
  const malformed = { ...options, agentTokenIssuancePolicy: invalid } as AgentTokenOptions;
  expect(tokenIssuanceBlocker(session, false, malformed)).toBe("Token issuance policy is unavailable.");
  expect(tokenIssuanceBlocker(session, true, malformed)).toBeNull();
});

test("missing TTL and target options still block administrators", () => {
  expect(tokenIssuanceBlocker({ authenticated: true, tokenIssuancePolicy: {} }, true, options)).toBe("Token issuance policy is unavailable.");
  expect(tokenIssuanceBlocker(session, true, null)).toBe("Token issuance policy is unavailable.");
  expect(tokenIssuanceBlocker(session, true, { ...options, executionContexts: [] })).toContain("active policy grant");
});

test("disabled creation has no effect on administrator issuance", () => {
  const disabled = { ...options, agentTokenIssuancePolicy: { source: "user" as const, contexts: [] } };
  expect(tokenIssuanceBlocker(session, false, disabled)).toBe("No granted execution contexts permit personal agent token issuance.");
  expect(tokenIssuanceBlocker(session, true, disabled)).toBeNull();
});

test("policy labels retain per-context provenance", () => {
  expect(agentTokenIssuanceDescription(policy)).toBe("internal: Write-capable, explicit account override");
  expect(agentTokenIssuanceDescription({ source: "groups", contexts: [{ ...row, mode: "read_only", groupIds: ["readers"] }, { executionContext: "external", mode: "write_capable", groupIds: ["writers"] }] }, [{ groupId: "readers", displayName: "Engineering readers" }])).toBe("internal: Read-only, inherited from Engineering readers; external: Write-capable, inherited from writers");
  expect(agentTokenIssuanceDescription({ source: "default", contexts: [] })).toBe("Disabled, no contributing groups");
});

test("token warnings describe only an explicit stored false; missing values never guess", () => {
  const badge = renderToStaticMarkup(createElement(TokenEffect, { readOnly: false }));
  expect(badge).toContain("Write-capable");
  expect(badge).toContain("May use granted write actions");
  for (const readOnly of [true, undefined, null, "false", 0]) expect(renderToStaticMarkup(createElement(TokenEffect, { readOnly }))).toBe("");
  expect(renderToStaticMarkup(createElement(TokenEffect, { readOnly: true, quiet: true }))).toContain("Read-only");
  expect(renderToStaticMarkup(createElement(TokenEffect, { readOnly: undefined, quiet: true }))).toContain("Restriction unavailable");
});

test.each([true, false])("required read-only policy is plain text for a draft with readOnly=%s", (readOnly) => {
  const changes: boolean[] = [];
  const markup = renderToStaticMarkup(createElement(TokenReadOnlyControl, { readOnly, required: true, disabled: false, onChange: (value) => changes.push(value) }));
  expect(markup).toContain("Read-only");
  expect(markup).toContain("Required by your account’s token issuance policy");
  expect(markup).not.toContain("<input");
  expect(markup.includes("Apply read-only restriction")).toBe(!readOnly);
  expect(changes).toEqual([]);
});

test.each([true, false])("selectable read-only control preserves the draft Boolean %s", (readOnly) => {
  const markup = renderToStaticMarkup(createElement(TokenReadOnlyControl, { readOnly, required: false, disabled: false, onChange: () => {} }));
  expect(markup).toContain('type="checkbox"');
  expect(markup.includes('checked=""')).toBe(readOnly);
  expect(markup).not.toContain("Required by your account");
});

test("independent refreshes intersect rows conservatively by name and preserve grant order", () => {
  const refreshed: Session = { ...session, tokenIssuancePolicy: { selfAgentInvoke: { ...ttl, access: { source: "user", contexts: [{ ...row, mode: "read_only" }, { ...row, executionContext: "external" }, { ...row, executionContext: "other" }] } } } };
  const owner: AgentTokenOptions = { ...options, executionContexts: ["external", "internal", "missing"], agentTokenIssuancePolicy: { source: "user", contexts: [row, { ...row, executionContext: "external", mode: "read_only" }] } };
  expect([...selfTokenIssuanceContexts(refreshed, owner)!]).toEqual([["internal", "read_only"], ["external", "read_only"]]);
  expect(eligibleTokenContexts(refreshed, false, owner)).toEqual(["external", "internal"]);
  expect(eligibleTokenContexts(refreshed, true, owner)).toEqual(["external", "internal", "missing"]);
});

test("authoring requires explicit configured selections and treats reorder as a no-op", () => {
  expect(issuanceSettingBlocker({ mode: "read_only", allowedExecutionContexts: [] }, ["default"])).toContain("Select at least one");
  expect(issuanceSettingBlocker({ mode: "read_only", allowedExecutionContexts: ["removed"] }, ["default"])).toContain("no longer configured");
  expect(issuanceSettingBlocker({ mode: "read_only", allowedExecutionContexts: ["default"] }, undefined)).toContain("unavailable");
  expect(issuanceSettingEqual({ mode: "read_only", allowedExecutionContexts: ["a", "b"] }, { mode: "read_only", allowedExecutionContexts: ["b", "a"] })).toBe(true);
});
