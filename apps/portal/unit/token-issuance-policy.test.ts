import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, test } from "vitest";
import type { AgentTokenIssuancePolicy, AgentTokenOptions, Session } from "../src/types";
import { agentTokenIssuanceDescription, isAgentTokenIssuancePolicy, selfTokenIssuanceMode, tokenIssuanceBlocker } from "../src/lib/token-issuance-policy";
import { TokenEffect, TokenReadOnlyControl } from "../src/features/tokens/token-effect";

const policy: AgentTokenIssuancePolicy = { mode: "write_capable", source: "user", groupIds: [] };
const ttl = { defaultTtl: "1h", maxTtl: "8h", options: ["1h"] };
const session: Session = { authenticated: true, tokenIssuancePolicy: { selfAgentInvoke: { ...ttl, access: policy }, administered: { agentInvoke: ttl, admin: ttl, userManage: ttl } } };
const options: AgentTokenOptions = { policyGeneration: 1, agentTokenIssuancePolicy: policy, resources: [], resourceGroups: [], executionContexts: ["default"], services: [], mcp: null };

test.each([undefined, null, {}, { ...policy, mode: "inherit" }, { ...policy, mode: "unknown" }, { ...policy, groupIds: null }, { ...policy, groupIds: [3] }, { ...policy, source: "groups" }, { ...policy, source: "missing" }, { ...policy, source: "default" }, { ...policy, source: "groups", groupIds: ["one", "one"] }])("invalid policy %j never enables issuance", (invalid) => {
  expect(isAgentTokenIssuancePolicy(invalid)).toBe(false);
  expect(tokenIssuanceBlocker(session, false, { ...options, agentTokenIssuancePolicy: invalid } as AgentTokenOptions)).toBe("Token issuance policy is unavailable.");
});

test("an intentionally absent self policy is unavailable even with valid options", () => {
  expect(tokenIssuanceBlocker({ authenticated: true, tokenIssuancePolicy: {} }, false, options)).toBe("Token issuance policy is unavailable.");
});

test("disabled creation has no effect on administrator issuance", () => {
  const disabled = { ...options, agentTokenIssuancePolicy: { ...policy, mode: "disabled" as const } };
  expect(tokenIssuanceBlocker(session, false, disabled)).toBe("Agent token issuance is disabled for this account.");
  expect(tokenIssuanceBlocker(session, true, disabled)).toBeNull();
});

test("policy labels distinguish overrides, named contributing groups and default", () => {
  expect(agentTokenIssuanceDescription(policy)).toBe("Write-capable, explicit account override");
  expect(agentTokenIssuanceDescription({ mode: "read_only", source: "groups", groupIds: ["readers"] }, [{ groupId: "readers", displayName: "Engineering readers" }])).toBe("Read-only, inherited from Engineering readers");
  expect(agentTokenIssuanceDescription({ mode: "disabled", source: "default", groupIds: [] })).toBe("Disabled, no contributing groups");
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
  expect(markup).not.toContain("Apply read-only restriction");
});


test("an independent refresh never relaxes the other projection's restriction", () => {
  const refreshed = { ...session, tokenIssuancePolicy: { ...session.tokenIssuancePolicy, selfAgentInvoke: { ...ttl, access: { ...policy, mode: "read_only" as const } } } };
  expect(selfTokenIssuanceMode(refreshed, options)).toBe("read_only");
  const disabled = { ...options, agentTokenIssuancePolicy: { ...policy, mode: "disabled" as const } };
  expect(selfTokenIssuanceMode(refreshed, disabled)).toBe("disabled");
});
