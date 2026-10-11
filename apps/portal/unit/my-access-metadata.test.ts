// My access reads service names, action classifications, and verification
// inputs from the token options and credential targets, never from agent
// discovery (`/v1/services`, filtered by the request's execution context).
import { describe, expect, it } from "vitest";
import { buildAccessSummary, serviceDisplayNames } from "../src/lib/access";
import { accessRows, filterAccessRows, ACCESS_STATE } from "../src/features/access/access-list";
import { credentialVerificationNeedsRepository } from "../src/mutations/credentials";
import { indexResourceTypes } from "../src/lib/resource-types";
import type { AgentTokenOptions, CredentialTarget } from "../src/types";
import { readUrlState, writeUrlState } from "../src/lib/url-state";
import { RESOURCE_TYPES } from "./resource-types.fixture";

const types = indexResourceTypes(RESOURCE_TYPES);

const action = (name: string, readOnly: boolean) => ({
  action: name,
  description: name,
  readOnly,
  requiredScopeTypes: [],
  resourceType: null,
  executionContexts: ["internal"],
  effectiveAccessByExecutionContext: { internal: [] }
});

// Grants only in `internal`; the session's default context has none.
const options: AgentTokenOptions = {
  policyGeneration: 3,
  resources: [],
  resourceGroups: [],
  executionContexts: ["default", "internal"],
  services: [
    { service: "cloudbees_ci", displayName: "CloudBees CI", brokerHosts: [], executionContexts: ["internal"], actions: [action("build.list", true), action("build.trigger", false)] },
    { service: "gitlab_git", displayName: "GitLab Git", brokerHosts: ["git.example.test"], executionContexts: ["internal"], actions: [action("repo.fetch", true)] }
  ]
};

const target = (service: string, displayName: string, credentialVerificationInputs: string[]): CredentialTarget => ({
  service,
  displayName,
  credentialVerificationInputs,
  credentialName: "default",
  profile: "token",
  credentialKind: "bearer_token",
  inputSchema: { fields: [] } as unknown as CredentialTarget["inputSchema"]
});

describe("My access metadata", () => {
  it("names services from the token options and credential targets, keeping the ID otherwise", () => {
    const names = serviceDisplayNames(options, [target("jira", "Jira", []), target("gitlab_git", "GitLab Git", ["repository"])]);
    expect(names.get("cloudbees_ci")).toBe("CloudBees CI");
    expect(names.get("gitlab_git")).toBe("GitLab Git");
    expect(names.get("jira")).toBe("Jira");
    expect(names.get("unknown")).toBeUndefined();
    expect(serviceDisplayNames(null).size).toBe(0);
  });

  it("classifies actions from the token options in any context", () => {
    const summary = buildAccessSummary(options);
    expect(summary.flatMap((service) => service.actions.map((item) => [item.action, item.readOnly]))).toEqual([
      ["build.list", true],
      ["build.trigger", false],
      ["repo.fetch", true]
    ]);
    const rows = accessRows(options, "internal", types);
    expect(rows.map((row) => [row.service, row.action, row.readOnly])).toEqual([
      ["cloudbees_ci", "build.list", true],
      ["cloudbees_ci", "build.trigger", false],
      ["gitlab_git", "repo.fetch", true]
    ]);
    expect(accessRows(options, "default", types)).toEqual([]);
  });

  it("treats a missing classification as write-capable", () => {
    const unclassified = { ...options, services: [{ ...options.services[0]!, actions: [{ ...action("build.list", true), readOnly: undefined as unknown as boolean }] }] };
    expect(accessRows(unclassified, null, types)[0]!.readOnly).toBe(false);
  });

  it("filters individual action effects together with service and resource search", () => {
    const rows = accessRows(options, null, types);
    const state = { service: "", q: "", effect: ["write"] as const };
    expect(filterAccessRows(rows, state, options.services).map((row) => row.action)).toEqual(["build.trigger"]);
    expect(filterAccessRows(rows, { ...state, effect: ["read"] }, options.services).map((row) => row.action)).toEqual(["build.list", "repo.fetch"]);
    expect(filterAccessRows(rows, { ...state, effect: [] }, options.services)).toEqual(rows);
    expect(filterAccessRows(rows, { ...state, effect: ["read", "write"] }, options.services)).toEqual(rows);
    expect(filterAccessRows(rows, { ...state, service: "gitlab_git" }, options.services)).toEqual([]);
    expect(filterAccessRows(rows, { ...state, q: "trigger" }, options.services).map((row) => row.action)).toEqual(["build.trigger"]);
    expect(filterAccessRows(rows, { ...state, q: "GitLab Git" }, options.services)).toEqual([]);
    expect(filterAccessRows(accessRows(options, "default", types), { ...state, effect: [] }, options.services)).toEqual([]);
  });

  it("keeps different resource boundaries separate when filtering all contexts", () => {
    const contextual = structuredClone(options);
    const service = contextual.services[0]!;
    service.executionContexts = ["default", "internal"];
    const action = service.actions[0]!;
    action.resourceType = "cloudbees_ci_job";
    action.executionContexts = ["default", "internal"];
    action.effectiveAccessByExecutionContext = {
      default: [{ included: [{ kind: "exact", value: "public/job" }], excluded: [] }],
      internal: [{ included: [{ kind: "exact", value: "private/job" }], excluded: [] }]
    };
    const rows = filterAccessRows(accessRows(contextual, null, types), { service: "cloudbees_ci", q: "build.list", effect: ["read"] }, contextual.services);
    expect(rows.map((row) => [row.contexts, row.resourceLabels])).toEqual([
      [["default"], ["public/job"]], [["internal"], ["private/job"]]
    ]);
    expect(new Set(rows.map((row) => row.key)).size).toBe(2);
    expect(filterAccessRows(rows, { service: "", q: "private/job", effect: ["read"] }, contextual.services)).toEqual([rows[1]]);
  });

  it("restores and clears effect/context URL state while preserving table settings", () => {
    const query = "?context=internal&effect=write&service=cloudbees_ci&sort=action:desc&group=service&q=build";
    expect(readUrlState(ACCESS_STATE, query)).toMatchObject({ context: "internal", effect: ["write"], service: "cloudbees_ci" });
    expect(readUrlState(ACCESS_STATE, "?effect=unknown&effect=write&effect=write&effect=read&effect=unknown").effect).toEqual(["read", "write"]);
    expect(readUrlState(ACCESS_STATE, "?effect=unknown").effect).toEqual([]);
    expect(writeUrlState(ACCESS_STATE, "", { effect: ["write", "read", "write"] }).getAll("effect")).toEqual(["read", "write"]);
    const cleared = writeUrlState(ACCESS_STATE, query, { context: "", effect: [], service: "", q: "", action: "" });
    expect(readUrlState(ACCESS_STATE, cleared)).toMatchObject({ context: "", effect: [], service: "", q: "", sort: { key: "action", dir: "desc" }, group: "service" });
  });

  it("asks for a repository when the target's verification needs one", () => {
    expect(credentialVerificationNeedsRepository(target("gitlab_git", "GitLab Git", ["repository"]))).toBe(true);
    expect(credentialVerificationNeedsRepository(target("jira", "Jira", []))).toBe(false);
  });
});
