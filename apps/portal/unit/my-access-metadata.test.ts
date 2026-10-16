// My access reads service names, action classifications, and verification
// inputs from the token options and credential connections, never from agent
// discovery (`/v1/services`, filtered by the request's execution context).
import { describe, expect, it } from "vitest";
import { buildAccessSummary, serviceDisplayNames } from "../src/lib/access";
import { accessRows, filterAccessRows, ACCESS_STATE } from "../src/features/access/access-list";
import { credentialVerificationNeedsRepository } from "../src/mutations/credentials";
import { indexResourceTypes } from "../src/lib/resource-types";
import type { AgentTokenOptions, ConnectionConsumer, CredentialConnection } from "../src/types";
import { administeredCredentialList, connectionForService, consumerSummary } from "../src/lib/credentials";
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
  ],
  mcp: null
};

const consumer = (service: string, displayName: string, credentialVerificationInputs: string[]): ConnectionConsumer => ({ service, displayName, credentialVerificationInputs });

const connection = (id: string, consumers: ConnectionConsumer[], otherConsumers = 0): CredentialConnection => ({
  connection: id,
  displayName: id,
  method: "token",
  consumers,
  otherConsumers,
  profile: "token",
  credentialKind: "bearer_token",
  registration: null,
  credential: null
});

describe("My access metadata", () => {
  it("names services from the token options and credential connections, keeping the ID otherwise", () => {
    const names = serviceDisplayNames(options, [connection("jira", [consumer("jira", "Jira", [])]), connection("gitlab", [consumer("gitlab_git", "GitLab Git", ["repository"])])]);
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

  it("asks for a repository when verifying through a consumer needs one", () => {
    expect(credentialVerificationNeedsRepository(consumer("gitlab_git", "GitLab Git", ["repository"]))).toBe(true);
    expect(credentialVerificationNeedsRepository(consumer("jira", "Jira", []))).toBe(false);
  });

  it("finds a service's connection and names its consumers", () => {
    const gitlab = connection("gitlab", [consumer("gitlab", "GitLab REST", []), consumer("gitlab_git", "GitLab Git", ["repository"])], 1);
    const list = { connections: [connection("jira", [consumer("jira", "Jira", [])]), gitlab], retained: [] };
    expect(connectionForService(list, "gitlab_git")).toBe(gitlab);
    expect(connectionForService(list, "confluence")).toBeUndefined();
    expect(consumerSummary(gitlab.consumers, gitlab.otherConsumers)).toBe("GitLab REST, GitLab Git and 1 other service");
    expect(consumerSummary([consumer("jira", "Jira", [])], 0)).toBe("Jira");
    expect(consumerSummary([], 2)).toBe("2 other services");
  });

  it("splits an administered principal's stored rows into active tokens and retained rows", () => {
    const stamp = { ownerPrincipal: "bot", ownerKind: "user", credentialKind: "bearer_token", metadata: {}, status: "active", createdAt: "", updatedAt: "", createdBy: "", updatedBy: "" };
    const target = { connection: "gitlab", displayName: "GitLab", consumers: [consumer("gitlab", "GitLab REST", [])], otherConsumers: 0, profile: "gitlab-access-token", credentialKind: "bearer_token", inputSchema: { connection: "gitlab", profile: "gitlab-access-token", credentialKind: "bearer_token", fields: [] } };
    const active = { ...stamp, credentialId: "active", service: "gitlab", name: "default", profile: "gitlab-access-token" };
    const gitOnly = { ...stamp, credentialId: "git-only", service: "gitlab_git", name: "default", profile: "git-bearer-token" };
    const otherName = { ...stamp, credentialId: "other-name", service: "gitlab", name: "work", profile: "gitlab-access-token" };
    const list = administeredCredentialList([target], [active, gitOnly, otherName]);
    expect(list.connections).toHaveLength(1);
    expect(list.connections[0]!.credential).toMatchObject({ credentialId: "active", connection: "gitlab" });
    expect(list.connections[0]!.credential).not.toHaveProperty("service");
    expect(list.retained.map((row) => row.credentialId)).toEqual(["git-only", "other-name"]);
  });
});
