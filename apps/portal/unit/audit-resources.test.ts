import { describe, expect, test } from "vitest";
import type { AuditRecord, Session } from "../src/types";
import { auditEntity, auditEntityCurrentPath, auditEntityName, auditResourceChange, auditResourceCompletionMissing, auditResourcePresentation, auditStoredDisplayName } from "../src/lib/audit-resources";
import { indexResourceTypes } from "../src/lib/resource-types";
import { RESOURCE_TYPES } from "./resource-types.fixture";

const types = indexResourceTypes(RESOURCE_TYPES);
const repository = { kind: "resource", id: "resource-id", displayName: "Payments API", displayNameTruncated: false, resourceType: "git_repository", selector: { kind: "exact", value: "engineering/payments" }, version: 2 };
const group = { kind: "resource_group", id: "group-id", displayName: "Engineering repositories", version: 1 };
function record(phase: string | null = "success", target: unknown = repository, change?: unknown, overrides: Partial<AuditRecord> = {}): AuditRecord {
  return { auditId: "a", nodeId: "test", timestamp: "2026-10-07T12:00:00Z", agentRequestId: "req", brokerRequestId: "request", principal: "alice", service: "broker", action: "admin.policy.resources.create", decision: "allow", providerAudit: { management: { phase, target, change } }, ...overrides };
}
const admin: Session = { authenticated: true, role: "admin" };


describe("recorded resource audit names", () => {
  test("uses recorded name, coverage fallback and explicit absence without catalog enrichment", () => {
    expect(auditEntityName(auditEntity(repository), types)).toBe("Payments API");
    expect(auditEntityName(auditEntity({ ...repository, displayName: " " }), types)).toBe("engineering/payments");
    expect(auditEntityName(auditEntity({ ...repository, displayName: null, selector: { kind: "namespace", value: "engineering" } }), types)).toBe("Repositories under engineering");
    expect(auditEntityName(auditEntity({ ...repository, displayName: null, selector: { kind: "all" } }), types)).toBe("All Git repositories");
    expect(auditEntityName(auditEntity({ kind: "resource", id: "old" }), types)).toBe("Name not recorded");
    expect(auditEntity({ id: "old" })).toBeNull();
    expect(auditEntity({ kind: "unknown", id: "old", displayName: "Untrusted" })).toBeNull();
    expect(auditEntityName(auditEntity({ ...repository, displayName: "<b>支付 API</b>" }), types)).toBe("<b>支付 API</b>");
  });

  test("links are explicit current-ID URLs only for admin readers", () => {
    const resource = auditEntity({ ...repository, id: "a?b&c/#日本語" })!;
    expect(auditEntityCurrentPath(resource, admin)).toBe("/ui/admin/catalog/resources?item=a%3Fb%26c%2F%23%E6%97%A5%E6%9C%AC%E8%AA%9E");
    expect(auditEntityCurrentPath(auditEntity(group)!, { ...admin, role: "auditor" })).toBe("/ui/admin/catalog/resource-groups?item=group-id");
    for (const role of ["user", "service_policy_manager"] as const) expect(auditEntityCurrentPath(resource, { ...admin, role })).toBeNull();
    expect(auditEntityCurrentPath(resource, { ...admin, authenticated: false })).toBeNull();
  });

  test("success, attempted, denied, failed and old missing phases have distinct wording", () => {
    expect(auditResourcePresentation(record(), types)?.summary).toBe("Created Git repository “Payments API”");
    expect(auditResourcePresentation(record("preflight", null), types)?.summary).toBe("Attempt recorded: Create resource");
    expect(auditResourcePresentation(record(null, repository), types)?.outcome.label).toBe("Outcome not recorded");
    expect(auditResourcePresentation(record("preflight", repository, null, { decision: "deny" }), types)?.summary).toMatch(/^Denied: Create/);
    expect(auditResourcePresentation(record(null, repository, null, { decision: "error" }), types)?.summary).toMatch(/^Failed: Create/);
    expect(auditResourcePresentation(record("success", repository, null, { service: "gitlab" }), types)).toBeNull();
    expect(auditResourcePresentation(record("success", repository, null, { action: "admin.policy.resources.get" }), types)).toBeNull();
  });

  test("rename summary preserves both event-time names", () => {
    const after = { ...repository, displayName: "Platform API" };
    const changed = record("success", after, { before: repository, after, changedFields: ["displayName"] }, { action: "admin.policy.resources.patch" });
    expect(auditResourcePresentation(changed, types)?.summary).toBe("Renamed Git repository “Payments API” to “Platform API”");
  });

  test("rename plus coverage names both changes", () => {
    const after = { ...repository, displayName: "Platform API", selector: { kind: "namespace", value: "engineering" } };
    const changed = record("success", after, { before: repository, after, changedFields: ["displayName", "selector"] }, { action: "admin.policy.resources.patch" });
    expect(auditResourcePresentation(changed, types)?.summary).toBe("Renamed Git repository “Payments API” to “Platform API” — changed coverage");
  });

  test("rename plus settings names every accompanying field", () => {
    const before = { ...repository, enabled: true, allowedExecutionContexts: ["default"] };
    const after = { ...before, displayName: "Platform API", resourceType: "cloudbees_ci_job", enabled: false, allowedExecutionContexts: ["external"] };
    const changed = record("success", after, { before, after, changedFields: ["displayName", "enabled", "allowedExecutionContexts", "privateAttributes", "resourceType"] }, { action: "admin.policy.resources.patch" });
    expect(auditResourcePresentation(changed, types)?.summary).toBe("Renamed CloudBees CI job “Payments API” to “Platform API” — changed enabled state, execution contexts, private attributes, resource type");
  });

  test("group rename plus membership retains both the rename and member change", () => {
    const after = { ...group, displayName: "Platform repositories" };
    const changed = record("success", after, { before: group, after, changedFields: ["name", "includedResourceIds"], membership: { includedAdded: { count: 1, items: [repository], truncated: false } } }, { action: "admin.policy.resource_groups.patch" });
    expect(auditResourcePresentation(changed, types)?.summary).toBe("Renamed resource group “Engineering repositories” to “Platform repositories” — Added “Payments API” to “Platform repositories” (included)");
  });

  test.each([
    [{ kind: "namespace", value: "engineering" }, "Repositories under engineering"],
    [{ kind: "all" }, "All Git repositories"]
  ])("unnamed coverage %j is a display label, not a stored name", (selector, label) => {
    const unnamed = { ...repository, displayName: null, selector };
    expect(auditStoredDisplayName(auditEntity(unnamed)!)).toBe("Not set");
    expect(auditEntityName(auditEntity(unnamed), types)).toBe(label);
    expect(auditResourcePresentation(record("success", unnamed), types)?.summary).toBe(`Created Git repository “${label}”`);
    const named = { ...unnamed, displayName: "Payments API" };
    const changed = record("success", named, { before: unnamed, after: named, changedFields: ["displayName"] }, { action: "admin.policy.resources.patch" });
    expect(auditResourcePresentation(changed, types)?.summary).toBe(`Set display name of Git repository “${label}” to “Payments API”`);
  });

  test("clearing a display name never claims the fallback coverage is a new stored name", () => {
    const after = { ...repository, displayName: null };
    const changed = record("success", after, { before: repository, after, changedFields: ["displayName"] }, { action: "admin.policy.resources.patch" });
    expect(auditResourcePresentation(changed, types)?.summary).toBe("Cleared display name of Git repository “Payments API”");
    const change = auditResourceChange(changed)!;
    expect(auditStoredDisplayName(change.before!)).toBe("Payments API");
    expect(auditStoredDisplayName(change.after!)).toBe("Not set");
    expect(auditEntityName(change.after, types)).toBe("engineering/payments");
  });

  test.each([
    ["includedAdded", "Added “Payments API” to “Engineering repositories” (included)"],
    ["includedRemoved", "Removed “Payments API” from “Engineering repositories” (included)"],
    ["excludedAdded", "Excluded “Payments API” from “Engineering repositories”"],
    ["excludedRemoved", "Removed exclusion of “Payments API” from “Engineering repositories”"]
  ])("%s uses the actual recorded membership delta", (key, summary) => {
    const changed = record("success", group, { before: group, after: group, changedFields: [], membership: { [key]: { count: 1, items: [repository], truncated: false } } }, { action: "admin.policy.resource_groups.patch" });
    expect(auditResourcePresentation(changed, types)?.summary).toBe(summary);
  });

  test("bounded names and lists remain visibly partial", () => {
    const entity = auditEntity({ ...repository, displayNameTruncated: true });
    expect(auditEntityName(entity, types)).toBe("Payments API…");
    const changed = record("success", group, { before: group, after: group, changedFields: ["includedResourceIds"], membership: { includedAdded: { count: 51, items: [repository], truncated: true } } }, { action: "admin.policy.resource_groups.patch" });
    expect(auditResourcePresentation(changed, types)?.summary).toContain("Payments API, 50 more");
    expect(auditResourceChange(changed)?.membership.includedAdded).toMatchObject({ count: 51, truncated: true });
  });

  test("only the selected operation's terminal record establishes completion", () => {
    const preflight = record("preflight", null);
    expect(auditResourceCompletionMissing(preflight, [preflight])).toBe(true);
    expect(auditResourceCompletionMissing(preflight, [preflight, record()])).toBe(false);
    expect(auditResourceCompletionMissing(preflight, [preflight, record(null, null, null, { decision: "error" })])).toBe(false);
    expect(auditResourceCompletionMissing(preflight, [preflight, record("success", null, null, { brokerRequestId: "other" })])).toBe(true);
    expect(auditResourceCompletionMissing(preflight, [preflight, record("success", null, null, { action: "tokens.issue" })])).toBe(true);
  });
});
