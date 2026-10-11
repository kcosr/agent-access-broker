import { describe, expect, test } from "vitest";
import type { PrincipalRole, Session } from "../src/types";
import { canViewAdmin, canWriteAdmin, canViewPolicies, canWritePolicies, canUseSelfService, canWriteSubject, capabilityKey, hasPolicyScope } from "../src/lib/capabilities";
import { landingPath, spaceTabs } from "../src/app/spaces";
import { portalRoutes } from "../src/app/router";
import type { RouteObject } from "react-router";
import type { PortalRouteHandle } from "../src/app/spaces";

const roles: PrincipalRole[] = ["user", "auditor", "service_policy_manager", "admin"];
const session = (role: PrincipalRole, selfServiceEnabled: boolean): Session => ({ authenticated: true, principal: "alice", role, selfServiceEnabled, policyManagementServices: role === "service_policy_manager" ? ["jira"] : [], auditQueryable: true });
const routes = (nodes: RouteObject[]): RouteObject[] => nodes.flatMap((node) => [node, ...routes(node.children ?? [])]);

describe("exclusive administrative roles and independent personal management", () => {
  for (const role of roles) for (const enabled of [false, true]) test(`${role}, self-service ${enabled}`, () => {
    const current = session(role, enabled);
    expect(canViewAdmin(current)).toBe(role === "admin" || role === "auditor");
    expect(canWriteAdmin(current)).toBe(role === "admin");
    expect(canViewPolicies(current)).toBe(role !== "user");
    expect(canWritePolicies(current, "jira")).toBe(role === "admin" || role === "service_policy_manager");
    expect(canWritePolicies(current, "other")).toBe(role === "admin");
    expect(canUseSelfService(current)).toBe(enabled);
    expect(canWriteSubject(current, { administered: true, principalId: "alice" })).toBe(role === "admin");
    expect(canWriteSubject(current, { administered: false, principalId: "alice" })).toBe(enabled);
    expect(spaceTabs("self", current).length).toBe(enabled ? 4 : 0);
    expect(landingPath(current)).toBe(role !== "user" ? "/ui/admin/policies" : enabled ? "/ui/access" : "/ui/account");
    for (const path of ["/ui/access", "/ui/tokens", "/ui/credentials", "/ui/activity"]) {
      const route = routes(portalRoutes).find((item) => item.path === path)!;
      expect((route.handle as PortalRouteHandle).allow?.(current)).toBe(enabled);
    }
  });

  test("scope data cannot grant a second role or auditor write privileges", () => {
    for (const role of ["user", "auditor"] as const) {
      expect(canWritePolicies({ ...session(role, true), policyManagementServices: ["jira"] }, "jira")).toBe(false);
    }
  });

  test("signed-out state cannot retain authority from cached account attributes", () => {
    for (const role of roles) {
      const current = { ...session(role, true), authenticated: false };
      expect(canViewAdmin(current)).toBe(false);
      expect(canWriteAdmin(current)).toBe(false);
      expect(canViewPolicies(current)).toBe(false);
      expect(hasPolicyScope(current)).toBe(false);
      expect(canWritePolicies(current, "jira")).toBe(false);
      expect(canUseSelfService(current)).toBe(false);
    }
  });

  test("a scope-less manager has a policy landing page without write or audit authority", () => {
    const current = { ...session("service_policy_manager", false), policyManagementServices: [] };
    expect(spaceTabs("admin", current).map((tab) => tab.key)).toEqual(["policies"]);
    expect(canWritePolicies(current)).toBe(false);
  });

  test("authority changes isolate cached metadata for the same principal", () => {
    expect(capabilityKey(session("admin", true))).not.toBe(capabilityKey(session("auditor", true)));
    expect(capabilityKey(session("auditor", true))).not.toBe(capabilityKey(session("auditor", false)));
  });
});
