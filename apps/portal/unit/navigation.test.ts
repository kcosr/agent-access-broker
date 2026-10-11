import { describe, expect, test } from "vitest";
import type { Session } from "../src/types";
import { isPortalPath, paths, sanitizedUiReturnTo } from "../src/app/paths";
import { hasAdminSpace, landingPath, spaceTabs } from "../src/app/spaces";
import { oidcErrorMessage } from "../src/app/sign-in";

const admin: Session = { role: "admin", selfServiceEnabled: true, authenticated: true, principal: "admin",  auditQueryable: true };
const manager: Session = { role: "service_policy_manager", selfServiceEnabled: true, authenticated: true, principal: "bob", policyManagementServices: ["jira"], auditQueryable: true };
const user: Session = { role: "user", selfServiceEnabled: true, authenticated: true, principal: "alice", auditQueryable: true };

describe("spaces and tabs", () => {
  test("global admins and service policy managers land in Admin; others in My access", () => {
    expect(hasAdminSpace(admin)).toBe(true);
    expect(hasAdminSpace(manager)).toBe(true);
    expect(hasAdminSpace(user)).toBe(false);
    expect(landingPath(admin)).toBe("/ui/admin/policies");
    expect(landingPath(manager)).toBe("/ui/admin/policies");
    expect(landingPath(user)).toBe("/ui/access");
  });

  test("admin tabs follow the role and a queryable audit store", () => {
    expect(spaceTabs("admin", admin).map((tab) => tab.key)).toEqual(["policies", "principals", "catalog", "audit"]);
    expect(spaceTabs("admin", manager).map((tab) => tab.key)).toEqual(["policies", "audit"]);
    expect(spaceTabs("admin", { ...manager, auditQueryable: false }).map((tab) => tab.key)).toEqual(["policies"]);
    expect(spaceTabs("admin", user)).toEqual([]);
  });

  test("My access tabs show Activity only with a queryable audit store", () => {
    expect(spaceTabs("self", user).map((tab) => tab.key)).toEqual(["access", "tokens", "credentials", "activity"]);
    expect(spaceTabs("self", { ...user, auditQueryable: false }).map((tab) => tab.key)).toEqual(["access", "tokens", "credentials"]);
  });
});

describe("portal paths", () => {
  test("recognizes portal pages, including entity pages and their tabs", () => {
    for (const path of ["/ui", "/ui/access", "/ui/admin/principals/alice%40example.test", "/ui/admin/principals/alice/tokens", "/ui/admin/groups/ops/members", "/ui/admin/catalog/services/jira/import", "/ui/admin/policies/new", "/ui/admin/policies/jira-read/edit"]) {
      expect(isPortalPath(path), path).toBe(true);
    }
    for (const path of ["/ui/admin/imports", "/ui/admin/users", "/ui/dashboard", "/ui/admin/audit/requests/x", "/unknown"]) {
      expect(isPortalPath(path), path).toBe(false);
    }
  });

  test("keeps recognized return paths and rejects external or unknown ones", () => {
    expect(sanitizedUiReturnTo("/ui/admin/groups/operators")).toBe("/ui/admin/groups/operators");
    expect(sanitizedUiReturnTo("/ui/tokens")).toBe("/ui/tokens");
    expect(sanitizedUiReturnTo("/ui/login")).toBe("/ui");
    expect(sanitizedUiReturnTo("//example.com/ui")).toBe("/ui");
    expect(sanitizedUiReturnTo("/ui\\example.com")).toBe("/ui");
    expect(sanitizedUiReturnTo("/unknown")).toBe("/ui");
  });

  test("builds entity and tab URLs with encoded identifiers", () => {
    expect(paths.principal("alice@example.test")).toBe("/ui/admin/principals/alice%40example.test");
    expect(paths.principal("alice", "tokens")).toBe("/ui/admin/principals/alice/tokens");
    expect(paths.group("ops team", "members")).toBe("/ui/admin/groups/ops%20team/members");
    expect(paths.catalogService("jira")).toBe("/ui/admin/catalog/services/jira");
    expect(paths.catalogService("jira", "import")).toBe("/ui/admin/catalog/services/jira/import");
    expect(paths.principals("groups", "ops")).toBe("/ui/admin/principals?kind=groups&item=ops");
    expect(paths.grantNew({ subject: "user:alice" })).toBe("/ui/admin/policies/new?subject=user%3Aalice");
  });
});

describe("sign-in errors", () => {
  test("explains Microsoft sign-in failures with the request ID", () => {
    expect(oidcErrorMessage(new URLSearchParams(""))).toBeNull();
    expect(oidcErrorMessage(new URLSearchParams("error=oidc_flow_expired&requestId=req-1"))).toEqual({
      text: "The sign-in attempt expired. Start again.",
      requestId: "req-1"
    });
    expect(oidcErrorMessage(new URLSearchParams("error=something_new"))?.text).toBe("Microsoft sign-in failed (something_new).");
    expect(oidcErrorMessage(new URLSearchParams("error=<script>&requestId=<b>"))).toEqual({ text: "Microsoft sign-in failed.", requestId: null });
  });
});
