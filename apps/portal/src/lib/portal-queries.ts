// Query keys shared by every portal query; the hooks live in `data/queries.ts`.
import { capabilityKey } from "./capabilities";
import type { Session } from "../types";

export type PortalQueryRunner = <T>(operation: (currentSession: Session) => Promise<T>) => Promise<T>;

export function viewerKey(session: Session) {
  return session.authenticated ? capabilityKey(session) : "anonymous";
}

const root = ["portal"] as const;
const consoleRoot = [...root, "console"] as const;
const adminRoot = (viewer: string) => [...root, "admin", viewer] as const;
const policyRoot = (viewer: string) => [...adminRoot(viewer), "policy"] as const;

export const portalQueryKeys = {
  root,
  session: [...root, "session"] as const,
  resourceTypes: (viewer: string) => [...root, "resource-types", viewer] as const,
  me: (viewer: string) => [...root, "me", viewer] as const,
  consoleRoot,
  consoleSelf: (viewer: string) => [...consoleRoot, "self", viewer] as const,
  consoleManaged: (viewer: string, principalId: string) => [...consoleRoot, "managed", viewer, principalId] as const,
  agentTokenOptionsRoot: [...consoleRoot, "agent-token-options"] as const,
  selfAgentTokenOptions: (viewer: string) => [...portalQueryKeys.agentTokenOptionsRoot, "self", viewer] as const,
  managedAgentTokenOptions: (viewer: string, principalId: string) =>
    [...portalQueryKeys.agentTokenOptionsRoot, "managed", viewer, principalId] as const,
  adminRoot,
  adminPrincipals: (viewer: string) => [...adminRoot(viewer), "principals"] as const,
  adminPrincipal: (viewer: string, principalId: string) => [...adminRoot(viewer), "principals", principalId] as const,
  adminGroups: (viewer: string) => [...adminRoot(viewer), "groups"] as const,
  adminUserDetail: (viewer: string, principalId: string) => [...adminRoot(viewer), "users", principalId] as const,
  adminGroupDetail: (viewer: string, groupId: string) => [...adminRoot(viewer), "groups", groupId] as const,
  adminExternalGroupBindings: (viewer: string, groupId: string) =>
    [...adminRoot(viewer), "groups", groupId, "external-group-bindings"] as const,
  policyRoot,
  policyStatus: (viewer: string) => [...policyRoot(viewer), "status"] as const,
  policyCatalog: (viewer: string) => [...policyRoot(viewer), "catalog"] as const,
  policyGrants: (viewer: string) => [...policyRoot(viewer), "grants"] as const,
  /** Deleted grants: the broker lists them only when asked by status. */
  deletedPolicyGrants: (viewer: string) => [...policyRoot(viewer), "grants", "deleted"] as const,
  servicePolicyManagers: (viewer: string) => [...policyRoot(viewer), "service-managers"] as const,
  configStatus: (viewer: string) => [...adminRoot(viewer), "config", "status"] as const,
  identityToken: (viewer: string, principalId: string) => [...adminRoot(viewer), "identity-token", principalId] as const,
  identityAccess: (viewer: string, principalId: string) => [...adminRoot(viewer), "identity-access", principalId] as const,
  identityBindings: (viewer: string, principalId: string) => [...adminRoot(viewer), "identity-bindings", principalId] as const,
  serviceLimits: (viewer: string, principalId: string) => [...adminRoot(viewer), "service-limits", principalId] as const,
  imports: (viewer: string) => [...adminRoot(viewer), "imports"] as const,
  importPreview: (viewer: string, service: string) => [...adminRoot(viewer), "import", service] as const,
  resourceCatalog: (viewer: string) => [...adminRoot(viewer), "resource-catalog"] as const,
  resourceUsedBy: (viewer: string, kind: string | undefined, id: string | undefined) => [...adminRoot(viewer), "resource-used-by", kind, id] as const,
  effectiveAccessRoot: [...root, "effective-access"] as const,
  // Audit pages own their queries; each paging session is its own key.
  auditOptions: (viewer: string, scope: "admin" | "self") => [...root, "audit", viewer, scope, "options"] as const,
  auditEvents: (viewer: string, scope: "admin" | "self", session: number, params: Record<string, string>) =>
    [...root, "audit", viewer, scope, "events", session, params] as const,
  auditRequest: (viewer: string, scope: "admin" | "self", brokerRequestId: string) =>
    [...root, "audit", viewer, scope, "requests", brokerRequestId] as const,
  oauthConnections: (viewer: string) => [...root, "oauth-connections", viewer] as const,
  // Under the console root so token changes refresh the Activity token names.
};
