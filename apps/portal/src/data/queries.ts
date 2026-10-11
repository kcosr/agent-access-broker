// Per-domain portal queries. Each hook gates itself on the session so a page
// can call it unconditionally; disabled queries still return cached data.
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { brokerApi } from "../api";
import type {
  AdminBrokerTokenRecord,
  AgentTokenOptions,
  BrokerTokenRecord,
  ConfigStatusResult,
  CredentialMetadata,
  CredentialTarget,
  ExternalGroupBinding,
  GroupDetail,
  GroupRecord,
  IdentityTokenMetadata,
  PrincipalIdentityAccess,
  PrincipalIdentityBindingsResponse,
  LoginMethodRecord,
  MeResult,
  OAuthConnectionTarget,
  PolicyCatalogResult,
  PolicyGrantRecord,
  PolicyStatusResult,
  PrincipalDetail,
  PrincipalRecord,
  ResourceTypeMetadata,
  ResourceGroupRecord,
  ResourceRecord,
  ResourceUsedBy,
  ServiceLimit,
  ServicePolicyManagerAssignment,
} from "../types";
import type { ImportListResult, ImportPreviewResult } from "../import-types";
import { portalQueryKeys, viewerKey } from "../lib/portal-queries";
import { indexResourceTypes, NO_RESOURCE_TYPES, type ResourceTypes } from "../lib/resource-types";
import { canViewAdmin, canUseSelfService, hasPolicyScope } from "../lib/capabilities";
import { useSession } from "../app/session";
import type { AccountSubject } from "../app/active-route";

export type ConsoleData = {
  targets: CredentialTarget[];
  credentials: CredentialMetadata[];
  tokens: BrokerTokenRecord[];
};

type AdminUserData = {
  methods: LoginMethodRecord[];
  userTokens: AdminBrokerTokenRecord[];
  userCredentials: CredentialMetadata[];
};

/** Session facts every query gate uses. */
export function useQueryAccess() {
  const { session, runQuery } = useSession();
  const signedIn = session.authenticated && !session.passwordChangeRequired;
  return {
    session,
    runQuery,
    viewer: viewerKey(session),
    signedIn,
    admin: signedIn && canViewAdmin(session),
    selfService: signedIn && canUseSelfService(session),
    policy: signedIn && hasPolicyScope(session)
  };
}

/** Registered resource types only change with the broker build. */
export function useResourceTypesQuery(): ResourceTypes {
  const { viewer, signedIn, runQuery } = useQueryAccess();
  const query = useQuery<ResourceTypeMetadata[], Error, ResourceTypes>({
    queryKey: portalQueryKeys.resourceTypes(viewer),
    enabled: signedIn,
    staleTime: Infinity,
    queryFn: () => runQuery(() => brokerApi.resourceTypes()),
    select: indexResourceTypes
  });
  return query.data ?? NO_RESOURCE_TYPES;
}

/**
 * Credential targets, credentials, and tokens (including revoked and expired
 * ones; views filter by status) for the signed-in user or an administered
 * principal. Service names and action classifications come from the targets
 * and the token options, never from agent discovery (`/v1/services`), which
 * depends on the request's execution context.
 */
export function useConsoleData(subject: AccountSubject, enabled = true) {
  const { viewer, selfService, admin, runQuery } = useQueryAccess();
  const principalId = subject.principalId;
  const self = useQuery<ConsoleData>({
    queryKey: portalQueryKeys.consoleSelf(viewer),
    enabled: enabled && selfService && !subject.administered,
    queryFn: () =>
      runQuery((current) =>
        Promise.all([
          brokerApi.credentialTargets(current),
          brokerApi.credentials(current),
          brokerApi.tokens(current, true, true)
        ]).then(([targets, credentials, tokens]) => ({ targets, credentials, tokens }))
      )
  });
  const managed = useQuery<ConsoleData>({
    queryKey: portalQueryKeys.consoleManaged(viewer, principalId),
    enabled: enabled && admin && subject.administered && Boolean(principalId),
    queryFn: () =>
      runQuery((current) =>
        Promise.all([
          brokerApi.adminPrincipalCredentialTargets(current, principalId),
          brokerApi.adminCredentials(current, principalId),
          brokerApi.adminPrincipalAgentTokens(current, principalId, true, true)
        ]).then(([targets, credentials, tokens]) => ({ targets, credentials, tokens }))
      )
  });
  const query = subject.administered ? managed : self;
  return {
    query,
    targets: query.data?.targets ?? [],
    credentials: query.data?.credentials ?? [],
    tokens: query.data?.tokens ?? [],
    loading: query.isPending && query.fetchStatus !== "idle"
  };
}

/**
 * Token issuance choices for the signed-in user or a managed principal: the
 * granted services (with display names and broker hosts) and actions (with
 * their read-only classification), independent of the request's context.
 */
export function useAgentTokenOptions(subject: AccountSubject, enabled = true) {
  const { viewer, selfService, admin, runQuery } = useQueryAccess();
  const principalId = subject.principalId;
  const self = useQuery<AgentTokenOptions>({
    queryKey: portalQueryKeys.selfAgentTokenOptions(viewer),
    enabled: enabled && selfService && !subject.administered,
    queryFn: () => runQuery((current) => brokerApi.agentTokenOptions(current))
  });
  const managed = useQuery<AgentTokenOptions>({
    queryKey: portalQueryKeys.managedAgentTokenOptions(viewer, principalId),
    enabled: enabled && admin && subject.administered && Boolean(principalId),
    queryFn: () => runQuery((current) => brokerApi.adminPrincipalAgentTokenOptions(current, principalId))
  });
  const query = subject.administered ? managed : self;
  return { query, options: query.data ?? null, loading: query.isPending && query.fetchStatus !== "idle" };
}

/**
 * The signed-in user's own `/v1/me` (per-service limits). Sessions that must
 * change their password are rejected there, and limits can change at any
 * time, so this refetches on every visit.
 */
export function useOwnServiceLimits(enabled: boolean) {
  const { viewer, selfService, runQuery } = useQueryAccess();
  const query = useQuery<MeResult>({
    queryKey: portalQueryKeys.me(viewer),
    enabled: selfService && enabled,
    staleTime: 0,
    queryFn: () => runQuery(() => brokerApi.me())
  });
  return { query, limits: query.data?.serviceLimits ?? null, loading: query.isLoading };
}

export function useAdminPrincipals(enabled = true) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<PrincipalRecord[]>({
    queryKey: portalQueryKeys.adminPrincipals(viewer),
    enabled: admin && enabled,
    placeholderData: keepPreviousData,
    queryFn: () => runQuery((current) => brokerApi.adminPrincipals(current))
  });
}

export function useAdminGroups(enabled = true) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<GroupRecord[]>({
    queryKey: portalQueryKeys.adminGroups(viewer),
    enabled: admin && enabled,
    placeholderData: keepPreviousData,
    queryFn: () => runQuery((current) => brokerApi.adminGroups(current))
  });
}

export function usePolicyStatus(enabled = true) {
  const { viewer, policy, runQuery } = useQueryAccess();
  return useQuery<PolicyStatusResult>({
    queryKey: portalQueryKeys.policyStatus(viewer),
    enabled: policy && enabled,
    placeholderData: keepPreviousData,
    queryFn: () => runQuery((current) => brokerApi.adminPolicyStatus(current))
  });
}

export function usePolicyCatalog(enabled = true) {
  const { viewer, policy, runQuery } = useQueryAccess();
  return useQuery<PolicyCatalogResult>({
    queryKey: portalQueryKeys.policyCatalog(viewer),
    enabled: policy && enabled,
    placeholderData: keepPreviousData,
    queryFn: () => runQuery((current) => brokerApi.adminPolicyCatalog(current))
  });
}

export function usePolicyGrants(enabled = true) {
  const { viewer, policy, runQuery } = useQueryAccess();
  return useQuery<PolicyGrantRecord[]>({
    queryKey: portalQueryKeys.policyGrants(viewer),
    enabled: policy && enabled,
    placeholderData: keepPreviousData,
    queryFn: () => runQuery((current) => brokerApi.adminPolicyGrants(current))
  });
}

/** Deleted grants (the default list omits them); loaded only when a view asks. */
export function useDeletedPolicyGrants(enabled: boolean) {
  const { viewer, policy, runQuery } = useQueryAccess();
  return useQuery<PolicyGrantRecord[]>({
    queryKey: portalQueryKeys.deletedPolicyGrants(viewer),
    enabled: policy && enabled,
    placeholderData: keepPreviousData,
    queryFn: () => runQuery((current) => brokerApi.adminPolicyGrants(current, { status: "deleted" }))
  });
}

export function useServicePolicyManagers(enabled = true) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<ServicePolicyManagerAssignment[]>({
    queryKey: portalQueryKeys.servicePolicyManagers(viewer),
    enabled: admin && enabled,
    placeholderData: keepPreviousData,
    queryFn: () => runQuery((current) => brokerApi.adminServicePolicyManagers(current))
  });
}

export function useConfigStatus(enabled = true) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<ConfigStatusResult>({
    queryKey: portalQueryKeys.configStatus(viewer),
    enabled: admin && enabled,
    placeholderData: keepPreviousData,
    queryFn: () => runQuery((current) => brokerApi.adminConfigStatus(current))
  });
}

/** Identity and policy write authorities; `unknown` while they load. */
export function writeAuthorities(config: ConfigStatusResult | null | undefined, policyStatus?: PolicyStatusResult | null) {
  const identityAuthority = config?.identityAuthority ?? "unknown";
  return {
    identityAuthority,
    groupWritesEnabled: identityAuthority === "managed",
    policyAuthority: policyStatus?.policyAuthority ?? config?.policyAuthority ?? "unknown",
    policyWritesEnabled: Boolean(policyStatus?.writable)
  };
}

export function useAdminPrincipal(principalId: string, enabled = true) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<PrincipalDetail>({
    queryKey: portalQueryKeys.adminPrincipal(viewer, principalId),
    enabled: admin && enabled && Boolean(principalId),
    queryFn: () => runQuery((current) => brokerApi.adminPrincipal(current, principalId))
  });
}

/** Login enrollment must remain available independently of token/credential reads. */
export function useAdminLoginMethods(principalId: string) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<LoginMethodRecord[]>({
    queryKey: [...portalQueryKeys.adminPrincipal(viewer, principalId), "login-methods"],
    enabled: admin && Boolean(principalId),
    queryFn: () => runQuery((current) => brokerApi.adminLoginMethods(current, principalId))
  });
}

/** Login methods, management tokens, and credentials shown on the admin user page. */
export function useAdminUserDetail(principalId: string) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<AdminUserData>({
    queryKey: portalQueryKeys.adminUserDetail(viewer, principalId),
    enabled: admin && Boolean(principalId),
    queryFn: () =>
      runQuery((current) =>
        Promise.all([
          brokerApi.adminLoginMethods(current, principalId),
          brokerApi.adminTokens(current, principalId),
          brokerApi.adminCredentials(current, principalId)
        ]).then(([methods, userTokens, userCredentials]) => ({ methods, userTokens, userCredentials }))
      )
  });
}

export function useAdminGroup(groupId: string) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<GroupDetail>({
    queryKey: portalQueryKeys.adminGroupDetail(viewer, groupId),
    enabled: admin && Boolean(groupId),
    queryFn: () => runQuery((current) => brokerApi.adminGroup(current, groupId))
  });
}

export function useExternalGroupBindings(groupId: string, enabled: boolean) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<ExternalGroupBinding[]>({
    queryKey: portalQueryKeys.adminExternalGroupBindings(viewer, groupId),
    enabled: admin && enabled && Boolean(groupId),
    queryFn: () => runQuery((current) => brokerApi.adminExternalGroupBindings(current, groupId))
  });
}

/** Identity token metadata only; revealed values stay in the mounted view. */
export function useIdentityToken(principalId: string) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<IdentityTokenMetadata>({
    queryKey: portalQueryKeys.identityToken(viewer, principalId),
    enabled: admin && Boolean(principalId),
    queryFn: () => runQuery((current) => brokerApi.adminIdentityToken(current, principalId))
  });
}

export function useIdentityAccess(principalId: string) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<PrincipalIdentityAccess>({
    queryKey: portalQueryKeys.identityAccess(viewer, principalId),
    enabled: admin && Boolean(principalId),
    queryFn: () => runQuery((current) => brokerApi.adminIdentityAccess(current, principalId))
  });
}

export function useIdentityBindings(principalId: string) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<PrincipalIdentityBindingsResponse>({
    queryKey: portalQueryKeys.identityBindings(viewer, principalId),
    enabled: admin && Boolean(principalId),
    queryFn: () => runQuery((current) => brokerApi.adminIdentityBindings(current, principalId))
  });
}

/** Per-principal service limits; fetched only under managed identity authority. */
export function useServiceLimits(principalId: string, enabled: boolean) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<ServiceLimit[]>({
    queryKey: portalQueryKeys.serviceLimits(viewer, principalId),
    enabled: admin && enabled && Boolean(principalId),
    queryFn: () => runQuery((current) => brokerApi.adminServiceLimits(current, principalId))
  });
}

export type ResourceCatalogData = { resources: ResourceRecord[]; resourceGroups: ResourceGroupRecord[] };

/** Full resource and resource-group records (administrators). */
export function useResourceCatalog(enabled = true) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<ResourceCatalogData>({
    queryKey: portalQueryKeys.resourceCatalog(viewer),
    enabled: admin && enabled,
    placeholderData: keepPreviousData,
    queryFn: () =>
      runQuery((current) =>
        Promise.all([brokerApi.resources(current), brokerApi.resourceGroups(current)]).then(([resources, resourceGroups]) => ({ resources, resourceGroups }))
      )
  });
}

export function useResourceUsedBy(kind: "resources" | "resource-groups", id: string, enabled = true) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<ResourceUsedBy>({
    queryKey: portalQueryKeys.resourceUsedBy(viewer, kind, id),
    enabled: admin && enabled && Boolean(id),
    staleTime: 0,
    queryFn: () => runQuery((current) => brokerApi.resourceUsedBy(current, kind, id))
  });
}

export function useImports(enabled = true) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<ImportListResult>({
    queryKey: portalQueryKeys.imports(viewer),
    enabled: admin && enabled,
    placeholderData: keepPreviousData,
    queryFn: () => runQuery((current) => brokerApi.imports(current))
  });
}

export function useImportPreview(service: string, enabled = true) {
  const { viewer, admin, runQuery } = useQueryAccess();
  return useQuery<ImportPreviewResult>({
    queryKey: portalQueryKeys.importPreview(viewer, service),
    enabled: admin && enabled && Boolean(service),
    queryFn: () => runQuery((current) => brokerApi.importPreview(current, service))
  });
}

/** The signed-in user's delegated OAuth connection targets. */
export function useOAuthConnections(enabled = true) {
  const { viewer, selfService, runQuery } = useQueryAccess();
  return useQuery<OAuthConnectionTarget[]>({
    queryKey: portalQueryKeys.oauthConnections(viewer),
    enabled: selfService && enabled,
    queryFn: () => runQuery((current) => brokerApi.oauthConnections(current))
  });
}
