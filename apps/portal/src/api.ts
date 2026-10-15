import type { ImportActionStatus, ImportDefinition, ImportListResult, ImportPreviewResult, ImportPurpose, ImportRecordResult, ImportResourceTypeIds, ImportSelection, ImportServiceStatus, ImportVersions } from "./import-types";
import type { CatalogMutation, ResourceRecord, ResourceGroupRecord, ResourceWriteBody, ResourceGroupWriteBody, ResourceUsedBy, EffectiveAccessResult, GrantEffectiveAccessBody, TokenEffectiveAccessBody } from "./types";
import type {
  IdentityTokenMetadata,
  PrincipalIdentityAccess,
  PrincipalIdentityBindingsResponse,
  PrincipalUsernameBinding,
  MeResult,
  AgentTokenIssueBody,
  AgentTokenOptions,
  AdminBrokerTokenRecord,
  AuditEventsPage,
  AuditOptions,
  AuditRequestTimeline,
  BrokerTokenRecord,
  ConfigReloadResult,
  ConfigStatusResult,
  CredentialInputSchema,
  CredentialMetadata,
  CredentialTarget,
  CredentialVerificationInput,
  GroupDetail,
  ExternalGroupBinding,
  GroupRecord,
  IssuedAdminBrokerToken,
  IssuedBrokerToken,
  LoginMethodRecord,
  PolicyCatalogResult,
  PolicyGrantRecord,
  PolicyGrantWriteBody,
  PolicyMutationResult,
  PolicyStatusResult,
  PolicyValidationResult,
  PrincipalRecord,
  PrincipalRole,
  PrincipalDetail,
  ResourceTypeMetadata,
  ServiceLimit,
  ServiceLimitInput,
  ServicePolicyManagerAssignment,
  ServicePolicyManagerDeleteResult,
  Session,
} from "./types";

type AuthEnvelope<T> = {
  ok: boolean;
  reasonCode?: string;
  requestId?: string;
  brokerRequestId?: string;
  result?: T;
  error?: { message: string };
};

type ManagementEnvelope<T> = {
  ok: boolean;
  decision: string;
  reasonCode?: string;
  requestId: string;
  brokerRequestId: string;
  operation: string;
  principal: string;
  target?: { conflict?: unknown };
  result?: T;
  error?: { message: string };
};

type ResponseEnvelope = {
  ok?: boolean;
  decision?: string;
  reasonCode?: string;
  reason?: string;
  agentRequestId?: string;
  brokerRequestId?: string;
  error?: { message: string };
};

type JsonBody = Record<string, unknown>;

/**
 * Portal pages the broker may return to after an OAuth consent: Credentials,
 * or the imported service's Import tab in Catalog (the broker appends the service).
 */
export type OAuthReturnPath = "/ui/credentials" | "/ui/admin/catalog";

export class ApiError extends Error {
  readonly status: number;
  readonly reasonCode?: string;
  readonly requestId?: string;
  readonly brokerRequestId?: string;
  readonly conflict?: unknown;

  constructor(message: string, status: number, reasonCode?: string, requestId?: string, brokerRequestId?: string, conflict?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.reasonCode = reasonCode;
    this.requestId = requestId;
    this.brokerRequestId = brokerRequestId;
    this.conflict = conflict;
  }
}

function requestId() {
  if (typeof globalThis.crypto?.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  if (typeof globalThis.crypto?.getRandomValues === "function") {
    const bytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
  return `req-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 14)}`;
}

function jsonHeaders(session?: Session, body?: BodyInit | null) {
  const headers = new Headers();
  headers.set("Accept", "application/json");
  headers.set("X-Agent-Access-Request-Id", requestId());
  if (body) {
    headers.set("Content-Type", "application/json");
  }
  if (session?.csrfHeader && session.csrfToken) {
    headers.set(session.csrfHeader, session.csrfToken);
  }
  return headers;
}

async function parseJson<T>(response: Response): Promise<T | null> {
  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError(
      `The broker returned an unreadable response (HTTP ${response.status}). Check the broker or its reverse proxy.`,
      response.status
    );
  }
}

function messageFromEnvelope(body: AuthEnvelope<unknown> | ManagementEnvelope<unknown> | ResponseEnvelope | null) {
  return body?.error?.message ?? (body && "reason" in body ? body.reason : undefined) ?? "Request failed";
}

async function authRequest<T>(path: string, init: RequestInit = {}, session?: Session): Promise<T> {
  const body = init.body ?? null;
  const response = await fetch(path, {
    ...init,
    headers: jsonHeaders(session, body),
    credentials: "same-origin"
  });
  const envelope = await parseJson<AuthEnvelope<T>>(response);
  if (!response.ok || !envelope?.ok || envelope.result === undefined) {
    throw new ApiError(
      messageFromEnvelope(envelope),
      response.status,
      envelope?.reasonCode,
      envelope?.requestId,
      envelope?.brokerRequestId
    );
  }
  return envelope.result;
}

async function managementRequest<T>(path: string, init: RequestInit = {}, session?: Session): Promise<T> {
  const body = init.body ?? null;
  const response = await fetch(path, {
    ...init,
    headers: jsonHeaders(session, body),
    credentials: "same-origin"
  });
  const envelope = await parseJson<ManagementEnvelope<T>>(response);
  if (!response.ok || !envelope?.ok || envelope.result === undefined) {
    throw new ApiError(
      messageFromEnvelope(envelope),
      response.status,
      envelope?.reasonCode,
      envelope?.requestId,
      envelope?.brokerRequestId,
      envelope?.target?.conflict
    );
  }
  return envelope.result;
}

async function discoveryRequest<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    headers: jsonHeaders(),
    credentials: "same-origin"
  });
  const body = await parseJson<T | ResponseEnvelope>(response);
  if (!response.ok) {
    const envelope = body as ResponseEnvelope | null;
    throw new ApiError(
      messageFromEnvelope(envelope),
      response.status,
      envelope?.reasonCode,
      envelope?.agentRequestId,
      envelope?.brokerRequestId
    );
  }
  return body as T;
}

function enc(value: string) {
  return encodeURIComponent(value);
}

function verifyInit(input: CredentialVerificationInput = {}): RequestInit {
  const init: RequestInit = { method: "POST" };
  if (input.repository) {
    init.body = JSON.stringify(input);
  }
  return init;
}

export const brokerApi = {
  imports: (session: Session) => managementRequest<ImportListResult>("/v1/admin/imports", {}, session),
  createImport: (session: Session, definition: ImportDefinition) => managementRequest<ImportRecordResult>("/v1/admin/imports", { method: "POST", body: JSON.stringify(definition) }, session),
  importDetail: (session: Session, service: string) => managementRequest<ImportRecordResult>(`/v1/admin/imports/${enc(service)}`, {}, session),
  updateImport: (session: Session, service: string, body: ImportVersions & { definition: ImportDefinition; confirmAffectedGrants: boolean }) => managementRequest<ImportRecordResult>(`/v1/admin/imports/${enc(service)}`, { method: "PATCH", body: JSON.stringify(body) }, session),
  importPreview: (session: Session, service: string) => managementRequest<ImportPreviewResult>(`/v1/admin/imports/${enc(service)}/preview`, {}, session),
  discoverImport: (session: Session, service: string, versions: ImportVersions) => managementRequest<ImportPreviewResult>(`/v1/admin/imports/${enc(service)}/discover`, { method: "POST", body: JSON.stringify(versions) }, session),
  acceptImport: (session: Session, service: string, body: ImportVersions & { manifestHash: string; selections: ImportSelection[]; confirmAffectedGrants: boolean; resourceTypeIds?: ImportResourceTypeIds }) => managementRequest<ImportRecordResult>(`/v1/admin/imports/${enc(service)}/accept`, { method: "POST", body: JSON.stringify(body) }, session),
  setImportStatus: (session: Session, service: string, body: ImportVersions & { status: Exclude<ImportServiceStatus, "draft">; confirm: boolean }) => managementRequest<ImportRecordResult>(`/v1/admin/imports/${enc(service)}/status`, { method: "POST", body: JSON.stringify(body) }, session),
  setImportActionStatus: (session: Session, service: string, action: string, body: ImportVersions & { status: Exclude<ImportActionStatus, "quarantined">; confirm: boolean }) => managementRequest<ImportRecordResult>(`/v1/admin/imports/${enc(service)}/actions/${enc(action)}/status`, { method: "POST", body: JSON.stringify(body) }, session),
  writeImportToken: (session: Session, service: string, purpose: ImportPurpose, body: ImportVersions & { token: string; username?: string }) => managementRequest<ImportRecordResult>(`/v1/admin/imports/${enc(service)}/credentials/${purpose}`, { method: "PUT", body: JSON.stringify(body) }, session),
  deleteImportToken: (session: Session, service: string, purpose: ImportPurpose, versions: ImportVersions) => managementRequest<ImportRecordResult>(`/v1/admin/imports/${enc(service)}/credentials/${purpose}`, { method: "DELETE", body: JSON.stringify(versions) }, session),
  oauthConnections(session: Session) {
    return managementRequest<import("./types").OAuthConnectionTarget[]>("/v1/oauth/connections", {}, session);
  },
  oauthConnect(session: Session, service: string, intent: "connect" | "reconnect" | "replace_account", returnPath?: OAuthReturnPath) {
    return managementRequest<{ authorizationUrl: string; expiresAt: number }>("/v1/oauth/connect", {
      method: "POST", body: JSON.stringify({ service, intent, returnPath })
    }, session);
  },
  oauthDisconnect(session: Session, service: string) {
    return managementRequest<{ disconnected: boolean }>(`/v1/oauth/connections/${encodeURIComponent(service)}`, { method: "DELETE" }, session);
  },
  resources: (session: Session) => managementRequest<ResourceRecord[]>("/v1/admin/policy/resources", {}, session),
  resourceGroups: (session: Session) => managementRequest<ResourceGroupRecord[]>("/v1/admin/policy/resource-groups", {}, session),
  revealResourceAttribute: (session: Session, id: string, attribute: string) => managementRequest<{ value: string }>(`/v1/admin/policy/resources/${enc(id)}/attributes/${enc(attribute)}/reveal`, { method: "POST", cache: "no-store" }, session),
  saveResource: (session: Session, body: ResourceWriteBody, id?: string) => managementRequest<CatalogMutation<ResourceRecord>>(`/v1/admin/policy/resources${id ? `/${enc(id)}` : ""}`, { method: id ? "PATCH" : "POST", body: JSON.stringify(body) }, session),
  saveResourceGroup: (session: Session, body: ResourceGroupWriteBody, id?: string) => managementRequest<CatalogMutation<ResourceGroupRecord>>(`/v1/admin/policy/resource-groups${id ? `/${enc(id)}` : ""}`, { method: id ? "PATCH" : "POST", body: JSON.stringify(body) }, session),
  resourceUsedBy: (session: Session, kind: "resources" | "resource-groups", id: string) => managementRequest<ResourceUsedBy>(`/v1/admin/policy/${kind}/${enc(id)}/used-by`, {}, session),
  deleteResourceEntry: (session: Session, kind: "resources" | "resource-groups", id: string, expectedVersion: number) => managementRequest<CatalogMutation<null>>(`/v1/admin/policy/${kind}/${enc(id)}?expectedVersion=${expectedVersion}`, { method: "DELETE" }, session),
  grantEffectiveAccess: (session: Session, body: GrantEffectiveAccessBody) => managementRequest<EffectiveAccessResult>("/v1/admin/policy/effective-access", { method: "POST", body: JSON.stringify(body) }, session),
  tokenEffectiveAccess: (session: Session, body: TokenEffectiveAccessBody, principalId?: string) => managementRequest<EffectiveAccessResult>(principalId ? `/v1/admin/principals/${enc(principalId)}/agent-token-effective-access` : "/v1/tokens/effective-access", { method: "POST", body: JSON.stringify(body) }, session),
  session: () => authRequest<Session>("/v1/auth/session"),
  login: (principalId: string, password: string, returnTo: string) =>
    authRequest<Session>("/v1/auth/local/login", {
      method: "POST",
      body: JSON.stringify({ principalId, password, returnTo })
    }),
  changePassword: (session: Session, currentPassword: string, newPassword: string) =>
    authRequest<Session>(
      "/v1/auth/local/password/change",
      {
        method: "POST",
        body: JSON.stringify({ currentPassword, newPassword })
      },
      session
    ),
  logout: (session: Session) => authRequest<Session>("/v1/auth/logout", { method: "POST" }, session),
  me: () => discoveryRequest<MeResult>("/v1/me"),
  // The runtime spec catalog describes every registered resource type to any
  // signed-in caller; the admin policy catalog carries the same list.
  resourceTypes: () =>
    discoveryRequest<{ resourceTypes: ResourceTypeMetadata[] }>("/v1/resource-types").then((result) => result.resourceTypes),
  credentialTargets: (session: Session) => managementRequest<CredentialTarget[]>("/v1/credentials/targets", {}, session),
  credentials: (session: Session) => managementRequest<CredentialMetadata[]>("/v1/credentials", {}, session),
  credentialSchema: (session: Session, service: string, name: string, profile: string) =>
    managementRequest<CredentialInputSchema>(
      `/v1/credentials/${enc(service)}/${enc(name)}/input-schema?profile=${enc(profile)}`,
      {},
      session
    ),
  saveCredential: (
    session: Session,
    service: string,
    name: string,
    profile: string,
    secret: JsonBody
  ) =>
    managementRequest<CredentialMetadata>(
      `/v1/credentials/${enc(service)}/${enc(name)}`,
      {
        method: "PUT",
        body: JSON.stringify({ profile, secret, metadata: {} })
      },
      session
    ),
  verifyCredential: (session: Session, service: string, name: string, input?: CredentialVerificationInput) =>
    managementRequest<CredentialMetadata>(
      `/v1/credentials/${enc(service)}/${enc(name)}/verify`,
      verifyInit(input),
      session
    ),
  deleteCredential: (session: Session, service: string, name: string) =>
    managementRequest<CredentialMetadata>(
      `/v1/credentials/${enc(service)}/${enc(name)}`,
      { method: "DELETE" },
      session
    ),
  tokens: (session: Session, includeRevoked: boolean, includeExpired: boolean) => {
    const params = new URLSearchParams();
    if (includeRevoked) params.set("includeRevoked", "true");
    if (includeExpired) params.set("includeExpired", "true");
    const query = params.toString();
    return managementRequest<BrokerTokenRecord[]>(`/v1/tokens${query ? `?${query}` : ""}`, {}, session);
  },
  agentTokenOptions: (session: Session) =>
    managementRequest<AgentTokenOptions>("/v1/tokens/options", {}, session),
  issueToken: (
    session: Session,
    body: AgentTokenIssueBody
  ) =>
    managementRequest<IssuedBrokerToken>(
      "/v1/tokens",
      {
        method: "POST",
        body: JSON.stringify(body)
      },
      session
    ),
  inspectToken: (session: Session, tokenId: string) =>
    managementRequest<BrokerTokenRecord>(`/v1/tokens/${enc(tokenId)}`, {}, session),
  revokeToken: (session: Session, tokenId: string) =>
    managementRequest<BrokerTokenRecord>(`/v1/tokens/${enc(tokenId)}`, { method: "DELETE" }, session),
  pauseToken: (session: Session, tokenId: string) =>
    managementRequest<BrokerTokenRecord>(`/v1/tokens/${enc(tokenId)}/pause`, { method: "POST" }, session),
  resumeToken: (session: Session, tokenId: string) =>
    managementRequest<BrokerTokenRecord>(`/v1/tokens/${enc(tokenId)}/resume`, { method: "POST" }, session),
  adminPrincipals: (session: Session) =>
    managementRequest<PrincipalRecord[]>("/v1/admin/principals", {}, session),
  adminGroups: (session: Session) => managementRequest<GroupRecord[]>("/v1/admin/groups", {}, session),
  adminGroup: (session: Session, groupId: string) =>
    managementRequest<GroupDetail>(`/v1/admin/groups/${enc(groupId)}`, {}, session),
  adminExternalGroupBindings: (session: Session, groupId: string) =>
    managementRequest<ExternalGroupBinding[]>(
      `/v1/admin/groups/${enc(groupId)}/external-group-bindings`,
      {},
      session
    ),
  adminCreateExternalGroupBinding: (session: Session, groupId: string, externalGroupId: string) =>
    managementRequest<ExternalGroupBinding>(
      `/v1/admin/groups/${enc(groupId)}/external-group-bindings`,
      { method: "POST", body: JSON.stringify({ externalGroupId }) },
      session
    ),
  adminPatchExternalGroupBinding: (
    session: Session,
    groupId: string,
    bindingId: string,
    status: "active" | "disabled"
  ) =>
    managementRequest<ExternalGroupBinding>(
      `/v1/admin/groups/${enc(groupId)}/external-group-bindings/${enc(bindingId)}`,
      { method: "PATCH", body: JSON.stringify({ status }) },
      session
    ),
  adminDeleteExternalGroupBinding: (session: Session, groupId: string, bindingId: string) =>
    managementRequest<{ deleted: boolean }>(
      `/v1/admin/groups/${enc(groupId)}/external-group-bindings/${enc(bindingId)}`,
      { method: "DELETE" },
      session
    ),
  adminCreateGroup: (
    session: Session,
    body: { groupId: string; displayName?: string; description?: string }
  ) =>
    managementRequest<GroupRecord>(
      "/v1/admin/groups",
      {
        method: "POST",
        body: JSON.stringify(body)
      },
      session
    ),
  adminPatchGroup: (
    session: Session,
    groupId: string,
    body: { displayName?: string | null; description?: string | null; status?: string }
  ) =>
    managementRequest<GroupRecord>(
      `/v1/admin/groups/${enc(groupId)}`,
      {
        method: "PATCH",
        body: JSON.stringify(body)
      },
      session
    ),
  adminAddGroupMember: (session: Session, groupId: string, principalId: string) =>
    managementRequest<{ ok: boolean }>(
      `/v1/admin/groups/${enc(groupId)}/members/${enc(principalId)}`,
      { method: "PUT" },
      session
    ),
  adminRemoveGroupMember: (session: Session, groupId: string, principalId: string) =>
    managementRequest<{ removed: boolean; effectiveMembershipRemains: boolean }>(
      `/v1/admin/groups/${enc(groupId)}/members/${enc(principalId)}`,
      { method: "DELETE" },
      session
    ),
  adminConfigStatus: (session: Session) =>
    managementRequest<ConfigStatusResult>("/v1/admin/config/status", {}, session),
  adminConfigReload: (session: Session) =>
    managementRequest<ConfigReloadResult>(
      "/v1/admin/config/reload",
      { method: "POST" },
      session
    ),
  adminPrincipal: (session: Session, principalId: string) =>
    managementRequest<PrincipalDetail>(`/v1/admin/principals/${enc(principalId)}`, {}, session),
  adminCreatePrincipal: (
    session: Session,
    body: { principalId: string; kind?: "user" | "service_account"; displayName?: string; email?: string; role?: PrincipalRole; selfServiceEnabled?: boolean }
  ) =>
    managementRequest<PrincipalRecord>(
      "/v1/admin/principals",
      {
        method: "POST",
        body: JSON.stringify(body)
      },
      session
    ),
  adminIdentityToken: (session: Session, principalId: string) =>
    managementRequest<IdentityTokenMetadata>(`/v1/admin/principals/${enc(principalId)}/identity-token`, { cache: "no-store" }, session),
  adminRevealIdentityToken: (session: Session, principalId: string) =>
    managementRequest<{ token: string }>(`/v1/admin/principals/${enc(principalId)}/identity-token/reveal`, { method: "POST", cache: "no-store" }, session),
  adminSetIdentityToken: (session: Session, principalId: string, token: string) =>
    managementRequest<IdentityTokenMetadata>(`/v1/admin/principals/${enc(principalId)}/identity-token`, { method: "PUT", body: JSON.stringify({ token }) }, session),
  adminIdentityTokenAction: (session: Session, principalId: string, action: "generate" | "remove") =>
    managementRequest<IdentityTokenMetadata>(`/v1/admin/principals/${enc(principalId)}/identity-token${action === "remove" ? "" : `/${action}`}`, { method: action === "remove" ? "DELETE" : "POST" }, session),
  adminIdentityAccess: (session: Session, principalId: string) =>
    managementRequest<PrincipalIdentityAccess>(`/v1/admin/principals/${enc(principalId)}/identity-access`, { cache: "no-store" }, session),
  adminSetIdentityAccess: (session: Session, principalId: string, body: { paused: boolean; expectedVersion: number }) =>
    managementRequest<PrincipalIdentityAccess>(`/v1/admin/principals/${enc(principalId)}/identity-access`, { method: "PATCH", body: JSON.stringify(body) }, session),
  adminIdentityBindings: (session: Session, principalId: string) =>
    managementRequest<PrincipalIdentityBindingsResponse>(`/v1/admin/principals/${enc(principalId)}/identity-bindings`, { cache: "no-store" }, session),
  adminCreateIdentityBinding: (session: Session, principalId: string, body: { namespace: string; username: string }) =>
    managementRequest<PrincipalUsernameBinding>(`/v1/admin/principals/${enc(principalId)}/identity-bindings`, { method: "POST", body: JSON.stringify(body) }, session),
  adminSetIdentityBinding: (session: Session, principalId: string, bindingId: string, body: { enabled: boolean; expectedVersion: number }) =>
    managementRequest<PrincipalUsernameBinding>(`/v1/admin/principals/${enc(principalId)}/identity-bindings/${enc(bindingId)}`, { method: "PATCH", body: JSON.stringify(body) }, session),
  adminDeleteIdentityBinding: (session: Session, principalId: string, bindingId: string, expectedVersion: number) =>
    managementRequest<{ deleted: true }>(`/v1/admin/principals/${enc(principalId)}/identity-bindings/${enc(bindingId)}?expectedVersion=${expectedVersion}`, { method: "DELETE" }, session),
  adminServiceLimits: (session: Session, principalId: string) =>
    managementRequest<ServiceLimit[]>(`/v1/admin/principals/${enc(principalId)}/service-limits`, {}, session),
  adminSetServiceLimit: (session: Session, principalId: string, service: string, limit: ServiceLimitInput) =>
    managementRequest<ServiceLimit>(
      `/v1/admin/principals/${enc(principalId)}/service-limits/${enc(service)}`,
      { method: "PUT", body: JSON.stringify({ requests: limit.requests, windowSeconds: limit.windowSeconds }) },
      session
    ),
  adminClearServiceLimit: (session: Session, principalId: string, service: string) =>
    managementRequest<ServiceLimit>(
      `/v1/admin/principals/${enc(principalId)}/service-limits/${enc(service)}`,
      { method: "DELETE" },
      session
    ),
  adminPatchPrincipal: (
    session: Session,
    principalId: string,
    body: { displayName?: string | null; email?: string | null; status?: string }
  ) =>
    managementRequest<PrincipalRecord>(
      `/v1/admin/principals/${enc(principalId)}`,
      {
        method: "PATCH",
        body: JSON.stringify(body)
      },
      session
    ),
  adminSetAccess: (session: Session, principalId: string, body: { role?: PrincipalRole; selfServiceEnabled?: boolean }) =>
    managementRequest<PrincipalRecord>(`/v1/admin/principals/${enc(principalId)}/access`, { method: "PATCH", body: JSON.stringify(body) }, session),
  adminAddGroup: (session: Session, principalId: string, group: string) =>
    managementRequest<{ ok: boolean }>(
      `/v1/admin/principals/${enc(principalId)}/groups/${enc(group)}`,
      { method: "PUT" },
      session
    ),
  adminRemoveGroup: (session: Session, principalId: string, group: string) =>
    managementRequest<{ removed: boolean; effectiveMembershipRemains: boolean }>(
      `/v1/admin/principals/${enc(principalId)}/groups/${enc(group)}`,
      { method: "DELETE" },
      session
    ),
  adminLoginMethods: (session: Session, principalId: string) =>
    managementRequest<LoginMethodRecord[]>(
      `/v1/admin/principals/${enc(principalId)}/login-methods`,
      {},
      session
    ),
  adminResetLocalPassword: (session: Session, principalId: string, password: string, mustChangePassword = true) =>
    managementRequest<LoginMethodRecord>(
      `/v1/admin/principals/${enc(principalId)}/login-methods/local-password`,
      {
        method: "PUT",
        body: JSON.stringify({ password, mustChangePassword })
      },
      session
    ),
  adminEnableLocalPassword: (session: Session, principalId: string, password: string, mustChangePassword = true) =>
    managementRequest<LoginMethodRecord>(
      `/v1/admin/principals/${enc(principalId)}/login-methods/local-password/enable`,
      { method: "POST", body: JSON.stringify({ password, mustChangePassword, acknowledgeSeparateSignIn: true }) },
      session
    ),
  adminDisableLocalPassword: (session: Session, principalId: string) =>
    managementRequest<LoginMethodRecord>(
      `/v1/admin/principals/${enc(principalId)}/login-methods/local-password`,
      { method: "DELETE" },
      session
    ),
  adminLinkMicrosoftLogin: (session: Session, principalId: string, userObjectId: string) =>
    managementRequest<LoginMethodRecord>(
      `/v1/admin/principals/${enc(principalId)}/login-methods/oidc/microsoft`,
      { method: "PUT", body: JSON.stringify({ userObjectId }) },
      session
    ),
  adminUnlinkMicrosoftLogin: (session: Session, principalId: string) =>
    managementRequest<{ unlinked: boolean }>(
      `/v1/admin/principals/${enc(principalId)}/login-methods/oidc/microsoft`,
      { method: "DELETE" },
      session
    ),
  adminUnlockLocalPassword: (session: Session, principalId: string) =>
    managementRequest<LoginMethodRecord>(
      `/v1/admin/principals/${enc(principalId)}/login-methods/local-password/unlock`,
      { method: "POST" },
      session
    ),
  adminTokens: (session: Session, principalId?: string) => {
    const query = principalId ? `?principal=${enc(principalId)}` : "";
    return managementRequest<AdminBrokerTokenRecord[]>(`/v1/admin/tokens${query}`, {}, session);
  },
  adminPrincipalIssueToken: (
    session: Session,
    principalId: string,
    body: { name: string; tokenClass: "user_manage" | "admin"; ttl: string; scopes: Record<string, never> }
  ) =>
    managementRequest<IssuedAdminBrokerToken>(
      `/v1/admin/principals/${enc(principalId)}/tokens`,
      {
        method: "POST",
        body: JSON.stringify(body)
      },
      session
    ),
  adminToken: (session: Session, tokenId: string) =>
    managementRequest<AdminBrokerTokenRecord>(`/v1/admin/tokens/${enc(tokenId)}`, {}, session),
  adminRevokeToken: (session: Session, tokenId: string) =>
    managementRequest<AdminBrokerTokenRecord>(
      `/v1/admin/tokens/${enc(tokenId)}`,
      { method: "DELETE" },
      session
    ),
  adminPrincipalCredentialTargets: (session: Session, principalId: string) =>
    managementRequest<CredentialTarget[]>(
      `/v1/admin/principals/${enc(principalId)}/credentials/targets`,
      {},
      session
    ),
  adminPrincipalSaveCredential: (
    session: Session,
    principalId: string,
    service: string,
    name: string,
    profile: string,
    secret: JsonBody
  ) =>
    managementRequest<CredentialMetadata>(
      `/v1/admin/principals/${enc(principalId)}/credentials/${enc(service)}/${enc(name)}`,
      {
        method: "PUT",
        body: JSON.stringify({ profile, secret, metadata: {} })
      },
      session
    ),
  adminPrincipalVerifyCredential: (
    session: Session,
    principalId: string,
    service: string,
    name: string,
    input?: CredentialVerificationInput
  ) =>
    managementRequest<CredentialMetadata>(
      `/v1/admin/principals/${enc(principalId)}/credentials/${enc(service)}/${enc(name)}/verify`,
      verifyInit(input),
      session
    ),
  adminPrincipalDeleteCredential: (session: Session, principalId: string, service: string, name: string) =>
    managementRequest<CredentialMetadata>(
      `/v1/admin/principals/${enc(principalId)}/credentials/${enc(service)}/${enc(name)}`,
      { method: "DELETE" },
      session
    ),
  adminPrincipalAgentTokens: (session: Session, principalId: string, includeRevoked: boolean, includeExpired: boolean) => {
    const params = new URLSearchParams();
    if (includeRevoked) params.set("includeRevoked", "true");
    if (includeExpired) params.set("includeExpired", "true");
    const query = params.toString();
    return managementRequest<BrokerTokenRecord[]>(
      `/v1/admin/principals/${enc(principalId)}/agent-tokens${query ? `?${query}` : ""}`,
      {},
      session
    );
  },
  adminPrincipalAgentTokenOptions: (session: Session, principalId: string) =>
    managementRequest<AgentTokenOptions>(
      `/v1/admin/principals/${enc(principalId)}/agent-token-options`,
      {},
      session
    ),
  adminPrincipalIssueAgentToken: (
    session: Session,
    principalId: string,
    body: AgentTokenIssueBody
  ) =>
    managementRequest<IssuedBrokerToken>(
      `/v1/admin/principals/${enc(principalId)}/agent-tokens`,
      {
        method: "POST",
        body: JSON.stringify(body)
      },
      session
    ),
  adminPrincipalInspectAgentToken: (session: Session, principalId: string, tokenId: string) =>
    managementRequest<BrokerTokenRecord>(
      `/v1/admin/principals/${enc(principalId)}/agent-tokens/${enc(tokenId)}`,
      {},
      session
    ),
  adminPrincipalRevokeAgentToken: (session: Session, principalId: string, tokenId: string) =>
    managementRequest<BrokerTokenRecord>(
      `/v1/admin/principals/${enc(principalId)}/agent-tokens/${enc(tokenId)}`,
      { method: "DELETE" },
      session
    ),
  adminPrincipalPauseAgentToken: (session: Session, principalId: string, tokenId: string) =>
    managementRequest<BrokerTokenRecord>(
      `/v1/admin/principals/${enc(principalId)}/agent-tokens/${enc(tokenId)}/pause`,
      { method: "POST" },
      session
    ),
  adminPrincipalResumeAgentToken: (session: Session, principalId: string, tokenId: string) =>
    managementRequest<BrokerTokenRecord>(
      `/v1/admin/principals/${enc(principalId)}/agent-tokens/${enc(tokenId)}/resume`,
      { method: "POST" },
      session
    ),
  adminCredentials: (session: Session, principalId?: string) => {
    const query = principalId ? `?principal=${enc(principalId)}` : "";
    return managementRequest<CredentialMetadata[]>(`/v1/admin/credentials${query}`, {}, session);
  },
  adminPolicyStatus: (session: Session) =>
    managementRequest<PolicyStatusResult>("/v1/admin/policy/status", {}, session),
  adminPolicyCatalog: (session: Session) =>
    managementRequest<PolicyCatalogResult>("/v1/admin/policy/catalog", {}, session),
  adminServicePolicyManagers: (session: Session, service?: string) => {
    const params = new URLSearchParams();
    if (service) params.set("service", service);
    const query = params.toString();
    return managementRequest<ServicePolicyManagerAssignment[]>(
      `/v1/admin/policy/service-managers${query ? `?${query}` : ""}`,
      {},
      session
    );
  },
  adminGrantServicePolicyManager: (
    session: Session,
    service: string,
    principalId: string
  ) =>
    managementRequest<ServicePolicyManagerAssignment>(
      `/v1/admin/policy/services/${enc(service)}/managers/${enc(principalId)}`,
      { method: "PUT" },
      session
    ),
  adminRevokeServicePolicyManager: (
    session: Session,
    service: string,
    principalId: string
  ) =>
    managementRequest<ServicePolicyManagerDeleteResult>(
      `/v1/admin/policy/services/${enc(service)}/managers/${enc(principalId)}`,
      { method: "DELETE" },
      session
    ),
  adminPolicyGrants: (
    session: Session,
    filters: { subject?: string; service?: string; executionContext?: string; status?: string } = {}
  ) => {
    const params = new URLSearchParams();
    if (filters.subject) params.set("subject", filters.subject);
    if (filters.service) params.set("service", filters.service);
    if (filters.executionContext) params.set("executionContext", filters.executionContext);
    if (filters.status) params.set("status", filters.status);
    const query = params.toString();
    return managementRequest<PolicyGrantRecord[]>(
      `/v1/admin/policy/grants${query ? `?${query}` : ""}`,
      {},
      session
    );
  },
  adminPolicyGrant: (session: Session, grantRef: string) =>
    managementRequest<PolicyGrantRecord>(`/v1/admin/policy/grants/${enc(grantRef)}`, {}, session),
  adminCreatePolicyGrant: (session: Session, body: PolicyGrantWriteBody) =>
    managementRequest<PolicyMutationResult>(
      "/v1/admin/policy/grants",
      {
        method: "POST",
        body: JSON.stringify(body)
      },
      session
    ),
  adminPatchPolicyGrant: (session: Session, grantRef: string, body: PolicyGrantWriteBody) =>
    managementRequest<PolicyMutationResult>(
      `/v1/admin/policy/grants/${enc(grantRef)}`,
      {
        method: "PATCH",
        body: JSON.stringify(body)
      },
      session
    ),
  adminValidatePolicyGrant: (session: Session, body: PolicyGrantWriteBody) =>
    managementRequest<PolicyValidationResult>(
      "/v1/admin/policy/grants/validate",
      {
        method: "POST",
        body: JSON.stringify(body)
      },
      session
    ),
  adminEnablePolicyGrant: (session: Session, grantRef: string, expectedVersion: number) =>
    managementRequest<PolicyMutationResult>(
      `/v1/admin/policy/grants/${enc(grantRef)}/enable`,
      {
        method: "POST",
        body: JSON.stringify({ expectedVersion })
      },
      session
    ),
  adminDisablePolicyGrant: (session: Session, grantRef: string, expectedVersion: number) =>
    managementRequest<PolicyMutationResult>(
      `/v1/admin/policy/grants/${enc(grantRef)}/disable`,
      {
        method: "POST",
        body: JSON.stringify({ expectedVersion })
      },
      session
    ),
  adminAddPolicyGrantSubject: (
    session: Session,
    grantRef: string,
    expectedVersion: number,
    subject: string
  ) =>
    managementRequest<PolicyMutationResult>(
      `/v1/admin/policy/grants/${enc(grantRef)}/subjects`,
      {
        method: "POST",
        body: JSON.stringify({ expectedVersion, subject })
      },
      session
    ),
  adminRemovePolicyGrantSubject: (
    session: Session,
    grantRef: string,
    expectedVersion: number,
    subject: string,
    lastSubjectBehavior: "reject" | "disable_grant" = "reject"
  ) =>
    managementRequest<PolicyMutationResult>(
      `/v1/admin/policy/grants/${enc(grantRef)}/subjects/remove`,
      {
        method: "POST",
        body: JSON.stringify({ expectedVersion, subject, lastSubjectBehavior })
      },
      session
    ),
  adminDeletePolicyGrant: (session: Session, grantRef: string, expectedVersion: number) =>
    managementRequest<PolicyMutationResult>(
      `/v1/admin/policy/grants/${enc(grantRef)}?expectedVersion=${enc(String(expectedVersion))}`,
      { method: "DELETE" },
      session
    ),
  auditOptions: (session: Session, scope: "admin" | "self") =>
    managementRequest<AuditOptions>(scope === "admin" ? "/v1/admin/audit/options" : "/v1/audit/options", {}, session),
  /** One page of audit records. `params` are sent as given: callers omit empty filters. */
  auditEvents: (session: Session, scope: "admin" | "self", params: Record<string, string>) => {
    const query = new URLSearchParams(params).toString();
    const base = scope === "admin" ? "/v1/admin/audit/events" : "/v1/audit/events";
    return managementRequest<AuditEventsPage>(`${base}${query ? `?${query}` : ""}`, {}, session);
  },
  auditRequest: (session: Session, scope: "admin" | "self", brokerRequestId: string) =>
    managementRequest<AuditRequestTimeline>(
      `${scope === "admin" ? "/v1/admin/audit/requests" : "/v1/audit/requests"}/${enc(brokerRequestId)}`,
      {},
      session
    )
};
