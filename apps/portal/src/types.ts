export type ThemeMode = "light" | "dark";

export type TokenTtlPolicy = {
  defaultTtl: string | null;
  maxTtl: string | null;
  options: string[];
};

export type TokenIssuancePolicy = {
  selfAgentInvoke: TokenTtlPolicy;
  administered?: {
    agentInvoke: TokenTtlPolicy;
    userManage: TokenTtlPolicy;
    admin: TokenTtlPolicy;
  };
};

/** Registered resource type id; the broker publishes the registered set as `resourceTypes`. */
export type ResourceType = string;

/** Broker-provided description of a registered resource type. */
export type ResourceTypeMetadata = {
  id: ResourceType;
  label: string;
  pluralLabel: string;
  example: string;
  selectors: string[];
  /** Whether resources of this type may be excluded by resource groups. */
  supportsExclusions: boolean;
  attributes?: ResourceAttributeMetadata[];
  /** Present only when the type accepts namespace selectors. */
  namespace?: { label: string; membersLabel: string; example: string };
  /** The imported service that declares the type. */
  importedService?: string;
  /** Present when the declaring import no longer does: the type accepts no new resources. */
  removed?: true;
};

export type OAuthScopeMode = "explicit" | "server_default";

/** A service consuming a credential connection, as list and target rows name it. */
export type ConnectionConsumer = {
  service: string;
  displayName: string;
  /** Inputs verifying through this service needs besides the credential (a Git gateway: `repository`); empty when none. */
  credentialVerificationInputs: string[];
};

/** One OAuth registration the signed-in user's credential connections use. */
/**
 * What the broker knows about revoking the owner's ended token families of
 * a registration at the provider, most severe of several reported.
 * `not_requested` when nothing was kept for revocation, as for providers the
 * broker cannot revoke tokens at.
 */
export type RemoteRevocation = "not_requested" | "pending" | "revoked" | "failed" | "unconfirmed";
export type OAuthConnectionTarget = {
  registration: string;
  /** The first selecting connection's display name. */
  displayName: string;
  /** What connecting allows, as a consuming service's backend describes it. */
  connectionDescription: string | null;
  /** Consuming services the user may set up through. */
  consumers: ConnectionConsumer[];
  /** Consuming services the connection serves too, which the user is not entitled to. */
  otherConsumers: number;
  /**
   * Null, like `scopeMode` and `target`, on a cleanup-only row for a
   * registration no credential connection selects any more: its consented
   * profile is unknown.
   */
  permissionProfile: string | null;
  scopeMode: OAuthScopeMode | null;
  requestedScopes: string[];
  target: string | null;
  canConnect: boolean;
  connectUnavailableReason: null | "no_personal_access" | "service_unavailable" | "login_binding_required";
  canDisconnect: boolean;
  remoteRevocation: RemoteRevocation;
  connection: null | {
    connectionId: string | null;
    subjectId: string | null;
    displayName: string | null;
    status: "ready" | "reconnect_required" | "operator_action_required" | "disconnected";
    reason: string | null;
    targets: Array<{ id: string; name: string; audience: string; scopes: string[] }>;
  };
};
export type ResourceSelector = { kind: "exact" | "namespace"; value: string } | { kind: "all" };
export type ResourceSelection = { resourceIds: string[]; resourceGroupIds: string[] };
export type ResourceDefinition = {
  id: string; resourceType: ResourceType; selector: ResourceSelector;
  displayName?: string | null; allowedExecutionContexts: string[]; enabled: boolean;
};
export type ResourceAttributeMetadata = { name: string; label: string; description: string; required: boolean; secret: boolean };
/** Who created and last changed a managed catalog entry (catalog management reads; absent from policy catalogs). */
export type CatalogStamp = { createdAt?: string; createdBy?: string; updatedAt?: string; updatedBy?: string };
export type ResourceRecord = ResourceDefinition & CatalogStamp & { version: number; configuredAttributes?: string[] };
export type ResourceGroupRecord = {
  id: string; name: string; includedResourceIds: string[]; excludedResourceIds: string[];
  version: number;
} & CatalogStamp;
export type ResourceGroupSummary = Pick<ResourceGroupRecord, "id" | "name">;
export type ResourceCatalog = { resources: ResourceDefinition[]; resourceGroups: ResourceGroupSummary[] };
export type CatalogMutation<T> = { record: T; previousRevision: { generation: number }; revision: { generation: number } };
export type ResourceWriteBody = Omit<ResourceRecord, "id" | "version" | "configuredAttributes" | keyof CatalogStamp> & { id?: string; expectedVersion?: number; attributes?: Record<string, string> };
export type ResourceGroupWriteBody = Omit<ResourceGroupRecord, "id" | "version" | keyof CatalogStamp> & { id?: string; expectedVersion?: number };

export type AgentTokenOptions = {
  policyGeneration: number;
  resources: ResourceDefinition[];
  resourceGroups: ResourceGroupSummary[];
  executionContexts: string[];
  services: AgentTokenServiceOption[];
  /**
   * The HTTP MCP endpoint that accepts an issued token as `Authorization:
   * Bearer`; null when there is none, or for callers that cannot issue one.
   */
  mcp: AgentTokenMcpEndpoint | null;
};

export type AgentTokenMcpEndpoint = { url: string };

/**
 * A service the principal holds grants for. Display name and broker hosts do
 * not depend on the caller's execution context (unlike agent discovery).
 */
export type AgentTokenServiceOption = {
  service: string;
  displayName: string;
  /** Hosts agents use for a gateway service (e.g. Git over HTTP); empty otherwise. */
  brokerHosts: string[];
  executionContexts: string[];
  actions: AgentTokenActionOption[];
};

export type EffectiveAccessClause = { included: ResourceSelector[]; excluded: ResourceSelector[]; excludedRequests?: EffectiveAccessClause[] };
export type EffectiveResourceAccess = { resourceType: ResourceType; clauses: EffectiveAccessClause[] };
export type EffectiveAccessItem = { service: string; action: string; executionContext: string; resourceType: ResourceType | null; clauses: EffectiveAccessClause[] };
export type EffectiveAccessResult = { policyGeneration: number; access: EffectiveAccessItem[] };
export type GrantEffectiveAccessBody = { service: string; actions: string[]; executionContexts: string[]; resources: ResourceSelection };
export type TokenEffectiveAccessBody = Pick<AgentTokenIssueBody, "allowedServices" | "allowedExecutionContexts" | "serviceRestrictions">;
export type ResourceUsage = { kind: string; id: string; service?: string | null; principalId?: string | null; viaGroupId?: string | null; effect?: string | null };
export type ResourceUsedBy = ResourceUsage[];

export type AgentTokenActionOption = {
  action: string;
  description: string;
  /** True only when the action is explicitly classified read-only. */
  readOnly: boolean;
  requiredScopeTypes: string[];
  executionContexts: string[];
  resourceType: ResourceType | null;
  effectiveAccessByExecutionContext: Record<string, EffectiveAccessClause[]>;
};

export type AgentTokenServiceRestriction = {
  actions: string[];
  resources?: ResourceSelection;
};

export type AgentTokenIssueBody = {
  name: string;
  ttl?: string;
  never?: boolean;
  allowedServices?: string[];
  allowedExecutionContexts: string[];
  serviceRestrictions?: Record<string, AgentTokenServiceRestriction>;
};

export type SignInMethods = {
  localPassword: "absent" | "active" | "disabled";
  microsoft: "absent" | "active" | "disabled";
};

export type Session = {
  signInMethods?: SignInMethods;
  authenticated: boolean;
  principal?: string;
  displayName?: string | null;
  email?: string | null;
  groups?: string[];
  tokenClass?: string;
  loginMethod?: string;
  expiresAt?: string;
  passwordChangeRequired?: boolean;
  role?: PrincipalRole;
  selfServiceEnabled?: boolean;
  policyManagementServices?: string[];
  csrfHeader?: string;
  csrfToken?: string;
  tokenIssuancePolicy?: TokenIssuancePolicy;
  /** Audit uses SQLite and management is enabled: the audit views work. */
  auditQueryable?: boolean;
  returnTo?: string;
  loginOptions?: {
    localPassword?: { enabled: boolean };
    microsoft?: {
      enabled: boolean;
      available: boolean;
      displayName: string;
      startPath: string;
    };
  };
};

export type CredentialInputField = {
  name: string;
  required: boolean;
  secret: boolean;
  prompt: string;
  description?: string;
  inputMethods?: string[];
};

export type CredentialInputPolicy = "token_header" | "http_basic" | "command_stdin";

/** Broker-derived input contract; never a writable credential kind selector. */
export type CredentialInputDescriptor = {
  credentialKind: string;
  inputPolicy?: CredentialInputPolicy;
  fields: CredentialInputField[];
};

export type CredentialInputSchema = CredentialInputDescriptor & {
  connection: string;
  profile: string;
};

/** A token profile (token type) a connection accepts from the principal, with its input form. */
export type CredentialTokenProfile = {
  profile: string;
  /** The name a consuming service declares; show the profile when null. */
  label: string | null;
  credentialKind: string;
  inputSchema: CredentialInputSchema;
};

/** A credential connection whose token the principal can store now. */
export type CredentialTarget = {
  connection: string;
  displayName: string;
  consumers: ConnectionConsumer[];
  otherConsumers: number;
  /** The token profiles the principal may store, in configuration order; never empty. */
  tokenProfiles: CredentialTokenProfile[];
};

/** Lifecycle and verification fields every stored credential has. */
export type CredentialState = {
  credentialId: string;
  ownerPrincipal: string;
  ownerKind: string;
  profile: string;
  credentialKind: string;
  metadata: Record<string, unknown>;
  status: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  updatedBy: string;
  lastUsedAt?: string | null;
  lastVerifiedAt?: string | null;
  verificationStatus?: string | null;
  lastVerificationAttemptAt?: string | null;
  lastVerificationErrorCode?: string | null;
};

/** A stored row with its stored service column and name (retained-row deletes). */
export type CredentialMetadata = CredentialState & { service: string; name: string };

/** The label a consumer of the row's connection declares for its stored profile; show the profile when null. */
type StoredProfileLabel = { label: string | null };

/** A stored row the configuration no longer selects, as the credential list reports it. */
export type RetainedCredential = CredentialMetadata & StoredProfileLabel;

/** A connection's active token, keyed by its connection. */
export type ConnectionCredential = CredentialState &
  StoredProfileLabel & {
    connection: string;
    /** The consumer whose probe answered the latest verification; `null` for a local check. */
    probeService?: string | null;
  };

export type CredentialMethod = "token" | "oauth" | "unavailable";

/** One credential connection of the principal, whatever its method. */
export type CredentialConnection = {
  connection: string;
  displayName: string;
  method: CredentialMethod;
  consumers: ConnectionConsumer[];
  otherConsumers: number;
  /** The token profiles the principal may store, for the token method; empty otherwise. */
  tokenProfiles: CredentialTokenProfile[];
  registration: string | null;
  /** For the OAuth method, as `GET /v1/oauth/connections` reports it. */
  remoteRevocation: RemoteRevocation | null;
  credential: ConnectionCredential | null;
};

/** `GET /v1/credentials`: the caller's connections and the stored rows the configuration no longer selects. */
export type CredentialList = {
  connections: CredentialConnection[];
  retained: RetainedCredential[];
};

export type CredentialVerificationInput = {
  /** The consuming service to verify through. */
  service?: string;
  repository?: string;
};

export type BrokerTokenRecord = {
  tokenId: string;
  principalId: string;
  name: string;
  tokenClass: string;
  scopes: {
    allowedServices?: string[];
    allowedExecutionContexts?: string[];
    serviceRestrictions?: Record<string, AgentTokenServiceRestriction>;
    [key: string]: unknown;
  };
  createdAt: string;
  expiresAt?: string | null;
  pausedAt?: string | null;
  pausedBy?: string | null;
  revokedAt?: string | null;
  revokedBy?: string | null;
  lastUsedAt?: string | null;
  createdBy: string;
};

export type AdminBrokerTokenRecord = BrokerTokenRecord & {
  browserSession: boolean;
};

export type PrincipalRole = "user" | "auditor" | "service_policy_manager" | "admin";

export type PrincipalKind = "user" | "service_account" | "system";

export type PrincipalRecord = {
  signInMethods: SignInMethods;
  principalId: string;
  kind: PrincipalKind;
  displayName?: string | null;
  email?: string | null;
  externalSubject?: string | null;
  status: string;
  groups: string[];
  role: PrincipalRole;
  selfServiceEnabled: boolean;
  createdAt: string;
  updatedAt: string;
  disabledAt?: string | null;
  createdBy: string;
};

export type GroupRecord = {
  groupId: string;
  displayName?: string | null;
  description?: string | null;
  status: string;
  autoEnrollNewMicrosoftUsers: boolean;
  createdAt?: string | null;
  createdBy?: string | null;
  updatedAt?: string | null;
  updatedBy?: string | null;
  disabledAt?: string | null;
  memberCount: number;
};

export type GroupMemberRecord = {
  principalId: string;
  kind?: string | null;
  displayName?: string | null;
  email?: string | null;
  status?: string | null;
  createdAt?: string | null;
  createdBy?: string | null;
  membership?: GroupMembershipProvenance | null;
};

export type ExternalGroupBinding = {
  bindingId: string;
  externalGroupId: string;
  groupId: string;
  status: "active" | "disabled";
  createdAt: string;
  createdBy: string;
  updatedAt: string;
  updatedBy: string;
};

export type GroupMembershipProvenance = {
  groupId: string;
  effective: boolean;
  source: string;
  local: { addedAt: string; addedBy: string } | null;
  microsoft: Array<{
    bindingId: string;
    externalGroupId: string;
    observedAt: string;
    validUntil: string;
    current: boolean;
  }>;
};

export type GroupPolicyReference = {
  grantRef: string;
  writable: boolean;
  grantId?: string | null;
  index?: number | null;
  subjects: string[];
  service: string;
  actions: string[];
  executionContexts: string[];
  credentialMode: string;
  priority?: number | null;
  resources: ResourceSelection;
  status: string;
  description?: string | null;
  version?: number | null;
  updatedAt?: string | null;
  updatedBy?: string | null;
  derivedViaSubjects?: string[];
  derivedViaGroups?: string[];
};

export type PolicyReferenceSection = {
  kind: string;
  title: string;
  subject?: string | null;
  subjectRuntimeEligible: boolean;
  runtimeIneligibleReason?: string | null;
  references: GroupPolicyReference[];
};

export type GroupDetail = GroupRecord & {
  members: GroupMemberRecord[];
  policyReferenceSections: PolicyReferenceSection[];
};

export type PrincipalDetail = PrincipalRecord & {
  groupMemberships: GroupMembershipProvenance[];
  activePolicyGroupSubjects: string[];
  policyReferenceSections: PolicyReferenceSection[];
};

export type LoginMethodRecord = {
  loginMethodId: string;
  principalId: string;
  method: string;
  externalProvider?: string | null;
  externalSubject?: string | null;
  oidc?: {
    provider: "microsoft";
    tenantId: string;
    userObjectId: string;
    /** Group renewal of this Microsoft method; null when it has no renewal record. */
    membershipRenewal: MicrosoftMembershipRenewal | null;
  };
  status: string;
  passwordSetAt?: string | null;
  mustChangePassword: boolean;
  /** Whether any source is currently locked out of this local password. */
  locked: boolean;
  /** Latest active lockout expiry across sources. */
  lockedUntil?: string | null;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  updatedBy: string;
};

export type IssuedBrokerToken = {
  token: string;
  record: BrokerTokenRecord;
};

export type IssuedAdminBrokerToken = {
  token: string;
  record: AdminBrokerTokenRecord;
};

export type IdentitySummary = {
  principal: string;
  groups: string[];
  policyGroups?: string[];
  authenticated: boolean;
  /** Present for a trusted fingerprint identity: whether its access path is read-only. */
  readOnlyAccess?: boolean;
};

/** The limit a caller sees for one visible service on `/v1/me`; no default/override distinction. */
export type SelfServiceLimit = {
  service: string;
  requests: number;
  windowSeconds: number;
};

/** `GET /v1/me`: the caller's identity summary plus their per-service invocation limits. */
export type MeResult = IdentitySummary & {
  serviceLimits: SelfServiceLimit[];
  /** Present when the caller's principal has a Microsoft login method. */
  microsoftMembership?: MicrosoftMembership;
};

/** A renewal record's state; an ended renewal reports why it ended. */
export type MicrosoftMembershipRenewalState = "active" | "retrying" | "blocked" | "sign_in_required" | "not_issued" | "identity_mismatch";

/** Why the latest renewal attempt of a `retrying` or `blocked` record failed. */
export type MicrosoftMembershipRenewalFailureCode =
  | "groups_incomplete"
  | "client_rejected"
  | "request_rejected"
  | "invalid_response"
  | "throttled"
  | "unavailable";

/** Renewal of one Microsoft login method's group evidence. */
export type MicrosoftMembershipRenewal = {
  state: MicrosoftMembershipRenewalState;
  lastRenewedAt: string | null;
  nextAttemptAfter: string | null;
  lastFailure: { code: MicrosoftMembershipRenewalFailureCode; at: string } | null;
};

/** `/v1/me` `microsoftMembership`: the caller's Microsoft group evidence window and its renewal. */
export type MicrosoftMembership = {
  /** When the current Microsoft group evidence expires; null when there is none. */
  validUntil: string | null;
  renewal: MicrosoftMembershipRenewal | null;
};

/** Admin view of a principal's effective limit for one configured service. */
export type ServiceLimit = SelfServiceLimit & {
  /** True when the principal has a managed-store override for this service. */
  overridden: boolean;
};

export type ServiceLimitInput = {
  requests: number;
  windowSeconds: number;
};


export type ConfigReloadAttempt = {
  trigger: string;
  attemptedAt: string;
  decision: string;
  reasonCode?: string | null;
  candidateConfigHash?: string | null;
  previousGeneration: number;
  activeGeneration: number;
  message?: string | null;
};

export type ConfigStatusResult = {
  generation: number;
  configHash: string;
  loadedAt: string;
  identityAuthority: string;
  policyAuthority: string;
  bodyHardCapBytes: number;
  reloadTimeoutMs: number;
  shutdownTimeoutMs: number;
  lastReloadAttempt?: ConfigReloadAttempt | null;
};

export type ConfigReloadResult = ConfigStatusResult & {
  previousGeneration: number;
  previousConfigHash: string;
};

export type PolicyGrantCounts = {
  active: number;
  disabled: number;
  deleted: number;
};

export type PolicyStatusResult = {
  identityAuthority: string;
  policyAuthority: string;
  writable: boolean;
  defaultDecision: string;
  configGeneration: number;
  policyGeneration: number;
  counts: PolicyGrantCounts;
  lastUpdatedAt?: string | null;
  lastUpdatedBy?: string | null;
  managementScope?:
    | { kind: "global" }
    | { kind: "services"; services: string[] };
};

export type ServicePolicyManagerAssignment = {
  assignmentId: string;
  service: string;
  principalId: string;
  displayName?: string | null;
  principalStatus: string;
  serviceConfigured: boolean;
  createdAt: string;
  createdBy: string;
};

export type ServicePolicyManagerDeleteResult = {
  removed: boolean;
};

export type PolicyCatalogSubject = {
  principalId?: string;
  groupId?: string;
  displayName?: string | null;
  status: string;
};

export type PolicyScopeCatalog = { resourceType: ResourceType; selectors: string[] };

export type PolicyActionCatalog = {
  available?: boolean;
  unavailableReason?: string;
  action: string;
  readOnly: boolean;
  description: string;
  requiredScopeTypes: string[];
  /** Explicit live enumeration under this action's own permissions. */
  listingOf?: ResourceType;
  credentialModes: string[];
  lookupRequired: boolean;
  inputSchema: Record<string, unknown>;
  /** A command import's action: whether the Broker or the command checks its resources. */
  resourcesCheckedBy?: ResourcesCheckedBy;
};

/** `broker` checks the resources an action names before it runs; `command` enforces the caller's grants itself. */
export type ResourcesCheckedBy = "broker" | "command";

export type PolicyServiceCatalog = {
  available?: boolean;
  unavailableReason?: string;
  service: string;
  displayName: string;
  surface: string;
  gatewayKind?: string | null;
  brokerHosts?: string[];
  credentialVerificationInputs?: string[];
  actions: PolicyActionCatalog[];
  resourceScopes: Record<string, PolicyScopeCatalog>;
  configuredCredentialModes: string[];
  lookupCredentialConfigured: boolean;
};

export type PolicyCatalogResult = {
  resources: ResourceDefinition[];
  resourceGroups: ResourceGroupRecord[];
  services: PolicyServiceCatalog[];
  executionContexts: {
    allowedValues: string[];
    defaultContext?: string | null;
    contextRequired: boolean;
  };
  subjects: {
    users: PolicyCatalogSubject[];
    groups: PolicyCatalogSubject[];
    anonymous: boolean;
  };
};

export type PolicyGrantRecord = {
  grantRef: string;
  writable: boolean;
  grantId?: string | null;
  index?: number | null;
  grantOrder?: number | null;
  subjects: string[];
  service: string;
  actions: string[];
  executionContexts: string[];
  resources: ResourceSelection;
  credentialMode: string;
  priority?: number | null;
  status: string;
  description?: string | null;
  version?: number | null;
  createdAt?: string | null;
  createdBy?: string | null;
  updatedAt?: string | null;
  updatedBy?: string | null;
  disabledAt?: string | null;
  deletedAt?: string | null;
};

export type PolicyValidationMessage = {
  field: string;
  code: string;
  message: string;
};

export type PolicyValidationResult = {
  valid: boolean;
  errors: PolicyValidationMessage[];
  warnings: PolicyValidationMessage[];
};

export type PolicyGrantWriteBody = {
  grantId?: string;
  expectedVersion?: number;
  subjects?: string[];
  service?: string;
  actions?: string[];
  executionContexts?: string[];
  resources?: ResourceSelection;
  credentialMode?: string;
  priority?: number | null;
  status?: string;
  description?: string | null;
};

export type PolicyMutationResult = {
  previousRevision: {
    generation: number;
    updatedAt: string;
    updatedBy: string;
  };
  revision: {
    generation: number;
    updatedAt: string;
    updatedBy: string;
  };
  grant: ManagedPolicyGrant;
  activeGrants: ManagedPolicyGrant[];
};

/** A managed-store grant as policy mutations return it: identified by `grantId` (its grant reference). */
export type ManagedPolicyGrant = Omit<PolicyGrantRecord, "grantRef" | "writable" | "grantId" | "index"> & { grantId: string };

/** Every human has exactly one identity-token record; `configured` reports whether it stores a secret. */
export type IdentityTokenMetadata = {
  principalId: string;
  configured: boolean;
  enabled: boolean;
  readOnly: boolean;
  revision: number;
  updatedAt: string;
};

/** A partial Enabled/Read-only change to one access path; at least one setting is required. */
export type IdentityPathSettings = {
  enabled?: boolean;
  readOnly?: boolean;
};

export type PrincipalIdentityAccess = {
  principalId: string;
  incarnation: string;
  paused: boolean;
  version: number;
  updatedAt: string;
  updatedBy: string;
};

export type PrincipalUsernameBinding = {
  bindingId: string;
  principalId: string;
  namespace: string;
  username: string;
  enabled: boolean;
  readOnly: boolean;
  version: number;
  createdAt: string;
  createdBy: string;
  updatedAt: string;
  updatedBy: string;
  namespaceAvailable: boolean;
};

export type PrincipalIdentityBindingsResponse = {
  bindings: PrincipalUsernameBinding[];
  configuredNamespaces: {
    namespace: string;
    credentialTransports: ("authorization_user" | "caller_authorization")[];
  }[];
};

/** One stored audit record, exactly as the broker wrote it. Only the fields
 * the viewer reads are typed; everything else stays reachable as JSON. */
export type AuditRecord = {
  auditId: string;
  nodeId: string;
  timestamp: string;
  agentRequestId: string;
  brokerRequestId: string;
  principal: string;
  principalSubject?: string | null;
  groups?: string[];
  service: string;
  action: string;
  resourceScopes?: Record<string, string[]>;
  matchedGrant?: {
    grantId?: string | null;
    configIndex?: number | null;
    grantVersion?: number | null;
    policyGeneration?: number | null;
    subject?: string | null;
    priority?: number | null;
    executionContexts?: string[];
    [key: string]: unknown;
  } | null;
  credentialMode?: string | null;
  decision: "allow" | "deny" | "error";
  reasonCode?: string | null;
  upstreamStatus?: number | null;
  upstreamDurationMs?: number | null;
  objectIds?: unknown;
  identitySource?: {
    name: string;
    type: string;
    tokenClass?: string | null;
    tokenId?: string | null;
    /** Present for attested identities: whether the admitted access path was read-only. */
    readOnlyAccess?: boolean;
    [key: string]: unknown;
  } | null;
  source?: { listener?: string; remote?: string; proxyChain?: string[]; [key: string]: unknown } | null;
  executionContext?: string | null;
  providerAudit?: Record<string, unknown> | null;
  configGeneration?: number | null;
  policyGeneration?: number | null;
  [key: string]: unknown;
};

export type AuditEventsPage = {
  items: AuditRecord[];
  nextCursor: string | null;
};

/** Canonical broker audit actions relevant to this caller's visibility tier. */
export type AuditOptions = {
  services: { service: string; actions: string[] }[];
};

export type AuditRequestTimeline = {
  brokerRequestId: string;
  items: AuditRecord[];
};
