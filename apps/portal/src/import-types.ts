import type { OAuthScopeMode } from "./types";

/** Secret-free import metadata. Token values exist only in write request bodies. */
export type ImportOwnerMode = "service" | "per_user";
export type ImportPurpose = "execution" | "discovery" | "transport";
export type ImportServiceStatus = "draft" | "disabled" | "enabled" | "retired";
export type ImportActionStatus = "enabled" | "disabled" | "quarantined" | "retired";
export type ImportDelivery = { kind: "bearer" } | { kind: "raw_header"; name: string };
export type ImportBinding = {
  ownerMode: ImportOwnerMode;
  mechanism: "static_token" | "oauth";
  delivery: ImportDelivery;
  status: "configured" | "unsupported";
  adapterId?: string;
  registrationId?: string;
  profile?: string;
};
export type ImportDefinition = {
  service: string;
  displayName: string;
  adapterKind: string;
  endpoint: string;
  connectionSettings: Record<string, string>;
  executionBindings: ImportBinding[];
  discovery: { kind: "anonymous" } | { kind: "execution" } | { kind: "slot" } | { kind: "per_user"; principal: string };
  transportAuth: boolean;
  invocationLimit?: { requests: number; windowSeconds: number };
};
export type ImportActionDefinition = {
  action: string;
  source: Record<string, unknown>;
  label?: string | null;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema?: unknown;
  annotations: unknown;
  readOnly: boolean;
};
export type ImportActionRecord = {
  definition: ImportActionDefinition;
  status: ImportActionStatus;
  version: number;
  definitionHash: string;
};
export type ImportedServiceRecord = {
  definition: ImportDefinition;
  status: ImportServiceStatus;
  version: number;
  actions: ImportActionRecord[];
  slotVersions: Partial<Record<ImportPurpose, string>>;
  createdAt: string;
  createdBy: string;
  updatedAt: string;
  updatedBy: string;
};
export type ImportedTool = {
  definition: ImportActionDefinition;
  unsupportedReason: string | null;
  readOnlyHint: boolean | null;
};
export type ImportDiscovery = { protocolVersion: string; metadata: unknown; tools: ImportedTool[] };
export type ImportPreview = {
  service: string;
  serviceVersion: number;
  catalogRevision: number;
  configRevision: string;
  credentialVersions: Record<string, string>;
  manifestHash: string;
  manifest: ImportDiscovery;
  createdAt: string;
  expiresAt: string;
  createdBy: string;
};
/** An operator OAuth registration an import kind's companion approves. */
export type ImportOAuthRegistration = {
  id: string;
  issuer: string;
  resource: string;
  permissionProfiles: Array<{ id: string; scopeMode: OAuthScopeMode; scopes: string[] }>;
};
/** The OAuth companion that authenticates one selected import kind, with the registrations it approves (possibly none). */
export type ImportAuthentication = { importKind: string; dialectId: string; registrations: ImportOAuthRegistration[] };
export type ImportSecurityScheme = { name: string; kind: "bearer" | "raw_header"; header?: string };
export type ImportListResult = { catalogRevision: number; operatorEnabled: boolean; availableKinds: string[]; importAuthentication: ImportAuthentication[]; services: ImportedServiceRecord[] };
export type ImportScopedMcpIssueCode = "service_unavailable" | "missing_name" | "invalid_name" | "reserved_name" | "duplicate_name" | "projection_budget";
export type ImportScopedMcp = { ready: boolean; issues: Array<{ code: ImportScopedMcpIssueCode; actions: string[] }>; truncated: boolean };
export type ImportScopedMcpWarning = { toolIndex: number; proposedAction: string; codes: ImportScopedMcpIssueCode[] };
export type ImportRecordResult = { catalogRevision: number; operatorAllowed: boolean; importAuthentication: ImportAuthentication[]; available?: boolean; unavailableReason?: string | null; scopedMcp: ImportScopedMcp; service: ImportedServiceRecord };
export type ImportPreviewResult = ImportRecordResult & { scopedMcpWarnings: ImportScopedMcpWarning[]; preview: ImportPreview | null; affectedGrants: string[]; affectedGrantsByAction: Record<string, string[]> };
export type ImportVersions = { expectedVersion: number; expectedCatalogRevision: number };
export type ImportSelection = { source: Record<string, unknown>; action: string; label?: string; readOnly: boolean };
