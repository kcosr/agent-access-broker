import type { CredentialInputDescriptor, CredentialInputPolicy, OAuthScopeMode } from "./types";

/** Secret-free import metadata. Token values exist only in write request bodies. */
export type ImportOwnerMode = "service" | "per_user";
export type ImportPurpose = "execution" | "discovery" | "transport";
export type ImportServiceStatus = "draft" | "disabled" | "enabled" | "retired";
export type ImportActionStatus = "enabled" | "disabled" | "quarantined" | "retired";
/** `stdin` is the delivery of command imports, whose request on stdin carries the credential. */
export type ImportDelivery = { kind: "bearer" } | { kind: "basic" } | { kind: "raw_header"; name: string } | { kind: "stdin" };
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
  /** Omitted on ordinary JSON actions. */
  download?: boolean;
};
export type ImportActionRecord = {
  definition: ImportActionDefinition;
  status: ImportActionStatus;
  version: number;
  definitionHash: string;
};
/** A command's credential kind: `token` is stored as `bearer_token`, `username_token` as `basic_api_token`. */
export type ImportCredentialKind = "token" | "username_token";
export type ImportResourceAttributeDeclaration = { name: string; label: string; description: string; required: boolean; pattern: string | null };
/** A declared resource type and the Broker type ID it is registered under. */
export type ImportResourceTypeDeclaration = {
  /** The source's type id, which requests' `resourceType` names. */
  id: string;
  brokerType: string;
  /** No longer declared, but kept registered for its remaining resources; it accepts no new ones. */
  removed: boolean;
  /** Omission in stored metadata means true. */
  supportsExclusions?: boolean;
  label: string;
  pluralLabel: string;
  pattern: string;
  maxLength: number;
  example: string;
  attributes: ImportResourceAttributeDeclaration[];
};
/** Service-level metadata of a command import: proposed by discovery, stored on acceptance. */
export type ImportServiceMetadata = {
  format: string;
  /** Display only ("Imported at version X"); never compared or pinned. */
  version: string;
  /** Absent (null) for a command that needs no credential. */
  credential: { kind: ImportCredentialKind; modes: ImportOwnerMode[] } | null;
  verify: boolean;
  resourceTypes: ImportResourceTypeDeclaration[];
};
export type ImportCredentialInput = (CredentialInputDescriptor & { state: "ready"; inputPolicy: CredentialInputPolicy }) | { state: "unavailable"; reason: string };
export type ImportedServiceRecord = {
  /** Read-only administrative projection; not part of a saved definition. */
  credentialInputs: Partial<Record<ImportPurpose, ImportCredentialInput>>;
  definition: ImportDefinition;
  status: ImportServiceStatus;
  version: number;
  actions: ImportActionRecord[];
  slotVersions: Partial<Record<ImportPurpose, string>>;
  /** Command imports after their first acceptance. */
  acceptedMetadata?: ImportServiceMetadata;
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
export type ImportDiscovery = {
  protocolVersion: string;
  metadata: unknown;
  tools: ImportedTool[];
  /** Command imports: the metadata acceptance would store. */
  serviceMetadata?: ImportServiceMetadata;
};
export type ImportResourceTypeChangeKind = "added" | "changed" | "restored" | "removed";
export type ImportResourceTypeOutcome = "applied" | "needs_new_id" | "retained" | "dropped";
export type ImportResourceTypeChangeDetail =
  | "label"
  | "plural_label"
  | "example"
  | "attribute_added"
  | "attribute_made_optional"
  | "attribute_text"
  | "attribute_order"
  | "attribute_removed"
  | "pattern"
  | "max_length"
  | "attribute_added_required"
  | "attribute_made_required"
  | "attribute_pattern"
  | "exclusions_supported"
  | "exclusions_unsupported";
/** The preview's decision for one changed resource type, with the stored resources it depends on. */
export type ImportResourceTypeChange = {
  id: string;
  brokerType: string;
  change: ImportResourceTypeChangeKind;
  outcome: ImportResourceTypeOutcome;
  details: ImportResourceTypeChangeDetail[];
  resourceCount: number;
  /** Resources that keep the type in its accepted form, or that prevent the change or drop (at most 100). */
  blockingResources: string[];
  /** Groups whose exclusions prevent this change (at most 100 groups and resource IDs per group). */
  blockingGroups: Array<{ id: string; resourceIds: string[] }>;
  /** Resources whose removed attributes' values acceptance deletes (at most 100). */
  affectedResources: string[];
  /** An added type's Broker type ID can still be chosen. */
  editable: boolean;
  /** Accepting now would be rejected because of this type. */
  blocked: boolean;
};
/**
 * Why an import change was refused: retained grants it would leave invalid,
 * resources its type changes no longer fit, and excluded group memberships
 * that prevent an opt-out (`target.affectedGrants`, `.resources`, `.resourceGroups`).
 */
export type ImportChangeBlocked = {
  /** Each grant once: `id` is its managed grant ID or `toml:<index>` (empty when unattributed); `reason` joins its subjects' messages. */
  affectedGrants: Array<{ id: string; reasonCode: string; reason: string }>;
  resources: Array<{ type: string; id: string }>;
  resourceGroups: Array<{ type: string; id: string; resourceIds: string[] }>;
};
/** An action's effects class: read-only identity access reaches only reads. */
export type ImportClassification = "read" | "write";
/** How an acceptance reclassifies one selected action: `from` is its current accepted class, or null for an action the acceptance adds. */
export type ImportClassificationChange = { action: string; from: ImportClassification | null; to: ImportClassification };
/** What an acceptance did to stored resources and types. */
export type ImportResourceTypeEffects = {
  deletedAttributeValues: Array<{ resourceId: string; attributes: string[] }>;
  droppedTypes: string[];
};
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
export type ImportSecurityScheme = { name: string; kind: "bearer" | "basic" | "raw_header"; header?: string };
export type ImportListResult = {
  catalogRevision: number;
  operatorEnabled: boolean;
  availableKinds: string[];
  /** Commands the operator approved under `[command_imports.<name>]`, by name only. */
  commandImports: Array<{ name: string }>;
  importAuthentication: ImportAuthentication[];
  services: ImportedServiceRecord[];
};
export type ImportScopedMcpIssueCode = "service_unavailable" | "missing_name" | "invalid_name" | "reserved_name" | "duplicate_name" | "projection_budget";
export type ImportScopedMcp = { ready: boolean; issues: Array<{ code: ImportScopedMcpIssueCode; actions: string[] }>; truncated: boolean };
export type ImportScopedMcpWarning = { toolIndex: number; proposedAction: string; codes: ImportScopedMcpIssueCode[] };
export type ImportRecordResult = {
  catalogRevision: number;
  operatorAllowed: boolean;
  importAuthentication: ImportAuthentication[];
  available?: boolean;
  unavailableReason?: string | null;
  scopedMcp: ImportScopedMcp;
  service: ImportedServiceRecord;
  /** The accepted command manifest's version. */
  commandVersion?: string;
  /** Acceptances that deleted attribute values or dropped resource types. */
  resourceTypeEffects?: ImportResourceTypeEffects;
};
/** An acceptance's result, with how it reclassified its selected actions (empty when nothing changed). */
export type ImportAcceptResult = ImportRecordResult & { classificationChanges: ImportClassificationChange[] };
export type ImportPreviewResult = ImportRecordResult & {
  scopedMcpWarnings: ImportScopedMcpWarning[];
  preview: ImportPreview | null;
  /** Command imports: the preview's resource type decisions; empty otherwise. */
  resourceTypeChanges?: ImportResourceTypeChange[];
  affectedGrants: string[];
  affectedGrantsByAction: Record<string, string[]>;
};
export type ImportVersions = { expectedVersion: number; expectedCatalogRevision: number };
export type ImportSelection = { source: Record<string, unknown>; action: string; label?: string; readOnly: boolean };
/** Broker type IDs chosen for added resource types, by the source's type id. */
export type ImportResourceTypeIds = Record<string, string>;
