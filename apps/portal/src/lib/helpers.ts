// Pure helpers and constants extracted from App.tsx (no JSX).
import { canViewPolicies, canUseSelfService, hasPolicyScope } from "./capabilities";
import { ApiError } from "../api";
import type {
  AgentTokenOptions,
  AgentTokenServiceRestriction,
  ResourceSelection,
  BrokerTokenRecord,
  CredentialMetadata,
  GroupPolicyReference,
  GroupRecord,
  PolicyCatalogResult,
  PolicyGrantRecord,
  PolicyGrantWriteBody,
  PolicyServiceCatalog,
  PolicyValidationMessage,
  Session,
} from "../types";
import type { BadgeTone, ModalState, PolicyGrantDraft, PolicySubjectKind } from "../app-types";

export const GENERATED_PASSWORD_LENGTH = 24;
export const GENERATED_PASSWORD_GROUPS = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#$%^&*_-+="] as const;
export const GENERATED_PASSWORD_ALPHABET = GENERATED_PASSWORD_GROUPS.join("");
export const POLICY_GRANT_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
export const RESERVED_POLICY_GRANT_IDS = new Set([".", "..", "export", "validate"]);
export const MASKED_TEXT_SECURITY_SUPPORTED =
  typeof CSS !== "undefined" && typeof CSS.supports === "function" && CSS.supports("-webkit-text-security", "disc");

export function canManagePolicies(session: Session) {
  return canViewPolicies(session);
}

/** The Audit page: admins and service policy managers, when audit is queryable. */
export function canViewAudit(session: Session) {
  return Boolean(session.auditQueryable && session.authenticated && hasPolicyScope(session));
}

/** The Activity page: every signed-in managed user, when audit is queryable. */
export function canViewActivity(session: Session) {
  return Boolean(canUseSelfService(session) && session.auditQueryable);
}

export function policyServiceLocked(session: Session, mode: PolicyGrantDraft["mode"]) {
  return Boolean(session.role === "service_policy_manager" && mode === "edit");
}

export function microsoftLoginControl(methodStatus: string | undefined, oidcEnabled: boolean) {
  if (methodStatus === "active") return "unlink" as const;
  return oidcEnabled ? "link" as const : "disabled" as const;
}

export function formatGroupOption(group: GroupRecord) {
  const name = group.displayName ? ` - ${group.displayName}` : "";
  const status = group.status === "active" ? "" : ` (${group.status})`;
  return `${group.groupId}${name}${status}`;
}

export function formatBytes(value?: number | null) {
  if (value === undefined || value === null) return "Unknown";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB"] as const;
  let scaled = value / 1024;
  for (const unit of units) {
    if (scaled < 1024 || unit === units[units.length - 1]) {
      return `${scaled.toFixed(scaled >= 10 ? 0 : 1)} ${unit}`;
    }
    scaled /= 1024;
  }
  return `${value} B`;
}

export function formatDurationMs(value?: number | null) {
  if (value === undefined || value === null) return "Unknown";
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(value >= 10_000 ? 0 : 1)} s`;
}

export type TokenStatus = "Active" | "Paused" | "Expired" | "Revoked";

export function tokenStatus(record: BrokerTokenRecord): TokenStatus {
  if (record.revokedAt) return "Revoked";
  if (record.expiresAt && new Date(record.expiresAt).getTime() <= Date.now()) return "Expired";
  if (record.pausedAt) return "Paused";
  return "Active";
}

export function tokenStatusTone(status: TokenStatus): "success" | "warning" | "neutral" {
  if (status === "Active") return "success";
  if (status === "Paused" || status === "Expired") return "warning";
  return "neutral";
}

export function availableAgentTokenServices(options: AgentTokenOptions, executionContexts: string[]) {
  return options.services
    .filter((option) => option.executionContexts.some((context) => executionContexts.includes(context)))
    .map((option) => option.service);
}

export function availableAgentTokenActions(options: AgentTokenOptions, service: string, executionContexts: string[]) {
  return options.services
    .find((option) => option.service === service)
    ?.actions.filter((action) => action.executionContexts.some((context) => executionContexts.includes(context))) ?? [];
}

/** Service IDs such as `constructor` must never resolve inherited object members. */
export function agentTokenSelectedActions(actionsByService: Readonly<Record<string, string[]>>, service: string): string[] {
  return Object.hasOwn(actionsByService, service) ? actionsByService[service] : [];
}

export function agentTokenResourceSelection(selections: Readonly<Record<string, ResourceSelection | undefined>>, service: string): ResourceSelection | undefined {
  return Object.hasOwn(selections, service) ? selections[service] : undefined;
}

export function agentTokenServiceHasResources(options: AgentTokenOptions, service: string, selectedActions: readonly string[]) {
  const option = options.services.find((item) => item.service === service);
  // A stale action may use resources when its grant returns. Dropping that
  // explicit boundary now would broaden the token's future effective access.
  return option === undefined
    || option.actions.some((action) => action.resourceType !== null)
    || selectedActions.some((selected) => !option.actions.some((action) => action.action === selected));
}

export function buildAgentTokenServiceRestrictions(services: string[], actionsByService: Record<string, string[]>, selections: Record<string, ResourceSelection | undefined>, options: AgentTokenOptions): Record<string, AgentTokenServiceRestriction> {
  return Object.fromEntries([...services].sort().map((service) => {
    const actions = agentTokenSelectedActions(actionsByService, service);
    const selection = agentTokenServiceHasResources(options, service, actions) ? agentTokenResourceSelection(selections, service) : undefined;
    return [service, {
      actions: [...actions].sort(),
      ...(selection === undefined ? {} : { resources: { resourceIds: [...selection.resourceIds].sort(), resourceGroupIds: [...selection.resourceGroupIds].sort() } })
    }];
  }));
}

export function tokenExecutionContextsSummary(record: BrokerTokenRecord, effectiveContexts?: string[]) {
  const items = tokenExecutionContextItems(record, effectiveContexts);
  if (items) return items.join(", ");
  if (record.tokenClass !== "agent_invoke") return "Not applicable";
  const contexts = record.scopes.allowedExecutionContexts;
  if (contexts === undefined) return "Legacy unbound";
  return "Invalid binding";
}

export function tokenExecutionContextItems(record: BrokerTokenRecord, effectiveContexts?: string[]) {
  if (record.tokenClass !== "agent_invoke") return null;
  const contexts = record.scopes.allowedExecutionContexts;
  if (!Array.isArray(contexts) || contexts.length === 0 || contexts.some((context) => typeof context !== "string")) {
    return null;
  }
  return contexts.map((context) =>
    effectiveContexts && !effectiveContexts.includes(context) ? `${context} (stale)` : context
  );
}

export function tokenAllowedServicesSummary(record: BrokerTokenRecord) {
  const items = tokenAllowedServiceItems(record);
  if (items) return items.join(", ");
  if (record.tokenClass !== "agent_invoke") return "Not applicable";
  const services = record.scopes.allowedServices;
  if (services === undefined) return "All configured";
  return "Invalid allowlist";
}

export function tokenAllowedServiceItems(record: BrokerTokenRecord) {
  if (record.tokenClass !== "agent_invoke") return null;
  const services = record.scopes.allowedServices;
  if (!Array.isArray(services) || services.length === 0 || services.some((service) => typeof service !== "string")) {
    return null;
  }
  return services;
}

/** Credentials keyed by `service/name`, the identity of a credential target. */
export function credentialsByTarget(credentials: CredentialMetadata[]) {
  return new Map(credentials.map((credential) => [`${credential.service}/${credential.name}`, credential]));
}

export function credentialStatus(credential?: CredentialMetadata) {
  if (!credential) return "Not saved";
  if (credential.status === "disabled") return "Disabled";
  if (credential.status !== "active") return credential.status;
  if (credential.verificationStatus === "verification_failed") return "Verification failed";
  if (credential.verificationStatus === "upstream_verified") return "Upstream verified";
  if (credential.verificationStatus === "local_verified") return "Local verified";
  return "Not verified";
}

/** The toast after a verification: a service without upstream verification checks the credential locally only. */
export function credentialVerifiedMessage(status: CredentialMetadata["verificationStatus"]) {
  return status === "local_verified" ? "Credential checked locally; the service does not verify it upstream" : "Credential verified";
}

export function credentialTone(credential?: CredentialMetadata): BadgeTone {
  if (!credential) return "neutral";
  if (credential.status !== "active") return "neutral";
  if (credential.verificationStatus === "verification_failed") return "danger";
  if (credential.verificationStatus === "upstream_verified" || credential.verificationStatus === "local_verified") return "success";
  return "warning";
}

export function splitCommaValues(value: string) {
  return value
    .split(/[,\n]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function policySubjectParts(subject: string): { kind: PolicySubjectKind; id: string } {
  if (subject === "user:anonymous") return { kind: "anonymousUser", id: "" };
  if (subject === "group:anonymous") return { kind: "anonymousGroup", id: "" };
  if (subject.startsWith("user:")) return { kind: "user", id: subject.slice("user:".length) };
  if (subject.startsWith("group:")) return { kind: "group", id: subject.slice("group:".length) };
  return { kind: "group", id: "" };
}

export function policySubjectLabel(subject: string) {
  const parts = policySubjectParts(subject);
  if (parts.kind === "anonymousUser") return "user:anonymous";
  if (parts.kind === "anonymousGroup") return "group:anonymous";
  return `${parts.kind}:${parts.id}`;
}

export function identityDisplayName(displayName?: string | null) {
  return displayName
    ?.trim()
    .replace(/[\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, "")
    .replace(/[|·—–]+/g, " ")
    .replace(/\b(?:ID|user|group)\s*:/gi, (value) => value.replace(":", " "))
    .replace(/\s+/g, " ")
    .trim();
}

export function principalIdentityLabel(principalId: string, displayName?: string | null) {
  const name = identityDisplayName(displayName);
  return name ? `${name} · ID: ${principalId}` : principalId;
}

export function policySubjectDisplayLabel(subject: string, catalog: PolicyCatalogResult | null) {
  const parts = policySubjectParts(subject);
  if (parts.kind === "anonymousUser" || parts.kind === "anonymousGroup") return policySubjectLabel(subject);
  const entry = parts.kind === "user"
    ? catalog?.subjects.users.find((item) => item.principalId === parts.id)
    : catalog?.subjects.groups.find((item) => item.groupId === parts.id);
  const name = identityDisplayName(entry?.displayName);
  return name ? `${name} · ID: ${subject}` : subject;
}

/** Display name alone when the catalog knows one, otherwise the raw subject; the ID stays in `policySubjectDisplayLabel`. */
export function policySubjectShortLabel(subject: string, catalog: PolicyCatalogResult | null) {
  const parts = policySubjectParts(subject);
  if (parts.kind === "anonymousUser" || parts.kind === "anonymousGroup") return policySubjectLabel(subject);
  const entry = parts.kind === "user"
    ? catalog?.subjects.users.find((item) => item.principalId === parts.id)
    : catalog?.subjects.groups.find((item) => item.groupId === parts.id);
  return identityDisplayName(entry?.displayName) || subject;
}

export function buildPolicySubject(kind: PolicySubjectKind, id: string) {
  if (kind === "anonymousUser") return "user:anonymous";
  if (kind === "anonymousGroup") return "group:anonymous";
  return `${kind}:${id.trim()}`;
}

export function policyGrantKey(grant: Pick<PolicyGrantRecord, "grantRef" | "index"> | GroupPolicyReference) {
  return grant.grantRef || `toml:${grant.index ?? "unknown"}`;
}

export function selectsAllPolicyActions(service: PolicyServiceCatalog | null, actions: string[]) {
  if (!service || service.actions.length === 0) return false;
  const selected = new Set(actions);
  return selected.size === service.actions.length && service.actions.every((action) => selected.has(action.action));
}

export function policyService(catalog: PolicyCatalogResult | null, serviceName: string) {
  return catalog?.services.find((service) => service.service === serviceName) ?? null;
}

export function selectedPolicyActions(service: PolicyServiceCatalog | null, actions: string[]) {
  if (!service) return [];
  return service.actions.filter((action) => actions.includes(action.action));
}

/** Whether a grant authorizes its actions without resources: every action it
 * names takes no resource selection, so its empty selection means the whole
 * account or service rather than nothing. */
export function isActionOnlyGrant(service: PolicyServiceCatalog | null, grant: { actions: string[]; resources: ResourceSelection }) {
  if (grant.resources.resourceIds.length > 0 || grant.resources.resourceGroupIds.length > 0) return false;
  const actions = selectedPolicyActions(service, grant.actions);
  return actions.length > 0 && actions.length === grant.actions.length && actions.every((action) => action.requiredScopeTypes.length === 0);
}

export const ACTION_GRANT_LABEL = "Action grant";

export function commonSupportedCredentialModes(service: PolicyServiceCatalog | null, actions: string[]) {
  const selected = selectedPolicyActions(service, actions);
  if (selected.length === 0) return service?.configuredCredentialModes ?? [];
  return selected
    .map((action) => action.credentialModes)
    .reduce<string[] | null>((common, modes) => {
      if (common === null) return [...modes];
      return common.filter((mode) => modes.includes(mode));
    }, null) ?? [];
}

export function commonCredentialModes(service: PolicyServiceCatalog | null, actions: string[]) {
  const supported = commonSupportedCredentialModes(service, actions);
  const configured = service?.configuredCredentialModes ?? [];
  return supported.filter((mode) => configured.includes(mode));
}

export function requiredPolicyScopeTypes(service: PolicyServiceCatalog | null, actions: string[]) {
  return Array.from(new Set(selectedPolicyActions(service, actions).flatMap((action) => action.requiredScopeTypes))).sort();
}

export function uniqueSortedOptions(values: string[], selected = "") {
  const options = Array.from(new Set(values)).sort();
  if (selected && !options.includes(selected)) {
    return [selected, ...options];
  }
  return options;
}

export function compactListPreview(items: string[], previewCount = 2) {
  const visible = items.slice(0, previewCount).join(", ");
  const remaining = items.length - previewCount;
  return remaining > 0 ? `${visible} +${remaining}` : visible;
}

export function policyGrantDraft(
  catalog: PolicyCatalogResult | null,
  mode: PolicyGrantDraft["mode"],
  grant?: PolicyGrantRecord | GroupPolicyReference,
  subject?: string
): PolicyGrantDraft {
  const firstService = catalog?.services.find((item) => item.available !== false)?.service ?? "";
  const serviceName = grant?.service ?? firstService;
  const service = policyService(catalog, serviceName);
  const actions = grant?.actions ?? [];
  const defaultContext = catalog?.executionContexts.defaultContext;
  const executionContexts = grant?.executionContexts ?? (defaultContext ? [defaultContext] : []);
  const credentialMode = grant?.credentialMode ?? commonCredentialModes(service, actions)[0] ?? service?.configuredCredentialModes[0] ?? "";
  const grantSubjects = grant?.subjects ?? (subject ? [subject] : []);
  const grantDescription = grant && "description" in grant ? grant.description : "";
  const subjectParts = policySubjectParts(subject ?? grantSubjects[0] ?? "");
  return {
    mode,
    originalService: mode === "edit" ? grant?.service : undefined,
    originalCredentialMode: mode === "edit" ? grant?.credentialMode : undefined,
    originalActions: mode === "edit" ? [...(grant?.actions ?? [])] : undefined,
    grantRef: mode === "edit" || mode === "inspect" ? grant?.grantRef : undefined,
    writable: (mode !== "edit" && mode !== "inspect") || Boolean(grant?.writable),
    version: mode === "edit" ? grant?.version : undefined,
    grantId: "",
    subjects: [...new Set(grantSubjects)],
    subjectKind: subjectParts.kind,
    subjectId: subjectParts.id,
    service: serviceName,
    actions,
    executionContexts: [...executionContexts],
    credentialMode,
    status: mode === "duplicate" ? "disabled" : grant?.status ?? "active",
    priority: grant?.priority === undefined || grant?.priority === null ? "" : String(grant.priority),
    description: grantDescription ?? "",
    resources: grant?.resources ?? { resourceIds: [], resourceGroupIds: [] },
    validationMessages: []
  };
}

export function policyGrantDraftForSubject(catalog: PolicyCatalogResult | null, subject: string) {
  const draft = policyGrantDraft(catalog, "create", undefined, subject);
  return draft;
}

export function policyGrantBody(
  draft: PolicyGrantDraft,
  catalog: PolicyCatalogResult | null
): { body: PolicyGrantWriteBody | null; messages: PolicyValidationMessage[]; preview: string } {
  const messages: PolicyValidationMessage[] = [];
  const service = policyService(catalog, draft.service);
  if (draft.executionContexts.length === 0) {
    messages.push({ field: "executionContexts", code: "required", message: "Choose at least one execution context." });
  } else {
    const allowedContexts = catalog?.executionContexts.allowedValues ?? [];
    const unknownContexts = draft.executionContexts.filter((context) => !allowedContexts.includes(context));
    if (unknownContexts.length > 0) {
      messages.push({
        field: "executionContexts",
        code: "invalid",
        message: `Choose only configured execution contexts. Not configured: ${unknownContexts.join(", ")}.`
      });
    }
  }
  if (draft.mode === "edit" && draft.status !== "active" && !service) {
    const body: PolicyGrantWriteBody = {
      executionContexts: draft.executionContexts,
      description: draft.description.trim() || null
    };
    if (!draft.grantRef || draft.version === undefined || draft.version === null) {
      messages.push({ field: "version", code: "required", message: "Editable grants must include a version." });
    } else {
      body.expectedVersion = draft.version;
    }
    const preview = JSON.stringify(body, null, 2);
    return { body: messages.length === 0 ? body : null, messages, preview };
  }
  const priorityText = draft.priority.trim();
  let priority: number | null | undefined;
  if (priorityText) {
    priority = Number(priorityText);
    if (!Number.isInteger(priority)) {
      messages.push({ field: "priority", code: "invalid", message: "Priority must be an integer." });
    }
  } else {
    priority = draft.mode === "edit" ? null : undefined;
  }
  if (draft.subjects.length === 0) {
    messages.push({ field: "subjects", code: "empty", message: "Add at least one policy subject." });
  }
  const grantId = draft.grantId.trim();
  if (draft.mode !== "edit" && grantId && !isPolicyGrantIdAllowed(grantId)) {
    messages.push({
      field: "grantId",
      code: "invalid",
      message: "Grant ID must be a safe slug and cannot be '.', '..', 'export', or 'validate'."
    });
  }
  if (!service) {
    messages.push({ field: "service", code: "required", message: "Choose a service." });
  }
  if (draft.actions.length === 0) {
    messages.push({ field: "actions", code: "required", message: "Choose at least one action." });
  }
  const retainedService = draft.mode === "edit" && draft.service === draft.originalService;
  const retainedSelection = retainedService && draft.actions.every((action) => draft.originalActions?.includes(action));
  if (service?.available === false && !retainedSelection) {
    messages.push({ field: "service", code: "unavailable", message: "This service is unavailable. Existing grant selections can be retained or removed." });
  }
  if (draft.actions.some((name) => {
    const action = service?.actions.find((item) => item.action === name);
    return (!action || action.available === false) && !(retainedService && draft.originalActions?.includes(name));
  })) {
    messages.push({ field: "actions", code: "unavailable", message: "Unavailable actions cannot be added to a grant." });
  }
  const credentialModes = commonCredentialModes(service, draft.actions);
  const retainedMode = retainedSelection && draft.credentialMode === draft.originalCredentialMode;
  if (!draft.credentialMode || (!credentialModes.includes(draft.credentialMode) && !retainedMode)) {
    messages.push({ field: "credentialMode", code: "invalid", message: "Choose a configured credential mode supported by the selected actions." });
  }
  const selectedActions = selectedPolicyActions(service, draft.actions);
  if (draft.credentialMode === "service" && selectedActions.some((action) => action.lookupRequired) && !service?.lookupCredentialConfigured) {
    messages.push({ field: "credentialMode", code: "lookup_missing", message: "Service-mode lookup-backed actions require a configured lookup credential." });
  }

  const body: PolicyGrantWriteBody = {
    subjects: draft.subjects,
    service: draft.service,
    actions: draft.actions,
    executionContexts: draft.executionContexts,
    resources: draft.resources,
    credentialMode: draft.credentialMode,
    priority,
    status: draft.status,
    description: draft.description.trim() || (draft.mode === "edit" ? null : undefined)
  };
  if (draft.mode !== "edit" && grantId) {
    body.grantId = grantId;
  }
  if (draft.mode === "edit") {
    if (!draft.grantRef || draft.version === undefined || draft.version === null) {
      messages.push({ field: "version", code: "required", message: "Editable grants must include a version." });
    } else {
      body.expectedVersion = draft.version;
    }
  }
  const preview = JSON.stringify(body, null, 2);
  return { body: messages.length === 0 ? body : null, messages, preview };
}

export function isPolicyGrantIdAllowed(grantId: string) {
  return POLICY_GRANT_ID_RE.test(grantId) && !RESERVED_POLICY_GRANT_IDS.has(grantId.toLowerCase());
}

export function passwordValidation(newPassword: string, confirmPassword: string) {
  if (!newPassword && !confirmPassword) return null;
  if (newPassword !== confirmPassword) {
    return "New passwords do not match.";
  }
  return null;
}

export function modalHasOneTimeSecret(modal: ModalState) {
  return modal?.type === "reveal" || modal?.type === "passwordReveal";
}

export function secureRandomIndex(length: number) {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("Secure random password generation is unavailable in this browser.");
  }
  const values = new Uint32Array(1);
  const limit = 0x100000000 - (0x100000000 % length);
  do {
    globalThis.crypto.getRandomValues(values);
  } while (values[0] >= limit);
  return values[0] % length;
}

export function randomCharacter(alphabet: string) {
  return alphabet[secureRandomIndex(alphabet.length)];
}

export function shuffleCharacters(characters: string[]) {
  for (let index = characters.length - 1; index > 0; index -= 1) {
    const swapIndex = secureRandomIndex(index + 1);
    [characters[index], characters[swapIndex]] = [characters[swapIndex], characters[index]];
  }
  return characters;
}

export function generateTemporaryPassword(principalId: string) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const characters = GENERATED_PASSWORD_GROUPS.map(randomCharacter);
    while (characters.length < GENERATED_PASSWORD_LENGTH) {
      characters.push(randomCharacter(GENERATED_PASSWORD_ALPHABET));
    }
    const password = shuffleCharacters(characters).join("");
    if (password.toLocaleLowerCase() !== principalId.toLocaleLowerCase()) {
      return password;
    }
  }
  throw new Error("Generated password matched the principal. Try again.");
}

export function errorMessage(error: unknown) {
  if (error instanceof ApiError) {
    const suffix = error.reasonCode ? ` (${error.reasonCode})` : "";
    return `${error.message}${suffix}`;
  }
  return error instanceof Error ? error.message : "Request failed";
}

export function sessionExpired(error: ApiError) {
  return (
    error.status === 401 ||
    error.reasonCode === "identity_required" ||
    error.reasonCode === "broker_token_expired" ||
    error.reasonCode === "broker_token_revoked"
  );
}
