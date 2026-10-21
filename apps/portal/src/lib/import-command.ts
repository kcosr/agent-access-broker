// Command imports: `command:<name>` endpoints, stdin credential bindings, the
// per-action "Resources checked by" declaration, and the preview's command
// metadata and resource type decisions.
import type {
  ImportActionDefinition,
  ImportBinding,
  ImportCredentialKind,
  ImportDiscovery,
  ImportOwnerMode,
  ImportResourceTypeChange,
  ImportResourceTypeChangeDetail,
  ImportResourceTypeChangeKind,
  ImportResourceTypeDeclaration,
  ImportResourceTypeEffects,
  ImportResourceTypeIds,
  ImportServiceMetadata
} from "../import-types";
import { plural } from "../workbench";
import type { ResourceTypes } from "./resource-types";

export const COMMAND_KIND = "command";
const COMMAND_PREFIX = "command:";

/** The approved command name of a `command:<name>` endpoint, else null. */
export function commandName(endpoint: string): string | null {
  return endpoint.startsWith(COMMAND_PREFIX) ? endpoint.slice(COMMAND_PREFIX.length) : null;
}

export function commandEndpoint(name: string): string {
  return `${COMMAND_PREFIX}${name}`;
}

/**
 * Static stdin bindings for the chosen modes, none for a command that needs no
 * credential. Stored bindings are kept as they are, in their stored order, so
 * presentation edits do not register as a credential change.
 */
export function commandBindings(existing: ImportBinding[], shared: boolean, personal: boolean): ImportBinding[] {
  const modes: ImportOwnerMode[] = [...(shared ? (["service"] as const) : []), ...(personal ? (["per_user"] as const) : [])];
  const rank = (mode: ImportOwnerMode) => {
    const index = existing.findIndex((binding) => binding.ownerMode === mode);
    return index < 0 ? existing.length + (mode === "service" ? 0 : 1) : index;
  };
  return modes
    .sort((left, right) => rank(left) - rank(right))
    .map((ownerMode) => existing.find((binding) => binding.ownerMode === ownerMode) ?? { ownerMode, mechanism: "static_token", delivery: { kind: "stdin" }, status: "configured" });
}

export const CREDENTIAL_KIND_LABEL: Record<ImportCredentialKind, string> = { token: "Token", username_token: "Username and token" };
const MODE_LABEL: Record<ImportOwnerMode, string> = { service: "shared", per_user: "personal" };

/** "shared and personal", "shared" or "personal". */
export function credentialModesText(modes: readonly ImportOwnerMode[]): string {
  return modes.map((mode) => MODE_LABEL[mode]).join(" and ");
}

/** "Username and token · shared or personal", or that the command needs none. */
export function commandCredentialText(credential: ImportServiceMetadata["credential"]): string {
  if (!credential) return "None: grants use service mode without a stored credential";
  return `${CREDENTIAL_KIND_LABEL[credential.kind]} · ${credential.modes.map((mode) => MODE_LABEL[mode]).join(" or ")}`;
}

/** Preview notices from the adapter, such as the phase-2 OAuth notice. */
export function commandNotices(manifest: ImportDiscovery | undefined): string[] {
  const notices = (manifest?.metadata as { notices?: unknown } | null | undefined)?.notices;
  return Array.isArray(notices) ? notices.filter((notice): notice is string => typeof notice === "string") : [];
}

/**
 * Who checks an action's resources, from its `annotations.command.resources`:
 * the Broker when the action names them in typed inputs, else the command,
 * with the caller's grants of the type (or of no type).
 */
export type ResourceCheck = { by: "broker" | "command"; type: string | null; inputs: string[] };

export function commandResourceCheck(definition: ImportActionDefinition): ResourceCheck {
  const resources = (definition.annotations as { command?: { resources?: { type?: unknown; inputs?: unknown } } } | null)?.command?.resources;
  const type = typeof resources?.type === "string" ? resources.type : null;
  const inputs = Array.isArray(resources?.inputs) ? resources.inputs.filter((input): input is string => typeof input === "string") : [];
  return { by: type && inputs.length ? "broker" : "command", type, inputs };
}

/** `/project` names the input `project`; JSON pointer escapes are decoded. */
function pointerName(pointer: string): string {
  return pointer.replace(/^\//, "").replaceAll("~1", "/").replaceAll("~0", "~");
}

/** The type's label and the inputs it is read from: "Project", from `project`; "Projects"; or no resource type. */
export function resourceCheckParts(check: ResourceCheck, types: readonly ImportResourceTypeDeclaration[]): { type: string | null; inputs: string[] } {
  const declared = check.type ? types.find((entry) => entry.id === check.type) : undefined;
  const type = check.type ? (check.by === "broker" ? declared?.label : declared?.pluralLabel) ?? check.type : null;
  return { type, inputs: check.by === "broker" ? check.inputs.map(pointerName) : [] };
}

/** Plain text for tables and filters: "Broker · Project, from project". */
export function resourceCheckText(check: ResourceCheck, types: readonly ImportResourceTypeDeclaration[]): string {
  const parts = resourceCheckParts(check, types);
  const detail = parts.type ? `${parts.type}${parts.inputs.length ? `, from ${parts.inputs.join(", ")}` : ""}` : "no resource type";
  return `${check.by === "broker" ? "Broker" : "Command"} · ${detail}`;
}

export const COMMAND_CHECK_CAVEAT =
  "The Broker checks the action grant and passes the caller's grants with their credentials. The command must limit its queries and results to each grant's resources; the Broker cannot check that.";

export const TYPE_CHANGE_LABEL: Record<ImportResourceTypeChangeKind, string> = { added: "New", changed: "Changed", restored: "Restored", removed: "Removed" };

const DETAIL_TEXT: Record<ImportResourceTypeChangeDetail, string> = {
  label: "label",
  plural_label: "plural label",
  example: "example",
  attribute_added: "new optional attribute",
  attribute_made_optional: "attribute made optional",
  attribute_text: "attribute label or description",
  attribute_order: "attribute order",
  attribute_removed: "attribute removed",
  pattern: "pattern",
  max_length: "maximum length",
  attribute_added_required: "new required attribute",
  attribute_made_required: "attribute made required",
  attribute_pattern: "attribute pattern",
  exclusions_supported: "exclusions supported",
  exclusions_unsupported: "exclusions no longer supported"
};

export function typeChangeDetails(change: ImportResourceTypeChange): string {
  return change.details.map((detail) => DETAIL_TEXT[detail]).join(", ");
}

/** What accepting the preview does with one type. */
export function typeChangeOutcome(change: ImportResourceTypeChange): string {
  const resources = `${change.resourceCount} ${plural(change.resourceCount, "resource")}`;
  switch (change.outcome) {
    case "applied":
      return change.change === "added" ? "Registered on acceptance." : "Applied on acceptance.";
    case "needs_new_id":
      return `Not applied: stored resources hold attribute values this change would need to check. The previously accepted type, including its exclusion support, is retained. Actions using the type are unsupported until the command declares it under a new type id.`;
    case "retained":
      return `Kept for its ${resources}; it accepts no new resources. Delete ${change.resourceCount === 1 ? "it" : "them"}, then accept a refresh to drop the type.`;
    case "dropped":
      return "Dropped on acceptance; no resources use it.";
  }
}

const TYPE_ID = /^[a-z][a-z0-9_]{0,63}$/;

/**
 * The Broker type IDs an administrator typed for added types, by source type
 * id. A Map, since type ids come from the manifest and may name
 * `Object.prototype` members such as `constructor`.
 */
export type ResourceTypeIdChoices = ReadonlyMap<string, string>;

/**
 * Problems with the Broker type IDs of added types, by source type id: the ID
 * grammar, IDs repeated within the import, and an ID another owner has
 * registered: the Broker's own proposal when the preview says so, or any ID
 * among the `registered` resource types not declared by `service`. Accepted
 * types keep their IDs.
 */
export function resourceTypeIdIssues(
  changes: readonly ImportResourceTypeChange[],
  metadata: ImportServiceMetadata | undefined,
  ids: ResourceTypeIdChoices,
  registered: ResourceTypes,
  service: string
): ReadonlyMap<string, string> {
  const issues = new Map<string, string>();
  const chosen = (id: string, brokerType: string) => ids.get(id)?.trim() ?? brokerType;
  const editable = new Set(changes.filter((change) => change.editable).map((change) => change.id));
  const counts = new Map<string, number>();
  for (const declared of metadata?.resourceTypes ?? []) {
    const value = editable.has(declared.id) ? chosen(declared.id, declared.brokerType) : declared.brokerType;
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  for (const change of changes.filter((entry) => entry.editable)) {
    const value = chosen(change.id, change.brokerType);
    if (!TYPE_ID.test(value)) issues.set(change.id, "Use up to 64 lowercase letters, digits or underscores, starting with a letter.");
    else if ((counts.get(value) ?? 0) > 1) issues.set(change.id, "Another type of this import uses this ID.");
    else if ((change.blocked && value === change.brokerType) || (registered.has(value) && registered.get(value)!.importedService !== service))
      issues.set(change.id, "This ID is already registered. Choose another.");
  }
  return issues;
}

/** The accept body's `resourceTypeIds`: only added types whose ID the administrator changed. */
export function chosenResourceTypeIds(changes: readonly ImportResourceTypeChange[], ids: ResourceTypeIdChoices): ImportResourceTypeIds {
  // `Object.fromEntries` defines own properties, so even `__proto__` is sent as a key.
  return Object.fromEntries(
    changes.flatMap((change) => {
      const value = ids.get(change.id)?.trim();
      return change.editable && value && value !== change.brokerType ? [[change.id, value]] : [];
    })
  );
}

/** Resource-dependent changes that would make acceptance fail now; an ID collision is fixed by choosing another ID instead. */
export function blockedTypeChanges(changes: readonly ImportResourceTypeChange[]): ImportResourceTypeChange[] {
  return changes.filter((change) => change.blocked && !change.editable);
}

/** "Deleted removed attribute values of 2 resources; dropped ticketing_queue", or null when nothing changed. */
export function resourceTypeEffectsText(effects: ImportResourceTypeEffects | undefined): string | null {
  if (!effects) return null;
  const parts: string[] = [];
  const count = effects.deletedAttributeValues.length;
  if (count) parts.push(`deleted removed attribute values of ${count} ${plural(count, "resource")}`);
  if (effects.droppedTypes.length) parts.push(`dropped ${effects.droppedTypes.join(", ")}`);
  return parts.length ? parts.join("; ") : null;
}
