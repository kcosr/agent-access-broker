// Resource audit presentation uses only recorded snapshots. A current catalog
// lookup cannot establish an event-time name, membership, or object identity.
import type { AuditRecord, ResourceSelector, Session } from "../types";
import { paths } from "../app/paths";
import { canViewAdmin } from "./capabilities";
import { auditManagement, auditRecordPhase } from "./audit";
import { selectorLabel } from "./resource-labels";
import { resourceTypeLabel, type ResourceTypes } from "./resource-types";

export type AuditEntity = {
  kind: "resource" | "resource_group";
  id: string;
  displayName: string | null;
  displayNameTruncated: boolean;
  resourceType: string | null;
  selector: ResourceSelector | null;
  selectorTruncated: boolean;
  version: number | null;
};
export type AuditResourceSnapshot = AuditEntity & {
  enabled: boolean | null;
  allowedExecutionContexts: string[];
  allowedExecutionContextsCount: number | null;
  allowedExecutionContextsTruncated: boolean;
  includedCount: number | null;
  excludedCount: number | null;
};
export type AuditMemberList = { count: number; items: AuditEntity[]; truncated: boolean };
export const MEMBERSHIP_LABELS = {
  includedAdded: "Included resources added",
  includedRemoved: "Included resources removed",
  excludedAdded: "Excluded resources added",
  excludedRemoved: "Excluded resources removed"
} as const;
export type AuditMembershipKey = keyof typeof MEMBERSHIP_LABELS;
export type AuditResourceChange = {
  before: AuditResourceSnapshot | null;
  after: AuditResourceSnapshot | null;
  changedFields: string[];
  membership: Partial<Record<AuditMembershipKey, AuditMemberList>>;
};

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}
function count(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}
function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}
function selector(value: unknown): ResourceSelector | null {
  const item = object(value);
  if (item?.kind === "all") return { kind: "all" };
  if ((item?.kind === "exact" || item?.kind === "namespace") && text(item.value)) return { kind: item.kind, value: item.value as string };
  return null;
}

/** Recognize the single supported safe entity-reference contract, never arbitrary IDs/URLs. */
export function auditEntity(value: unknown): AuditEntity | null {
  const item = object(value);
  if (!item || (item.kind !== "resource" && item.kind !== "resource_group") || !text(item.id)) return null;
  return {
    kind: item.kind, id: item.id as string,
    displayName: text(item.displayName), displayNameTruncated: item.displayNameTruncated === true,
    resourceType: text(item.resourceType), selector: selector(item.selector), selectorTruncated: item.selectorTruncated === true,
    version: count(item.version)
  };
}
function snapshot(value: unknown): AuditResourceSnapshot | null {
  const entity = auditEntity(value);
  const item = object(value);
  if (!entity || !item) return null;
  return { ...entity, enabled: typeof item.enabled === "boolean" ? item.enabled : null,
    allowedExecutionContexts: strings(item.allowedExecutionContexts),
    allowedExecutionContextsCount: count(item.allowedExecutionContextsCount),
    allowedExecutionContextsTruncated: item.allowedExecutionContextsTruncated === true,
    includedCount: count(item.includedCount), excludedCount: count(item.excludedCount) };
}
export function auditResourceChange(record: AuditRecord): AuditResourceChange | null {
  const change = object(object(object(record.providerAudit)?.management)?.change);
  if (!change) return null;
  const membership: AuditResourceChange["membership"] = {};
  const members = object(change.membership);
  for (const key of Object.keys(MEMBERSHIP_LABELS) as AuditMembershipKey[]) {
    const list = object(members?.[key]);
    if (!list || count(list.count) === null || !Array.isArray(list.items)) continue;
    const items = list.items.map(auditEntity).filter((item): item is AuditEntity => item !== null);
    membership[key] = { count: list.count as number, items, truncated: list.truncated === true || items.length < (list.count as number) };
  }
  return { before: snapshot(change.before), after: snapshot(change.after), changedFields: strings(change.changedFields), membership };
}

export function auditEntityName(entity: AuditEntity | null, types: ResourceTypes): string {
  if (!entity) return "Name not recorded";
  if (entity.displayName) return `${entity.displayName}${entity.displayNameTruncated ? "…" : ""}`;
  if (entity.resourceType && entity.selector) return `${selectorLabel(types, entity.resourceType, entity.selector)}${entity.selectorTruncated ? "…" : ""}`;
  return "Name not recorded";
}
/** A raw optional display-name field is distinct from the entity's coverage label. */
export function auditStoredDisplayName(entity: AuditEntity): string {
  return entity.displayName === null ? "Not set" : `${entity.displayName}${entity.displayNameTruncated ? "…" : ""}`;
}

const CHANGE_FIELD_LABELS: Record<string, string> = {
  displayName: "display name", name: "group name", resourceType: "resource type", selector: "coverage",
  enabled: "enabled state", allowedExecutionContexts: "execution contexts", privateAttributes: "private attributes",
  includedResourceIds: "included resources", excludedResourceIds: "excluded resources"
};

function nameChangeSummary(change: AuditResourceChange, baseType: string, types: ResourceTypes): string | null {
  const { before, after } = change;
  if (!before || !after || !change.changedFields.some((field) => field === "name" || field === "displayName")) return null;
  if (before.displayName !== null && after.displayName !== null) {
    return `Renamed ${baseType} “${auditStoredDisplayName(before)}” to “${auditStoredDisplayName(after)}”`;
  }
  if (after.displayName !== null) {
    return `Set display name of ${baseType} “${auditEntityName(before, types)}” to “${auditStoredDisplayName(after)}”`;
  }
  if (before.displayName !== null) {
    return `Cleared display name of ${baseType} “${auditStoredDisplayName(before)}”`;
  }
  return null;
}

export function auditEntityType(entity: AuditEntity | null, types: ResourceTypes): string {
  return entity?.kind === "resource_group" ? "Resource group" : entity?.resourceType ? resourceTypeLabel(types, entity.resourceType) : "Resource";
}
/** The URL identifies today's entry at this ID; it does not assert historical identity. */
export function auditEntityCurrentPath(entity: AuditEntity, session: Session): string | null {
  if (!canViewAdmin(session)) return null;
  return entity.kind === "resource" ? paths.resources(entity.id) : paths.resourceGroups(entity.id);
}
export function auditResourceOperation(record: AuditRecord) {
  if (record.service !== "broker") return null;
  const operation = /^admin\.policy\.(resources|resource_groups)\.(create|patch|delete)$/.exec(record.action);
  return operation ? { kind: operation[1] === "resources" ? "resource" as const : "resource_group" as const, verb: operation[2] as "create" | "patch" | "delete" } : null;
}

/** Success wording requires the explicit management success phase, never Allow alone. */
export function auditResourcePresentation(record: AuditRecord, types: ResourceTypes) {
  const operation = auditResourceOperation(record);
  if (!operation) return null;
  const entity = auditEntity(auditManagement(record)?.target);
  const change = auditResourceChange(record);
  const phase = auditRecordPhase(record);
  const completed = record.decision === "allow" && phase === "success";
  const label = record.decision === "deny" ? "Denied" : record.decision === "error" || phase === "failed" ? "Failed" : completed ? "Completed" : phase === "preflight" ? "Attempt recorded" : "Outcome not recorded";
  const tone = label === "Completed" ? "success" as const : label === "Failed" ? "danger" as const : label === "Denied" ? "warning" as const : "neutral" as const;
  const icon = label === "Completed" ? "circle-check" as const : label === "Failed" ? "alert-circle" as const : label === "Denied" ? "ban" as const : "info" as const;
  const baseType = operation.kind === "resource_group" ? "resource group" : entity?.resourceType ? resourceTypeLabel(types, entity.resourceType) : "resource";
  const name = auditEntityName(entity, types);
  const verbs = { create: completed ? "Created" : "Create", patch: completed ? "Updated" : "Update", delete: completed ? "Deleted" : "Delete" };
  let summary = `${verbs[operation.verb]} ${baseType}${entity ? ` “${name}”` : ""}`;
  if (completed && change && operation.verb === "patch") {
    const membership = Object.entries(change.membership).filter(([, list]) => list.count > 0);
    const rename = nameChangeSummary(change, baseType, types);
    if (rename) summary = rename;
    if (membership.length === 1 && membership[0][1].count === 1 && membership[0][1].items.length === 1) {
      const [key, list] = membership[0];
      const memberName = auditEntityName(list.items[0], types);
      const memberVerbs: Record<AuditMembershipKey, string> = {
        includedAdded: `Added “${memberName}” to “${name}” (included)`,
        includedRemoved: `Removed “${memberName}” from “${name}” (included)`,
        excludedAdded: `Excluded “${memberName}” from “${name}”`,
        excludedRemoved: `Removed exclusion of “${memberName}” from “${name}”`
      };
      const memberSummary = memberVerbs[key as AuditMembershipKey];
      summary = rename ? `${summary} — ${memberSummary}` : memberSummary;
    } else if (membership.length) {
      const memberSummaries = membership.map(([key, list]) => {
        const shown = list.items.slice(0, 2).map((item) => auditEntityName(item, types));
        const rest = list.count - shown.length;
        return `${MEMBERSHIP_LABELS[key as AuditMembershipKey].toLowerCase()}: ${shown.join(", ")}${rest > 0 ? `${shown.length ? ", " : ""}${rest} more` : ""}`;
      });
      summary += ` — ${memberSummaries.join("; ")}`;
    }
    const remainingFields = change.changedFields.filter((field) => {
      if (rename && (field === "displayName" || field === "name")) return false;
      if (field === "includedResourceIds" && membership.some(([key]) => key.startsWith("included"))) return false;
      if (field === "excludedResourceIds" && membership.some(([key]) => key.startsWith("excluded"))) return false;
      return true;
    });
    if (remainingFields.length) summary += ` — changed ${remainingFields.map((field) => CHANGE_FIELD_LABELS[field] ?? field).join(", ")}`;
  }
  if (!completed) summary = `${label}: ${summary}`;
  return { entity, change, summary, outcome: { label, tone, icon }, completed };
}

/** Called only after the full visible request timeline has loaded. */
export function auditResourceCompletionMissing(record: AuditRecord, records: AuditRecord[]): boolean {
  if (!auditResourceOperation(record) || record.decision !== "allow" || auditRecordPhase(record) !== "preflight") return false;
  return !records.some((item) => item.brokerRequestId === record.brokerRequestId && item.action === record.action && (auditRecordPhase(item) === "success" || item.decision === "error" || item.decision === "deny"));
}
