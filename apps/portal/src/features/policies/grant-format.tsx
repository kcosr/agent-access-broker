// Shared presentation of a grant's subjects, actions, and resources.
import type { GroupPolicyReference, PolicyCatalogResult, PolicyGrantRecord } from "../../types";
import {
  ACTION_GRANT_LABEL,
  isActionOnlyGrant,
  policyService,
  policySubjectDisplayLabel,
  policySubjectParts,
  policySubjectShortLabel,
  selectsAllPolicyActions
} from "../../lib/helpers";
import { resourceSelectionLabels } from "../../lib/resource-labels";
import type { ResourceTypes } from "../../lib/resource-types";
import { AppLink, Badge, type Tone } from "../../workbench";
import { paths } from "../../app/paths";

type GrantLike = PolicyGrantRecord | GroupPolicyReference;

export const GRANT_STATUS_TONE: Record<string, Tone> = { active: "success", disabled: "muted", deleted: "danger" };

/** The first `count` items and how many more there are (tables keep "+N" beside the truncating text). */
export function previewParts(items: string[], count = 2) {
  return { text: items.slice(0, count).join(", "), more: Math.max(0, items.length - count) };
}

export function preview(items: string[], count = 2) {
  const { text, more } = previewParts(items, count);
  return more ? `${text} +${more}` : text;
}

export function subjectsPreview(grant: GrantLike, catalog: PolicyCatalogResult | null) {
  return previewParts(grant.subjects.map((subject) => policySubjectShortLabel(subject, catalog)));
}

export function actionsPreview(grant: GrantLike, catalog: PolicyCatalogResult | null) {
  const service = policyService(catalog, grant.service);
  if (selectsAllPolicyActions(service, grant.actions)) return { text: `All ${grant.actions.length} ${grant.actions.length === 1 ? "action" : "actions"}`, more: 0 };
  return previewParts(grant.actions);
}

export function resourcesSummary(grant: GrantLike, catalog: PolicyCatalogResult | null, types: ResourceTypes) {
  if (isActionOnlyGrant(policyService(catalog, grant.service), grant)) return [ACTION_GRANT_LABEL];
  const labels = resourceSelectionLabels(types, grant.resources, catalog);
  return labels.length ? labels : ["No resources selected"];
}

/** A subject with its display name; links to the principal or group page for administrators. */
export function SubjectLabel({ subject, catalog, link }: { subject: string; catalog: PolicyCatalogResult | null; link: boolean }) {
  const parts = policySubjectParts(subject);
  const label = policySubjectDisplayLabel(subject, catalog);
  if (!link || !parts.id || (parts.kind !== "user" && parts.kind !== "group")) return <span>{label}</span>;
  return (
    <AppLink className="wb-link" href={parts.kind === "user" ? paths.principal(parts.id) : paths.group(parts.id)}>
      {label}
    </AppLink>
  );
}

export function GrantStatusBadge({ status }: { status: string }) {
  return status === "active" ? null : <Badge tone={GRANT_STATUS_TONE[status] ?? "neutral"}>{status}</Badge>;
}
