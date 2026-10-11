import { useSession } from "../../app/session";
import type { AuditRecord } from "../../types";
import { auditEntityCurrentPath, auditEntityName, auditEntityType, auditResourcePresentation, auditStoredDisplayName, MEMBERSHIP_LABELS, type AuditEntity, type AuditMembershipKey, type AuditResourceSnapshot } from "../../lib/audit-resources";
import { selectorLabel } from "../../lib/resource-labels";
import { resourceTypeLabel, useResourceTypes, type ResourceTypes } from "../../lib/resource-types";
import { AppLink, Button, DrawerSection, KeyValue, useToast } from "../../workbench";

/** Recorded label; links always refer explicitly to the current entry at the ID. */
export function AuditEntityName({ entity }: { entity: AuditEntity }) {
  const { session } = useSession();
  const types = useResourceTypes();
  const href = auditEntityCurrentPath(entity, session);
  const name = auditEntityName(entity, types);
  return href ? (
    <AppLink className="wb-link" href={href} title={`Open current ${entity.kind === "resource" ? "resource" : "resource group"} at this ID: ${entity.id}`}>
      {name}
    </AppLink>
  ) : <span title={entity.id}>{name}</span>;
}

function EntityIdentity({ entity }: { entity: AuditEntity }) {
  const types = useResourceTypes();
  const toast = useToast();
  const coverage = entity.resourceType && entity.selector ? selectorLabel(types, entity.resourceType, entity.selector) : null;
  async function copy() {
    try {
      if (!navigator.clipboard) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(entity.id);
      toast("ID copied", { tone: "success" });
    } catch {
      toast("Copying failed. Select and copy the ID by hand.", { tone: "error" });
    }
  }
  return (
    <div className="pt-audit-entity">
      <AuditEntityName entity={entity} />
      <span className="wb-small wb-muted">{auditEntityType(entity, types)}{coverage ? ` · ${coverage}${entity.selectorTruncated ? "…" : ""}` : ""}{entity.version !== null ? ` · version ${entity.version}` : ""}</span>
      <span className="pt-audit-entity-id"><span className="wb-num">{entity.id}</span><Button size="sm" icon="copy" aria-label={`Copy ${entity.kind === "resource" ? "resource" : "resource group"} ID`} onClick={() => void copy()}>Copy ID</Button></span>
      {entity.displayNameTruncated || entity.selectorTruncated ? <span className="wb-small wb-muted">Recorded text was truncated.</span> : null}
    </div>
  );
}

const FIELD_LABELS: Record<string, string> = {
  displayName: "Display name", name: "Group name", resourceType: "Resource type", selector: "Coverage",
  enabled: "Enabled", allowedExecutionContexts: "Execution contexts", privateAttributes: "Private attributes"
};
function fieldValue(snapshot: AuditResourceSnapshot | null, field: string, types: ResourceTypes): string {
  if (!snapshot) return "Not present";
  switch (field) {
    case "displayName": case "name": return auditStoredDisplayName(snapshot);
    case "resourceType": return snapshot.resourceType ? resourceTypeLabel(types, snapshot.resourceType) : "Not recorded";
    case "selector": return snapshot.resourceType && snapshot.selector ? `${selectorLabel(types, snapshot.resourceType, snapshot.selector)}${snapshot.selectorTruncated ? "…" : ""}` : "Not recorded";
    case "enabled": return snapshot.enabled === null ? "Not recorded" : snapshot.enabled ? "Yes" : "No";
    case "allowedExecutionContexts": return `${snapshot.allowedExecutionContexts.join(", ") || "None"}${snapshot.allowedExecutionContextsTruncated ? ` (showing ${snapshot.allowedExecutionContexts.length} of ${snapshot.allowedExecutionContextsCount ?? "more"})` : ""}`;
    default: return "Not recorded";
  }
}

export function AuditResourceDetails({ record }: { record: AuditRecord }) {
  const types = useResourceTypes();
  const presentation = auditResourcePresentation(record, types);
  if (!presentation) return null;
  const { entity, change, completed } = presentation;
  const fields = change?.changedFields.filter((field) => field in FIELD_LABELS) ?? [];
  const membership = Object.entries(change?.membership ?? {}).filter(([, list]) => list.count > 0);
  return (
    <>
      <DrawerSection title="Affected resource">
        {entity ? <EntityIdentity entity={entity} /> : <p className="pt-prose">Name not recorded. This event does not contain a resource snapshot.</p>}
        <p className="pt-prose pt-audit-note">Names and changes are recorded at the time of the event. Links open the current entry at that ID, which may have changed or been replaced.</p>
        {!completed ? <p className="pt-prose pt-audit-note">This record does not confirm a completed change.</p> : null}
      </DrawerSection>
      {completed && change ? (
        <DrawerSection title="Changes">
          {fields.length ? <KeyValue labelWidth={145} items={fields.map((field) => ({
            label: FIELD_LABELS[field],
            value: field === "privateAttributes" ? "Changed; private values are not recorded." : <span className="pt-audit-change-value">{fieldValue(change.before, field, types)} → {fieldValue(change.after, field, types)}</span>
          }))} /> : null}
          {membership.map(([key, list]) => (
            <div className="pt-audit-membership" key={key}>
              <h4>{MEMBERSHIP_LABELS[key as AuditMembershipKey]} ({list.count})</h4>
              <ul className="pt-audit-members">
                {list.items.map((member) => <li key={member.id}><EntityIdentity entity={member} /></li>)}
              </ul>
              {list.truncated ? <p className="pt-prose pt-audit-note">Showing {list.items.length} of {list.count} resources. The audit record contains a bounded list.</p> : null}
            </div>
          ))}
          {!change.changedFields.length && !membership.length ? <p className="pt-prose">No values changed.</p> : null}
        </DrawerSection>
      ) : null}
    </>
  );
}
