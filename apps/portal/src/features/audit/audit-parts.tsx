// Small presentation pieces shared by the audit list, drawer, and user tab.
import type { AuditRecord } from "../../types";
import { auditManagement, auditTokenLabel, type AuditDecision, type AuditScope, type AuditSessionRange } from "../../lib/audit";
import { Badge, Time, type IconName, type Tone } from "../../workbench";

export const DECISIONS: Record<AuditDecision, { label: string; filterLabel: string; tone: Tone; icon: IconName }> = {
  allow: { label: "Allowed", filterLabel: "Allowed", tone: "success", icon: "circle-check" },
  deny: { label: "Denied", filterLabel: "Denied", tone: "warning", icon: "ban" },
  error: { label: "Error", filterLabel: "Errors", tone: "danger", icon: "alert-circle" }
};

export function decisionMeta(decision: string) {
  return DECISIONS[decision as AuditDecision] ?? { label: decision, filterLabel: decision, tone: "neutral" as Tone, icon: "info" as IconName };
}

export const DECISION_FILTERS: { value: "" | AuditDecision; label: string; icon: IconName; tone?: Tone }[] = [
  { value: "", label: "All decisions", icon: "inbox" },
  { value: "allow", label: DECISIONS.allow.filterLabel, icon: DECISIONS.allow.icon, tone: DECISIONS.allow.tone },
  { value: "deny", label: DECISIONS.deny.filterLabel, icon: DECISIONS.deny.icon, tone: DECISIONS.deny.tone },
  { value: "error", label: DECISIONS.error.filterLabel, icon: DECISIONS.error.icon, tone: DECISIONS.error.tone }
];

/** Scope sentence for the view: what this viewer can see. */
export function auditScopeDescription(scope: AuditScope, managedServices: string[] | null) {
  if (scope === "self") return "Your own broker activity, including requests made with your agent tokens.";
  if (managedServices) return `Audit records for the services you manage: ${managedServices.join(", ")}.`;
  return "Every broker audit record.";
}

/** The resolved bounds of the current paging session: "from …", "from … to …", "before …", or "all time". */
export function RangeSentence({ range }: { range: AuditSessionRange }) {
  const at = (value: string) => <Time value={value} format="datetime" />;
  if (range.from && range.to) return <>from {at(range.from)} to {at(range.to)}</>;
  if (range.from) return <>from {at(range.from)}</>;
  if (range.to) return <>before {at(range.to)}</>;
  return <>all time</>;
}

/** A principal ID shown by display name when one is known (the ID stays in the title). */
export function PrincipalName({ principal, names }: { principal: string; names: Map<string, string> }) {
  const name = names.get(principal);
  return name && name !== principal ? <span title={principal}>{name}</span> : <span className="wb-mono">{principal}</span>;
}

/** The record's token: its name, "Browser session", or its ID. */
export function TokenName({ record, names, short = false }: { record: AuditRecord; names: Map<string, string>; short?: boolean }) {
  const token = auditTokenLabel(record, names);
  if (!token.id) return null;
  if (token.name) return <span title={token.id}>{token.name}</span>;
  if (token.browserSession) return <span title={token.id}>Browser session</span>;
  return (
    <span className="wb-num" title={token.id}>
      {short ? token.id.slice(0, 8) : token.id}
    </span>
  );
}

/** The service a broker management record changed (e.g. a grant for Jira), if any. */
export function relatedServiceOf(record: AuditRecord) {
  return record.service === "broker" ? auditManagement(record)?.targetService ?? null : null;
}

/** Broker management records name the service they changed. */
export function RelatedService({ record }: { record: AuditRecord }) {
  const related = relatedServiceOf(record);
  return related ? (
    <Badge variant="outline" icon="package" title={`Related service: ${related}`}>
      <span className="wb-sr-only">Related service: </span>
      {related}
    </Badge>
  ) : null;
}
