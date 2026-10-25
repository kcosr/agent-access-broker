import type { AuditInputRule } from "../../audit-request-types";
import type { ImportActionDefinition } from "../../import-types";
import { auditDisplayText, auditObject } from "../../lib/audit-request";
import { importSourceKey } from "../../lib/imports";
import { Disclosure } from "../../workbench";

export function commandAuditInputs(definition: ImportActionDefinition): AuditInputRule[] | "unavailable" {
  const rules = auditObject(auditObject(definition.annotations)?.command)?.auditInputs;
  if (rules === undefined) return [];
  const valid = (value: unknown, child = false): boolean => {
    const rule = auditObject(value);
    if (!rule || typeof rule.key !== "string" || typeof rule.pointer !== "string") return false;
    if (rule.capture === "omit") return Object.keys(rule).every(key => ["key", "pointer", "capture"].includes(key));
    return ["value", "presence", "itemCount", "utf8ByteCount", ...(child ? [] : ["records"])].includes(String(rule.capture))
      && typeof rule.label === "string" && ["primary", "detail", "raw"].includes(String(rule.display))
      && ["target", "change", "fact"].includes(String(rule.role)) && ["text", "query", "identifier", "path", "email", "date", "number", "boolean", "bytes", "records"].includes(String(rule.kind))
      && (rule.capture !== "value" || ["scalar", "list"].includes(String(rule.shape)))
      && (rule.maxBytes === undefined || typeof rule.maxBytes === "number")
      && (rule.overflow === undefined || rule.overflow === "prefix" || rule.overflow === "omit")
      && (rule.capture !== "records" || Array.isArray(rule.fields) && rule.fields.every(field => valid(field, true)));
  };
  return Array.isArray(rules) && rules.length > 0 && rules.every(rule => valid(rule)) ? rules as AuditInputRule[] : "unavailable";
}

function RuleTable({ rules, label }: { rules: AuditInputRule[] | "unavailable"; label: string }) {
  if (rules === "unavailable") return <p className="pt-prose">Audit declaration unavailable</p>;
  if (!rules.length) return <p className="pt-prose wb-small">{label}: no request inputs are captured.</p>;
  const rows = rules.flatMap(rule => [{ rule, parent: null as AuditInputRule | null }, ...(rule.fields ?? []).map(child => ({ rule: child, parent: rule }))]);
  return <div className="pt-import-audit-scroll" tabIndex={0} role="region" aria-label={label}>
    <table className="pt-import-audit-table"><caption>{label}</caption><thead><tr><th>Label / key</th><th>Exact selector</th><th>Capture</th><th>Shape / kind</th><th>Limit / overflow</th><th>Role / placement</th></tr></thead>
      <tbody>{rows.map(({ rule, parent }, index) => <tr key={index}>
        <th scope="row">{parent ? <span className="wb-muted">{auditDisplayText(parent.label ?? parent.key)} / </span> : null}{auditDisplayText(rule.label ?? rule.key)}<div className="wb-muted wb-mono">{auditDisplayText(rule.key)}</div></th>
        <td className="wb-mono">{parent ? <><span>{auditDisplayText(parent.pointer)} [each item]</span><br /></> : null}{auditDisplayText(rule.pointer)}</td>
        <td>{rule.capture}</td><td>{rule.capture === "omit" ? "—" : `${rule.shape ? `${rule.shape} / ` : ""}${rule.kind}`}</td>
        <td>{rule.maxBytes !== undefined ? `${rule.maxBytes} bytes / ${rule.overflow}` : rule.capture === "records" || rule.shape === "list" ? "20 items" : "—"}{rule.maxBytes !== undefined && rule.shape === "list" ? " · 20 items" : ""}</td>
        <td>{rule.capture === "omit" ? "—" : `${rule.role} / ${rule.display}`}</td>
      </tr>)}</tbody>
    </table>
  </div>;
}

/** Approval covers this declaration. It contains static selectors, never invocation values. */
export function CommandAuditInputs({ definition, accepted, preview = false }: { definition: ImportActionDefinition; accepted?: ImportActionDefinition; preview?: boolean }) {
  const proposed = commandAuditInputs(definition);
  const prior = accepted ? commandAuditInputs(accepted) : [];
  const changed = !!accepted && importSourceKey(proposed) !== importSourceKey(prior);
  const changes: string[] = [];
  if (changed && Array.isArray(prior) && Array.isArray(proposed)) {
    for (const rule of proposed) {
      const before = prior.find(item => item.key === rule.key);
      if (!before) changes.push(`Added: ${rule.label ?? rule.key}`);
      else if (importSourceKey(before) !== importSourceKey(rule)) changes.push(`Changed: ${rule.label ?? rule.key}`);
    }
    for (const rule of prior) if (!proposed.some(item => item.key === rule.key)) changes.push(`Removed: ${rule.label ?? rule.key}`);
    const common = prior.filter(rule => proposed.some(item => item.key === rule.key)).map(rule => rule.key);
    if (importSourceKey(common) !== importSourceKey(proposed.filter(rule => common.includes(rule.key)).map(rule => rule.key))) changes.push("Rule order changed");
  }
  return <Disclosure summary="Audit inputs">
    <p className="pt-prose wb-small">Unlisted inputs are omitted. Recorded data is visible to readers of the complete audit record, including service managers. Retained text may be searchable even with raw placement.</p>
    {changed ? <p className="pt-prose wb-small">Audit declaration changed. Review both declarations, including their order, before accepting.</p> : null}
    {changes.length ? <ul className="pt-prose wb-small" aria-label="Audit declaration changes">{changes.map((change, index) => <li key={index}>{auditDisplayText(change)}</li>)}</ul> : null}
    {changed ? <RuleTable rules={prior} label="Accepted audit inputs" /> : null}
    <RuleTable rules={proposed} label={preview ? "Proposed audit inputs" : "Accepted audit inputs"} />
  </Disclosure>;
}
