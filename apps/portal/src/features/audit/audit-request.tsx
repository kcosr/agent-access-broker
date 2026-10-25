import { useState } from "react";
import type { AuditCell, AuditFieldMetadata, AuditRequestField, AuditScalar } from "../../audit-request-types";
import type { AuditRecord } from "../../types";
import { attachmentAuditOutcomes, auditCollectionNote, auditDisplayText, auditScalarText, auditTruncation, commandExecutionFacts, requestAudit, requestAuditLayout, suppliedAuditLabels } from "../../lib/audit-request";
import { Badge, Button, Disclosure, DrawerSection, Icon, KeyValue, useToast } from "../../workbench";

function Scalar({ value, metadata }: { value: AuditScalar; metadata: AuditFieldMetadata }) {
  const [expanded, setExpanded] = useState(false);
  const toast = useToast();
  const stored = value.state === "captured" && value.value !== undefined ? String(value.value) : null;
  const display = auditDisplayText(auditScalarText(value, metadata.kind));
  const characters = Array.from(display);
  const long = characters.length > 200;
  const truncation = auditTruncation(value);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(stored!);
      toast(truncation ? `Recorded value copied. ${truncation}` : "Recorded value copied", { tone: "success" });
    } catch {
      toast("Copying needs clipboard access in this browser.", { tone: "error" });
    }
  };
  return <div className="pt-audit-value">
    <span className={metadata.kind === "query" || metadata.kind === "identifier" || metadata.kind === "path" ? "pt-audit-value-text wb-mono" : "pt-audit-value-text"}>{long && !expanded ? `${characters.slice(0, 200).join("")}…` : display}</span>
    {long || stored !== null ? <span className="pt-audit-value-actions">
      {long ? <Button size="sm" variant="ghost" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>{expanded ? "Show less" : "Show full text"}</Button> : null}
      {stored !== null ? <Button size="sm" variant="ghost" icon="copy" aria-label={`Copy ${metadata.label}`} onClick={() => void copy()} /> : null}
    </span> : null}
    {truncation ? <span className="pt-audit-capture-note">{truncation}</span> : null}
  </div>;
}

function Cell({ value, metadata }: { value: AuditCell; metadata: AuditFieldMetadata }) {
  const [expanded, setExpanded] = useState(false);
  if (value.state !== "captured" || !value.items) return <Scalar value={value} metadata={metadata} />;
  return <div className="pt-audit-collection">
    <p className="pt-audit-capture-note">{auditCollectionNote(value)}</p>
    {value.items.length ? <ol className="pt-audit-input-list" aria-label={metadata.label}>
      {(expanded ? value.items : value.items.slice(0, 5)).map(item => <li key={item.index} value={item.index + 1}><Scalar value={item} metadata={metadata} /></li>)}
    </ol> : <span>Empty retained list</span>}
    {value.items.length > 5 ? <Button size="sm" variant="ghost" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>{expanded ? "Show fewer items" : `${value.items.length - 5} more retained`}</Button> : null}
  </div>;
}

function Field({ field }: { field: AuditRequestField }) {
  const [expanded, setExpanded] = useState(false);
  if (field.state !== "captured" || !field.rows) return <Cell value={field} metadata={field} />;
  const columns = (field.columns ?? []).filter(column => column.display !== "raw");
  return <div className="pt-audit-collection">
    <p className="pt-audit-capture-note">{auditCollectionNote(field)}</p>
    {field.rows.length ? <ol className="pt-audit-record-list" aria-label={field.label}>
      {(expanded ? field.rows : field.rows.slice(0, 5)).map(row => <li key={row.index}>
        <span className="pt-audit-capture-note">Input item {row.index + 1}</span>
        {row.state === "invalid" ? <p>Not recorded: unexpected input shape</p> : <>
          <KeyValue labelWidth={120} items={columns.filter(column => column.display === "primary").flatMap(column => {
            const cell = Object.hasOwn(row.cells ?? {}, column.key) ? row.cells?.[column.key] : null;
            return cell && cell.state !== "absent" ? [{ label: auditDisplayText(column.label), value: <Cell value={cell} metadata={column} /> }] : [];
          })} />
          {columns.some(column => column.display === "detail" && row.cells?.[column.key]?.state !== "absent" && Object.hasOwn(row.cells ?? {}, column.key)) ? <Disclosure summary="Additional item details"><KeyValue labelWidth={120} items={columns.filter(column => column.display === "detail").flatMap(column => {
            const cell = Object.hasOwn(row.cells ?? {}, column.key) ? row.cells?.[column.key] : null;
            return cell && cell.state !== "absent" ? [{ label: auditDisplayText(column.label), value: <Cell value={cell} metadata={column} /> }] : [];
          })} /></Disclosure> : null}
        </>}
      </li>)}
    </ol> : <span>Empty retained list</span>}
    {field.rows.length > 5 ? <Button size="sm" variant="ghost" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>{expanded ? "Show fewer items" : `${field.rows.length - 5} more retained`}</Button> : null}
  </div>;
}

export function AuditRequestDetails({ record }: { record: AuditRecord }) {
  const audit = requestAudit(record);
  if (!audit) return null;
  if (audit === "unavailable") return <DrawerSection title="Request details"><p className="pt-prose">Request details unavailable</p></DrawerSection>;
  const layout = requestAuditLayout(audit);
  const changes = suppliedAuditLabels(audit);
  const target = layout.main.find(field => field.role === "target");
  return <DrawerSection title="Request details">
    <div className="pt-audit-request-details">
      {target ? <div className="pt-audit-request-target"><span className="pt-audit-target-icon"><Icon name="file-text" /></span><div className="pt-audit-target-main"><div className="pt-audit-capture-note">{auditDisplayText(target.label)}</div><Field field={target} /></div></div> : null}
      <KeyValue labelWidth={132} items={layout.main.filter(field => field !== target).map(field => ({ label: auditDisplayText(field.label), value: <Field key={field.key} field={field} /> }))} />
      {changes.length ? <div className="pt-audit-supplied"><span className="pt-audit-capture-note">{audit.status === "partial" ? "Fields supplied (recorded fields only)" : "Fields supplied"}</span><div className="pt-audit-field-chips">{changes.map(label => <Badge key={label} variant="outline">{auditDisplayText(label)}</Badge>)}</div></div> : null}
      {layout.query ? <div className="pt-audit-query"><div className="pt-audit-capture-note">{auditDisplayText(layout.query.label)}</div><Field field={layout.query} /></div> : null}
      <p className="pt-audit-capture-note">Requested values and supplied fields; these do not establish the operation's outcome.</p>
      {audit.status === "partial" ? <p className="pt-audit-capture-note">Some request details were not fully recorded.{audit.budgetOmittedFields ? ` ${audit.budgetOmittedFields} fields omitted by the audit budget.` : ""}</p> : null}
      {layout.additional.length ? <Disclosure summary="Additional request details"><KeyValue labelWidth={132} items={layout.additional.map(field => ({ label: auditDisplayText(field.label), value: <Field key={field.key} field={field} /> }))} /></Disclosure> : null}
    </div>
  </DrawerSection>;
}

export function AuditExecutionDetails({ record }: { record: AuditRecord }) {
  const facts = commandExecutionFacts(record);
  return facts.length ? <div className="wb-drawer-section"><Disclosure summary="Execution details"><KeyValue labelWidth={150} items={facts} /></Disclosure></div> : null;
}

export function AuditAttachmentOutcomes({ record }: { record: AuditRecord }) {
  const rows = attachmentAuditOutcomes(record);
  return rows.length ? <Disclosure summary={`Attachment outcomes (${rows.length})`}><ol className="pt-audit-record-list" aria-label="Attachment outcomes">{rows.map((row, index) => <li key={index}>
    <span>Input item {row.index + 1}: {row.status}</span>
    {row.attachmentId ? <div>Observed attachment ID: <span className="wb-mono">{auditDisplayText(row.attachmentId)}</span></div> : null}
    {row.note ? <p className="pt-audit-capture-note">{row.note}</p> : null}
  </li>)}</ol></Disclosure> : null;
}
