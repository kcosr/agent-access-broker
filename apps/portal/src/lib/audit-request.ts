import type { AuditCell, AuditFieldMetadata, AuditRequestField, AuditScalar, RequestAuditV1 } from "../audit-request-types";
import type { AuditRecord } from "../types";

export function auditObject(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

const kinds = ["text", "query", "identifier", "path", "email", "date", "number", "boolean", "bytes", "records"];
const states = ["captured", "absent", "null", "invalid", "tooLarge", "budget"];
const count = (value: unknown) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const includes = (values: string[], value: unknown) => typeof value === "string" && values.includes(value);
function metadata(value: unknown): boolean {
  const field = auditObject(value);
  return !!field && typeof field.key === "string" && typeof field.label === "string"
    && includes(["primary", "detail", "raw"], field.display) && includes(["target", "change", "fact"], field.role)
    && includes(kinds, field.kind) && includes(["value", "presence", "itemCount", "utf8ByteCount", "records"], field.capture)
    && (field.capture === "value" ? includes(["scalar", "list"], field.shape) : field.shape === undefined);
}
function scalar(value: unknown): boolean {
  const cell = auditObject(value);
  return !!cell && includes(states, cell.state)
    && (cell.value === undefined || ["string", "boolean"].includes(typeof cell.value) || typeof cell.value === "number" && Number.isFinite(cell.value))
    && (cell.encoding === undefined || cell.encoding === "decimalInteger" && typeof cell.value === "string" && /^-?(0|[1-9][0-9]*)$/.test(cell.value))
    && (cell.truncated === undefined || cell.truncated === true && typeof cell.value === "string" && count(cell.originalBytes));
}
function collection(value: Record<string, unknown>): boolean {
  return ["totalCount", "limitedCount", "invalidCount", "budgetOmittedCount"].every(key => count(value[key]));
}
function cell(value: unknown): boolean {
  const item = auditObject(value);
  return !!item && scalar(item) && [true, false, null].includes(item.supplied as boolean | null)
    && (item.items === undefined || Array.isArray(item.items) && collection(item) && item.items.every(entry => scalar(entry) && count(auditObject(entry)?.index)));
}
function field(value: unknown): boolean {
  const item = auditObject(value);
  return !!item && metadata(item) && cell(item)
    && (item.columns === undefined || Array.isArray(item.columns) && item.columns.every(metadata))
    && (item.rows === undefined || Array.isArray(item.rows) && Array.isArray(item.columns) && collection(item)
      && item.rows.every(entry => {
        const row = auditObject(entry);
        return !!row && count(row.index) && (row.state === "invalid" || row.state === "captured" && !!auditObject(row.cells) && Object.values(row.cells as object).every(cell));
      }));
}

/** Unknown or malformed versions are unavailable, never guessed from live catalog data. */
export function requestAudit(record: Pick<AuditRecord, "requestAudit">): RequestAuditV1 | "unavailable" | null {
  const raw = record.requestAudit;
  if (raw === undefined || raw === null) return null;
  const value = auditObject(raw);
  if (!value || value.version !== 1 || !includes(["complete", "partial", "unavailable"], value.status)) return "unavailable";
  if (value.status === "unavailable") return "unavailable";
  if (!Array.isArray(value.fields) || !value.fields.every(field) || !count(value.budgetOmittedFields) || !count(value.absentOmittedFields)) return "unavailable";
  return value as RequestAuditV1;
}

export function visibleAuditFields(fields: AuditRequestField[]) {
  return fields.filter(field => field.display !== "raw" && field.state !== "absent");
}

export function requestAuditLayout(audit: RequestAuditV1) {
  const visible = visibleAuditFields(audit.fields);
  const primary = visible.filter(field => field.display === "primary");
  const query = primary.find(field => field.kind === "query" && field.shape === "scalar");
  const ordinary = primary.filter(field => field !== query);
  // Targets and supplied titles lead; stable sorting preserves declaration order within each group.
  const rank = (field: AuditRequestField) => field.role === "target" ? 0 : field.role === "change" && field.kind === "text" ? 1 : 2;
  const main = [...ordinary].sort((a, b) => rank(a) - rank(b)).slice(0, 6);
  return { main, query, additional: visible.filter(field => field !== query && !main.includes(field)) };
}

export function suppliedAuditLabels(audit: RequestAuditV1): string[] {
  const labels: string[] = [];
  for (const field of visibleAuditFields(audit.fields)) {
    if (field.role === "change" && field.supplied === true) labels.push(field.label);
    for (const column of field.columns ?? []) {
      if (column.display !== "raw" && column.role === "change" && field.rows?.some(row => Object.hasOwn(row.cells ?? {}, column.key) && row.cells?.[column.key]?.supplied === true)) labels.push(column.label);
    }
  }
  return [...new Set(labels)];
}

/** Visible notation for controls and bidi/format characters; copy always uses the original. */
export function auditDisplayText(text: string): string {
  return text.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, char => char === "\n" ? char : `\\u{${char.codePointAt(0)!.toString(16).toUpperCase()}}`);
}
export function auditScalarText(value: AuditScalar, kind: AuditFieldMetadata["kind"]): string {
  if (value.state === "absent") return "Not supplied";
  if (value.state === "null") return "Explicit null";
  if (value.state === "invalid") return "Not recorded: unexpected input shape";
  if (value.state === "tooLarge") return "Not recorded: exceeds audit limit";
  if (value.state === "budget") return "Not recorded: audit budget";
  if (typeof value.value === "boolean") return value.value ? "Yes" : "No";
  if (value.value === "") return "Empty text";
  if (value.value === undefined) return "Not recorded";
  const text = String(value.value); // decimalInteger deliberately never passes through Number.
  return kind === "bytes" ? `${text} bytes` : text;
}
export function auditTruncation(value: AuditScalar) {
  return value.truncated && typeof value.value === "string"
    ? `Truncated at capture: ${new TextEncoder().encode(value.value).byteLength.toLocaleString("en-US")} of ${value.originalBytes?.toLocaleString("en-US")} bytes recorded.` : null;
}
export function auditCollectionNote(value: AuditCell) {
  return `${value.totalCount ?? 0} input items · ${(value.limitedCount ?? 0) + (value.budgetOmittedCount ?? 0)} omitted at capture${value.budgetOmittedCount ? ` (${value.budgetOmittedCount} by audit budget)` : ""}${value.invalidCount ? ` · ${value.invalidCount} unexpected shapes` : ""}`;
}

/** Host-owned command facts only. Never flatten arbitrary provider JSON. */
export function commandExecutionFacts(record: Pick<AuditRecord, "providerAudit">) {
  const command = auditObject(record.providerAudit?.command);
  if (!command) return [];
  return ([['name', 'Approved command', 'string'], ['spawned', 'Process spawned', 'boolean'], ['operationDispatched', 'Operation dispatched', 'boolean'], ['exitCode', 'Exit code', 'number'], ['signal', 'Signal', 'number'], ['durationMs', 'Duration (ms)', 'number'], ['contractViolation', 'Contract violation', 'boolean']] as const)
    .flatMap(([key, label, type]) => Object.hasOwn(command, key) && (command[key] === null || typeof command[key] === type)
      ? [{ label, value: command[key] === null ? "Unknown" : typeof command[key] === "boolean" ? command[key] ? "Yes" : "No" : auditDisplayText(String(command[key])) }] : []);
}

export function auditOutcomeWarning(record: Pick<AuditRecord, "decision" | "reasonCode" | "providerAudit">) {
  const provider = record.providerAudit;
  const jiraCreateReadbackFailed = provider?.provider === "jira" && provider.operation === "issue.create"
    && (provider.failurePhase === "create_response_validation" || provider.failurePhase === "post_create_readback");
  const uploadUnverified = provider?.provider === "confluence" && Array.isArray(provider.attachments)
    && provider.attachments.some(row => auditObject(row)?.status === "unverified");
  if (provider?.mutationStatus === "unknown" || provider?.mutationStatus === "applied_unverified" || provider?.verificationStatus === "failed" || provider?.sideEffectPossible === true || jiraCreateReadbackFailed || uploadUnverified || record.reasonCode === "mutation_verification_failed") return "The operation's final outcome is unverified. Recorded request details do not prove that changes were applied.";
  if (record.reasonCode?.includes("timeout") || record.reasonCode === "operation_cancelled" || record.reasonCode === "operation_failed" || record.reasonCode === "operation_outcome_unknown") return "The request did not finish normally. Its final outcome may be unknown; recorded request details do not prove that changes were applied.";
  return null;
}

/** Reviewed native attachment outcomes. Indices associate outcomes with this event's snapshot only. */
export function attachmentAuditOutcomes(record: AuditRecord) {
  if (record.providerAudit?.provider !== "jira" && record.providerAudit?.provider !== "confluence") return [];
  if (!["attachment.add", "blog.attachment.add", "page.draft.attachment.add", "blog.draft.attachment.add"].includes(record.action)) return [];
  const outcomes = record.providerAudit?.attachments;
  if (!Array.isArray(outcomes)) return [];
  const audit = requestAudit(record);
  const metadata = audit && audit !== "unavailable" ? audit.fields.find(field => field.key === "attachments" && field.display !== "raw" && field.capture === "records") : null;
  return outcomes.flatMap(value => {
    const row = auditObject(value);
    if (!row || !count(row.inputIndex) || !includes(["created", "failed", "skipped", "unverified"], row.status)) return [];
    const index = row.inputIndex as number;
    const retained = metadata?.rows?.find(row => row.index === index);
    const note = !metadata ? "Request metadata unavailable" : retained ? retained.state === "invalid" ? "Request metadata not recorded: unexpected input shape" : null
      : metadata.state === "invalid" ? "Request metadata not recorded: unexpected input shape"
      : metadata.state === "budget" ? "Request metadata not retained: audit budget"
      : metadata.state !== "captured" ? "Request metadata unavailable"
      : index >= 20 && (metadata.limitedCount ?? 0) > 0 && index < (metadata.totalCount ?? 0) ? "Request metadata sampled; not retained"
      : (metadata.budgetOmittedCount ?? 0) > 0 ? "Request metadata not retained: audit budget" : "Request metadata unavailable";
    return [{ index, status: row.status as string, attachmentId: typeof row.attachmentId === "string" || typeof row.attachmentId === "number" && Number.isSafeInteger(row.attachmentId) ? String(row.attachmentId) : null, note }];
  });
}
