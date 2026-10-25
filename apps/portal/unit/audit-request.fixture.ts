import type { AuditRequestField, RequestAuditV1 } from "../src/audit-request-types";
import type { AuditRecord } from "../src/types";

export const AUDIT_REQUEST_ID = "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a3b";
export const LARGE_IDENTIFIER = "18446744073709551615";
export const STORED_QUERY = 'status = "In Progress"\n<script>alert("never")</script>\u0001\u202E' + "é".repeat(220);
export const auditField = (key: string, patch: Partial<AuditRequestField> = {}): AuditRequestField => ({
  key, label: key, display: "primary", role: "fact", kind: "text", capture: "value", shape: "scalar", state: "captured", supplied: true, value: key, ...patch,
});
export const auditEnvelope = (fields: AuditRequestField[] = []): RequestAuditV1 => ({ version: 1, declarationSha256: "a".repeat(64), status: "complete", fields, budgetOmittedFields: 0, absentOmittedFields: 0 });
export function requestRecord(patch: Partial<AuditRecord> = {}): AuditRecord {
  return { auditId: "request-snapshot", nodeId: "fixture", timestamp: new Date().toISOString(), agentRequestId: "example", brokerRequestId: AUDIT_REQUEST_ID,
    principal: "alice", service: "retired-jira", action: "issue.update", decision: "allow",
    requestAudit: { ...auditEnvelope([
      auditField("issue", { label: "Requested issue", kind: "identifier", role: "target", value: LARGE_IDENTIFIER, encoding: "decimalInteger" }),
      auditField("summary", { label: "Summary", role: "change", value: "A requested title" }),
      auditField("description", { label: "Description supplied", kind: "boolean", capture: "presence", shape: undefined, role: "change", display: "detail", value: true }),
      auditField("notify", { label: "Notify users", kind: "boolean", value: false }),
      auditField("offset", { label: "Requested offset", kind: "number", value: 0 }),
      auditField("empty", { label: "Empty value", value: "" }),
      auditField("nullable", { label: "Nullable value", state: "null", value: undefined }),
      auditField("query", { label: "Requested query", kind: "query", value: STORED_QUERY, truncated: true, originalBytes: 9200 }),
      auditField("raw-change", { label: "Raw change secret label", display: "raw", role: "change", value: "raw-only-canary" }),
      auditField("raw-target", { label: "Raw target secret label", display: "raw", role: "target", value: "raw-target-canary" }),
      auditField("absent", { label: "Absent value", state: "absent", supplied: false, value: undefined }),
      auditField("invalid", { label: "Invalid value", state: "invalid", value: undefined, display: "detail" }),
      auditField("long-id", { label: "Long identity", kind: "identifier", state: "tooLarge", value: undefined, display: "detail" }),
      auditField("budget", { label: "Budget value", state: "budget", value: undefined, display: "detail" }),
    ]), status: "partial" }, ...patch };
}
export function attachmentsField(): AuditRequestField {
  return auditField("attachments", {
    label: "Requested attachments", capture: "records", shape: undefined, kind: "records", role: "change", value: undefined,
    columns: [
      { key: "filename", label: "Filename", display: "primary", role: "fact", kind: "text", capture: "value", shape: "scalar" },
      { key: "raw", label: "Hidden child label", display: "raw", role: "change", kind: "text", capture: "value", shape: "scalar" },
    ],
    rows: Array.from({ length: 20 }, (_, index) => ({ index, state: "captured", cells: {
      filename: { state: "captured", supplied: true, value: `image-${index}.png` }, raw: { state: "captured", supplied: true, value: "raw-child-canary" },
    } })), totalCount: 21, limitedCount: 1, invalidCount: 0, budgetOmittedCount: 0,
  });
}
