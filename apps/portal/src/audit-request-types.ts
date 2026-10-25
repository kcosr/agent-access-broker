/** Event-time request facts. Future versions remain untouched in Raw. */
export type AuditKind = "text" | "query" | "identifier" | "path" | "email" | "date" | "number" | "boolean" | "bytes" | "records";
export type AuditPlacement = "primary" | "detail" | "raw";
export type AuditCapture = "value" | "presence" | "itemCount" | "utf8ByteCount" | "records";
export type AuditFieldMetadata = {
  key: string;
  label: string;
  display: AuditPlacement;
  role: "target" | "change" | "fact";
  kind: AuditKind;
  capture: AuditCapture;
  shape?: "scalar" | "list";
};
export type AuditValueState = "captured" | "absent" | "null" | "invalid" | "tooLarge" | "budget";
export type AuditScalar = {
  state: AuditValueState;
  value?: string | number | boolean;
  encoding?: "decimalInteger";
  truncated?: true;
  originalBytes?: number;
};
export type AuditCollectionCounts = {
  totalCount: number;
  limitedCount: number;
  invalidCount: number;
  budgetOmittedCount: number;
};
export type AuditCell = AuditScalar & Partial<AuditCollectionCounts> & {
  supplied: boolean | null;
  items?: Array<AuditScalar & { index: number }>;
};
export type AuditRequestField = AuditFieldMetadata & AuditCell & {
  columns?: AuditFieldMetadata[];
  rows?: Array<{ index: number; state: "captured" | "invalid"; cells?: Record<string, AuditCell> }>;
};
export type RequestAuditV1 = {
  version: 1;
  declarationSha256?: string;
  status: "complete" | "partial" | "unavailable";
  reason?: "projectionFailed";
  fields: AuditRequestField[];
  budgetOmittedFields: number;
  absentOmittedFields: number;
};

/** Reviewed declaration metadata, never invocation values. */
export type AuditInputRule = {
  key: string;
  pointer: string;
  capture: AuditCapture | "omit";
  label?: string;
  display?: AuditPlacement;
  role?: "target" | "change" | "fact";
  kind?: AuditKind;
  shape?: "scalar" | "list";
  maxBytes?: number;
  overflow?: "omit" | "prefix";
  fields?: AuditInputRule[];
};
