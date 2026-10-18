import type { ImportActionRecord, ImportPreviewResult, ImportScopedMcpWarning, ImportSelection, ImportedServiceRecord, ImportedTool } from "../import-types";

/** Adapter locators are compared by value, independently of JSON key order. */
export function importSourceKey(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(importSourceKey).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${importSourceKey(item)}`).join(",")}}`;
  return JSON.stringify(value) ?? "null";
}
export type ImportReviewRow = {
  key: string;
  tool: ImportedTool;
  existing?: ImportActionRecord;
  change: "New" | "Changed" | "Metadata changed" | "Unchanged" | "Removed" | "Unsupported" | "Retired" | "Retired – new identity required";
  reason?: string;
  scopedMcpWarning?: ImportScopedMcpWarning;
  selectable: boolean;
  selected: boolean;
  action: string;
  label: string;
  readOnly: boolean;
  secretInputs: Array<{ pointer: string }>;
  secretInputCandidates: string[];
};
/** Only the MCP annotation title is presentation metadata; all other fields retain their meaning. */
function behavioralAnnotations(value: unknown): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const annotations = value as Record<string, unknown>;
  const tool = annotations.toolAnnotations;
  if (!tool || typeof tool !== "object" || Array.isArray(tool)) return value;
  return { ...annotations, toolAnnotations: Object.fromEntries(Object.entries(tool).filter(([key]) => key !== "title")) };
}
function behaviorChanged(old: ImportActionRecord["definition"], next: ImportActionRecord["definition"]): boolean {
  return importSourceKey(old.inputSchema) !== importSourceKey(next.inputSchema)
    || importSourceKey(old.outputSchema) !== importSourceKey(next.outputSchema)
    || importSourceKey(behavioralAnnotations(old.annotations)) !== importSourceKey(behavioralAnnotations(next.annotations));
}
export function importReviewRows(data: ImportPreviewResult): ImportReviewRow[] {
  if (!data.preview) return [];
  const existing = new Map(data.service.actions.filter((action) => action.status !== "retired").map((action) => [importSourceKey(action.definition.source), action]));
  const seen = new Set<string>();
  const warnings = new Map(data.scopedMcpWarnings.map((warning) => [warning.toolIndex, warning]));
  const candidates = new Map(data.secretInputCandidates.map((candidate) => [candidate.toolIndex, candidate.pointers]));
  const rows: ImportReviewRow[] = data.preview.manifest.tools.map((tool, toolIndex) => {
    const key = importSourceKey(tool.definition.source);
    seen.add(key);
    const old = existing.get(key) ?? data.service.actions.find((action) => action.status === "retired" && importSourceKey(action.definition.source) === key);
    const retired = old?.status === "retired";
    const changed = old && behaviorChanged(old.definition, tool.definition);
    const metadataChanged = old && (old.definition.description !== tool.definition.description || importSourceKey(old.definition.annotations) !== importSourceKey(tool.definition.annotations));
    const reason = tool.unsupportedReason || (retired ? "Review this action under a new action name. Its retired identity and grants remain unchanged." : undefined);
    const change = tool.unsupportedReason ? "Unsupported" : retired ? "Retired – new identity required" : !old ? "New" : changed ? "Changed" : metadataChanged ? "Metadata changed" : "Unchanged";
    return { key, tool, secretInputs: !retired && old ? old.secretInputs : [], secretInputCandidates: candidates.get(toolIndex) ?? [], existing: old, change, reason, scopedMcpWarning: warnings.get(toolIndex), selectable: !tool.unsupportedReason, selected: !tool.unsupportedReason && old?.status === "enabled" && !changed, action: !retired && old ? old.definition.action : tool.definition.action, label: (!retired && old ? old.definition.label : tool.definition.label) ?? "", readOnly: !retired && !changed && old?.definition.readOnly === true };
  });
  for (const old of data.service.actions) {
    const retired = old.status === "retired";
    if (retired || !seen.has(importSourceKey(old.definition.source))) rows.push({ secretInputs: old.secretInputs, secretInputCandidates: [], key: `retained:${old.definition.action}`, tool: { definition: old.definition, unsupportedReason: null, readOnlyHint: null }, existing: old, change: retired ? "Retired" : "Removed", reason: retired ? "This identity is permanently retired. Its grants do not transfer to a replacement action." : "Absent from this complete discovery. Its identity and grants are retained.", selectable: false, selected: false, action: old.definition.action, label: old.definition.label ?? "", readOnly: old.definition.readOnly });
  }
  return rows;
}
export function selectedImportActions(rows: ImportReviewRow[]): ImportSelection[] {
  return rows.filter((row) => row.selected && row.selectable).map((row) => ({ source: row.tool.definition.source, action: row.action.trim(), ...(row.label.trim() ? { label: row.label.trim() } : {}), readOnly: row.readOnly, secretInputs: [...row.secretInputs].sort((a, b) => a.pointer.localeCompare(b.pointer)) }));
}
/** What an adapter's discovered items are called: OpenAPI operations, command actions, MCP tools. */
export function importItemNoun(adapterKind: string): "operation" | "action" | "tool" {
  return adapterKind === "openapi_http" ? "operation" : adapterKind === "command" ? "action" : "tool";
}
/**
 * Whether the preview may be accepted with no selections: a command preview
 * for an import that already has accepted actions, which then applies only
 * its service metadata and resource type changes. A draft needs a selection.
 */
export function metadataOnlyAcceptance(data: ImportPreviewResult): boolean {
  return data.service.actions.length > 0 && Boolean(data.preview?.manifest.serviceMetadata);
}
export function importSelectionError(data: ImportPreviewResult, rows: ImportReviewRow[]): string | null {
  const service = data.service;
  const selected = rows.filter((row) => row.selected && row.selectable);
  if (!selected.length) return metadataOnlyAcceptance(data) ? null : `Select at least one supported ${importItemNoun(service.definition.adapterKind)}.`;
  const names = new Set<string>();
  for (const row of selected) {
    if (row.secretInputs.some(({ pointer }) => !row.secretInputCandidates.includes(pointer))) return "Remove or correct receiver fields that are no longer eligible before accepting this action.";
    if (row.secretInputs.length > 16) return "Select at most 16 secret receiver fields per action.";
    const name = row.action.trim();
    if (name.length > 256 || !/^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$/.test(name) || name.startsWith(`${service.definition.service}.`)) return "Action names must use lowercase words, dots, hyphens or underscores, and must not repeat the service prefix.";
    if (names.has(name) || service.actions.some((old) => old.definition.action === name && (old.status === "retired" || importSourceKey(old.definition.source) !== row.key))) return `Action name ${name} is already used.`;
    if (row.existing && row.existing.status !== "retired" && name !== row.existing.definition.action) return "Accepted action names cannot be changed.";
    names.add(name);
  }
  return null;
}
/** `record[key]` only when the record itself has it: keys such as action names may name `Object.prototype` members. */
function ownEntry<T>(record: Readonly<Record<string, T>>, key: string): T | undefined {
  return Object.hasOwn(record, key) ? record[key] : undefined;
}
export function affectedImportGrants(data: ImportPreviewResult, rows: ImportReviewRow[]): string[] {
  return [...new Set(rows.filter((row) => row.selected && row.selectable && row.existing && row.existing.status !== "retired"
    && (row.existing.status !== "enabled" || row.readOnly !== row.existing.definition.readOnly || behaviorChanged(row.existing.definition, row.tool.definition) || importSourceKey([...row.secretInputs].sort((a, b) => a.pointer.localeCompare(b.pointer))) !== importSourceKey([...row.existing.secretInputs].sort((a, b) => a.pointer.localeCompare(b.pointer)))))
    .flatMap((row) => ownEntry(data.affectedGrantsByAction, row.existing!.definition.action) ?? []))].sort();
}
export function importVersions(data: { catalogRevision: number; service: ImportedServiceRecord }) {
  return { expectedVersion: data.service.version, expectedCatalogRevision: data.catalogRevision };
}

export const RECEIVER_NOTICE = "This action will return a completion receipt only. Its upstream response content will be hidden for every call. Use a separately authorized read action to inspect stored metadata.";
/** Display source details for a server-validated candidate; never determines eligibility. */
export function receiverFieldSchema(schema: Record<string, unknown>, pointer: string): Record<string, unknown> | undefined {
  let node: unknown = schema;
  for (const part of pointer.slice(8).split("/")) {
    if (!node || typeof node !== "object") return undefined;
    const properties = (node as Record<string, unknown>).properties;
    if (!properties || typeof properties !== "object") return undefined;
    const key = part.replaceAll("~1", "/").replaceAll("~0", "~");
    if (!Object.hasOwn(properties, key)) return undefined;
    node = (properties as Record<string, unknown>)[key];
  }
  return node && typeof node === "object" ? node as Record<string, unknown> : undefined;
}
/** Presentation of the derived contract; the server revalidates all selected paths. */
export function receiverSchemaPreview(row: ImportReviewRow): Record<string, unknown> {
  const schema = structuredClone(row.tool.definition.inputSchema);
  for (const { pointer } of row.secretInputs) {
    const leaf = receiverFieldSchema(schema, pointer);
    if (!leaf) continue;
    const literal = { ...leaf, writeOnly: true };
    for (const key of Object.keys(leaf)) delete leaf[key];
    Object.assign(leaf, { oneOf: [literal, { type: "object", required: ["secretRef"], additionalProperties: false, properties: { secretRef: { type: "string", pattern: "^sr_[A-Za-z0-9_-]{43}$", minLength: 46, maxLength: 46 }, expiresAt: { type: "string", format: "date-time", maxLength: 64, description: "Informational expiry; the Broker’s stored deadline is authoritative." } } }], writeOnly: true });
  }
  return schema;
}
