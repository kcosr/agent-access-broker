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
  const rows: ImportReviewRow[] = data.preview.manifest.tools.map((tool, toolIndex) => {
    const key = importSourceKey(tool.definition.source);
    seen.add(key);
    const old = existing.get(key) ?? data.service.actions.find((action) => action.status === "retired" && importSourceKey(action.definition.source) === key);
    const retired = old?.status === "retired";
    const changed = old && behaviorChanged(old.definition, tool.definition);
    const metadataChanged = old && (old.definition.description !== tool.definition.description || importSourceKey(old.definition.annotations) !== importSourceKey(tool.definition.annotations));
    const reason = tool.unsupportedReason || (retired ? "Review this action under a new action name. Its retired identity and grants remain unchanged." : undefined);
    const change = tool.unsupportedReason ? "Unsupported" : retired ? "Retired – new identity required" : !old ? "New" : changed ? "Changed" : metadataChanged ? "Metadata changed" : "Unchanged";
    return { key, tool, existing: old, change, reason, scopedMcpWarning: warnings.get(toolIndex), selectable: !tool.unsupportedReason, selected: !tool.unsupportedReason && old?.status === "enabled" && !changed, action: !retired && old ? old.definition.action : tool.definition.action, label: (!retired && old ? old.definition.label : tool.definition.label) ?? "", readOnly: !retired && !changed && old?.definition.readOnly === true };
  });
  for (const old of data.service.actions) {
    const retired = old.status === "retired";
    if (retired || !seen.has(importSourceKey(old.definition.source))) rows.push({ key: `retained:${old.definition.action}`, tool: { definition: old.definition, unsupportedReason: null, readOnlyHint: null }, existing: old, change: retired ? "Retired" : "Removed", reason: retired ? "This identity is permanently retired. Its grants do not transfer to a replacement action." : "Absent from this complete discovery. Its identity and grants are retained.", selectable: false, selected: false, action: old.definition.action, label: old.definition.label ?? "", readOnly: old.definition.readOnly });
  }
  return rows;
}
export function selectedImportActions(rows: ImportReviewRow[]): ImportSelection[] {
  return rows.filter((row) => row.selected && row.selectable).map((row) => ({ source: row.tool.definition.source, action: row.action.trim(), ...(row.label.trim() ? { label: row.label.trim() } : {}), readOnly: row.readOnly }));
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
    const name = row.action.trim();
    if (name.length > 256 || !/^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$/.test(name) || name.startsWith(`${service.definition.service}.`)) return "Action names must use lowercase words, dots, hyphens or underscores, and must not repeat the service prefix.";
    if (names.has(name) || service.actions.some((old) => old.definition.action === name && (old.status === "retired" || importSourceKey(old.definition.source) !== row.key))) return `Action name ${name} is already used.`;
    if (row.existing && row.existing.status !== "retired" && name !== row.existing.definition.action) return "Accepted action names cannot be changed.";
    names.add(name);
  }
  return null;
}
export function affectedImportGrants(data: ImportPreviewResult, rows: ImportReviewRow[]): string[] {
  return [...new Set(rows.filter((row) => row.selected && row.selectable && row.existing && row.existing.status !== "retired"
    && (row.existing.status !== "enabled" || row.readOnly !== row.existing.definition.readOnly || behaviorChanged(row.existing.definition, row.tool.definition)))
    .flatMap((row) => data.affectedGrantsByAction[row.existing!.definition.action] ?? []))].sort();
}
export function importVersions(data: { catalogRevision: number; service: ImportedServiceRecord }) {
  return { expectedVersion: data.service.version, expectedCatalogRevision: data.catalogRevision };
}
/**
 * A rejection that names what to fix, as `message (a; b)` or `message: a; b`,
 * split into the message and its items, such as the resources that block a
 * resource type change or the retained grants a change would invalidate. Any
 * other message stays whole.
 */
export function importErrorList(text: string): { message: string; items: string[] } {
  const listed = /^(.*\S) \(([^()]*[;:][^()]*)\)$/s.exec(text) ?? /^([^:]*?): (.*;.*)$/s.exec(text);
  if (!listed) return { message: text, items: [] };
  return { message: listed[1]!, items: listed[2]!.split("; ").map((item) => item.trim()).filter(Boolean) };
}
