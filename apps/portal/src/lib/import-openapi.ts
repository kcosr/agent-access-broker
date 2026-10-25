import type { ImportActionDefinition, ImportBinding, ImportDelivery, ImportDiscovery, ImportSecurityScheme } from "../import-types";

export type OpenApiDocumentSource = "url" | "upload";

export function openApiDocumentSource(settings: Record<string, string> | undefined): OpenApiDocumentSource {
  return settings?.definitionSource === "upload" ? "upload" : "url";
}

export function openApiConnectionSettings(existing: Record<string, string> | undefined, mutable: boolean, draft: { source: OpenApiDocumentSource; definitionUrl: string; definitionAuthKind: string; definitionAuthHeader: string; securityScheme: string }): Record<string, string> {
  // CLI-created services may omit defaults. Presentation and limit edits must
  // preserve a frozen definition exactly.
  const sameSource = draft.source === openApiDocumentSource(existing);
  const sameDocument = draft.source === "upload" || draft.definitionUrl.trim() === existing?.definitionUrl
    && draft.definitionAuthKind === (existing?.definitionAuthKind ?? "none")
    && draft.definitionAuthHeader.trim() === (existing?.definitionAuthHeader ?? "");
  if (existing && (!mutable || sameSource && sameDocument && draft.securityScheme === (existing.securityScheme ?? ""))) return existing;
  if (draft.source === "upload") return { definitionSource: "upload", ...(draft.securityScheme ? { securityScheme: draft.securityScheme } : {}) };
  return { definitionUrl: draft.definitionUrl.trim(), definitionAuthKind: draft.definitionAuthKind, ...(draft.definitionAuthKind === "raw_header" ? { definitionAuthHeader: draft.definitionAuthHeader.trim() } : {}), ...(draft.securityScheme ? { securityScheme: draft.securityScheme } : {}) };
}

export function openApiSecuritySchemes(manifest?: ImportDiscovery): ImportSecurityScheme[] {
  const metadata = manifest?.metadata as { securitySchemes?: unknown } | undefined;
  if (!Array.isArray(metadata?.securitySchemes)) return [];
  return metadata.securitySchemes.filter((value): value is ImportSecurityScheme => Boolean(value && typeof value === "object" && typeof value.name === "string" && (value.kind === "bearer" || value.kind === "basic" || value.kind === "raw_header" && typeof value.header === "string")));
}

export function openApiDelivery(scheme: ImportSecurityScheme): ImportDelivery {
  return scheme.kind === "raw_header" ? { kind: "raw_header", name: scheme.header! } : { kind: scheme.kind };
}

export function openApiBindings(existing: ImportBinding[], shared: boolean, personal: boolean, delivery: ImportDelivery): ImportBinding[] {
  const modes = existing.map((binding) => binding.ownerMode);
  if (shared && !modes.includes("service")) modes.push("service");
  if (personal && !modes.includes("per_user")) modes.push("per_user");
  return modes.map((ownerMode) => ({ ownerMode, mechanism: "static_token", status: "configured", delivery }));
}

export type OpenApiOperation = {
  method: string;
  path: string;
  security?: ImportSecurityScheme;
  /** Undefined for unsupported placeholders whose body plan was never compiled. */
  requestMedia?: string | null;
  requestBodyRequired?: boolean;
  requiredBodyFields?: string[];
  noContentStatuses: string[];
};

function schemaObject(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

/** Presentation only: follow bounded local references, omitting summaries we cannot establish. */
function simpleObjectSchema(root: Record<string, unknown>, value: unknown): Record<string, unknown> | undefined {
  const seen = new Set<string>();
  for (let depth = 0; depth < 32; depth++) {
    const schema = schemaObject(value);
    if (!schema || Object.hasOwn(schema, "$id")) return undefined;
    if (!Object.hasOwn(schema, "$ref")) {
      if (schema.type !== "object" || ["allOf", "anyOf", "oneOf", "not", "if", "then", "else", "dependentRequired", "dependentSchemas", "const", "enum", "$dynamicRef", "$recursiveRef"].some((key) => Object.hasOwn(schema, key))) return undefined;
      return schema;
    }
    if (typeof schema.$ref !== "string" || !schema.$ref.startsWith("#/") || seen.has(schema.$ref)
      || Object.keys(schema).some((key) => !["$ref", "title", "description", "summary", "default", "example", "examples", "$defs"].includes(key))) return undefined;
    seen.add(schema.$ref);
    let pointer: string;
    try { pointer = decodeURIComponent(schema.$ref.slice(1)); } catch { return undefined; }
    value = root;
    for (const part of pointer.slice(1).split("/")) {
      const object = schemaObject(value);
      const key = part.replace(/~1/g, "/").replace(/~0/g, "~");
      if (!object || !Object.hasOwn(object, key)) return undefined;
      value = object[key];
    }
  }
  return undefined;
}

function requiredNames(schema: Record<string, unknown> | undefined): string[] | undefined {
  if (!schema) return undefined;
  const names = schema.required ?? [];
  return Array.isArray(names) && names.every((name): name is string => typeof name === "string") ? names : undefined;
}

function bodySummary(definition: ImportActionDefinition, form: unknown): Pick<OpenApiOperation, "requestBodyRequired" | "requiredBodyFields"> {
  const root = simpleObjectSchema(definition.inputSchema, definition.inputSchema);
  const properties = schemaObject(root?.properties);
  const required = requiredNames(root);
  const bodyRequired = properties && Object.hasOwn(properties, "body") && required ? required.includes("body") : undefined;
  const formFields = schemaObject(form)?.fields;
  const fields = form
    ? Array.isArray(formFields) && formFields.every((field) => typeof field?.name === "string" && typeof field.required === "boolean")
      ? formFields.filter((field) => field.required).map((field) => field.name as string)
      : undefined
    : requiredNames(simpleObjectSchema(definition.inputSchema, properties?.body));
  return {
    ...(bodyRequired !== undefined ? { requestBodyRequired: bodyRequired } : {}),
    ...(fields?.length ? { requiredBodyFields: fields } : {})
  };
}

export function openApiOperation(definition: ImportActionDefinition): OpenApiOperation | null {
  const annotations = definition.annotations as { openapi?: { method?: unknown; path?: unknown; security?: { scheme?: unknown; kind?: unknown; header?: unknown }; requestBody?: unknown; formBody?: unknown; responses?: Record<string, { contentType?: unknown; schema?: unknown }> } } | null;
  const plan = annotations?.openapi;
  if (typeof plan?.method !== "string" || typeof plan.path !== "string") return null;
  const security = plan.security;
  return {
    method: plan.method.toUpperCase(), path: plan.path,
    ...(typeof plan.requestBody === "boolean" ? { requestMedia: plan.requestBody ? plan.formBody ? "application/x-www-form-urlencoded" : "application/json" : null } : {}),
    ...(plan.requestBody === true ? bodySummary(definition, plan.formBody) : {}),
    noContentStatuses: Object.entries(plan.responses ?? {}).filter(([, response]) => response?.contentType === null && response.schema === null).map(([status]) => status),
    ...(security && typeof security.scheme === "string" && (security.kind === "bearer" || security.kind === "basic" || security.kind === "raw_header" && typeof security.header === "string") ? { security: { name: security.scheme, kind: security.kind, ...(typeof security.header === "string" ? { header: security.header } : {}) } } : {})
  };
}

export function openApiSchemeLabel(scheme: ImportSecurityScheme): string {
  return `${scheme.name} · ${scheme.kind === "bearer" ? "Authorization: Bearer" : scheme.kind === "basic" ? "Authorization: Basic" : scheme.header}`;
}
