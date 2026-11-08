import type { ImportActionDefinition, ImportBinding, ImportDelivery, ImportDiscovery, ImportGatewayBinding, ImportSecurityScheme } from "../import-types";

export const OPENAPI_GATEWAY_KIND = "openapi_gateway";
export const OPENAPI_ACTIONS_KIND = "openapi_http";
export type OpenApiExposure = typeof OPENAPI_ACTIONS_KIND | typeof OPENAPI_GATEWAY_KIND;

export function isOpenApiImport(kind: string): kind is OpenApiExposure {
  return kind === OPENAPI_ACTIONS_KIND || kind === OPENAPI_GATEWAY_KIND;
}

export function openApiExposureLabel(kind: OpenApiExposure): string {
  return kind === OPENAPI_GATEWAY_KIND ? "HTTP gateway" : "Actions/tools";
}

export const GATEWAY_AUTHORITY_NOTICE = "Whole-action access: a grant permits every parameter value allowed by the operation and the selected upstream credential. Path parameters do not restrict access to individual resources.";
export const GATEWAY_BODY_NOTICE = "Body schema not validated by gateway. The Broker checks body presence, media type and transfer limits; JSON and form fields are documentation only.";
export const GATEWAY_TEMPLATE_NOTICE = "Include backend paths that take precedence over accepted templates, even when you do not accept those operations. The Broker retains source-derived denial guards; it cannot discover an undeclared backend route.";

/** Broker ingress authentication is independent of the document's upstream scheme. */
export function gatewayIngressLabel(binding: ImportGatewayBinding): string {
  const labels = binding.authModes.map((mode) => mode === "bearer_broker_token" ? "Broker Bearer token" : mode === "basic_broker_token" ? "Broker Basic token" : mode);
  if (binding.allowForwardedIdentity) labels.push("Approved trusted-ingress identity");
  return labels.join("; ");
}

/** Preserve frozen settings exactly; anonymous execution never retains a static security scheme. */
export function gatewayConnectionSettings(existing: Record<string, string> | undefined, mutable: boolean, draft: Parameters<typeof openApiConnectionSettings>[2], authentication: "anonymous" | "static"): Record<string, string> {
  if (existing && !mutable) return existing;
  const selected = authentication === "anonymous" ? { ...draft, securityScheme: "" } : draft;
  const settings = openApiConnectionSettings(existing, mutable, selected);
  const { securityScheme: _scheme, ...withoutScheme } = settings;
  return { ...(authentication === "anonymous" ? withoutScheme : settings), executionAuthentication: authentication };
}

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
  /** Generated gateways forward raw HTTP; Actions/tools build typed requests. */
  gateway?: true;
  security?: ImportSecurityScheme;
  anonymous?: true;
  /** Undefined for unsupported placeholders whose body plan was never compiled. */
  requestMedia?: string | null;
  requestBodyRequired?: boolean;
  requiredBodyFields?: string[];
  requestMediaTypes?: string[];
  parameters?: Array<{ name: string; location: string; required: boolean; style: string; explode: boolean }>;
  responseHeaders?: Array<{ status: string; names: string[] }>;
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
  const annotationsObject = schemaObject(definition.annotations);
  if (annotationsObject && Object.hasOwn(annotationsObject, "openapiGateway")) return gatewayOperation(annotationsObject.openapiGateway);
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

/** Read only the explicit gateway plan version, never interpret invoke-plan body rules as raw HTTP. */
function gatewayOperation(value: unknown): OpenApiOperation | null {
  const plan = schemaObject(value);
  if (plan?.version !== 1 || typeof plan.method !== "string" || typeof plan.path !== "string") return null;
  const security = schemaObject(plan.security);
  const authentication = security?.kind;
  const compiled = authentication === "anonymous" || authentication === "basic" || authentication === "bearer" || authentication === "raw_header";
  const requestBody = schemaObject(plan.requestBody);
  const mediaTypes = requestBody?.mediaTypes;
  const body = requestBody && typeof requestBody.required === "boolean" && Array.isArray(mediaTypes) && mediaTypes.every((entry): entry is string => typeof entry === "string")
    ? { requestBodyRequired: requestBody.required, requestMediaTypes: mediaTypes }
    : compiled && !Object.hasOwn(plan, "requestBody") ? { requestMediaTypes: [] } : {};
  const parameters = Array.isArray(plan.parameters) ? plan.parameters.flatMap((entry) => {
    const parameter = schemaObject(entry);
    return parameter && typeof parameter.name === "string" && typeof parameter.location === "string" && typeof parameter.required === "boolean" && typeof parameter.style === "string" && typeof parameter.explode === "boolean"
      ? [{ name: parameter.name, location: parameter.location, required: parameter.required, style: parameter.style, explode: parameter.explode }]
      : [];
  }) : undefined;
  const responses = schemaObject(plan.responses);
  const responseHeaders = responses ? Object.entries(responses).flatMap(([status, entry]) => {
    const response = schemaObject(entry);
    if (!Array.isArray(response?.headers)) return [];
    const names = response.headers.flatMap((header) => {
      const item = schemaObject(header);
      return typeof item?.name === "string" ? [item.name] : [];
    });
    return names.length ? [{ status, names }] : [];
  }) : undefined;
  return {
    method: plan.method.toUpperCase(), path: plan.path, gateway: true,
    ...body,
    ...(parameters ? { parameters } : {}),
    ...(responseHeaders ? { responseHeaders } : {}),
    noContentStatuses: [],
    ...(authentication === "anonymous" ? { anonymous: true } : {}),
    ...(security && typeof security.scheme === "string" && (authentication === "bearer" || authentication === "basic" || authentication === "raw_header" && typeof security.header === "string")
      ? { security: { name: security.scheme, kind: authentication, ...(typeof security.header === "string" ? { header: security.header } : {}) } } : {})
  };
}

export function openApiSchemeLabel(scheme: ImportSecurityScheme): string {
  return `${scheme.name} · ${scheme.kind === "bearer" ? "Authorization: Bearer" : scheme.kind === "basic" ? "Authorization: Basic" : scheme.header}`;
}
