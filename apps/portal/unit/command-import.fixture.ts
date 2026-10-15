import type {
  ImportActionDefinition,
  ImportActionRecord,
  ImportBinding,
  ImportDefinition,
  ImportListResult,
  ImportPreviewResult,
  ImportResourceTypeChange,
  ImportResourceTypeDeclaration,
  ImportServiceMetadata,
  ImportedTool
} from "../src/import-types";
import type { PolicyServiceCatalog, ResourceTypeMetadata } from "../src/types";

/**
 * Management results shaped as the Broker serializes a command import of the
 * reference command, crates/agent-access/tests/fixtures/command-imports/ticketing.py:
 * a draft, its discovery of the default manifest, the accepted import, and a
 * refresh to the `v2` manifest. The refresh also keeps a removed `queue` type
 * for one resource and carries the OAuth notice, which the reference command
 * does not produce, so the preview shows those states too.
 */
const stamp = { createdAt: "2026-10-15T09:00:00Z", createdBy: "admin", updatedAt: "2026-10-15T09:00:00Z", updatedBy: "admin" };
const MODES = ["service", "per_user"] as const;

export const PROJECT: ImportResourceTypeDeclaration = {
  id: "project",
  brokerType: "ticketing_project",
  removed: false,
  label: "Project",
  pluralLabel: "Projects",
  pattern: "[A-Z][A-Z0-9]{1,9}",
  maxLength: 10,
  example: "OPS",
  attributes: [
    { name: "region", label: "Region", description: "Hosting region.", required: false, pattern: "[a-z0-9-]{1,32}" },
    { name: "webhookSecret", label: "Webhook secret", description: "Per-project signing secret.", required: false, pattern: null }
  ]
};
const PROJECT_V2: ImportResourceTypeDeclaration = { ...PROJECT, attributes: [...PROJECT.attributes, { name: "owner", label: "Owner", description: "Owning team.", required: false, pattern: null }] };
const QUEUE: ImportResourceTypeDeclaration = { id: "queue", brokerType: "ticketing_queue", removed: false, label: "Queue", pluralLabel: "Queues", pattern: "[a-z][a-z0-9-]{0,31}", maxLength: 32, example: "triage", attributes: [] };

export const OAUTH_NOTICE = "This command declares OAuth, which this Broker does not support yet; static credentials still work.";

function action(name: string, description: string, properties: Record<string, unknown>, required: string[], resources?: { type: string; inputs?: string[] }, credentialModes: readonly string[] = MODES): ImportActionDefinition {
  return {
    action: name,
    source: { name },
    description,
    inputSchema: { type: "object", required, properties, additionalProperties: false },
    annotations: { command: { ...(resources ? { resources } : {}), credentialModes } },
    // The administrator classifies; the manifest's readOnly is only a hint.
    readOnly: false
  };
}
const project = { type: "string" };
export const VIEW = action("issue.view", "Show one issue.", { project, issue: { type: "integer", minimum: 1 } }, ["project", "issue"], { type: "project", inputs: ["/project"] });
export const SEARCH = action("issue.search", "Search issues with a query expression, such as `status = open ORDER BY updated DESC`.", { query: { type: "string", maxLength: 2000 } }, ["query"], { type: "project" });
const SEARCH_V2 = action("issue.search", SEARCH.description, { query: { type: "string", maxLength: 2000 }, limit: { type: "integer", minimum: 1, maximum: 50 } }, ["query"], { type: "project" });
export const CREATE = action("issue.create", "Create an issue in a project.", { project, summary: { type: "string", minLength: 1, maxLength: 200 }, description: { type: "string", maxLength: 4000 } }, ["project", "summary"], { type: "project", inputs: ["/project"] });
export const WHOAMI = action("whoami", "Show the caller and execution context the command received.", {}, []);
const COMMENT = action("issue.comment", "Comment on an issue as the calling user.", { project, issue: { type: "integer", minimum: 1 }, body: { type: "string", minLength: 1, maxLength: 4000 } }, ["project", "issue", "body"], { type: "project", inputs: ["/project"] }, ["per_user"]);

const tool = (definition: ImportActionDefinition, readOnlyHint: boolean): ImportedTool => ({ definition, unsupportedReason: null, readOnlyHint });

export function stdinBinding(ownerMode: ImportBinding["ownerMode"]): ImportBinding {
  return { ownerMode, mechanism: "static_token", delivery: { kind: "stdin" }, status: "configured" };
}

export function commandDefinition(bindings: ImportBinding[] = [stdinBinding("service"), stdinBinding("per_user")]): ImportDefinition {
  return { service: "ticketing", displayName: "Ticketing", adapterKind: "command", endpoint: "command:ticketing", connectionSettings: {}, executionBindings: bindings, discovery: { kind: "anonymous" }, transportAuth: false };
}

export function commandMetadata(version = "1.4.0", resourceTypes: ImportResourceTypeDeclaration[] = [PROJECT]): ImportServiceMetadata {
  return { format: "agent-access-command/1", version, credential: { kind: "username_token", modes: [...MODES] }, verify: true, resourceTypes };
}

function change(entry: Partial<ImportResourceTypeChange> & Pick<ImportResourceTypeChange, "id" | "brokerType" | "change" | "outcome">): ImportResourceTypeChange {
  return { details: [], resourceCount: 0, blockingResources: [], affectedResources: [], editable: false, blocked: false, ...entry };
}

function record(id: string, status: ImportActionRecord["status"], definition: ImportActionDefinition, readOnly: boolean): ImportActionRecord {
  return { definition: { ...definition, readOnly }, status, version: 1, definitionHash: `hash-${id}` };
}

/** A new draft before discovery. */
export function commandDraft(definition = commandDefinition()): ImportPreviewResult {
  return {
    catalogRevision: 3,
    operatorAllowed: true,
    available: false,
    unavailableReason: "Imported service is not enabled.",
    importAuthentication: [],
    scopedMcp: { ready: true, issues: [], truncated: false },
    scopedMcpWarnings: [],
    service: { definition, status: "draft", version: 1, actions: [], slotVersions: {}, ...stamp },
    preview: null,
    resourceTypeChanges: [],
    affectedGrants: [],
    affectedGrantsByAction: {}
  };
}

function preview(data: ImportPreviewResult, tools: ImportedTool[], serviceMetadata: ImportServiceMetadata, notices: string[] = []): ImportPreviewResult["preview"] {
  return {
    service: data.service.definition.service,
    serviceVersion: data.service.version,
    catalogRevision: data.catalogRevision,
    configRevision: "1:fixture",
    credentialVersions: {},
    manifestHash: `manifest-${serviceMetadata.version}`,
    manifest: { protocolVersion: "agent-access-command/1", metadata: { adapterKind: "command", command: "ticketing", commandVersion: serviceMetadata.version, ...(notices.length ? { notices } : {}) }, tools, serviceMetadata },
    createdAt: "2026-10-15T09:05:00Z",
    expiresAt: "2026-10-15T09:20:00Z",
    createdBy: "admin"
  };
}

/** The draft after discovering the default manifest: one added type with an editable Broker type ID. */
export function commandDiscovered(): ImportPreviewResult {
  const data = commandDraft();
  data.catalogRevision = 4;
  data.service.version = 2;
  data.preview = preview(data, [tool(VIEW, true), tool(SEARCH, true), tool(CREATE, false), tool(WHOAMI, true)], commandMetadata());
  data.resourceTypeChanges = [change({ id: "project", brokerType: "ticketing_project", change: "added", outcome: "applied", editable: true })];
  return data;
}

/** The enabled import after accepting the default manifest (and, earlier, a `queue` type). */
export function commandAccepted(): ImportPreviewResult {
  const data = commandDraft();
  data.catalogRevision = 6;
  data.available = true;
  data.unavailableReason = null;
  data.commandVersion = "1.4.0";
  data.service = {
    ...data.service,
    status: "enabled",
    version: 5,
    slotVersions: { execution: "1" },
    acceptedMetadata: commandMetadata("1.4.0", [PROJECT, QUEUE]),
    actions: [record("view", "enabled", VIEW, true), record("search", "enabled", SEARCH, true), record("create", "enabled", CREATE, false), record("whoami", "enabled", WHOAMI, true)]
  };
  return data;
}

/** A refresh to the `v2` manifest: `project` gains an optional attribute and `queue`, no longer declared, is kept for one resource. */
export function commandRefreshed(): ImportPreviewResult {
  const data = commandAccepted();
  data.affectedGrants = ["grant-search"];
  data.affectedGrantsByAction = { "issue.search": ["grant-search"], whoami: [] };
  data.preview = preview(
    data,
    [tool(VIEW, true), tool(SEARCH_V2, true), tool(CREATE, false), tool(COMMENT, false)],
    commandMetadata("1.5.0", [PROJECT_V2, { ...QUEUE, removed: true }]),
    [OAUTH_NOTICE]
  );
  data.resourceTypeChanges = [
    change({ id: "project", brokerType: "ticketing_project", change: "changed", outcome: "applied", details: ["attribute_added"], resourceCount: 2 }),
    change({ id: "queue", brokerType: "ticketing_queue", change: "removed", outcome: "retained", resourceCount: 1, blockingResources: ["triage-queue"] })
  ];
  return data;
}

export function commandImportList(services: ImportPreviewResult[], names = ["ticketing", "deploy-tools"]): ImportListResult {
  return {
    catalogRevision: services[0]?.catalogRevision ?? 1,
    operatorEnabled: true,
    availableKinds: ["mcp_http", "openapi_http", "command"],
    commandImports: names.map((name) => ({ name })),
    importAuthentication: [],
    services: services.map((data) => data.service)
  };
}

/** `GET /v1/resource-types` entries of the accepted types; the removed one accepts no new resources. */
export const COMMAND_RESOURCE_TYPES: ResourceTypeMetadata[] = [
  { id: "ticketing_project", label: "Project", pluralLabel: "Projects", example: "OPS", selectors: ["exact", "all"], attributes: PROJECT.attributes.map(({ name, label, description, required }) => ({ name, label, description, required, secret: true })), importedService: "ticketing" },
  { id: "ticketing_queue", label: "Queue", pluralLabel: "Queues", example: "triage", selectors: ["exact", "all"], importedService: "ticketing", removed: true }
];

/** The accepted actions as the policy catalog lists them. */
export function commandPolicyService(data: ImportPreviewResult): PolicyServiceCatalog {
  return {
    service: "ticketing",
    displayName: "Ticketing",
    surface: "invoke",
    available: data.service.status === "enabled",
    actions: data.service.actions.map((entry) => {
      const resources = (entry.definition.annotations as { command?: { resources?: { type: string; inputs?: string[] } } }).command?.resources;
      return {
        action: entry.definition.action,
        readOnly: entry.definition.readOnly,
        description: entry.definition.description,
        requiredScopeTypes: resources ? ["ticketing_project"] : [],
        credentialModes: ["service", "per_user"],
        lookupRequired: false,
        inputSchema: entry.definition.inputSchema,
        resourcesCheckedBy: resources?.inputs ? ("broker" as const) : ("command" as const)
      };
    }),
    resourceScopes: {},
    configuredCredentialModes: ["service", "per_user"],
    lookupCredentialConfigured: false
  };
}
