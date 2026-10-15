import { vi } from "vitest";
vi.mock("../src/app/session", () => ({ useSession: () => ({ session: { authenticated: true, role: "admin", selfServiceEnabled: true, principal: "admin" } }) }));
import { describe, expect, test } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { ImportPreviewResult, ImportResourceTypeChange } from "../src/import-types";
import {
  blockedTypeChanges,
  chosenResourceTypeIds,
  commandBindings,
  commandCredentialText,
  commandName,
  commandNotices,
  commandResourceCheck,
  resourceCheckText,
  resourceTypeEffectsText,
  resourceTypeIdIssues,
  type ResourceTypeIdChoices
} from "../src/lib/import-command";
import { affectedImportGrants, importReviewRows, importSelectionError, metadataOnlyAcceptance, selectedImportActions } from "../src/lib/imports";
import { creatableResourceTypes, indexResourceTypes } from "../src/lib/resource-types";
import { ImportEditor } from "../src/features/catalog/import-editor";
import { ImportErrorAlert, ImportReview } from "../src/features/catalog/import-review";
import { ApiError } from "../src/api";
import { ImportTokenModal } from "../src/features/catalog/import-token-modal";
import { inlineFrame } from "../src/features/catalog/catalog-ui";
import { GrantActionSelector } from "../src/components/grant-actions";
import { RESOURCE_TYPES } from "./resource-types.fixture";
import { COMMAND_RESOURCE_TYPES, CREATE, OAUTH_NOTICE, PROJECT, PROTOTYPE_NAMES, REFRESHED_RESOURCE_TYPES, SEARCH, VIEW, WHOAMI, commandAccepted, commandDefinition, commandDiscovered, commandRefreshed, prototypeNamedDiscovered, stdinBinding } from "./command-import.fixture";

/** An accepted MCP or OpenAPI import with a pending refresh: no service metadata. */
function urlImport(kind: "mcp_http" | "openapi_http"): ImportPreviewResult {
  const data = commandRefreshed();
  const source = (action: string) => (kind === "mcp_http" ? { toolName: action } : { operationId: action });
  data.service.definition = {
    ...data.service.definition,
    adapterKind: kind,
    endpoint: "https://api.example.test/v1",
    executionBindings: [{ ownerMode: "service", mechanism: "static_token", delivery: { kind: "bearer" }, status: "configured" }],
    discovery: { kind: "execution" }
  };
  delete data.service.acceptedMetadata;
  data.service.actions = data.service.actions.map((action) => ({ ...action, definition: { ...action.definition, source: source(action.definition.action), annotations: {} } }));
  data.preview!.manifest = {
    protocolVersion: kind === "mcp_http" ? "2026-07-28" : "3.1.0",
    metadata: {},
    tools: data.preview!.manifest.tools.map((tool) => ({ ...tool, definition: { ...tool.definition, source: source(tool.definition.action), annotations: {} } }))
  };
  data.resourceTypeChanges = [];
  return data;
}

function renderEditor(data?: ImportPreviewResult, commandImports = ["ticketing", "deploy-tools"]) {
  return renderToStaticMarkup(createElement(ImportEditor, { principal: "admin", data, availableKinds: ["command"], commandImports, authentication: [], onClose: () => {}, onSave: async () => true, frame: inlineFrame }));
}
/** Typed Broker type ID choices, keyed by source type id. */
function choices(entries: Record<string, string>): ResourceTypeIdChoices {
  return new Map(Object.entries(entries));
}

function renderReview(data: ImportPreviewResult) {
  return renderToStaticMarkup(createElement(ImportReview, { data, onClose: () => {}, onAccept: async () => true, frame: inlineFrame }));
}
/** The review's Accept button, whose disabled state gates submission. */
function acceptButton(html: string) {
  return /<button[^>]*>[^<]*Accept selected actions/.exec(html)?.[0] ?? "";
}

describe("command import configuration", () => {
  test("the endpoint names an approved command, never a path, and credentials go on stdin in the chosen modes", () => {
    expect(commandName("command:ticketing")).toBe("ticketing");
    expect(commandName("https://mcp.example.test/mcp")).toBeNull();
    expect(commandBindings([], false, false)).toEqual([]);
    expect(commandBindings([], true, true)).toEqual([stdinBinding("service"), stdinBinding("per_user")]);
    // Stored bindings keep their order and shape, so unchanged modes are not a credential change.
    const stored = [stdinBinding("per_user")];
    expect(commandBindings(stored, true, true)).toEqual([stdinBinding("per_user"), stdinBinding("service")]);
    expect(commandBindings(stored, false, true)[0]).toBe(stored[0]);
  });

  test("new imports pick an approved command by name and may choose no credential", () => {
    const html = renderEditor();
    expect(html).toContain("Local command");
    expect(html).toContain('<option value="ticketing">ticketing</option>');
    expect(html).toContain('<option value="deploy-tools">deploy-tools</option>');
    expect(html).toContain("its path is not shown");
    expect(html).not.toContain("HTTP MCP endpoint");
    expect(html).not.toContain("API base URL");
    expect(html).toContain("No credential: for a command that needs none");
    expect(html).toContain("Credentials reach the command only in the request on its stdin");
    const single = renderEditor(undefined, ["ticketing"]);
    expect(single).toMatch(/<option value="ticketing" selected="">ticketing<\/option>/);
  });

  test("the hint names the modes the manifest declares and warns about undeclared ones", () => {
    const draft = commandDiscovered();
    draft.preview!.manifest.serviceMetadata = { ...draft.preview!.manifest.serviceMetadata!, credential: { kind: "token", modes: ["per_user"] } };
    const html = renderEditor(draft);
    expect(html).toContain("The command&#x27;s manifest declares a token credential in personal mode.");
    expect(html).toContain("The manifest does not declare shared mode; it declares personal only.");
    const matching = commandDiscovered();
    expect(renderEditor(matching)).toContain("declares a username and token credential in shared and personal mode.");
    expect(renderEditor(matching)).not.toContain("does not declare");
    const free = commandDiscovered();
    free.preview!.manifest.serviceMetadata = { ...free.preview!.manifest.serviceMetadata!, credential: null };
    expect(renderEditor(free)).toContain("declares no credential: clear both modes.");
    expect(renderEditor(free)).toContain("The manifest does not declare shared and personal mode.");
  });

  test("without approved commands the editor explains the operator step and cannot create a draft", () => {
    const html = renderEditor(undefined, []);
    expect(html).toContain("No approved commands");
    expect(html).toContain("[command_imports.&lt;name&gt;]");
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>[^<]*Create draft/);
  });

  test("an accepted import keeps its command and stored modes and offers only declared ones", () => {
    const data = commandAccepted();
    data.service.definition = commandDefinition([stdinBinding("service")]);
    const html = renderEditor(data, []);
    expect(html).toMatch(/<select disabled=""[^>]*><option value="ticketing" selected="">ticketing \(no longer approved\)<\/option><\/select>/);
    expect(html).toContain("Operator configuration no longer approves this command");
    expect(html).toContain("declares a username and token credential in shared and personal mode. Existing credential modes are retained");
    // The stored shared mode stays; the declared personal mode can be added.
    expect(html).toMatch(/<input disabled="" id="[^"]+" type="checkbox" class="wb-checkbox" checked=""\/><span class="wb-check-text"><label[^>]*>Shared service credential/);
    expect(html).toMatch(/<input id="[^"]+" type="checkbox" class="wb-checkbox"\/><span class="wb-check-text"><label[^>]*>Personal credentials for each user/);
    const free = commandAccepted();
    free.service.definition = commandDefinition([]);
    free.service.acceptedMetadata = { ...free.service.acceptedMetadata!, credential: null, verify: false };
    expect(renderEditor(free)).toContain("The accepted manifest declares no credential");
  });

  test("a username-and-token execution credential takes the username with the token", () => {
    const html = renderToStaticMarkup(createElement(ImportTokenModal, { purpose: "execution", rotate: false, withUsername: true, noun: "credential", onClose: () => {}, onSave: async () => true, frame: inlineFrame }));
    expect(html).toContain("Set execution credential");
    expect(html).toContain("Username");
    expect(html).toContain("Save credential");
    // A command's token credential takes no username; other imports' slots hold tokens.
    const token = renderToStaticMarkup(createElement(ImportTokenModal, { purpose: "execution", rotate: true, noun: "credential", onClose: () => {}, onSave: async () => true, frame: inlineFrame }));
    expect(token).toContain("Rotate execution credential");
    expect(token).toContain("Save credential");
    expect(token).not.toContain("Username");
    const other = renderToStaticMarkup(createElement(ImportTokenModal, { purpose: "execution", rotate: true, noun: "token", onClose: () => {}, onSave: async () => true, frame: inlineFrame }));
    expect(other).toContain("Rotate execution token");
    expect(other).toContain("Save token");
  });
});

describe("resources checked by", () => {
  test("typed inputs are checked by the Broker; type-only and untyped actions by the command", () => {
    expect(commandResourceCheck(VIEW)).toEqual({ by: "broker", type: "project", inputs: ["/project"] });
    expect(resourceCheckText(commandResourceCheck(VIEW), [PROJECT])).toBe("Broker · Project, from project");
    expect(resourceCheckText(commandResourceCheck(CREATE), [PROJECT])).toBe("Broker · Project, from project");
    expect(resourceCheckText(commandResourceCheck(SEARCH), [PROJECT])).toBe("Command · Projects");
    expect(resourceCheckText(commandResourceCheck(WHOAMI), [PROJECT])).toBe("Command · no resource type");
    // An undeclared type is shown by its id; escaped pointer segments are decoded.
    const escaped = { ...VIEW, annotations: { command: { resources: { type: "board", inputs: ["/a~1b", "/c~0d"] } } } };
    expect(resourceCheckText(commandResourceCheck(escaped), [PROJECT])).toBe("Broker · board, from a/b, c~d");
  });
});

describe("grant editor", () => {
  test("command-import actions say who checks their resources and command rows point to the caveat", () => {
    const html = renderToStaticMarkup(
      createElement(GrantActionSelector, {
        available: [
          { action: "issue.view", description: "Show one issue.", readOnly: true, resourcesCheckedBy: "broker" },
          { action: "issue.search", description: "Search issues.", readOnly: true, resourcesCheckedBy: "command" },
          { action: "item.read", description: "An MCP tool.", readOnly: true }
        ],
        selected: [],
        disabled: false,
        commandCaveatId: "caveat",
        onChange: () => {}
      })
    );
    expect(html).toContain("<b>Resources checked by: Broker. </b>Show one issue.");
    expect(html).toContain("<b>Resources checked by: Command. </b>Search issues.");
    expect(html).not.toMatch(/Resources checked by: [A-Za-z]+\. <\/b>An MCP tool/);
    expect(html.match(/aria-describedby="caveat /g)).toHaveLength(1);
  });
});

describe("command import preview", () => {
  test("discovery shows the version, credential, verification and editable proposed type IDs", () => {
    const data = commandDiscovered();
    const html = renderReview(data);
    expect(html).toContain("Review discovered actions");
    expect(html).toContain("1.4.0");
    expect(html).toContain("Username and token · shared or personal");
    expect(html).toContain("Supported");
    expect(html).toContain("Broker type ID for project");
    expect(html).toContain('value="ticketing_project"');
    expect(html).toContain("Registered on acceptance.");
    expect(html).toContain("Resources checked by: <b>Broker</b>");
    expect(html).toContain('<span class="wb-mono">project</span>');
    expect(html).toContain("Resources checked by: <b>Command</b>");
    expect(html).toContain("no resource type");
    expect(html).toContain("the Broker cannot check that");
    // Command rows point to that explanation.
    const caveat = /<p id="([^"]+)" class="pt-prose wb-small"><b>Resources checked by: Command\.<\/b>/.exec(html)?.[1];
    expect(caveat).toBeTruthy();
    expect(html).toContain(`aria-describedby="${caveat}"`);
    expect(html).not.toContain(OAUTH_NOTICE);
    // A draft needs at least one selected action.
    expect(importSelectionError(data, importReviewRows(data))).toBe("Select at least one supported action.");
    expect(acceptButton(html)).toContain('disabled=""');
  });

  test("a refresh lists type changes with their resources, the OAuth notice and the previous version", () => {
    const data = commandRefreshed();
    const html = renderReview(data);
    expect(commandNotices(data.preview!.manifest)).toEqual([OAUTH_NOTICE]);
    expect(html).toContain(OAUTH_NOTICE);
    expect(html).toContain("1.5.0");
    expect(html).toContain("imported at version 1.4.0");
    expect(html).toContain("Changed: new optional attribute.");
    expect(html).toContain("Applied on acceptance.");
    expect(html).toContain("Kept for its 1 resource; it accepts no new resources. Delete it, then accept a refresh to drop the type.");
    expect(html).toContain('<span class="wb-mono">triage-queue</span>');
    expect(html).not.toContain("Broker type ID for project");
    const rows = importReviewRows(data);
    expect(rows.map((row) => [row.action, row.change])).toEqual([
      ["issue.view", "Unchanged"],
      ["issue.search", "Changed"],
      ["issue.create", "Unchanged"],
      ["issue.comment", "New"],
      ["whoami", "Removed"]
    ]);
  });

  test("an accepted import may accept a preview with no selections; drafts and other kinds may not", () => {
    const data = commandRefreshed();
    const rows = importReviewRows(data).map((row) => ({ ...row, selected: false }));
    expect(metadataOnlyAcceptance(data)).toBe(true);
    expect(selectedImportActions(rows)).toEqual([]);
    expect(importSelectionError(data, rows)).toBeNull();
    expect(metadataOnlyAcceptance(commandDiscovered())).toBe(false);
    for (const [kind, noun] of [["mcp_http", "tool"], ["openapi_http", "operation"]] as const) {
      const other = urlImport(kind);
      const none = importReviewRows(other).map((row) => ({ ...row, selected: false }));
      expect(metadataOnlyAcceptance(other)).toBe(false);
      expect(importSelectionError(other, none)).toBe(`Select at least one supported ${noun}.`);
    }
  });

  test("Broker type IDs are checked before acceptance and only changed IDs are sent", () => {
    const data = commandDiscovered();
    const changes = data.resourceTypeChanges!;
    const metadata = data.preview!.manifest.serviceMetadata;
    const registered = indexResourceTypes([...RESOURCE_TYPES, ...COMMAND_RESOURCE_TYPES]);
    const issues = (list: typeof changes, declared: typeof metadata, ids: Record<string, string>, service = "ticketing") =>
      resourceTypeIdIssues(list, declared, choices(ids), registered, service);
    expect(issues(changes, metadata, {}).size).toBe(0);
    expect(chosenResourceTypeIds(changes, choices({}))).toEqual({});
    expect(chosenResourceTypeIds(changes, choices({ project: " ticketing_project " }))).toEqual({});
    expect(chosenResourceTypeIds(changes, choices({ project: "tickets_project" }))).toEqual({ project: "tickets_project" });
    expect(issues(changes, metadata, { project: "Tickets" }).get("project")).toContain("lowercase");
    // Another added type of the import may not take the same ID.
    const twice = { ...metadata!, resourceTypes: [...metadata!.resourceTypes, { ...PROJECT, id: "board", brokerType: "ticketing_board" }] };
    const both = [...changes, { ...changes[0]!, id: "board", brokerType: "ticketing_board" }];
    expect(issues(both, twice, { board: "ticketing_project" }).get("board")).toContain("Another type");
    // A chosen ID another owner registers is refused before acceptance;
    // this import's own registered types are not another owner's.
    expect(issues(changes, metadata, { project: "jira_project" }).get("project")).toContain("already registered");
    expect(issues(changes, metadata, { project: "ticketing_queue" }).size).toBe(0);
    expect(issues(changes, metadata, { project: "ticketing_queue" }, "other").has("project")).toBe(true);
    // A proposal another owner registered must be replaced; a new choice clears it.
    const taken = [{ ...changes[0]!, blocked: true }];
    expect(issues(taken, metadata, {}).get("project")).toContain("already registered");
    expect(issues(taken, metadata, { project: "tickets_project" }).size).toBe(0);
    expect(blockedTypeChanges(taken)).toEqual([]);
  });

  test("resource-dependent blocks disable acceptance and name the resources to fix", () => {
    const data = commandRefreshed();
    const blocked: ImportResourceTypeChange = { ...data.resourceTypeChanges![0]!, details: ["pattern"], blocked: true, blockingResources: ["legacy-project"] };
    const deleted: ImportResourceTypeChange = { ...data.resourceTypeChanges![0]!, id: "queue", brokerType: "ticketing_queue", change: "changed", details: ["attribute_removed"], affectedResources: ["ops-queue"] };
    data.resourceTypeChanges = [blocked, deleted];
    const html = renderReview(data);
    expect(blockedTypeChanges(data.resourceTypeChanges)).toEqual([blocked]);
    expect(html).toContain("Accepting is rejected until you edit or delete:");
    expect(html).toContain('<span class="wb-mono">legacy-project</span>');
    expect(html).toContain("Accepting deletes the removed attributes&#x27; values from:");
    expect(html).toContain('<span class="wb-mono">ops-queue</span>');
    expect(html).toContain("Resolve the blocked resource type change first.");
    expect(acceptButton(html)).toContain('disabled=""');
  });

  test("credential-free commands say so; acceptance effects summarize what changed", () => {
    expect(commandCredentialText(null)).toContain("None");
    const data = commandDiscovered();
    data.service.definition = commandDefinition([]);
    data.preview!.manifest.serviceMetadata = { ...data.preview!.manifest.serviceMetadata!, credential: null, verify: false };
    const html = renderReview(data);
    expect(html).toContain("None: grants use service mode without a stored credential");
    expect(html).toContain("Not supported");
    expect(resourceTypeEffectsText(undefined)).toBeNull();
    expect(resourceTypeEffectsText({ deletedAttributeValues: [], droppedTypes: [] })).toBeNull();
    expect(resourceTypeEffectsText({ deletedAttributeValues: [{ resourceId: "ops", attributes: ["webhookSecret"] }, { resourceId: "web", attributes: ["webhookSecret"] }], droppedTypes: ["ticketing_queue"] })).toBe(
      "deleted removed attribute values of 2 resources; dropped ticketing_queue"
    );
  });
});

describe("acceptance errors", () => {
  test("refusals list the retained grants and stored resources to fix, linked to them", () => {
    const blocked = new ApiError("input is invalid: refused", 400, "input_invalid", undefined, undefined, undefined, {
      affectedGrants: [
        { id: "grant-search", reasonCode: "credential_mode_unsupported", reason: "the action no longer supports per_user" },
        { id: "toml:0", reasonCode: "credential_mode_invalid", reason: "policy.grants[0] subjects[0] ...; policy.grants[0] subjects[1] ..." },
        { id: "", reasonCode: "credential_mode_invalid", reason: "policy grant subjects[0] unattributed" }
      ],
      resources: [
        { type: "ticketing_project", id: "legacy" },
        { type: "ticketing_project", id: "web" },
        { type: "ticketing_queue", id: "triage" }
      ]
    });
    const html = renderToStaticMarkup(createElement(ImportErrorAlert, { error: blocked }));
    expect(html).toContain("This change would leave retained grants invalid. Update or remove them first:");
    expect(html).toContain('href="/ui/admin/policies?grant=grant-search"');
    expect(html).toContain("the action no longer supports per_user");
    // A configured grant opens by its `toml:<index>` reference; an unattributed one is plain text.
    expect(html).toContain('href="/ui/admin/policies?grant=toml%3A0"');
    expect(html).toContain('<span class="wb-muted">Unidentified grant</span>: policy grant subjects[0] unattributed');
    expect(html).not.toContain('href="/ui/admin/policies?grant="');
    expect(html).toContain("Stored resources no longer fit these resource type changes.");
    expect(html).toContain('href="/ui/admin/catalog/resources?item=legacy"');
    expect(html).toContain('href="/ui/admin/catalog/resources?item=triage"');
    expect(html.match(/<li>/g)).toHaveLength(5);
    // The message text is not parsed; other failures show it as it is.
    expect(html).not.toContain("refused");
    const plain = renderToStaticMarkup(createElement(ImportErrorAlert, { error: new ApiError("select at least one discovered tool", 400, "input_invalid") }));
    expect(plain).toContain("select at least one discovered tool (input_invalid)");
    expect(plain).not.toContain("<li>");
  });
});

describe("manifest names that are Object.prototype members", () => {
  test("type ids render in the preview with their proposed Broker type IDs", () => {
    const html = renderReview(prototypeNamedDiscovered());
    for (const id of PROTOTYPE_NAMES) expect(html).toContain(`Broker type ID for ${id}`);
    expect(html).toContain('value="ticketing_constructor"');
    expect(html).toContain('value="ticketing_proto__"');
    expect(html).toContain('value="ticketing_tostring"');
    expect(html).not.toContain("Use up to 64 lowercase letters");
    expect(html).not.toContain("already registered");
  });

  test("type ID choices and issues are keyed by own entries, and overrides are sent as own keys", () => {
    const data = prototypeNamedDiscovered();
    const changes = data.resourceTypeChanges!;
    const metadata = data.preview!.manifest.serviceMetadata;
    const registered = indexResourceTypes([...RESOURCE_TYPES, ...COMMAND_RESOURCE_TYPES]);
    expect(resourceTypeIdIssues(changes, metadata, new Map(), registered, "ticketing").size).toBe(0);
    expect(chosenResourceTypeIds(changes, new Map())).toEqual({});
    const typed = new Map([["constructor", "tickets_constructor"], ["__proto__", "tickets_proto"], ["toString", "Tickets"]]);
    expect(resourceTypeIdIssues(changes, metadata, typed, registered, "ticketing")).toEqual(
      new Map([["toString", "Use up to 64 lowercase letters, digits or underscores, starting with a letter."]])
    );
    const sent = chosenResourceTypeIds(changes, typed);
    expect(Object.hasOwn(sent, "__proto__")).toBe(true);
    expect(JSON.stringify(sent)).toBe('{"constructor":"tickets_constructor","__proto__":"tickets_proto","toString":"Tickets"}');
  });

  test("an action named constructor names only the grants the Broker lists for it", () => {
    const data = commandRefreshed();
    data.service.actions = data.service.actions.map((record) =>
      record.definition.action === "issue.search" ? { ...record, definition: { ...record.definition, action: "constructor" } } : record
    );
    data.affectedGrantsByAction = {};
    const rows = importReviewRows(data).map((row) => (row.existing?.definition.action === "constructor" ? { ...row, selected: true } : row));
    expect(affectedImportGrants(data, rows)).toEqual([]);
    data.affectedGrantsByAction = Object.fromEntries([["constructor", ["grant-search"]]]);
    expect(affectedImportGrants(data, rows)).toEqual(["grant-search"]);
  });
});

describe("removed resource types", () => {
  test("accept no new resources but stay selectable for an existing resource of the type", () => {
    const types = indexResourceTypes([...RESOURCE_TYPES, ...REFRESHED_RESOURCE_TYPES]);
    const ids = (current?: string) => creatableResourceTypes(types, current).map((type) => type.id);
    expect(ids()).toContain("ticketing_project");
    expect(ids()).not.toContain("ticketing_queue");
    expect(ids("ticketing_queue")).toContain("ticketing_queue");
    expect(ids()[0]).toBe(RESOURCE_TYPES[0]!.id);
  });
});
