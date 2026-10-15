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
  resourceTypeIdIssues
} from "../src/lib/import-command";
import { importErrorList, importReviewRows, importSelectionError, metadataOnlyAcceptance, selectedImportActions } from "../src/lib/imports";
import { creatableResourceTypes, indexResourceTypes } from "../src/lib/resource-types";
import { ImportEditor } from "../src/features/catalog/import-editor";
import { ImportReview } from "../src/features/catalog/import-review";
import { ImportTokenModal } from "../src/features/catalog/import-token-modal";
import { inlineFrame } from "../src/features/catalog/catalog-ui";
import { RESOURCE_TYPES } from "./resource-types.fixture";
import { COMMAND_RESOURCE_TYPES, CREATE, OAUTH_NOTICE, PROJECT, SEARCH, VIEW, WHOAMI, commandAccepted, commandDefinition, commandDiscovered, commandDraft, commandRefreshed, stdinBinding } from "./command-import.fixture";

function renderEditor(data?: ImportPreviewResult, commandImports = ["ticketing", "deploy-tools"]) {
  return renderToStaticMarkup(createElement(ImportEditor, { principal: "admin", data, availableKinds: ["command"], commandImports, authentication: [], onClose: () => {}, onSave: async () => true, frame: inlineFrame }));
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
    expect(html).toContain("takes a username and token credential");
    // The stored shared mode stays; the declared personal mode can be added.
    expect(html).toMatch(/<input disabled="" id="[^"]+" type="checkbox" class="wb-checkbox" checked=""\/><span class="wb-check-text"><label[^>]*>Shared service credential/);
    expect(html).toMatch(/<input id="[^"]+" type="checkbox" class="wb-checkbox"\/><span class="wb-check-text"><label[^>]*>Personal credentials for each user/);
    const free = commandAccepted();
    free.service.definition = commandDefinition([]);
    free.service.acceptedMetadata = { ...free.service.acceptedMetadata!, credential: null, verify: false };
    expect(renderEditor(free)).toContain("The accepted manifest declares no credential");
  });

  test("a username-and-token execution credential takes the username with the token", () => {
    const html = renderToStaticMarkup(createElement(ImportTokenModal, { purpose: "execution", rotate: false, withUsername: true, onClose: () => {}, onSave: async () => true, frame: inlineFrame }));
    expect(html).toContain("Set execution credential");
    expect(html).toContain("Username");
    expect(html).toContain("Save credential");
    const token = renderToStaticMarkup(createElement(ImportTokenModal, { purpose: "execution", rotate: true, onClose: () => {}, onSave: async () => true, frame: inlineFrame }));
    expect(token).toContain("Rotate execution token");
    expect(token).not.toContain("Username");
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
    const mcp = commandRefreshed();
    delete mcp.preview!.manifest.serviceMetadata;
    expect(metadataOnlyAcceptance(mcp)).toBe(false);
    expect(importSelectionError(mcp, rows)).toBe("Select at least one supported action.");
  });

  test("Broker type IDs are checked before acceptance and only changed IDs are sent", () => {
    const data = commandDiscovered();
    const changes = data.resourceTypeChanges!;
    const metadata = data.preview!.manifest.serviceMetadata;
    expect(resourceTypeIdIssues(changes, metadata, {})).toEqual({});
    expect(chosenResourceTypeIds(changes, {})).toEqual({});
    expect(chosenResourceTypeIds(changes, { project: " ticketing_project " })).toEqual({});
    expect(chosenResourceTypeIds(changes, { project: "tickets_project" })).toEqual({ project: "tickets_project" });
    expect(resourceTypeIdIssues(changes, metadata, { project: "Tickets" }).project).toContain("lowercase");
    // Another added type of the import may not take the same ID.
    const twice = { ...metadata!, resourceTypes: [...metadata!.resourceTypes, { ...PROJECT, id: "board", brokerType: "ticketing_board" }] };
    const both = [...changes, { ...changes[0]!, id: "board", brokerType: "ticketing_board" }];
    expect(resourceTypeIdIssues(both, twice, { board: "ticketing_project" }).board).toContain("Another type");
    // A proposal another owner registered must be replaced; a new choice clears it.
    const taken = [{ ...changes[0]!, blocked: true }];
    expect(resourceTypeIdIssues(taken, metadata, {}).project).toContain("already registered");
    expect(resourceTypeIdIssues(taken, metadata, { project: "tickets_project" })).toEqual({});
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
  test("rejections that name resources or grants become lists; other messages stay whole", () => {
    expect(
      importErrorList("resource type changes no longer apply to stored resources; edit or delete them, or refresh the preview (ticketing_project: legacy, web; ticketing_queue: triage)")
    ).toEqual({
      message: "resource type changes no longer apply to stored resources; edit or delete them, or refresh the preview",
      items: ["ticketing_project: legacy, web", "ticketing_queue: triage"]
    });
    expect(importErrorList("resource type changes no longer apply to stored resources; edit or delete them, or refresh the preview (ticketing_project: legacy)").items).toEqual([
      "ticketing_project: legacy"
    ]);
    expect(importErrorList("the change would leave retained grants invalid; update or remove them first: managed policy grant g1 credentialMode is unsupported; managed policy grant g2 credentialMode is unsupported")).toEqual({
      message: "the change would leave retained grants invalid; update or remove them first",
      items: ["managed policy grant g1 credentialMode is unsupported", "managed policy grant g2 credentialMode is unsupported"]
    });
    expect(importErrorList("select at least one discovered tool")).toEqual({ message: "select at least one discovered tool", items: [] });
  });
});

describe("removed resource types", () => {
  test("accept no new resources but stay selectable for an existing resource of the type", () => {
    const types = indexResourceTypes([...RESOURCE_TYPES, ...COMMAND_RESOURCE_TYPES]);
    const ids = (current?: string) => creatableResourceTypes(types, current).map((type) => type.id);
    expect(ids()).toContain("ticketing_project");
    expect(ids()).not.toContain("ticketing_queue");
    expect(ids("ticketing_queue")).toContain("ticketing_queue");
    expect(ids()[0]).toBe(RESOURCE_TYPES[0]!.id);
  });
});

describe("command fixtures", () => {
  test("follow the Broker's shapes for drafts", () => {
    const draft = commandDraft();
    expect(draft.service.definition).toMatchObject({ adapterKind: "command", endpoint: "command:ticketing", discovery: { kind: "anonymous" }, connectionSettings: {}, transportAuth: false });
    expect(draft.service.acceptedMetadata).toBeUndefined();
  });
});
