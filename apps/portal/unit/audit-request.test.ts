import { describe, expect, test } from "vitest";
import { attachmentAuditOutcomes, auditCollectionNote, auditDisplayText, auditOutcomeWarning, auditScalarText, auditTruncation, commandExecutionFacts, requestAudit, requestAuditLayout, suppliedAuditLabels } from "../src/lib/audit-request";
import { commandAuditInputs } from "../src/features/catalog/import-audit-inputs";
import { commandAccepted } from "./command-import.fixture";
import { attachmentsField, auditEnvelope, auditField, LARGE_IDENTIFIER, requestRecord } from "./audit-request.fixture";

describe("event-time audit input snapshots", () => {
  test("historical records have no invented details; unknown/unavailable versions are not interpreted", () => {
    expect(requestAudit({})).toBeNull();
    expect(requestAudit({ requestAudit: { version: 2, fields: [auditField("secret")] } })).toBe("unavailable");
    expect(requestAudit({ requestAudit: { ...auditEnvelope(), status: "unavailable", reason: "projectionFailed" } })).toBe("unavailable");
    expect(requestAudit({ requestAudit: { version: 1, status: "complete", fields: [{}] } })).toBe("unavailable");
  });
  test("finite metadata accepts shape and lossless integers and rejects malformed tags", () => {
    const record = requestRecord();
    expect(requestAudit(record)).toEqual(record.requestAudit);
    expect(requestAudit({ requestAudit: auditEnvelope([auditField("id", { encoding: "decimalInteger", value: "1e20" })]) })).toBe("unavailable");
    expect(requestAudit({ requestAudit: auditEnvelope([auditField("id", { shape: undefined })]) })).toBe("unavailable");
  });
  test("six ordinary primary rows plus one query; detail and raw placement win over roles", () => {
    const audit = requestRecord().requestAudit as ReturnType<typeof auditEnvelope>;
    const layout = requestAuditLayout(audit);
    expect(layout.main).toHaveLength(6);
    expect(layout.main[0].key).toBe("issue");
    expect(layout.query?.key).toBe("query");
    expect(layout.additional.map(field => field.key)).toContain("description");
    expect([...layout.main, ...layout.additional].map(field => field.key)).not.toContain("raw-target");
    expect(suppliedAuditLabels(audit)).toEqual(["Summary", "Description supplied"]);
  });
  test("change summaries include only supplied non-raw retained fields and children", () => {
    const fields = [attachmentsField(), auditField("absent", { role: "change", supplied: false, state: "absent" }), auditField("unknown", { role: "change", supplied: null, state: "budget" })];
    expect(suppliedAuditLabels(auditEnvelope(fields))).toEqual(["Requested attachments"]);
    fields[0].display = "raw";
    expect(suppliedAuditLabels(auditEnvelope(fields))).toEqual([]);
  });
  test.each([
    ["false", { state: "captured", value: false }, "No"],
    ["zero", { state: "captured", value: 0 }, "0"],
    ["empty", { state: "captured", value: "" }, "Empty text"],
    ["null", { state: "null" }, "Explicit null"],
    ["invalid", { state: "invalid" }, "Not recorded: unexpected input shape"],
    ["too large", { state: "tooLarge" }, "Not recorded: exceeds audit limit"],
    ["budget", { state: "budget" }, "Not recorded: audit budget"],
  ] as const)("distinguishes %s", (_label, value, text) => expect(auditScalarText(value, "text")).toBe(text));
  test("large decimal identifiers and UTF-8 capture lengths stay exact", () => {
    expect(auditScalarText({ state: "captured", encoding: "decimalInteger", value: LARGE_IDENTIFIER }, "identifier")).toBe(LARGE_IDENTIFIER);
    expect(auditTruncation({ state: "captured", value: "é😺", truncated: true, originalBytes: 9200 })).toBe("Truncated at capture: 6 of 9,200 bytes recorded.");
    expect(auditCollectionNote(attachmentsField())).toBe("21 input items · 1 omitted at capture");
  });
  test("HTML stays text; control/format characters become visible without losing line breaks", () => {
    expect(auditDisplayText('<img>\n\t\u0000\r\u202E')).toBe('<img>\n\\u{9}\\u{0}\\u{D}\\u{202E}');
  });
  test("command execution accepts only reviewed host facts and preserves null as unknown", () => {
    const facts = commandExecutionFacts({ providerAudit: { command: { name: "ticketing", spawned: true, operationDispatched: true, exitCode: null, signal: null, durationMs: 0, contractViolation: false, executable: "/secret/canary", argv: ["secret"], stdin: "secret", stdout: "secret", stderr: "secret" } } });
    expect(facts).toHaveLength(7);
    expect(facts.find(fact => fact.label === "Exit code")?.value).toBe("Unknown");
    expect(JSON.stringify(facts)).not.toContain("secret");
  });
  test("error resultCount is never presented as returned; explicit verification errors warn", () => {
    expect(auditOutcomeWarning(requestRecord({ decision: "error", reasonCode: "input_invalid", providerAudit: { resultCount: 50 } }))).toBeNull();
    expect(auditOutcomeWarning(requestRecord({ decision: "error", reasonCode: "upstream_timeout" }))).toContain("outcome may be unknown");
    expect(auditOutcomeWarning(requestRecord({ decision: "error", providerAudit: { verificationStatus: "failed" } }))).toContain("unverified");
    expect(auditOutcomeWarning(requestRecord({ decision: "error", reasonCode: "operation_cancelled" }))).toContain("outcome may be unknown");
    expect(auditOutcomeWarning(requestRecord({ decision: "error", providerAudit: { provider: "jira", operation: "issue.create", failurePhase: "create_response_validation" } }))).toContain("unverified");
  });
  test("the twenty-first upload result survives its independently sampled metadata", () => {
    const record = requestRecord({ action: "attachment.add", requestAudit: auditEnvelope([attachmentsField()]), providerAudit: { provider: "jira", attachments: [{ inputIndex: 0, status: "created", attachmentId: "A1" }, { inputIndex: 20, status: "created", attachmentId: "A21" }] } });
    expect(attachmentAuditOutcomes(record)).toEqual([{ index: 0, status: "created", attachmentId: "A1", note: null }, { index: 20, status: "created", attachmentId: "A21", note: "Request metadata sampled; not retained" }]);
  });
});

test("command preview reads only the canonical reviewed annotation", () => {
  const definition = commandAccepted().service.actions[0].definition;
  expect(commandAuditInputs(definition)).toEqual([]);
  expect(commandAuditInputs({ ...definition, annotations: { command: { auditInputs: [] } } })).toBe("unavailable");
  const rules = [{ key: "q", pointer: "/query", capture: "value", label: "Requested query", display: "primary", role: "fact", kind: "query", shape: "scalar", maxBytes: 4096, overflow: "prefix" }];
  expect(commandAuditInputs({ ...definition, annotations: { command: { auditInputs: rules } } })).toEqual(rules);
});
