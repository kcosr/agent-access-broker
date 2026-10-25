import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, test, vi } from "vitest";
vi.mock("../src/app/session", () => ({ useSession: () => ({ session: { authenticated: true, role: "admin", selfServiceEnabled: true, principal: "admin" } }) }));
import { CredentialFields } from "../src/components/credential-fields";
import { ImportTokenModal } from "../src/features/catalog/import-token-modal";
import { inlineFrame } from "../src/features/catalog/catalog-ui";
import { tokenFormReady, tokenTypeValues } from "../src/lib/credentials";
import { importCredentialReady, importCredentialValues } from "../src/lib/import-credentials";
import type { CredentialTokenProfile } from "../src/types";
import { BASIC_INPUT, COMMAND_INPUT, TOKEN_INPUT } from "./credential-input.fixture";

describe("Broker-derived credential fields", () => {
  test("Basic values retain spaces and Unicode, including all-space nonempty passwords", () => {
    if (BASIC_INPUT.state !== "ready") throw new Error("ready fixture");
    const values = { username: " opérateur ", token: " päss word: " };
    const type: CredentialTokenProfile = { profile: "username-token", label: null, credentialKind: BASIC_INPUT.credentialKind, inputSchema: { ...BASIC_INPUT, connection: "inventory", profile: "username-token" } };
    expect(tokenTypeValues(type, values)).toEqual(values);
    expect(tokenFormReady(type, values)).toBe(true);
    expect(importCredentialReady(BASIC_INPUT, { username: " ", token: " " })).toBe(true);
    expect(importCredentialReady(BASIC_INPUT, { username: "", token: "password" })).toBe(false);
    expect(importCredentialValues(BASIC_INPUT, values)).toEqual(values);
    const html = renderToStaticMarkup(createElement(CredentialFields, { descriptor: BASIC_INPUT, values, onChange: () => {} }));
    expect(html).toContain('value=" opérateur "');
    expect(html).toContain('value=" päss word: "');
    expect(html).toContain("Password or API token");
    expect(html).toContain("including spaces");
  });
  test("token header readiness preserves whitespace-only rejection without choosing fields by kind", () => {
    if (TOKEN_INPUT.state !== "ready" || COMMAND_INPUT.state !== "ready") throw new Error("ready fixture");
    expect(importCredentialReady(TOKEN_INPUT, { token: " " })).toBe(false);
    expect(importCredentialReady(TOKEN_INPUT, { token: "synthetic-token" })).toBe(true);
    const html = renderToStaticMarkup(createElement(CredentialFields, { descriptor: COMMAND_INPUT, values: {}, onChange: () => {} }));
    expect(html).toContain("Username");
    expect(html).not.toContain("Password or API token");
    expect(html).not.toContain("including spaces");
  });
  test("command import slots reject blanks and trim only the username", () => {
    if (COMMAND_INPUT.state !== "ready") throw new Error("ready fixture");
    expect(importCredentialReady(COMMAND_INPUT, { username: " ", token: "secret" })).toBe(false);
    expect(importCredentialReady(COMMAND_INPUT, { username: "operator", token: " " })).toBe(false);
    const values = { username: " opérateur ", token: " exact token " };
    expect(importCredentialReady(COMMAND_INPUT, values)).toBe(true);
    expect(importCredentialValues(COMMAND_INPUT, values)).toEqual({ username: "opérateur", token: " exact token " });
    const tokenOnly = { ...COMMAND_INPUT, fields: COMMAND_INPUT.fields.filter((field) => field.name === "token") };
    expect(importCredentialReady(tokenOnly, { token: " " })).toBe(false);
    expect(importCredentialValues(tokenOnly, values)).toEqual({ token: " exact token " });
  });
  test.each([BASIC_INPUT, COMMAND_INPUT, TOKEN_INPUT])("personal and administered $inputPolicy forms keep their original exact-value semantics", (descriptor) => {
    if (descriptor.state !== "ready") throw new Error("ready fixture");
    for (const policy of [descriptor.inputPolicy, undefined]) {
      const type: CredentialTokenProfile = { profile: "credential", label: null, credentialKind: descriptor.credentialKind, inputSchema: { ...descriptor, inputPolicy: policy, connection: "service", profile: "credential" } };
      const values = Object.fromEntries(descriptor.fields.map((field) => [field.name, " "]));
      expect(tokenFormReady(type, values)).toBe(true);
      expect(tokenTypeValues(type, values)).toEqual(values);
      expect(tokenFormReady(type, {})).toBe(false);
    }
  });
  test("unavailable slots show the Broker reason and cannot accept guessed fields", () => {
    const html = renderToStaticMarkup(createElement(ImportTokenModal, { purpose: "execution", rotate: false, descriptor: { state: "unavailable", reason: "Retired imports cannot receive credentials" }, noun: "credential", onClose: () => {}, onSave: async () => {}, frame: inlineFrame }));
    expect(html).toContain("Retired imports cannot receive credentials");
    expect(html).not.toContain("<input");
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Save credential<\/button>/);
  });
});
