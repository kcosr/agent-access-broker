// Token types on the Credentials list: a connection accepting one token type
// keeps its plain form; several add a labelled Token type select, with none
// chosen for a first save and the stored type chosen when replacing, and the
// fields follow the chosen type. Rows, drawers and retained "Not used" rows
// name a stored token's type by its label, else its profile. The browser
// interactions (choosing, the no-type error, saving) are in
// tests/credentials.spec.ts.
import { describe, expect, test, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import type { ConnectionCredential, CredentialConnection, CredentialList, CredentialTarget, CredentialTokenProfile, RetainedCredential } from "../src/types";

const mocks = vi.hoisted(() => ({
  session: { authenticated: true, principal: "viewer", role: "user" as string, selfServiceEnabled: true },
  credentials: { connections: [], retained: [] } as CredentialList,
  targets: [] as CredentialTarget[],
  saved: [] as Array<{ administered: boolean; principal?: string; connection: string; profile: string; secret: unknown }>
}));
vi.mock("../src/app/session", () => ({
  useSession: () => ({ session: mocks.session, reportError: vi.fn(), attempt: (call: (session: unknown) => Promise<unknown>) => call(mocks.session) })
}));
vi.mock("../src/app/modal", () => ({ useModal: () => ({ setModal: vi.fn(), confirm: vi.fn() }) }));
vi.mock("../src/data/invalidation", () => ({ usePortalInvalidation: () => ({ console: vi.fn(), admin: vi.fn(), oauthConnections: vi.fn(), portal: vi.fn() }) }));
vi.mock("../src/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/api")>()),
  brokerApi: {
    saveCredential: async (_session: unknown, connection: string, profile: string, secret: unknown) => {
      mocks.saved.push({ administered: false, connection, profile, secret });
    },
    adminPrincipalSaveCredential: async (_session: unknown, principal: string, connection: string, profile: string, secret: unknown) => {
      mocks.saved.push({ administered: true, principal, connection, profile, secret });
    }
  }
}));
vi.mock("../src/data/queries", () => ({
  useConsoleData: () => ({
    query: { isError: false, isFetching: false, error: null, refetch: vi.fn() },
    targets: mocks.targets,
    credentials: mocks.credentials,
    tokens: [],
    loading: false
  }),
  useOAuthConnections: () => ({ data: [], isError: false, error: null, refetch: vi.fn() })
}));
import { CredentialDrawer, CredentialRows, CredentialToolbar, useCredentialList } from "../src/features/credentials/credential-list";
import { useCredentialActions } from "../src/mutations/credentials";
import { chosenTokenType, connectionTokenType, initialTokenType, tokenFormReady, tokenTypeName, tokenTypeValues } from "../src/lib/credentials";
import { adminSubject, type AccountSubject } from "../src/app/active-route";

const stamp = { createdAt: "2026-10-01T00:00:00Z", updatedAt: "2026-10-01T00:00:00Z", createdBy: "viewer", updatedBy: "viewer" };
const consumer = { service: "conformance", displayName: "Conformance", credentialVerificationInputs: [] };
const inputMethods = ["prompt", "env", "file", "stdin"];

/** A token type of `connection` (display name `display`), with the fields the Broker's input schema gives its kind. */
function tokenType(connection: string, display: string, profile: string, label: string | null, credentialKind: "basic_api_token" | "bearer_token"): CredentialTokenProfile {
  const token = { name: "token", required: true, secret: true, prompt: `${display} ${credentialKind === "basic_api_token" ? "API" : "bearer"} token`, inputMethods };
  const fields = credentialKind === "basic_api_token" ? [{ name: "username", required: true, secret: false, prompt: `${display} username`, inputMethods }, token] : [token];
  return { profile, label, credentialKind, inputSchema: { connection, profile, credentialKind, fields } };
}

// One accepted type; two Git types of different kinds without labels, in
// configuration order; two labelled conformance types of the same kind.
const ciToken = tokenType("ci", "CI", "ci-token", null, "bearer_token");
const gitBearer = tokenType("git", "Git", "git-bearer-token", null, "bearer_token");
const gitBasic = tokenType("git", "Git", "git-basic-api-token", null, "basic_api_token");
const apiToken = tokenType("conformance", "Conformance", "api_token", "API token", "bearer_token");
const routedToken = tokenType("conformance", "Conformance", "routed_token", "Routed token", "bearer_token");

function stored(connection: string, type: CredentialTokenProfile, owner = "viewer"): ConnectionCredential {
  return { credentialId: `credential-${connection}`, ownerPrincipal: owner, ownerKind: "user", connection, profile: type.profile, label: type.label, credentialKind: type.credentialKind, metadata: {}, status: "active", verificationStatus: "not_verified", ...stamp };
}
function retained(service: string, type: CredentialTokenProfile): RetainedCredential {
  return { credentialId: `credential-old-${service}`, ownerPrincipal: "viewer", ownerKind: "user", service, name: "default", profile: type.profile, label: type.label, credentialKind: type.credentialKind, metadata: {}, status: "active", ...stamp };
}
function connection(id: string, displayName: string, tokenProfiles: CredentialTokenProfile[], credential: ConnectionCredential | null = null): CredentialConnection {
  return { connection: id, displayName, method: "token", consumers: [consumer], otherConsumers: 0, tokenProfiles, registration: null, remoteRevocation: null, credential };
}
function target(row: CredentialConnection): CredentialTarget {
  return { connection: row.connection, displayName: row.displayName, consumers: row.consumers, otherConsumers: row.otherConsumers, tokenProfiles: row.tokenProfiles };
}

function Harness({ subject }: { subject: AccountSubject }) {
  const model = useCredentialList(subject);
  return createElement("div", null, createElement(CredentialToolbar, { model }), createElement(CredentialRows, { model }), createElement(CredentialDrawer, { model }));
}
/** The Credentials page of these connections, each with its target, and retained rows, with `open` as the drawer's row key. */
function render(connections: CredentialConnection[], open: string, options: { retained?: RetainedCredential[]; subject?: AccountSubject } = {}) {
  const subject = options.subject ?? { administered: false, principalId: "viewer" };
  mocks.session.role = subject.administered ? "admin" : "user";
  mocks.credentials = { connections, retained: options.retained ?? [] };
  mocks.targets = connections.map(target);
  const base = subject.administered ? `/ui/admin/principals/${subject.principalId}/credentials` : "/ui/credentials";
  return renderToStaticMarkup(createElement(MemoryRouter, { initialEntries: [`${base}?credential=${encodeURIComponent(open)}`] }, createElement(Harness, { subject })));
}
function tableRow(html: string, key: string) {
  return (html.match(/<tr\b[\s\S]*?<\/tr>/g) ?? []).find((row) => row.includes(`data-wb-row="${key}"`)) ?? "";
}
/** Rendered text without markup or attributes. */
function text(html: string) {
  return html.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}
function drawer(html: string) {
  return html.slice(html.indexOf("<aside"));
}
/** The drawer's token form. */
function form(html: string) {
  return /<form class="wb-form-stack"[\s\S]*?<\/form>/.exec(drawer(html))?.[0] ?? "";
}
/** The token form's Token type select, if any. */
function typeSelect(html: string) {
  return /<select\b[\s\S]*?<\/select>/.exec(form(html))?.[0] ?? "";
}
/** The labels of a form's fields, in order. */
function fieldLabels(html: string) {
  return [...form(html).matchAll(/<label class="wb-field-label"[^>]*>([\s\S]*?)<\/label>/g)].map((match) => text(match[1]));
}
function submitButton(html: string) {
  return /<button[^>]*type="submit"[^>]*>[\s\S]*?<\/button>/.exec(form(html))?.[0] ?? "";
}
/** The `<dt>`/`<dd>` value of a drawer key-value row. */
function keyValue(html: string, label: string) {
  const match = new RegExp(`<dt[^>]*>${label}</dt>\\s*<dd[^>]*>([\\s\\S]*?)</dd>`).exec(drawer(html));
  return match ? text(match[1]) : undefined;
}

describe("token type helpers", () => {
  test("name a type by its label, else its profile", () => {
    expect(tokenTypeName(apiToken)).toBe("API token");
    expect(tokenTypeName(gitBasic)).toBe("git-basic-api-token");
  });

  test("name a connection's type: the stored token's, else its only one, else how many it accepts", () => {
    expect(connectionTokenType(connection("ci", "CI", [ciToken]))).toBe("ci-token");
    expect(connectionTokenType(connection("git", "Git", [gitBearer, gitBasic]))).toBe("2 token types");
    expect(connectionTokenType(connection("conformance", "Conformance", [apiToken, routedToken], stored("conformance", routedToken)))).toBe("Routed token");
    expect(connectionTokenType({ ...connection("gmail", "Gmail", []), method: "oauth" })).toBe("");
  });

  test("start a form on the only type, on the stored type while it is accepted, else on none", () => {
    expect(initialTokenType([ciToken], undefined)).toBe("ci-token");
    expect(initialTokenType([gitBearer, gitBasic], undefined)).toBe("");
    expect(initialTokenType([gitBearer, gitBasic], "git-basic-api-token")).toBe("git-basic-api-token");
    // A stored type the connection no longer accepts is not offered.
    expect(initialTokenType([gitBearer, gitBasic], "git-retired-token")).toBe("");
    expect(chosenTokenType([ciToken], "")).toBe(ciToken);
    expect(chosenTokenType([gitBearer, gitBasic], "")).toBeUndefined();
    expect(chosenTokenType([gitBearer, gitBasic], "git-basic-api-token")).toBe(gitBasic);
    expect(chosenTokenType([gitBearer, gitBasic], "git-retired-token")).toBeUndefined();
  });

  test("switching type keeps only the fields the new type has, and saving needs a type and its required fields", () => {
    const basic = { username: "casey@example.test", token: "synthetic-token" };
    expect(tokenTypeValues(gitBearer, basic)).toEqual({ token: "synthetic-token" });
    expect(tokenTypeValues(gitBasic, { token: "synthetic-token" })).toEqual({ username: "", token: "synthetic-token" });
    expect(tokenFormReady(undefined, basic)).toBe(false);
    expect(tokenFormReady(gitBasic, { username: "", token: "synthetic-token" })).toBe(false);
    expect(tokenFormReady(gitBasic, basic)).toBe(true);
    expect(tokenFormReady(gitBearer, { token: "" })).toBe(false);
    expect(tokenFormReady(gitBearer, { token: "synthetic-token" })).toBe(true);
  });
});

describe("the token form", () => {
  test("with one accepted type is unchanged: no type select, the type's fields, and Save credential", () => {
    const html = render([connection("ci", "CI", [ciToken])], "ci");
    expect(text(tableRow(html, "ci"))).toContain("ci-token");
    expect(typeSelect(html)).toBe("");
    expect(fieldLabels(html)).toEqual(["CI bearer token"]);
    expect(submitButton(html)).toContain("Save credential");
    expect(submitButton(html)).toMatch(/disabled=""/);
  });

  test("with several accepted types asks for a type first, with none chosen, no fields, and saving disabled", () => {
    const html = render([connection("git", "Git", [gitBearer, gitBasic])], "git");
    expect(text(tableRow(html, "git"))).toContain("2 token types");
    expect(fieldLabels(html)).toEqual(["Token type"]);
    const select = typeSelect(html);
    // A labelled, required native select whose placeholder is selected and cannot be chosen again.
    const id = /<label class="wb-field-label" for="([^"]+)">Token type<\/label>/.exec(form(html))?.[1];
    expect(id).toBeTruthy();
    expect(select).toContain(`id="${id}"`);
    expect(select).toMatch(/<select[^>]*required=""/);
    expect(select).toMatch(/<option value="" disabled="" selected="">Choose a token type<\/option>/);
    // Configuration order, named by profile without labels; no error before the select is left empty.
    expect([...select.matchAll(/<option value="([^"]*)"[^>]*>([^<]*)<\/option>/g)].map((match) => [match[1], match[2]])).toEqual([
      ["", "Choose a token type"],
      ["git-bearer-token", "git-bearer-token"],
      ["git-basic-api-token", "git-basic-api-token"]
    ]);
    expect(select).not.toContain("aria-invalid");
    expect(form(html)).toContain("The fields to fill in follow the token type.");
    expect(submitButton(html)).toContain("Save credential");
    expect(submitButton(html)).toMatch(/disabled=""/);
  });

  test("replacing preselects the stored type, by its label, and shows that type's fields", () => {
    const html = render([connection("conformance", "Conformance", [apiToken, routedToken], stored("conformance", routedToken))], "conformance");
    const select = typeSelect(html);
    expect(select).toMatch(/<option value="routed_token" selected="">Routed token<\/option>/);
    expect(select).toMatch(/<option value="api_token">API token<\/option>/);
    expect(select).not.toContain("Choose a token type");
    expect(fieldLabels(html)).toEqual(["Token type", "Conformance bearer token"]);
    expect(submitButton(html)).toContain("Replace credential");

    // A stored basic token asks for its username and token.
    const basic = render([connection("git", "Git", [gitBearer, gitBasic], stored("git", gitBasic))], "git");
    expect(typeSelect(basic)).toMatch(/<option value="git-basic-api-token" selected="">/);
    expect(fieldLabels(basic)).toEqual(["Token type", "Git username", "Git API token"]);
  });

  test("saving sends the chosen type and only its fields, so a replacement can change the stored type", async () => {
    let actions: ReturnType<typeof useCredentialActions> | undefined;
    const Probe = ({ subject }: { subject: AccountSubject }) => {
      actions = useCredentialActions(subject);
      return null;
    };
    mocks.saved.length = 0;
    renderToStaticMarkup(createElement(Probe, { subject: { administered: false, principalId: "viewer" } }));
    // The stored basic token is replaced by a bearer token; the username typed for basic is not sent.
    await actions!.save("git", gitBearer, { username: "casey@example.test", token: "synthetic-bearer" });
    renderToStaticMarkup(createElement(Probe, { subject: adminSubject("build-bot") }));
    await actions!.save("git", gitBasic, { username: "build-bot@example.test", token: "synthetic-basic" });
    expect(mocks.saved).toEqual([
      { administered: false, connection: "git", profile: "git-bearer-token", secret: { token: "synthetic-bearer" } },
      { administered: true, principal: "build-bot", connection: "git", profile: "git-basic-api-token", secret: { username: "build-bot@example.test", token: "synthetic-basic" } }
    ]);
  });

  test("lets an administrator choose a service account's token type", () => {
    const subject = adminSubject("build-bot");
    const empty = render([connection("git", "Git", [gitBearer, gitBasic])], "git", { subject });
    expect(typeSelect(empty)).toMatch(/<option value="" disabled="" selected="">Choose a token type<\/option>/);
    expect(submitButton(empty)).toMatch(/disabled=""/);
    const html = render([connection("conformance", "Conformance", [apiToken, routedToken], stored("conformance", apiToken, "build-bot"))], "conformance", { subject });
    expect(text(tableRow(html, "conformance"))).toContain("API token");
    expect(typeSelect(html)).toMatch(/<option value="api_token" selected="">API token<\/option>/);
    expect(submitButton(html)).toContain("Replace credential");
  });
});

describe("token type labels", () => {
  test("name the stored type in the row, the drawer's meta and its status, with the profile beside a label", () => {
    const html = render([connection("conformance", "Conformance", [apiToken, routedToken], stored("conformance", routedToken))], "conformance");
    expect(text(tableRow(html, "conformance"))).toContain("Routed token");
    expect(text(tableRow(html, "conformance"))).not.toContain("routed_token");
    expect(text(/<div class="wb-drawer-meta">[\s\S]*?<\/div>/.exec(drawer(html))?.[0] ?? "")).toContain("Routed token");
    expect(keyValue(html, "Token type")).toBe("Routed token routed_token");
    expect(keyValue(html, "Kind")).toBe("bearer_token");
    // Without a label, the profile alone.
    const unlabeled = render([connection("git", "Git", [gitBearer, gitBasic], stored("git", gitBasic))], "git");
    expect(text(tableRow(unlabeled, "git"))).toContain("git-basic-api-token");
    expect(keyValue(unlabeled, "Token type")).toBe("git-basic-api-token");
  });

  test("name a Not used row's type: a stored token whose type the connection no longer accepts", () => {
    // The connection now accepts only the routed token; the stored API token is kept but not used.
    const rows = [connection("conformance", "Conformance", [routedToken])];
    const html = render(rows, "retained:credential-old-conformance", { retained: [retained("conformance", apiToken)] });
    const row = tableRow(html, "retained:credential-old-conformance");
    expect(text(row)).toContain("conformance/default");
    expect(text(row)).toContain("Not used");
    expect(text(row)).toContain("API token");
    expect(text(tableRow(html, "conformance"))).toContain("Not saved");
    expect(text(tableRow(html, "conformance"))).toContain("Routed token");
    expect(text(/<div class="wb-drawer-meta">[\s\S]*?<\/div>/.exec(drawer(html))?.[0] ?? "")).toContain("API token");
    expect(keyValue(html, "Token type")).toBe("API token api_token");
    expect(text(drawer(html))).toContain("its connection no longer accepts its token type from this account");
    expect(text(drawer(html))).toContain("A token kept for its type is used again, without re-entry, once its connection accepts that type again.");
    expect(html).toMatch(/Not used[\s\S]*?>1</);
    // Without a label, the profile.
    const unlabeled = render(rows, "retained:credential-old-git", { retained: [retained("git", gitBasic)] });
    expect(text(tableRow(unlabeled, "retained:credential-old-git"))).toContain("git-basic-api-token");
    expect(keyValue(unlabeled, "Token type")).toBe("git-basic-api-token");
  });

  test("filter rows by a stored or accepted type's profile or label", () => {
    const rows = [connection("conformance", "Conformance", [apiToken, routedToken]), connection("ci", "CI", [ciToken], stored("ci", ciToken))];
    const filtered = (q: string) => {
      mocks.credentials = { connections: rows, retained: [retained("git", gitBasic)] };
      mocks.targets = rows.map(target);
      mocks.session.role = "user";
      const html = renderToStaticMarkup(createElement(MemoryRouter, { initialEntries: [`/ui/credentials?q=${encodeURIComponent(q)}`] }, createElement(Harness, { subject: { administered: false, principalId: "viewer" } })));
      return (html.match(/data-wb-row="([^"]+)"/g) ?? []).map((match) => match.slice('data-wb-row="'.length, -1));
    };
    expect(filtered("routed token")).toEqual(["conformance"]);
    expect(filtered("api_token")).toEqual(["conformance"]);
    expect(filtered("ci-token")).toEqual(["ci"]);
    expect(filtered("git-basic")).toEqual(["retained:credential-old-git"]);
  });
});
