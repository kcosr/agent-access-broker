// Explicit management API fixtures for the access key, username and access key
// type screens: a synthetic person, an administrator, a service account and a
// group. Every response is the contract the broker documents; no Broker runs.
import type { Page, Route } from "@playwright/test";
import type {
  AccessKeyAccountProblem,
  AccessKeyIssueBody,
  AccessKeyOptions,
  AccessKeyType,
  AccessKeyTypePolicy,
  AccessKeyView,
  AccountUsernameChange,
  AccountUsernameRecord,
  AccountUsernameSetBody,
  GroupAccessKeyTypes,
  PrincipalAccessKeyTypes,
  PrincipalAccountUsername,
  Session
} from "../../src/types";

export const DAY = 86_400;
export const INFERENCE: AccessKeyType = { id: "inference", displayName: "Model inference", description: "Call the hosted models through the gateway.", lifetimeOptions: ["1d", "7d", "14d", "30d"], defaultLifetime: "7d", selfService: true };
export const SEARCH: AccessKeyType = { id: "web-search", displayName: "Web search", description: "Search the web from tools that support it.", lifetimeOptions: ["1d", "7d", "14d", "30d"], defaultLifetime: "7d", selfService: true };
export const PREMIUM: AccessKeyType = { id: "premium-models", displayName: "Premium models", description: "Call the larger hosted models for evaluation work.", lifetimeOptions: ["1d", "7d", "14d"], defaultLifetime: "7d", selfService: true };
export const PACKAGES: AccessKeyType = { id: "package-downloads", displayName: "Package downloads", description: null, lifetimeOptions: ["1d", "7d"], defaultLifetime: "7d", selfService: false };
/** The configured types, in ID order as the broker lists them. */
export const TYPES: AccessKeyType[] = [INFERENCE, PACKAGES, PREMIUM, SEARCH];

export const ALICE = "usr-3f1c9a52-7b1e-4c0d-9a61-2f6d1c0e8a11";
export const BOB = "usr-a41d07be-22c9-4f6e-8d15-90b7c3e5f2a8";
export const CAROL = "usr-c7e9b3d0-5a14-4b82-93f6-1e0d8a4c6b57";
export const CAROL_EXAMPLE = "usr-5d0a3c11-8e42-4f19-b6a7-0c2e9d4f1a36";
export const DANA = "usr-6b2e0f94-3c71-4d8a-a5e2-7f19c04d3b68";
export const SERVICE = "svc-build-runner";
export const KEY_SECRET = "aab_ak_EXAMPLE-not-a-real-key-000000000000000000";

const NOW = Date.parse("2026-11-27T15:00:00Z");
const at = (offsetSeconds: number) => new Date(NOW + offsetSeconds * 1000).toISOString();
function fixtureLifetimeSeconds(value: string) {
  const match = /^(\d+)([smhd])$/.exec(value.trim());
  if (!match) throw new Error("The fixture received an invalid lifetime");
  return Number(match[1]) * ({ s: 1, m: 60, h: 3600, d: DAY }[match[2]!]!);
}
const stamp = { createdAt: "2026-11-03T12:00:00Z", updatedAt: "2026-11-24T10:12:00Z", createdBy: "admin", updatedBy: "admin" };
const envelope = (result: unknown) => ({ ok: true, result });

export function allocation(principalId: string, accountUsername: string, changes: Partial<AccountUsernameRecord> = {}): AccountUsernameRecord {
  return { principalId, accountUsername, holderKind: "user", incarnation: `${accountUsername}-1`, origin: "derived", assignedAt: "2026-11-03T12:00:00Z", assignedBy: "admin", confirmedAt: null, confirmedBy: null, state: "usable", ...changes };
}

export function usernameOf(principalId: string, displayName: string, email: string, changes: Partial<PrincipalAccountUsername> = {}): PrincipalAccountUsername {
  const local = email.split("@")[0]!;
  return {
    principalId, holderKind: "user", displayName, email, mode: "from_email", state: "usable", reason: null,
    name: allocation(principalId, local), conflict: null, fromEmail: { accountUsername: local, reason: null, conflict: null }, liveKeys: 0, ...changes
  };
}

/** A listed key; `days` place its creation, expiry and last use relative to the fixture's now. */
export function key(name: string, types: { id: string; displayName: string | null; held: boolean }[], changes: Partial<AccessKeyView> & { createdDaysAgo?: number; expiresInDays?: number | null; usedHoursAgo?: number | null } = {}): AccessKeyView {
  const { createdDaysAgo = 3, expiresInDays = 28, usedHoursAgo = 1, ...rest } = changes;
  const held = types.filter((type) => type.held);
  return {
    keyId: `ak_${name.replace(/[^a-z0-9]/g, "").padEnd(32, "0").slice(0, 32)}`, principalId: ALICE, name, origin: "portal",
    accessKeyTypes: types.map((type) => type.id), usernameIncarnation: "alice-1", createdAt: at(-createdDaysAgo * DAY), createdBy: ALICE,
    expiresAt: expiresInDays === null ? null : at(expiresInDays * DAY), revokedAt: null, revokedBy: null, lastUsedAt: usedHoursAgo === null ? null : at(-usedHoursAgo * 3600),
    status: held.length ? "active" : "no_access_key_type", usableAccessKeyTypes: held.map((type) => ({ name: type.id, validUntil: expiresInDays === null ? null : at(expiresInDays * DAY) })),
    accessKeyTypeStates: types, access: held.length === types.length ? "full" : held.length ? "partial" : "none", ...rest
  };
}

const T = (type: AccessKeyType, held = true) => ({ id: type.id, displayName: type.displayName, held });

/** Alice's keys in the mock-up: full, partial, no access left and expired. */
export function aliceKeys(): AccessKeyView[] {
  return [
    key("laptop-models", [T(INFERENCE)], { createdDaysAgo: 3, expiresInDays: 27, usedHoursAgo: 0.2 }),
    key("research-notebook", [T(INFERENCE), T(SEARCH, false)], { createdDaysAgo: 14, expiresInDays: 14, usedHoursAgo: 1 }),
    key("premium-eval", [T(INFERENCE), T(PREMIUM)], { createdDaysAgo: 5, expiresInDays: 7, usedHoursAgo: 48, origin: "administrator", createdBy: "admin" }),
    key("search-helper", [T(SEARCH, false)], { createdDaysAgo: 21, expiresInDays: 7, usedHoursAgo: 144 }),
    key("old-desktop", [T(INFERENCE)], { createdDaysAgo: 60, expiresInDays: -21, usedHoursAgo: 720, status: "expired", access: "none", usableAccessKeyTypes: [] })
  ];
}

type Account = {
  principalId: string;
  kind: "user" | "service_account" | "system";
  displayName: string;
  email: string | null;
  status: "active" | "disabled";
  accessKeyTypes: PrincipalAccessKeyTypes;
  policy: AccessKeyTypePolicy;
  accountUsername: PrincipalAccountUsername;
  /** The detail's `accessKeyProblem`: why no key of the account can work, or null. */
  accessKeyProblem: AccessKeyAccountProblem | null;
  /** A person's shared identity access pause, which stops every key of theirs. */
  identityAccessPaused: boolean;
  groups: string[];
};

/** The problem a username alone gives an active account whose identity access is not paused, as the broker decides it. */
export function usernameProblem(username: Pick<PrincipalAccountUsername, "state">): AccessKeyAccountProblem | null {
  return username.state === "usable" ? null : username.state === "awaiting_confirmation" ? "account_username_awaiting_confirmation" : username.state === "reserved" ? "account_username_reserved" : "no_account_username";
}

function account(fields: Omit<Account, "status" | "accessKeyProblem" | "identityAccessPaused">): Account {
  return { ...fields, status: "active", accessKeyProblem: usernameProblem(fields.accountUsername), identityAccessPaused: false };
}

/** The detail's `accessKeyProblem` as the broker decides it: a pause outranks the username. */
function problemOf(account: Account): AccessKeyAccountProblem | null {
  return account.status === "active" && account.identityAccessPaused ? "identity_access_paused" : account.accessKeyProblem;
}

/** A listed key of a paused person no longer resolves. */
function listed(owner: Account | undefined, key: AccessKeyView): AccessKeyView {
  return owner?.identityAccessPaused && key.status === "active" ? { ...key, status: "identity_access_paused", usableAccessKeyTypes: [], access: "none" } : key;
}

function policyOf(allowed: Record<string, "account" | "groups" | "deny" | "none">, groupIds: string[] = ["ml-team"]): AccessKeyTypePolicy {
  return { accessKeyTypes: TYPES.map((type) => {
    const source = allowed[type.id] ?? "none";
    return { accessKeyType: type.id, allowed: source === "account" || source === "groups", source: source === "deny" ? "account" : source, groupIds: source === "groups" ? groupIds : [] };
  }) };
}

/**
 * The person's own routes as the catalog lists them (without their schemas):
 * only while a type is configured, and to a browser session only.
 */
const PERSONAL_ROUTES = [
  ["GET", "/v1/access-keys", "access_keys.list"],
  ["GET", "/v1/access-keys/options", "access_keys.options"],
  ["POST", "/v1/access-keys", "access_keys.issue"],
  ["DELETE", "/v1/access-keys/{key_id}", "access_keys.revoke"]
].map(([method, route, operation]) => ({ method, route, operation, access: "account_management", requiredFeature: "access_keys", browserSessionOnly: true }));

export type AccessKeyModel = ReturnType<typeof newModel>;

function newModel() {
  const accounts: Record<string, Account> = {
    [ALICE]: account({ principalId: ALICE, kind: "user", displayName: "Alice Example", email: "alice@example.com", accessKeyTypes: { allow: [], deny: [] }, policy: policyOf({ inference: "groups", "web-search": "groups" }), accountUsername: usernameOf(ALICE, "Alice Example", "alice@example.com", { liveKeys: 3 }), groups: ["ml-team"] }),
    [BOB]: account({ principalId: BOB, kind: "user", displayName: "Bob Example", email: "bob@example.com", accessKeyTypes: { allow: [], deny: [] }, policy: policyOf({ inference: "groups" }), accountUsername: usernameOf(BOB, "Bob Example", "bob@example.com", { state: "awaiting_confirmation", name: allocation(BOB, "bob", { state: "awaiting_confirmation" }) }), groups: ["ml-team"] }),
    [CAROL]: account({ principalId: CAROL, kind: "user", displayName: "Carol Sample", email: "carol@example.org", accessKeyTypes: { allow: [], deny: [] }, policy: policyOf({ inference: "groups" }), accountUsername: usernameOf(CAROL, "Carol Sample", "carol@example.org", { state: "conflict", reason: "name_taken", name: null, conflict: { accountUsername: "carol", heldBy: CAROL_EXAMPLE }, fromEmail: { accountUsername: null, reason: "name_taken", conflict: { accountUsername: "carol", heldBy: CAROL_EXAMPLE } } }), groups: ["ml-team"] }),
    [CAROL_EXAMPLE]: account({ principalId: CAROL_EXAMPLE, kind: "user", displayName: "Carol Example", email: "carol@example.com", accessKeyTypes: { allow: [], deny: [] }, policy: policyOf({}), accountUsername: usernameOf(CAROL_EXAMPLE, "Carol Example", "carol@example.com"), groups: [] }),
    [DANA]: account({ principalId: DANA, kind: "user", displayName: "Dana Example", email: "dana.example@example.com", accessKeyTypes: { allow: ["package-downloads", "premium-models"], deny: [] }, policy: policyOf({ inference: "groups", "web-search": "groups", "premium-models": "account", "package-downloads": "account" }), accountUsername: usernameOf(DANA, "Dana Example", "dana.example@example.com", { mode: "manual", name: allocation(DANA, "dana", { origin: "administrator", assignedAt: "2026-11-20T16:05:00Z" }), liveKeys: 1 }), groups: ["ml-team"] }),
    [SERVICE]: account({ principalId: SERVICE, kind: "service_account", displayName: SERVICE, email: null, accessKeyTypes: { allow: ["package-downloads"], deny: [] }, policy: policyOf({ "package-downloads": "account" }), accountUsername: { principalId: SERVICE, holderKind: "service_account", displayName: null, email: null, mode: null, state: "usable", reason: null, name: allocation(SERVICE, SERVICE, { holderKind: "service_account", origin: "service_account" }), conflict: null, fromEmail: null, liveKeys: 0 }, groups: [] })
  };
  return {
    session: null as unknown as Session,
    /** Whether the runtime catalog lists the personal access key routes. */
    offered: true,
    options: {
      accountUsername: { name: "alice", state: "usable", mode: "from_email", reason: null, fromEmail: { accountUsername: "alice", reason: null } },
      refusal: null, accessKeyTypes: [INFERENCE, PACKAGES, PREMIUM], hasSelfServiceType: true, hasKeys: true, problem: null
    } as AccessKeyOptions,
    keys: aliceKeys(),
    adminKeys: { [ALICE]: aliceKeys(), [DANA]: [] as AccessKeyView[], [SERVICE]: [] as AccessKeyView[] } as Record<string, AccessKeyView[]>,
    types: TYPES,
    accounts,
    group: { groupId: "ml-team", displayName: "ML team", accessKeyTypes: { allow: ["inference", "web-search"] } as GroupAccessKeyTypes },
    /** What a username PUT or an email PATCH reports it did. */
    nextChange: null as AccountUsernameChange | null,
    requests: [] as string[],
    issued: [] as { pathname: string; body: AccessKeyIssueBody }[],
    revoked: [] as string[],
    accessPatches: [] as { principalId: string; body: Record<string, unknown> }[],
    groupPatches: [] as Record<string, unknown>[],
    usernameSets: [] as { principalId: string; body: AccountUsernameSetBody }[],
    confirms: [] as { principalId: string; body: unknown }[],
    /** Reads that answer 503 while set: the person's options, the type list, or one account's detail. */
    fail: { options: false, types: false, principal: "" },
    /**
     * Answers the next issue (a person's or an administrator's) with this refusal, then clears it; changes the
     * person's options first when given, and runs `then` before answering.
     */
    refuseNextIssue: null as null | { refusal: string; accessKeyType?: string; options?: Partial<AccessKeyOptions>; then?: () => void },
    /** Called when a local membership is added (true) or removed (false) through either page. */
    onMembership: null as null | ((member: boolean) => void),
    profilePatches: [] as { principalId: string; body: Record<string, unknown> }[],
    /** Configuration reloads answered. */
    reloads: 0,
    errors: [] as string[]
  };
}

const sessionFor = (principal: string, role: "user" | "admin", selfServiceEnabled: boolean, displayName: string): Session => ({
  authenticated: true, principal, displayName, role, selfServiceEnabled, policyManagementServices: [], csrfHeader: "x-csrf-token", csrfToken: "fixture",
  loginOptions: { localPassword: { enabled: true } }, auditQueryable: false
} as Session);

export const PERSON = (selfServiceEnabled = true) => sessionFor(ALICE, "user", selfServiceEnabled, "Alice Example");
export const ADMIN = () => sessionFor("admin", "admin", true, "Admin");

function detail(model: AccessKeyModel, account: Account) {
  return {
    principalId: account.principalId, kind: account.kind, displayName: account.displayName, email: account.email, status: account.status,
    groups: account.groups, role: "user", selfServiceEnabled: account.kind === "user", microsoftEnrollment: null,
    signInMethods: { localPassword: "absent", microsoft: account.kind === "user" ? "active" : "absent" },
    agentTokenIssuance: { mode: "inherit", allowedExecutionContexts: [] }, agentTokenIssuancePolicy: { source: "default", contexts: [] },
    groupMemberships: account.groups.map((groupId) => ({ groupId, effective: true, source: "local", local: { addedAt: stamp.createdAt, addedBy: "admin" }, microsoft: [] })),
    activePolicyGroupSubjects: account.groups.map((groupId) => `group:${groupId}`), policyReferenceSections: [],
    accessKeyTypes: account.accessKeyTypes, accessKeyTypePolicy: account.policy, accountUsername: account.accountUsername,
    accessKeyProblem: problemOf(account), ...stamp
  };
}

function record(account: Account) {
  const { policy: _policy, accountUsername: _username, accessKeyProblem: _problem, identityAccessPaused: _paused, ...rest } = account;
  return { ...rest, role: "user", selfServiceEnabled: account.kind === "user", microsoftEnrollment: null, signInMethods: { localPassword: "absent", microsoft: "absent" }, agentTokenIssuance: { mode: "inherit", allowedExecutionContexts: [] }, ...stamp };
}

let latest: AccessKeyModel | null = null;

/** The model of the latest `routeAccessKeyApi` call, for checks after a test; reading it forgets it. */
export function latestAccessKeyModel() {
  const model = latest;
  latest = null;
  return model;
}

/** Answers every `/v1` request the access key screens make, recording writes. */
export async function routeAccessKeyApi(page: Page, session: Session, configure: (model: AccessKeyModel) => void = () => undefined) {
  const model = newModel();
  latest = model;
  model.session = session;
  configure(model);
  page.on("pageerror", (error) => model.errors.push(error.message));
  await page.route("**/v1/**", async (route: Route) => {
    const request = route.request();
    const url = new URL(request.url());
    const { pathname } = url;
    const method = request.method();
    model.requests.push(`${method} ${pathname}`);
    // A browser session's writes carry its CSRF header; the sign-in routes are not used here.
    if (method !== "GET" && method !== "HEAD" && request.headers()["x-csrf-token"] !== "fixture") model.errors.push(`${method} ${pathname} without the session's CSRF header`);
    const unavailable = () => route.fulfill({ status: 503, json: { ok: false, reasonCode: "store_unavailable", error: { message: "The managed store is unavailable." } } });
    // As the broker answers an account or group setting that names a type the configuration does not define.
    const namesUnconfiguredType = (body: Record<string, unknown>) => {
      const setting = body.accessKeyTypes as { allow: string[]; deny?: string[] } | undefined;
      return Boolean(setting) && [...setting!.allow, ...(setting!.deny ?? [])].some((id) => !model.types.some((type) => type.id === id));
    };
    const refuseUnconfiguredType = () => route.fulfill({ status: 400, json: { ok: false, reasonCode: "input_invalid", error: { message: "an access key type setting names an access key type that is not configured" } } });
    if (method === "GET" && ((model.fail.options && pathname === "/v1/access-keys/options") || (model.fail.types && pathname === "/v1/admin/access-key-types")
      || (model.fail.principal && pathname === `/v1/admin/principals/${model.fail.principal}`))) {
      await unavailable();
      return;
    }
    if (method === "POST" && model.refuseNextIssue && (pathname === "/v1/access-keys" || /^\/v1\/admin\/principals\/[^/]+\/access-keys$/.test(pathname))) {
      const refusal = model.refuseNextIssue;
      model.refuseNextIssue = null;
      model.issued.push({ pathname, body: request.postDataJSON() as AccessKeyIssueBody });
      if (refusal.options) model.options = { ...model.options, ...refusal.options };
      refusal.then?.();
      await route.fulfill({ status: 403, json: { ok: false, reasonCode: "broker_access_key_denied", error: { message: "access key refused" }, details: { refusal: refusal.refusal, ...(refusal.accessKeyType ? { accessKeyType: refusal.accessKeyType } : {}) } } });
      return;
    }
    // As the broker does: no key is issued for an account in which none could work, whatever the types,
    // with the code the person's options (`refusal`) or the account detail (`accessKeyProblem`) report.
    const issueFor = method === "POST" ? (pathname === "/v1/access-keys" ? ALICE : /^\/v1\/admin\/principals\/([^/]+)\/access-keys$/.exec(pathname)?.[1]) : undefined;
    const standing = issueFor === undefined ? null : pathname === "/v1/access-keys" ? model.options.refusal : (model.accounts[decodeURIComponent(issueFor)] ? problemOf(model.accounts[decodeURIComponent(issueFor)]!) : null);
    if (standing) {
      model.issued.push({ pathname, body: request.postDataJSON() as AccessKeyIssueBody });
      await route.fulfill({ status: 403, json: { ok: false, reasonCode: "broker_access_key_denied", error: { message: "access key refused" }, details: { refusal: standing } } });
      return;
    }
    const json = () => request.postDataJSON() as Record<string, unknown>;
    let result: unknown = [];
    const principalMatch = /^\/v1\/admin\/principals\/([^/]+)(\/.*)?$/.exec(pathname);
    if (/^\/v1\/admin\/(groups\/[^/]+\/members|principals\/[^/]+\/groups)\/[^/]+$/.test(pathname) && (method === "PUT" || method === "DELETE")) {
      model.onMembership?.(method === "PUT");
      await route.fulfill({ json: envelope(method === "PUT" ? { ok: true } : { removed: true, effectiveMembershipRemains: false }) });
      return;
    }
    if (pathname === "/v1/auth/session") result = model.session;
    else if (pathname === "/v1/spec/catalog") {
      await route.fulfill({ json: { routes: model.offered ? PERSONAL_ROUTES : [{ operation: "tokens.list" }] } });
      return;
    } else if (pathname === "/v1/resource-types") {
      await route.fulfill({ json: { resourceTypes: [] } });
      return;
    } else if (pathname === "/v1/access-keys/options") result = model.options;
    else if (pathname === "/v1/access-keys" && method === "GET") result = { keys: model.keys };
    else if ((pathname === "/v1/access-keys" || /^\/v1\/admin\/principals\/[^/]+\/access-keys$/.test(pathname)) && method === "POST") {
      const body = request.postDataJSON() as AccessKeyIssueBody;
      model.issued.push({ pathname, body });
      const owner = pathname === "/v1/access-keys" ? ALICE : decodeURIComponent(pathname.split("/")[4]!);
      const types = body.accessKeyTypes.map((id) => ({ id, displayName: TYPES.find((type) => type.id === id)?.displayName ?? null, held: true }));
      const issued = key(body.name, types, { principalId: owner, createdDaysAgo: 0, expiresInDays: body.lifetime === "never" ? null : fixtureLifetimeSeconds(body.lifetime) / DAY, usedHoursAgo: null, keyId: "ak_5d2f8e1c90ab4c3e8f7a6b5c4d3e2f10", origin: owner === ALICE && pathname === "/v1/access-keys" ? "portal" : "administrator", createdBy: pathname === "/v1/access-keys" ? ALICE : "admin" });
      if (pathname === "/v1/access-keys") model.keys = [issued, ...model.keys];
      // One account's keys, whichever route issued them.
      model.adminKeys[owner] = [issued, ...(model.adminKeys[owner] ?? [])];
      const holder = model.accounts[owner];
      if (holder) holder.accountUsername = { ...holder.accountUsername, liveKeys: holder.accountUsername.liveKeys + 1 };
      const { status: _s, usableAccessKeyTypes: _u, accessKeyTypeStates: _t, access: _a, ...stored } = issued;
      result = { key: KEY_SECRET, record: stored };
    } else if (/^\/v1\/(admin\/)?access-keys\/[^/]+$/.test(pathname) && method === "DELETE") {
      const keyId = pathname.split("/").at(-1)!;
      model.revoked.push(pathname);
      const revoke = (keys: AccessKeyView[]) => keys.map((item) => (item.keyId === keyId ? { ...item, revokedAt: at(0), revokedBy: model.session.principal ?? null, status: "revoked" as const, usableAccessKeyTypes: [], access: "none" as const } : item));
      const owner = [...model.keys, ...Object.values(model.adminKeys).flat()].find((item) => item.keyId === keyId && item.revokedAt === null)?.principalId;
      model.keys = revoke(model.keys);
      for (const holder of Object.keys(model.adminKeys)) model.adminKeys[holder] = revoke(model.adminKeys[holder]!);
      const holder = owner ? model.accounts[owner] : undefined;
      if (holder) holder.accountUsername = { ...holder.accountUsername, liveKeys: Math.max(0, holder.accountUsername.liveKeys - 1) };
      const revoked = [...model.keys, ...Object.values(model.adminKeys).flat()].find((item) => item.keyId === keyId);
      // The answer carries the stored record, without what a list adds.
      const { status: _s, usableAccessKeyTypes: _u, accessKeyTypeStates: _t, access: _a, ...stored } = revoked ?? key("unknown", [], { keyId });
      result = { revoked: true, newlyRevoked: true, record: stored };
    } else if (pathname === "/v1/admin/access-key-types") result = { accessKeyTypes: model.types };
    else if (pathname === "/v1/admin/access-keys") {
      const owner = url.searchParams.get("principal") ?? "";
      result = { keys: (model.adminKeys[owner] ?? []).map((item) => listed(model.accounts[owner], item)) };
    } else if (pathname === "/v1/admin/config/reload" && method === "POST") {
      model.reloads += 1;
      result = { identityAuthority: "managed", policyAuthority: "managed", generation: 12 + model.reloads, previousGeneration: 11 + model.reloads, loadedAt: stamp.createdAt, configHash: "fixture-reloaded", previousConfigHash: "fixture" };
    }
    else if (pathname === "/v1/admin/principals" && method === "GET") result = Object.values(model.accounts).map(record).concat([{ ...record(model.accounts[ALICE]!), principalId: "admin", displayName: "Admin", email: null }]);
    else if (principalMatch) {
      const principalId = decodeURIComponent(principalMatch[1]!);
      const rest = principalMatch[2] ?? "";
      const account = model.accounts[principalId];
      if (!account) {
        await route.fulfill({ status: 404, json: { ok: false, reasonCode: "principal_not_found", error: { message: "principal not found" } } });
        return;
      }
      if (rest === "" && method === "GET") result = detail(model, account);
      else if (rest === "" && method === "PATCH") {
        const body = json();
        model.profilePatches.push({ principalId, body });
        if (typeof body.email === "string" || body.email === null) account.email = body.email as string | null;
        const change = "email" in body && account.kind === "user" ? model.nextChange : null;
        if (change) {
          // A change that renamed nobody keeps the name's state (awaiting confirmation stays awaiting).
          account.accountUsername = { ...account.accountUsername, email: account.email, name: change.after, state: change.renamed ? (change.after ? "usable" : "none") : account.accountUsername.state, liveKeys: change.renamed ? 0 : account.accountUsername.liveKeys, fromEmail: { accountUsername: change.after?.accountUsername ?? null, reason: change.reason as never, conflict: change.conflict } };
          account.accessKeyProblem = usernameProblem(account.accountUsername);
        }
        result = { ...record(account), accountUsernameChange: change };
      } else if (rest === "/access" && method === "PATCH") {
        const body = json();
        model.accessPatches.push({ principalId, body });
        if (namesUnconfiguredType(body)) {
          await refuseUnconfiguredType();
          return;
        }
        if (body.accessKeyTypes) account.accessKeyTypes = body.accessKeyTypes as PrincipalAccessKeyTypes;
        result = { ...record(account) };
      } else if (rest === "/account-username" && method === "PUT") {
        const body = request.postDataJSON() as AccountUsernameSetBody;
        model.usernameSets.push({ principalId, body });
        const change = model.nextChange!;
        account.accountUsername = { ...account.accountUsername, mode: change.mode, name: change.after, state: change.after ? "usable" : "none", liveKeys: change.renamed ? 0 : account.accountUsername.liveKeys };
        account.accessKeyProblem = usernameProblem(account.accountUsername);
        result = { ...account.accountUsername, accountUsernameChange: change };
      } else if (rest === "/account-username/confirm" && method === "POST") {
        model.confirms.push({ principalId, body: request.postDataJSON() });
        account.accountUsername = { ...account.accountUsername, state: "usable", name: { ...account.accountUsername.name!, state: "usable", confirmedAt: at(0), confirmedBy: "admin" } };
        account.accessKeyProblem = usernameProblem(account.accountUsername);
        result = account.accountUsername;
      } else if (rest.endsWith("/login-methods")) result = [];
      else if (rest.endsWith("/identity-token")) result = { principalId, configured: false, enabled: true, readOnly: false, revision: 1, updatedAt: stamp.createdAt };
      else if (rest.endsWith("/identity-access") && method === "PATCH") {
        account.identityAccessPaused = Boolean(json().paused);
        result = { principalId, incarnation: "fixture", paused: account.identityAccessPaused, version: 2, ...stamp };
      } else if (rest.endsWith("/identity-access")) result = { principalId, incarnation: "fixture", paused: account.identityAccessPaused || account.accessKeyProblem === "identity_access_paused", version: 1, ...stamp };
      else if (rest.endsWith("/identity-bindings")) result = { bindings: [], configuredNamespaces: [] };
      else if (rest.endsWith("/application-access")) result = { access: [] };
      else if (rest.endsWith("/agent-tokens")) result = [];
    } else if (pathname === "/v1/admin/groups" && method === "GET") result = [{ groupId: "ml-team", displayName: "ML team", status: "active", memberCount: 4, autoEnrollNewMicrosoftUsers: false, agentTokenIssuance: { mode: "disabled", allowedExecutionContexts: [] }, accessKeyTypes: model.group.accessKeyTypes, ...stamp }];
    else if (pathname === "/v1/admin/groups/ml-team") {
      if (method === "PATCH") {
        const body = json();
        model.groupPatches.push(body);
        if (namesUnconfiguredType(body)) {
          await refuseUnconfiguredType();
          return;
        }
        if (body.accessKeyTypes) model.group.accessKeyTypes = body.accessKeyTypes as GroupAccessKeyTypes;
      }
      result = { groupId: "ml-team", displayName: "ML team", description: "People who run model experiments.", status: "active", memberCount: 4, autoEnrollNewMicrosoftUsers: false, agentTokenIssuance: { mode: "disabled", allowedExecutionContexts: [] }, accessKeyTypes: model.group.accessKeyTypes, members: [], policyReferenceSections: [], ...stamp };
    } else if (pathname === "/v1/admin/policy/catalog") result = { services: [], subjects: { users: [], groups: [], anonymous: false }, resources: [], resourceGroups: [], executionContexts: { allowedValues: ["default"], defaultContext: "default" } };
    else if (pathname === "/v1/admin/policy/status") result = { policyGeneration: 12, writable: true, policyAuthority: "managed", counts: { active: 0, disabled: 0, deleted: 0 }, managementScope: { kind: "global" } };
    else if (pathname === "/v1/admin/config/status") result = { identityAuthority: "managed", policyAuthority: "managed", generation: 12, loadedAt: stamp.createdAt, configHash: "fixture" };
    else if (pathname === "/v1/admin/policy/grants" || pathname === "/v1/admin/imports" || pathname === "/v1/admin/policy/service-managers") result = pathname === "/v1/admin/imports" ? { services: [], availableKinds: [], importAuthentication: [], commandImports: [], gatewayBindings: [], operatorEnabled: false } : [];
    else if (pathname === "/v1/admin/policy/resources" || pathname === "/v1/admin/policy/resource-groups") result = [];
    else if (pathname === "/v1/me") result = { serviceLimits: [] };
    else if (pathname === "/v1/credentials") result = { connections: [], retained: [] };
    else if (pathname === "/v1/tokens/options") result = { policyGeneration: 1, agentTokenIssuancePolicy: { source: "default", contexts: [] }, executionContexts: [], resources: [], resourceGroups: [], services: [], mcp: null };
    else if (pathname === "/v1/tokens") result = [];
    else if (pathname === "/v1/applications/access") result = { access: [] };
    await route.fulfill({ json: envelope(result) });
  });
  return model;
}
