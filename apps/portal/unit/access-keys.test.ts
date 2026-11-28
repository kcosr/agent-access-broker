// Access keys, access key types and usernames in the portal: what each server
// fact reads as, the issue form's draft, and the components that show them.
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, test } from "vitest";
import {
  accessKeyAccountProblem,
  accessKeyTypeLabels,
  accessKeyCounts,
  accessKeyLifetimeChoices,
  accessKeyLifetimeHint,
  accessKeyLifetimeLabel,
  accessKeyLifetimeSeconds,
  defaultAccessKeyLifetime,
  offeredAccessKeyLifetime,
  reconcileAccessKeyLifetime,
  accessKeyRefusalMessage,
  accessKeysShown,
  accessKeyStatusLabel,
  accessKeyTypeResult,
  accessKeyTypeSettingBlocker,
  accessKeyTypesSettingEqual,
  administeredAccessKeyTypes,
  administeredIssueBlocker,
  buildAccessKeyIssue,
  canIssueOwnAccessKey,
  catalogListsAccessKeys,
  fromEmailExplanation,
  newAccessKeyDraft,
  ownAccessKeyBlocker,
  principalAccessKeyTypeChoice,
  selfServiceTypes,
  setGroupAccessKeyType,
  setPrincipalAccessKeyTypeChoice,
  toggleAccessKeyType,
  unavailableChoices,
  unconfiguredAccessKeyTypes,
  USERNAME_STATE_BADGE,
  usernameStateBadge,
  usernameChangeSummary,
  usernameChangeWarning
} from "../src/lib/access-keys";
import { accessDraft, accessDraftPatch, refreshAccessDraft } from "../src/lib/access-draft";
import { isPortalPath, paths, ROUTE } from "../src/app/paths";
import { spaceTabs } from "../src/app/spaces";
import { modalHasOneTimeSecret } from "../src/lib/helpers";
import { AccessKeyPills, AccessKeyStatusCell } from "../src/features/access-keys/key-list";
import { GroupAccessKeyTypeChecks, PrincipalAccessKeyTypeTable } from "../src/features/principals/access-key-type-settings";
import { UsernameHistory } from "../src/features/principals/account-username";
import type { AccessKeyOptions, AccessKeyRecord, AccessKeyType, AccessKeyTypePolicy, AccessKeyView, AccountUsernameChange, AccountUsernameRecord, PrincipalAccountUsername, Session } from "../src/types";

const DAY = 86_400;
const INFERENCE: AccessKeyType = { id: "inference", displayName: "Model inference", description: "Call the hosted models through the gateway.", lifetimeOptions: ["1d", "7d", "14d", "30d"], defaultLifetime: "7d", selfService: true };
const SEARCH: AccessKeyType = { id: "web-search", displayName: "Web search", description: null, lifetimeOptions: ["1d", "7d", "14d", "30d"], defaultLifetime: "7d", selfService: true };
const PREMIUM: AccessKeyType = { id: "premium-models", displayName: "Premium models", description: "Call the larger hosted models for evaluation work.", lifetimeOptions: ["1d", "7d", "14d"], defaultLifetime: "7d", selfService: true };
const PACKAGES: AccessKeyType = { id: "package-downloads", displayName: "Package downloads", description: null, lifetimeOptions: ["1d", "7d"], defaultLifetime: "7d", selfService: false };
const TYPES = [INFERENCE, PACKAGES, PREMIUM, SEARCH];

const options = (changes: Partial<AccessKeyOptions> = {}): AccessKeyOptions => ({
  accountUsername: { name: "alice", state: "usable", mode: "from_email", reason: null, fromEmail: { accountUsername: "alice", reason: null } },
  refusal: null, accessKeyTypes: [INFERENCE, PACKAGES], hasSelfServiceType: true, hasKeys: false, problem: null, ...changes
});

const record: AccessKeyRecord = {
  keyId: "ak_0123456789abcdef0123456789abcdef", principalId: "usr-alice", name: "research-notebook", origin: "portal",
  accessKeyTypes: ["inference", "web-search"], usernameIncarnation: "incarnation-1", createdAt: "2026-11-13T15:00:00Z", createdBy: "usr-alice",
  expiresAt: "2026-12-11T15:00:00Z", revokedAt: null, revokedBy: null, lastUsedAt: "2026-11-27T14:00:00Z"
};
const view = (changes: Partial<AccessKeyView> = {}): AccessKeyView => ({
  ...record, status: "active", usableAccessKeyTypes: [{ name: "inference", validUntil: record.expiresAt }],
  accessKeyTypeStates: [{ id: "inference", displayName: "Model inference", held: true }, { id: "web-search", displayName: "Web search", held: false }],
  access: "partial", ...changes
});

const allocation = (changes: Partial<AccountUsernameRecord> = {}): AccountUsernameRecord => ({
  principalId: "usr-alice", accountUsername: "alice", holderKind: "user", incarnation: "incarnation-1", origin: "derived",
  assignedAt: "2026-11-03T12:00:00Z", assignedBy: "admin", confirmedAt: null, confirmedBy: null, state: "usable", ...changes
});
const username = (changes: Partial<PrincipalAccountUsername> = {}): PrincipalAccountUsername => ({
  principalId: "usr-alice", holderKind: "user", displayName: "Alice Example", email: "alice@example.com", mode: "from_email", state: "usable", reason: null,
  name: allocation(), conflict: null, fromEmail: { accountUsername: "alice", reason: null, conflict: null }, liveKeys: 3, ...changes
});
const change = (changes: Partial<AccountUsernameChange> = {}): AccountUsernameChange => ({
  previousMode: "from_email", mode: "from_email", before: allocation(), after: allocation({ accountUsername: "alice.example", incarnation: "incarnation-2" }),
  renamed: true, endedKeys: 3, reason: null, conflict: null, ...changes
});

describe("whether the person sees access keys", () => {
  test("the catalog lists the personal routes only while a type is configured; the portal reads it, never probes", () => {
    expect(catalogListsAccessKeys({ routes: [{ operation: "access_keys.options" }, { operation: "access_keys.list" }] })).toBe(true);
    expect(catalogListsAccessKeys({ routes: [{ operation: "applications.access.list" }] })).toBe(false);
    expect(catalogListsAccessKeys({} as never)).toBe(false);
  });

  test("Keys shows for a type the person may issue, a key they hold, or a problem only an administrator can fix", () => {
    expect(accessKeysShown(options())).toBe(true);
    expect(accessKeysShown(options({ hasSelfServiceType: false, hasKeys: true }))).toBe(true);
    expect(accessKeysShown(options({ hasSelfServiceType: false, hasKeys: true, problem: "no_account_username", refusal: "no_account_username" }))).toBe(true);
    // A paused person keeps seeing the keys they hold; with nothing to issue and no key there is nothing to show.
    expect(accessKeysShown(options({ hasKeys: true, refusal: "identity_access_paused" }))).toBe(true);
    expect(accessKeysShown(options({ hasSelfServiceType: false, hasKeys: false, refusal: "identity_access_paused" }))).toBe(false);
    expect(accessKeysShown(options({ hasSelfServiceType: false, accessKeyTypes: [], hasKeys: false, problem: null }))).toBe(false);
    expect(accessKeysShown(null)).toBe(false);
  });

  test("issuing is offered only with a self-service type, no refusal and no problem", () => {
    expect(canIssueOwnAccessKey(options())).toBe(true);
    expect(canIssueOwnAccessKey(options({ problem: "group_limit_exceeded", refusal: "group_limit_exceeded" }))).toBe(false);
    expect(canIssueOwnAccessKey(options({ refusal: "identity_access_paused" }))).toBe(false);
    expect(canIssueOwnAccessKey(options({ hasSelfServiceType: false }))).toBe(false);
  });

  test("the reason beside the title is the server's problem, else its refusal, in one sentence that sends the person to an administrator", () => {
    expect(ownAccessKeyBlocker(options({ problem: "no_account_username", refusal: "no_account_username" }))).toBe("You have no username yet. Ask an administrator to set one.");
    expect(ownAccessKeyBlocker(options({ problem: "group_limit_exceeded", refusal: "group_limit_exceeded" }))).toBe("You are in too many groups for access keys to work. Ask an administrator for help.");
    expect(ownAccessKeyBlocker(options({ refusal: "identity_access_missing" }))).toBe("Your access cannot be confirmed. Ask an administrator for help.");
    expect(ownAccessKeyBlocker(options({ refusal: "identity_access_paused" }))).toContain("Ask an administrator");
    expect(ownAccessKeyBlocker(options({ refusal: "account_username_awaiting_confirmation" }))).toContain("confirm");
    expect(ownAccessKeyBlocker(options())).toBeNull();
    for (const code of ["no_account_username", "account_username_awaiting_confirmation", "account_username_reserved", "group_limit_exceeded"] as const) {
      expect(ownAccessKeyBlocker(options({ problem: code, refusal: code }))).toMatch(/administrator/);
    }
    for (const code of ["principal_disabled", "identity_access_paused", "identity_access_missing"] as const) {
      expect(ownAccessKeyBlocker(options({ refusal: code }))).toMatch(/administrator/);
    }
  });

  test("a person issues only the types marked self-service, in the server's order", () => {
    expect(selfServiceTypes(options({ accessKeyTypes: TYPES })).map((type) => type.id)).toEqual(["inference", "premium-models", "web-search"]);
  });
});

describe("listed keys", () => {
  test("status and access read as the server states them", () => {
    expect(accessKeyStatusLabel({ status: "active", access: "full" })).toMatchObject({ label: "Active", tone: "success", quiet: true });
    expect(accessKeyStatusLabel({ status: "active", access: "partial" })).toMatchObject({ label: "Partial access", quiet: false });
    expect(accessKeyStatusLabel({ status: "no_access_key_type", access: "none" }).label).toBe("No access left");
    expect(accessKeyStatusLabel({ status: "expired", access: "none" }).label).toBe("Expired");
    expect(accessKeyStatusLabel({ status: "revoked", access: "none" }).label).toBe("Revoked");
    expect(accessKeyStatusLabel({ status: "username_incarnation_changed", access: "none" }).title).toMatch(/username changed after the key was issued/);
    expect(accessKeyStatusLabel({ status: "group_limit_exceeded", access: "none" }).label).toBe("Too many groups");
    expect(accessKeyStatusLabel({ status: "something_new" as never, access: "none" }).label).toBe("Not working");
  });

  test("a type the key no longer holds is shown by its name and marked no longer available; a removed type by its ID", () => {
    const markup = renderToStaticMarkup(createElement(AccessKeyPills, { keyView: view({ accessKeyTypeStates: [{ id: "inference", displayName: "Model inference", held: true }, { id: "web-search", displayName: "Web search", held: false }, { id: "retired", displayName: null, held: false }] }) }));
    expect(markup).toContain(">Model inference<");
    expect(markup).toContain("Web search");
    expect(markup.match(/no longer available/g)?.length).toBeGreaterThanOrEqual(2);
    expect(markup).toContain("retired");
    expect(markup).toContain("wb-chip--readonly");
  });

  test("a held type of an expired key stays an ordinary chip; the status says why the key does not work", () => {
    const expired = view({ status: "expired", access: "none", accessKeyTypeStates: [{ id: "inference", displayName: "Model inference", held: true }] });
    expect(renderToStaticMarkup(createElement(AccessKeyPills, { keyView: expired }))).not.toContain("no longer available");
    expect(renderToStaticMarkup(createElement(AccessKeyStatusCell, { keyView: expired }))).toContain("Expired");
    expect(renderToStaticMarkup(createElement(AccessKeyStatusCell, { keyView: view() }))).toContain("Partial access");
  });

  test("the administrator's filters count revoked first, then expired, else current", () => {
    const keys = [view(), view({ status: "expired" }), view({ status: "expired", revokedAt: "2026-11-20T00:00:00Z" }), view({ status: "no_access_key_type" })];
    expect(accessKeyCounts(keys)).toEqual({ current: 2, expired: 1, revoked: 1, all: 4 });
  });
});

describe("the issue form", () => {
  test("nothing is chosen, also when only one type is offered, and the form waits for access", () => {
    const draft = newAccessKeyDraft();
    expect(draft).toEqual({ name: "", accessKeyTypes: [], lifetime: null, lifetimeManuallyChosen: false });
    expect(accessKeyLifetimeChoices([INFERENCE], [])).toEqual([]);
    const refused = buildAccessKeyIssue({ ...draft, name: "laptop-models" }, [INFERENCE]);
    expect(refused).toEqual({ valid: false, issues: [{ field: "access", message: "Choose what this key gives access to." }] });
    const chosen = buildAccessKeyIssue(toggleAccessKeyType({ ...draft, name: "laptop-models" }, "inference", true, [INFERENCE]), [INFERENCE]);
    expect(chosen).toEqual({ valid: true, body: { name: "laptop-models", accessKeyTypes: ["inference"], lifetime: "7d" } });
  });

  test("issues come in the form's order, and an empty name is one of them", () => {
    const result = buildAccessKeyIssue(newAccessKeyDraft(), TYPES);
    expect(result.valid ? [] : result.issues.map((issue) => issue.field)).toEqual(["access", "name"]);
  });

  test("choices are common effective durations in first-selected-type order, retaining that type's spelling", () => {
    const types = [
      { ...INFERENCE, lifetimeOptions: ["never", "90m", "7d", "1d"], defaultLifetime: "24h" },
      { ...PREMIUM, lifetimeOptions: ["1440m", "never", "5400s", "168h"], defaultLifetime: "90m" }
    ];
    expect(accessKeyLifetimeChoices(types, ["inference", "premium-models"])).toEqual(["never", "90m", "7d", "1d"]);
    expect(accessKeyLifetimeChoices(types, ["premium-models", "inference"])).toEqual(["1440m", "never", "5400s", "168h"]);
    expect(defaultAccessKeyLifetime(types, ["inference", "premium-models"])).toBe("90m");
    expect(defaultAccessKeyLifetime(types, ["premium-models", "inference"])).toBe("5400s");
  });

  test("the shortest offered chosen-type default wins even when a shorter common option exists", () => {
    const types = [
      { ...INFERENCE, lifetimeOptions: ["1d", "7d", "14d"], defaultLifetime: "14d" },
      { ...PREMIUM, lifetimeOptions: ["14d", "7d", "1d"], defaultLifetime: "168h" }
    ];
    expect(defaultAccessKeyLifetime(types, ["inference", "premium-models"])).toBe("7d");
  });

  test("when no chosen-type default is common, preselection is the shortest common option", () => {
    const types = [
      { ...INFERENCE, lifetimeOptions: ["12h", "never", "7d", "1d"], defaultLifetime: "12h" },
      { ...PREMIUM, lifetimeOptions: ["2d", "7d", "24h", "never"], defaultLifetime: "2d" }
    ];
    expect(accessKeyLifetimeChoices(types, ["inference", "premium-models"])).toEqual(["never", "7d", "1d"]);
    expect(defaultAccessKeyLifetime(types, ["inference", "premium-models"])).toBe("1d");
  });

  test("never participates as an unlimited duration and can be the configured default", () => {
    const types = [
      { ...INFERENCE, lifetimeOptions: ["never", "1d"], defaultLifetime: "never" },
      { ...PREMIUM, lifetimeOptions: ["2d", "24h", "never"], defaultLifetime: "2d" }
    ];
    expect(defaultAccessKeyLifetime(types, ["inference", "premium-models"])).toBe("never");
    expect(defaultAccessKeyLifetime([{ ...INFERENCE, lifetimeOptions: ["never"], defaultLifetime: "never" }], ["inference"])).toBe("never");
    expect(accessKeyLifetimeLabel("never")).toBe("Never expires");
  });

  test("type changes recompute automatic defaults, preserve a common manual choice, and replace an unavailable one", () => {
    const types = [
      { ...INFERENCE, lifetimeOptions: ["never", "7d", "1d"], defaultLifetime: "7d" },
      { ...PREMIUM, lifetimeOptions: ["never", "24h", "168h"], defaultLifetime: "24h" },
      { ...SEARCH, lifetimeOptions: ["24h", "7d"], defaultLifetime: "7d" }
    ];
    const first = toggleAccessKeyType(newAccessKeyDraft(), "inference", true, types);
    expect(first).toMatchObject({ lifetime: "7d", lifetimeManuallyChosen: false });
    const automatic = toggleAccessKeyType(first, "premium-models", true, types);
    expect(automatic).toMatchObject({ lifetime: "1d", lifetimeManuallyChosen: false });
    const manual = toggleAccessKeyType({ ...first, lifetime: "never", lifetimeManuallyChosen: true }, "premium-models", true, types);
    expect(manual).toMatchObject({ lifetime: "never", lifetimeManuallyChosen: true });
    const replaced = toggleAccessKeyType(manual, "web-search", true, types);
    expect(replaced).toMatchObject({ lifetime: "1d", lifetimeManuallyChosen: false });
    // Removing the shortest default now recomputes, rather than treating the fallback as manual.
    expect(toggleAccessKeyType(replaced, "premium-models", false, types)).toMatchObject({ lifetime: "7d", lifetimeManuallyChosen: false });
  });

  test("refreshes preserve a manual duration using the current spelling and clear it when no longer offered", () => {
    const manual = { ...newAccessKeyDraft(), accessKeyTypes: ["inference"], lifetime: "24h", lifetimeManuallyChosen: true };
    const preserved = reconcileAccessKeyLifetime(manual, [INFERENCE]);
    expect(preserved).toMatchObject({ lifetime: "1d", lifetimeManuallyChosen: true });
    const changed = [{ ...INFERENCE, lifetimeOptions: ["never", "7d"], defaultLifetime: "never" }];
    expect(reconcileAccessKeyLifetime(preserved, changed)).toMatchObject({ lifetime: "never", lifetimeManuallyChosen: false });
    expect(reconcileAccessKeyLifetime(preserved, []).lifetime).toBeNull();
  });

  test("a lifetime need not be a usual step, but it must be an offered duration", () => {
    const types = [{ ...INFERENCE, lifetimeOptions: ["90m", "2d"], defaultLifetime: "90m" }];
    expect(accessKeyLifetimeChoices(types, ["inference"])).toEqual(["90m", "2d"]);
    expect(buildAccessKeyIssue({ name: "eval", accessKeyTypes: ["inference"], lifetime: "90m" }, types)).toEqual({ valid: true, body: { name: "eval", accessKeyTypes: ["inference"], lifetime: "90m" } });
    expect(buildAccessKeyIssue({ name: "eval", accessKeyTypes: ["inference"], lifetime: "1d" }, types)).toEqual({ valid: false, issues: [{ field: "lifetime", message: "Choose an available lifetime." }] });
  });

  test("no common lifetime blocks issuing and has no preselection", () => {
    const types = [
      { ...INFERENCE, lifetimeOptions: ["never", "1d"], defaultLifetime: "never" },
      { ...PREMIUM, lifetimeOptions: ["2d"], defaultLifetime: "2d" }
    ];
    expect(accessKeyLifetimeChoices(types, ["inference", "premium-models"])).toEqual([]);
    expect(defaultAccessKeyLifetime(types, ["inference", "premium-models"])).toBeNull();
    expect(accessKeyLifetimeHint(types, ["inference", "premium-models"])).toBe("The chosen access types have no lifetime in common.");
    expect(buildAccessKeyIssue({ name: "eval", accessKeyTypes: ["inference", "premium-models"], lifetime: "1d" }, types)).toEqual({ valid: false, issues: [{ field: "lifetime", message: "The chosen access types have no lifetime in common." }] });
  });

  test("the selected option and request keep first-selected-type spelling and request order", () => {
    const types = [{ ...INFERENCE, lifetimeOptions: ["1d"], defaultLifetime: "1d" }, { ...PREMIUM, lifetimeOptions: ["24h"], defaultLifetime: "24h" }];
    expect(offeredAccessKeyLifetime(["24h"], "1440m")).toBe("24h");
    expect(offeredAccessKeyLifetime(["24h"], "never")).toBeNull();
    expect(buildAccessKeyIssue({ name: "eval", accessKeyTypes: ["premium-models", "inference"], lifetime: "1d" }, types)).toEqual({ valid: true, body: { name: "eval", accessKeyTypes: ["premium-models", "inference"], lifetime: "24h" } });
  });

  test("lifetime parsing follows Broker duration grammar and the access-key ceiling", () => {
    expect(accessKeyLifetimeSeconds("never")).toBe(Infinity);
    expect(accessKeyLifetimeSeconds(" 001d ")).toBe(DAY);
    expect(accessKeyLifetimeSeconds("\u008590m\u0085")).toBe(5400);
    expect(accessKeyLifetimeSeconds("3650d")).toBe(3650 * DAY);
    for (const invalid of [" never ", "1D", "+1d", "1 d", "0s", "1.5h", "3651d", "\uFEFF1d", "9999999999999999999999999d", "", null, 3600]) {
      expect(accessKeyLifetimeSeconds(invalid)).toBeNull();
    }
    expect(accessKeyLifetimeLabel("24h")).toBe("1 day");
    expect(accessKeyLifetimeLabel("90m")).toBe("90 minutes");
    expect(accessKeyLifetimeHint(TYPES, [])).toBe("Choose access to see its lifetime options.");
    expect(accessKeyLifetimeHint(TYPES, ["inference", "premium-models"])).toBe("These lifetimes are offered by every chosen access type.");
  });

  test("a type no longer offered is never sent or dropped silently", () => {
    const draft = { name: "eval", accessKeyTypes: ["inference", "web-search"], lifetime: "7d" };
    expect(accessKeyLifetimeChoices([INFERENCE], draft.accessKeyTypes)).toEqual([]);
    expect(accessKeyLifetimeHint([INFERENCE], draft.accessKeyTypes)).toBe("Remove access that is no longer offered before choosing a lifetime.");
    expect(accessKeyLifetimeHint([], draft.accessKeyTypes)).toBe("Remove access that is no longer offered before choosing a lifetime.");
    expect(buildAccessKeyIssue(draft, [INFERENCE])).toEqual({ valid: false, issues: [{ field: "access", message: "Remove access that is no longer offered." }] });
  });

  test("a chosen type no longer offered is listed by its last offered name, for removal", () => {
    const seen = new Map(TYPES.map((type) => [type.id, type]));
    const draft = { name: "eval", accessKeyTypes: ["inference", "premium-models", "retired"], lifetime: "7d", lifetimeManuallyChosen: true };
    expect(unavailableChoices(draft, [INFERENCE], seen)).toEqual([{ id: "premium-models", label: "Premium models" }, { id: "retired", label: "retired" }]);
    expect(unavailableChoices(draft, TYPES, seen)).toEqual([{ id: "retired", label: "retired" }]);
    const removed = toggleAccessKeyType(draft, "premium-models", false, TYPES);
    expect(removed.accessKeyTypes).toEqual(["inference", "retired"]);
  });

  test("names are checked in bytes, as the broker checks them", () => {
    const result = buildAccessKeyIssue({ name: "é".repeat(65), accessKeyTypes: ["inference"], lifetime: "1d" }, [INFERENCE]);
    expect(result).toEqual({ valid: false, issues: [{ field: "name", message: "Shorten the key name to 128 bytes or fewer." }] });
  });

  test("an administrator is offered the types the account's resolved policy allows, people-cannot-issue ones included", () => {
    const policy: AccessKeyTypePolicy = { accessKeyTypes: [
      { accessKeyType: "inference", allowed: true, source: "groups", groupIds: ["ml-team"] },
      { accessKeyType: "package-downloads", allowed: true, source: "account", groupIds: [] },
      { accessKeyType: "premium-models", allowed: false, source: "none", groupIds: [] },
      { accessKeyType: "web-search", allowed: false, source: "account", groupIds: [] }
    ] };
    const { offered, notOffered } = administeredAccessKeyTypes(TYPES, policy);
    expect(offered.map((type) => type.id)).toEqual(["inference", "package-downloads"]);
    expect(notOffered.map((type) => type.id)).toEqual(["premium-models", "web-search"]);
  });

  test("an administrator's form needs an account that holds keys and a type it is allowed, and names the fix only where there is one", () => {
    const base = { kind: "user", offered: 2 };
    expect(administeredIssueBlocker(base)).toBeNull();
    expect(administeredIssueBlocker({ ...base, offered: 0 })).toEqual({ text: expect.stringMatching(/not allowed any access key type/), fix: "overview" });
    expect(administeredIssueBlocker({ kind: "service_account", offered: 0 })?.fix).toBe("overview");
    // Nothing on an account that cannot hold keys makes it hold them.
    expect(administeredIssueBlocker({ ...base, kind: "system" })).toEqual({ text: "This account cannot hold access keys.", fix: null });
    expect(administeredIssueBlocker({ kind: "system", offered: 0 })).toEqual({ text: "This account cannot hold access keys.", fix: null });
    expect(administeredIssueBlocker({ ...base, kind: "service_account" })).toBeNull();
  });

  test("why no key of an account can work is the server's accessKeyProblem, worded for an administrator with what to fix", () => {
    const person = { kind: "user" as const, accountUsername: username() };
    const service = { kind: "service_account" as const, accountUsername: username({ holderKind: "service_account", mode: null, name: allocation({ accountUsername: "svc-build-runner", origin: "service_account", holderKind: "service_account" }) }) };
    expect(accessKeyAccountProblem({ ...person, accessKeyProblem: null })).toBeNull();
    expect(accessKeyAccountProblem({ ...service, accessKeyProblem: null })).toBeNull();
    expect(accessKeyAccountProblem({ ...person, accessKeyProblem: "principal_disabled" })).toEqual({ text: "This account is disabled. Enable it before issuing access keys.", fix: null });
    expect(accessKeyAccountProblem({ ...person, accessKeyProblem: "identity_access_paused" })).toEqual({ text: "This person’s identity access is paused. Resume it under Identity access on the Overview tab first.", fix: "overview" });
    expect(accessKeyAccountProblem({ ...person, accessKeyProblem: "identity_access_missing" })).toEqual({ text: "This person’s identity access record is missing, so their access keys cannot work. Ask the operator to check the managed store.", fix: null });
    expect(accessKeyAccountProblem({ ...person, accessKeyProblem: "no_account_username", accountUsername: username({ state: "none", name: null, reason: "domain_not_listed" }) })).toEqual({ text: "This account has no username. Set one on the Overview tab first.", fix: "overview" });
    expect(accessKeyAccountProblem({ ...person, accessKeyProblem: "no_account_username", accountUsername: username({ state: "conflict", name: null, reason: "name_taken" }) })).toEqual({ text: "This account has no username: the one its email gives belongs to someone else. Set one by hand on the Overview tab.", fix: "overview" });
    expect(accessKeyAccountProblem({ ...service, accessKeyProblem: "no_account_username" })).toEqual({ text: "This service account’s ID cannot be used as a username. Issue keys for a service account whose ID can be.", fix: null });
    expect(accessKeyAccountProblem({ ...person, accessKeyProblem: "account_username_awaiting_confirmation" })).toEqual({ text: "This account’s username is waiting for confirmation. Confirm it on the Overview tab first.", fix: "overview" });
    expect(accessKeyAccountProblem({ ...person, accessKeyProblem: "account_username_reserved" })).toEqual({ text: "This account’s username is one the operator reserved. Set another on the Overview tab first.", fix: "overview" });
    expect(accessKeyAccountProblem({ ...service, accessKeyProblem: "account_username_reserved" })).toEqual({ text: "This service account’s ID is a username the operator reserved. Ask the operator to change the username settings.", fix: null });
    expect(accessKeyAccountProblem({ ...person, accessKeyProblem: "group_limit_exceeded" })).toEqual({ text: "This account is in too many groups for access keys to work. Remove it from some groups on the Groups tab first.", fix: "groups" });
    // A cause this portal does not know still offers nothing.
    expect(accessKeyAccountProblem({ ...person, accessKeyProblem: "something_new" as never })).toEqual({ text: "No access key of this account can work now.", fix: null });
  });

  test("a refused mint's reason reads as one sentence", () => {
    expect(accessKeyRefusalMessage("no_account_username", true)).toBe("You have no username yet. Ask an administrator to set one.");
    expect(accessKeyRefusalMessage("no_account_username", false)).toMatch(/Overview tab/);
    expect(accessKeyRefusalMessage("lifetime_not_offered", true)).toMatch(/available lifetime/);
    expect(accessKeyRefusalMessage(undefined, true)).toBeNull();
  });

  test("every refusal code a side can receive reads as its own sentence; a person's never names a type", () => {
    const own = ["principal_disabled", "identity_access_paused", "identity_access_missing", "owner_kind", "no_account_username", "account_username_awaiting_confirmation",
      "account_username_reserved", "group_limit_exceeded", "access_key_type_not_eligible", "access_key_type_not_self_service", "lifetime_not_offered", "session_required"];
    const administered = ["principal_disabled", "identity_access_paused", "identity_access_missing", "owner_kind", "no_account_username", "account_username_awaiting_confirmation",
      "account_username_reserved", "group_limit_exceeded", "access_key_type_unknown", "access_key_type_not_eligible", "lifetime_not_offered"];
    for (const code of own) expect(accessKeyRefusalMessage(code, true), code).toEqual(expect.any(String));
    for (const code of administered) expect(accessKeyRefusalMessage(code, false), code).toEqual(expect.any(String));
    expect(new Set(own.map((code) => accessKeyRefusalMessage(code, true))).size).toBe(own.length);
    expect(new Set(administered.map((code) => accessKeyRefusalMessage(code, false))).size).toBe(administered.length);
    for (const code of own) expect(accessKeyRefusalMessage(code, true)).not.toMatch(/inference|search|premium|package|downloads|models/i);
    expect(accessKeyRefusalMessage("group_limit_exceeded", true)).toBe("You are in too many groups for access keys to work. Ask an administrator for help.");
    expect(accessKeyRefusalMessage("identity_access_missing", true)).toBe("Your access cannot be confirmed. Ask an administrator for help.");
    // An administrator's refusal is worded as the account's reason on the Keys tab.
    expect(accessKeyRefusalMessage("group_limit_exceeded", false)).toBe(accessKeyAccountProblem({ kind: "user", accessKeyProblem: "group_limit_exceeded" })!.text);
    expect(accessKeyRefusalMessage("identity_access_missing", false)).toBe(accessKeyAccountProblem({ kind: "user", accessKeyProblem: "identity_access_missing" })!.text);
    expect(accessKeyRefusalMessage("identity_access_paused", false)).toBe(accessKeyAccountProblem({ kind: "user", accessKeyProblem: "identity_access_paused" })!.text);
    expect(accessKeyRefusalMessage("principal_disabled", false)).toBe(accessKeyAccountProblem({ kind: "user", accessKeyProblem: "principal_disabled" })!.text);
  });

  test("each side reads only the refusals the server sends it", () => {
    // A person is told access_key_type_not_eligible for a type that is not configured too.
    expect(accessKeyRefusalMessage("access_key_type_not_eligible", true)).toBe("One of the chosen types is no longer allowed. Reload the page and choose again.");
    expect(accessKeyRefusalMessage("access_key_type_not_self_service", true)).toMatch(/yourself/);
    expect(accessKeyRefusalMessage("session_required", true)).toBe("Sign in again in this browser to issue an access key.");
    expect(accessKeyRefusalMessage("access_key_type_unknown", true)).toBeNull();
    // Only an administrator is told that a type is not configured.
    expect(accessKeyRefusalMessage("access_key_type_unknown", false)).toBe("An access key type is no longer configured. Reload the page and choose again.");
    expect(accessKeyRefusalMessage("access_key_type_not_eligible", false)).toMatch(/no longer allowed/);
    expect(accessKeyRefusalMessage("access_key_type_not_self_service", false)).toBeNull();
    expect(accessKeyRefusalMessage("session_required", false)).toBeNull();
  });
});

describe("usernames", () => {
  test("the state badge reads from the server's state", () => {
    expect(USERNAME_STATE_BADGE.usable.label).toBe("Working");
    expect(USERNAME_STATE_BADGE.awaiting_confirmation.label).toBe("Awaiting confirmation");
    expect(USERNAME_STATE_BADGE.conflict).toEqual({ label: "Conflict", tone: "danger" });
    expect(usernameStateBadge("reserved")).toEqual(USERNAME_STATE_BADGE.reserved);
    // A state this portal does not know, or one named like an object property, reads as a neutral Unknown.
    for (const state of ["held_elsewhere", "constructor", "toString"]) expect(usernameStateBadge(state as never)).toEqual({ label: "Unknown", tone: "neutral" });
  });

  test("From email explains the server's value for the saved email and never works one out", () => {
    expect(fromEmailExplanation(username())).toBe("Given by the saved email, alice@example.com.");
    expect(fromEmailExplanation(username({ name: null, state: "conflict", fromEmail: { accountUsername: null, reason: "name_taken", conflict: { accountUsername: "carol", heldBy: "usr-carol" } }, email: "carol@example.org" })))
      .toBe("The saved email, carol@example.org, gives carol, which is taken.");
    expect(fromEmailExplanation(username({ name: null, fromEmail: { accountUsername: null, reason: "domain_not_listed", conflict: null } }))).toMatch(/not in a domain the operator lists/);
    expect(fromEmailExplanation(username({ fromEmail: null }))).toBe("");
  });

  test("before saving, the page says the change may change the username and what follows if it does", () => {
    expect(usernameChangeWarning("Alice Example", 3)).toBe("This may change Alice Example’s username. If it changes, their 3 active access keys stop working and their usage starts under the new username.");
    expect(usernameChangeWarning("Bob Example", 1)).toContain("their 1 active access key stops working");
    expect(usernameChangeWarning("Bob Example", 0)).toContain("any access keys they hold stop working");
  });

  test("after saving, the page reports what the server says happened: old and new username and keys ended", () => {
    expect(usernameChangeSummary(change())).toEqual({ changed: true, text: "The username changed from alice to alice.example. 3 access keys ended." });
    expect(usernameChangeSummary(change({ renamed: false, endedKeys: 0, after: allocation() }))).toEqual({ changed: false, text: "The username stayed alice. No access keys ended." });
    expect(usernameChangeSummary(change({ after: null, endedKeys: 1, reason: "name_taken", conflict: { accountUsername: "alice.example", heldBy: "usr-other" } })).text)
      .toBe("The username alice was released; the account has no username now. The name the email gives, alice.example, belongs to someone else. 1 access key ended.");
    expect(usernameChangeSummary(change({ before: null, endedKeys: 0 })).text).toBe("The username is now alice.example. No access keys ended.");
  });

  test("the history row shows when and how the name was set, its confirmation and the live keys", () => {
    const markup = renderToStaticMarkup(createElement(UsernameHistory, { username: username() }));
    expect(markup).toContain("by admin, from the email");
    expect(markup).toContain("Not required");
    expect(markup).toContain("3 active");
    const conflict = renderToStaticMarkup(createElement(UsernameHistory, { username: username({ name: null, state: "conflict", liveKeys: 0 }) }));
    expect(conflict).toContain("Never set");
    expect(conflict).toContain("Not applicable");
    expect(conflict).toContain("None; issuing is blocked");
    expect(renderToStaticMarkup(createElement(UsernameHistory, { username: username({ state: "awaiting_confirmation", name: allocation({ state: "awaiting_confirmation", assignedBy: "system:sign_in" }) }) }))).toContain("Awaiting an administrator");
  });
});

describe("access key type settings", () => {
  test("an account overrides one type and leaves the rest inheriting; the lists stay complete and disjoint", () => {
    const empty = { allow: [], deny: [] };
    const allowed = setPrincipalAccessKeyTypeChoice(empty, "premium-models", "allow");
    expect(allowed).toEqual({ allow: ["premium-models"], deny: [] });
    const denied = setPrincipalAccessKeyTypeChoice(allowed, "premium-models", "deny");
    expect(denied).toEqual({ allow: [], deny: ["premium-models"] });
    expect(setPrincipalAccessKeyTypeChoice(denied, "premium-models", "inherit")).toEqual(empty);
    expect(principalAccessKeyTypeChoice({ allow: ["inference"], deny: ["web-search"] }, "web-search")).toBe("deny");
    expect(principalAccessKeyTypeChoice({ allow: ["inference"], deny: ["web-search"] }, "premium-models")).toBe("inherit");
  });

  test("a group allows a type or says nothing about it", () => {
    expect(setGroupAccessKeyType({ allow: ["web-search"] }, "inference", true)).toEqual({ allow: ["inference", "web-search"] });
    expect(setGroupAccessKeyType({ allow: ["inference", "web-search"] }, "inference", false)).toEqual({ allow: ["web-search"] });
  });

  test("the setting rides the access draft: only a changed setting is sent, whole, and reordering is no change", () => {
    const base = { agentTokenIssuance: { mode: "inherit" as const, allowedExecutionContexts: [] }, accessKeyTypes: { allow: ["a", "b"], deny: [] } };
    const draft = accessDraft(base);
    expect(accessDraftPatch({ ...draft, value: { ...base, accessKeyTypes: { allow: ["b", "a"], deny: [] } } })).toEqual({});
    expect(accessDraftPatch({ ...draft, value: { ...base, accessKeyTypes: { allow: ["a"], deny: ["b"] } } })).toEqual({ accessKeyTypes: { allow: ["a"], deny: ["b"] } });
    const refreshed = refreshAccessDraft({ ...draft, value: { ...base, accessKeyTypes: { allow: ["a"], deny: [] } } }, { ...base, accessKeyTypes: { allow: ["c"], deny: [] } });
    expect(refreshed.conflicts).toEqual(["accessKeyTypes"]);
    expect(accessKeyTypesSettingEqual({ allow: ["x"] }, { allow: ["x"] })).toBe(true);
  });

  test("the result column is the server's decision with its source and allowing groups", () => {
    const policy: AccessKeyTypePolicy = { accessKeyTypes: [
      { accessKeyType: "inference", allowed: true, source: "groups", groupIds: ["ml-team"] },
      { accessKeyType: "web-search", allowed: false, source: "account", groupIds: [] },
      { accessKeyType: "premium-models", allowed: true, source: "account", groupIds: [] },
      { accessKeyType: "package-downloads", allowed: false, source: "none", groupIds: [] }
    ] };
    expect(accessKeyTypeResult(policy, "inference", false)).toMatchObject({ label: "Allowed", detail: "from group", groupIds: ["ml-team"] });
    expect(accessKeyTypeResult(policy, "web-search", false)).toMatchObject({ label: "Denied", detail: "set on this account" });
    expect(accessKeyTypeResult(policy, "premium-models", false)).toMatchObject({ label: "Allowed", detail: "set on this account" });
    expect(accessKeyTypeResult(policy, "package-downloads", false).detail).toBe("none of their groups allows it");
    expect(accessKeyTypeResult(policy, "package-downloads", true).detail).toBe("none of its groups allows it");
    const markup = renderToStaticMarkup(createElement(PrincipalAccessKeyTypeTable, { types: TYPES, value: { allow: ["premium-models"], deny: [] }, saved: { allow: [], deny: [] }, policy, serviceAccount: false, writable: true, disabled: false, onChange: () => undefined }));
    expect(markup).toContain("Inherit from groups");
    expect(markup).toContain("ml-team");
    expect(markup).toContain("the change applies after saving");
    expect(markup).toContain("package-downloads");
  });

  test("a group's checks name each type, its ID and whether people can issue it themselves", () => {
    const markup = renderToStaticMarkup(createElement(GroupAccessKeyTypeChecks, { types: TYPES, value: { allow: ["inference"] }, saved: { allow: [] }, disabled: false, onChange: () => undefined }));
    expect(markup).toContain("Access key types this group allows");
    expect(markup).toContain("people can issue it themselves");
    expect(markup).toContain("issued by administrators only");
    expect(markup.match(/checked=""/g)).toHaveLength(1);
    expect(markup).not.toContain("no longer configured");
  });

  test("a type a draft names that is no longer configured is listed for removal, and saving waits for it", () => {
    const configured = [INFERENCE, SEARCH];
    expect(unconfiguredAccessKeyTypes({ allow: ["premium-models", "inference"], deny: ["package-downloads"] }, { allow: [], deny: [] }, configured)).toEqual(["package-downloads", "premium-models"]);
    expect(unconfiguredAccessKeyTypes({ allow: ["premium-models", "inference"] }, { allow: ["inference"] }, configured)).toEqual(["premium-models"]);
    // The broker refuses a configuration without a type a saved setting names: such a type is newer than the list.
    expect(unconfiguredAccessKeyTypes({ allow: ["premium-models"], deny: [] }, { allow: [], deny: ["premium-models"] }, configured)).toEqual([]);
    expect(accessKeyTypeSettingBlocker({ allow: ["premium-models"], deny: [] }, { allow: [], deny: [] }, configured)).toBe("Remove access key types that are no longer configured.");
    expect(accessKeyTypeSettingBlocker({ allow: ["inference"], deny: ["web-search"] }, { allow: [], deny: [] }, configured)).toBeNull();
    expect(accessKeyTypeSettingBlocker({ allow: ["premium-models"] }, { allow: [] }, configured)).toBe("Remove access key types that are no longer configured.");
  });

  test("an account's table shows a type the draft names that is no longer configured, with its choice and a Remove control", () => {
    const props = { types: [INFERENCE, SEARCH], value: { allow: ["premium-models"], deny: ["web-search"] }, saved: { allow: [], deny: [] }, policy: null, serviceAccount: false, disabled: false, onChange: () => undefined };
    const markup = renderToStaticMarkup(createElement(PrincipalAccessKeyTypeTable, { ...props, writable: true }));
    expect(markup).toContain("premium-models");
    expect(markup).toContain("No longer configured");
    expect(markup).toContain('aria-label="Remove premium-models setting"');
    expect(markup).toContain("Remove access key types that are no longer configured.");
    expect(markup.match(/<tr>/g)).toHaveLength(4);
    // Nothing extra for a draft that names only configured types.
    const clean = renderToStaticMarkup(createElement(PrincipalAccessKeyTypeTable, { ...props, value: { allow: [], deny: ["web-search"] }, writable: true }));
    expect(clean).not.toContain("No longer configured");
    expect(clean).not.toContain("Remove");
  });

  test("a group's checks keep a type the draft allows that is no longer configured, ticked, for unticking", () => {
    const markup = renderToStaticMarkup(createElement(GroupAccessKeyTypeChecks, { types: [INFERENCE, SEARCH], value: { allow: ["inference", "premium-models"] }, saved: { allow: ["inference"] }, disabled: false, onChange: () => undefined }));
    expect(markup).toContain("premium-models");
    expect(markup).toContain("· no longer configured");
    expect(markup.match(/checked=""/g)).toHaveLength(2);
    expect(markup).toContain("Remove access key types that are no longer configured.");
  });
});

describe("navigation and routes", () => {
  const user: Session = { role: "user", selfServiceEnabled: true, authenticated: true, principal: "alice", auditQueryable: true };
  test("Keys sits after Tokens only when there is something to show, also without self-service", () => {
    expect(spaceTabs("self", user, true).map((tab) => tab.key)).toEqual(["access", "tokens", "keys", "credentials", "activity"]);
    expect(spaceTabs("self", user).map((tab) => tab.key)).toEqual(["access", "tokens", "credentials", "activity"]);
    expect(spaceTabs("self", { ...user, selfServiceEnabled: false }, true).map((tab) => tab.key)).toEqual(["keys"]);
    expect(spaceTabs("self", { ...user, selfServiceEnabled: false })).toEqual([]);
    const tabs = spaceTabs("self", user, true);
    expect(tabs.find((tab) => tab.key === "keys")).toMatchObject({ label: "Keys", icon: "key" });
    expect(tabs.find((tab) => tab.key === "tokens")).toMatchObject({ label: "Tokens", icon: "ticket" });
  });

  test("the key pages are portal pages", () => {
    for (const path of [ROUTE.keys, ROUTE.keyNew, paths.principalAccessKeyNew("svc-build-runner"), paths.principal("usr-alice", "keys"), ROUTE.accessKeyTypes]) {
      expect(isPortalPath(path), path).toBe(true);
    }
    expect(paths.accessKeys("ak_1")).toBe("/ui/keys?key=ak_1");
    expect(paths.principalAccessKeys("usr-alice", "ak_1")).toBe("/ui/admin/principals/usr-alice/keys?key=ak_1");
  });

  test("a newly issued key counts as a one-time secret (history clearing is in tests/access-keys.spec.ts)", () => {
    expect(modalHasOneTimeSecret({ type: "accessKeyReveal", key: "aab_ak_x", record, username: "alice", ownerName: "Alice Example", typeLabels: [{ id: "inference", label: "Model inference" }], destination: "/ui/keys" })).toBe(true);
  });
});


test("malformed options do not expose navigation or crash type selection", () => {
  expect(accessKeysShown({} as never)).toBe(false);
  expect(accessKeysShown({ hasSelfServiceType: "yes", hasKeys: 1 } as never)).toBe(false);
  for (const accessKeyTypes of [undefined, null, {}, "inference"]) {
    expect(selfServiceTypes({ accessKeyTypes } as never)).toEqual([]);
  }
});

test("type labels retain distinct IDs when display names are shared", () => {
  const types = [INFERENCE, { ...SEARCH, displayName: INFERENCE.displayName }];
  expect(accessKeyTypeLabels(types, [INFERENCE.id, SEARCH.id, "removed"])).toEqual([
    { id: INFERENCE.id, label: INFERENCE.displayName },
    { id: SEARCH.id, label: INFERENCE.displayName },
    { id: "removed", label: "removed" }
  ]);
});
