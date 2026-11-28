// Access keys, access key types and usernames: how the server's facts read on
// screen, and the issue form's draft. Pure helpers, no JSX. The portal derives
// nothing the server states: each label maps one member of a response.
import type { Tone } from "../workbench";
import type {
  AccessKeyAccountProblem,
  AccessKeyIssueBody,
  AccessKeyOptions,
  AccessKeyProblem,
  AccessKeyRefusal,
  AccessKeyStatus,
  AccessKeyType,
  AccessKeyTypePolicy,
  AccessKeyView,
  AccountUsernameChange,
  AccountUsernameReason,
  AccountUsernameState,
  GroupAccessKeyTypes,
  PrincipalAccessKeyTypes,
  PrincipalAccountUsername,
  PrincipalDetail,
  RouteCatalog
} from "../types";

/** The longest key name the broker accepts, in UTF-8 bytes. */
export const ACCESS_KEY_NAME_MAX_BYTES = 128;
/** The most access key types one key may carry. */
export const ACCESS_KEY_MAX_TYPES = 16;

/**
 * Whether the caller's runtime catalog lists the personal access key routes.
 * The broker lists them only while an access key type is configured.
 */
export function catalogListsAccessKeys(catalog: RouteCatalog) {
  return Array.isArray(catalog.routes) && catalog.routes.some((route) => route.operation === "access_keys.options");
}

type Shown = Pick<AccessKeyOptions, "hasSelfServiceType" | "hasKeys" | "problem">;

/**
 * Whether the person sees the Keys page and its navigation item: they may
 * issue a type, they hold a key, or a type is theirs but only an
 * administrator can make it work.
 */
export function accessKeysShown(options: Shown | null | undefined) {
  return Boolean(options && (options.hasSelfServiceType === true || options.hasKeys === true || typeof options.problem === "string"));
}

/** Whether **Issue access key** is offered: a type they may issue, and nothing in the way. */
export function canIssueOwnAccessKey(options: Pick<AccessKeyOptions, "hasSelfServiceType" | "refusal" | "problem">) {
  return options.hasSelfServiceType && options.refusal === null && options.problem === null;
}

const OWN_REASONS: Record<AccessKeyProblem | AccessKeyRefusal, string> = {
  no_account_username: "You have no username yet. Ask an administrator to set one.",
  account_username_awaiting_confirmation: "Your username is waiting for an administrator to confirm it. Ask an administrator for help.",
  account_username_reserved: "Your username is one the operator reserved. Ask an administrator to set another.",
  group_limit_exceeded: "You are in too many groups for access keys to work. Ask an administrator for help.",
  identity_access_paused: "Your access is paused. Ask an administrator for help.",
  identity_access_missing: "Your access cannot be confirmed. Ask an administrator for help.",
  principal_disabled: "Your account is disabled. Ask an administrator for help.",
  owner_kind: "This account cannot hold access keys."
};

/**
 * The one sentence beside the page title when an issue is blocked by
 * something only an administrator can fix: the server's `problem`, else its
 * `refusal`. Null when nothing blocks the person.
 */
export function ownAccessKeyBlocker(options: Pick<AccessKeyOptions, "refusal" | "problem">) {
  const code = options.problem ?? options.refusal;
  if (code === null) return null;
  return Object.hasOwn(OWN_REASONS, code) ? OWN_REASONS[code] : "You cannot issue access keys now. Ask an administrator for help.";
}

/** The types a person may issue themselves, in the server's order. */
export function selfServiceTypes(options: Pick<AccessKeyOptions, "accessKeyTypes">) {
  return Array.isArray(options.accessKeyTypes) ? options.accessKeyTypes.filter((type) => type.selfService === true) : [];
}

export type AccessKeyStatusLabel = { label: string; tone: Tone; quiet: boolean; title?: string };

const STATUS_LABELS: Record<Exclude<AccessKeyStatus, "active">, AccessKeyStatusLabel> = {
  revoked: { label: "Revoked", tone: "neutral", quiet: false },
  expired: { label: "Expired", tone: "muted", quiet: false },
  no_access_key_type: { label: "No access left", tone: "warning", quiet: false, title: "The key gives access to nothing its owner may hold now." },
  username_incarnation_changed: { label: "Username changed", tone: "muted", quiet: false, title: "The username changed after the key was issued, so the key no longer works." },
  no_account_username: { label: "No username", tone: "warning", quiet: false, title: "The owner has no username. An administrator sets one." },
  account_username_awaiting_confirmation: { label: "Username unconfirmed", tone: "warning", quiet: false, title: "The owner’s username is waiting for an administrator to confirm it." },
  account_username_reserved: { label: "Username reserved", tone: "warning", quiet: false, title: "The owner’s username is one the operator reserved." },
  group_limit_exceeded: { label: "Too many groups", tone: "warning", quiet: false, title: "The owner is in too many groups for access keys to work." },
  identity_access_paused: { label: "Access paused", tone: "warning", quiet: false, title: "The owner’s access is paused." },
  identity_access_missing: { label: "Access unavailable", tone: "warning", quiet: false, title: "The owner’s access is unavailable." },
  principal_disabled: { label: "Account disabled", tone: "muted", quiet: false, title: "The owner’s account is disabled." },
  origin_unsupported: { label: "Not usable", tone: "muted", quiet: false, title: "Keys of this origin do not work." }
};

/**
 * A key's status cell, from the server's `status` and `access`: a quiet green
 * dot for full access, "Partial access" while only some of its types work,
 * and otherwise why the key does not work.
 */
export function accessKeyStatusLabel(key: Pick<AccessKeyView, "status" | "access">): AccessKeyStatusLabel {
  if (key.status === "active") {
    return key.access === "partial"
      ? { label: "Partial access", tone: "warning", quiet: false, title: "Some of what this key gives access to is no longer available." }
      : { label: "Active", tone: "success", quiet: true };
  }
  return Object.hasOwn(STATUS_LABELS, key.status) ? STATUS_LABELS[key.status] : { label: "Not working", tone: "warning", quiet: false };
}

/** Whether a key is still live: neither revoked nor expired. */
export function accessKeyLive(key: Pick<AccessKeyView, "revokedAt" | "status">) {
  return key.revokedAt === null && key.status !== "expired";
}

export const ACCESS_KEY_FILTERS = ["current", "expired", "revoked", "all"] as const;
export type AccessKeyFilter = (typeof ACCESS_KEY_FILTERS)[number];

/** Revoked first, then expired, else current: what each status filter counts. */
export function accessKeyFilterOf(key: Pick<AccessKeyView, "revokedAt" | "status">): Exclude<AccessKeyFilter, "all"> {
  return key.revokedAt !== null ? "revoked" : key.status === "expired" ? "expired" : "current";
}

export function accessKeyCounts(keys: readonly Pick<AccessKeyView, "revokedAt" | "status">[]) {
  const counts: Record<AccessKeyFilter, number> = { current: 0, expired: 0, revoked: 0, all: keys.length };
  for (const key of keys) counts[accessKeyFilterOf(key)] += 1;
  return counts;
}

/** One pill per type the key carries: its display name (the ID once the type is gone) and whether the key still holds it. */
export function accessKeyPills(key: Pick<AccessKeyView, "accessKeyTypeStates">) {
  return key.accessKeyTypeStates.map((state) => ({ id: state.id, label: state.displayName ?? state.id, held: state.held }));
}

/** Display names for type IDs, from a types list; an unknown ID stays as it is. */
export function accessKeyTypeLabels(types: readonly AccessKeyType[], ids: readonly string[]) {
  const names = new Map(types.map((type) => [type.id, type.displayName]));
  return ids.map((id) => ({ id, label: names.get(id) ?? id }));
}

const SECOND = 1;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const LIFETIME_UNITS: Record<string, number> = { s: SECOND, m: MINUTE, h: HOUR, d: DAY };

/** The Broker's duration syntax, bounded to access-key lifetimes; never sorts after every finite duration. */
export function accessKeyLifetimeSeconds(lifetime: unknown): number | null {
  if (lifetime === "never") return Infinity;
  if (typeof lifetime !== "string") return null;
  // Rust's str::trim uses Unicode White_Space, including U+0085 and excluding U+FEFF.
  const trimmed = lifetime.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
  const match = /^([0-9]+)([smhd])$/.exec(trimmed);
  if (!match) return null;
  const seconds = Number(match[1]) * LIFETIME_UNITS[match[2]!]!;
  return Number.isSafeInteger(seconds) && seconds > 0 && seconds <= 3650 * DAY ? seconds : null;
}

/** A configured lifetime in the largest whole unit, or Never expires. */
export function accessKeyLifetimeLabel(lifetime: string) {
  const seconds = accessKeyLifetimeSeconds(lifetime);
  if (seconds === Infinity) return "Never expires";
  if (seconds === null) return lifetime;
  const [size, unit] = seconds % DAY === 0 ? [DAY, "day"] : seconds % HOUR === 0 ? [HOUR, "hour"] : seconds % MINUTE === 0 ? [MINUTE, "minute"] : [SECOND, "second"];
  const count = seconds / size;
  return `${count} ${unit}${count === 1 ? "" : "s"}`;
}

function chosenAccessKeyTypes(types: readonly AccessKeyType[], chosen: readonly string[]) {
  const byId = new Map(types.map((type) => [type.id, type]));
  const picked = chosen.map((id) => byId.get(id));
  return picked.every((type) => type !== undefined) ? picked : [];
}

/** Common effective durations, using the first chosen type's spellings and configured order. */
export function accessKeyLifetimeChoices(types: readonly AccessKeyType[], chosen: readonly string[]) {
  const picked = chosenAccessKeyTypes(types, chosen);
  if (!picked.length || picked.some((type) => !Array.isArray(type.lifetimeOptions))) return [];
  return picked[0]!.lifetimeOptions.filter((lifetime) => {
    const seconds = accessKeyLifetimeSeconds(lifetime);
    return seconds !== null && picked.every((type) => type.lifetimeOptions.some((option) => accessKeyLifetimeSeconds(option) === seconds));
  });
}

/** The shortest common chosen-type default, otherwise the shortest common option. */
export function defaultAccessKeyLifetime(types: readonly AccessKeyType[], chosen: readonly string[]) {
  const choices = accessKeyLifetimeChoices(types, chosen);
  const defaults = new Set(chosenAccessKeyTypes(types, chosen).map((type) => accessKeyLifetimeSeconds(type.defaultLifetime)));
  const preferred = choices.filter((lifetime) => defaults.has(accessKeyLifetimeSeconds(lifetime)));
  return (preferred.length ? preferred : choices).reduce<string | null>((shortest, lifetime) => (
    shortest === null || accessKeyLifetimeSeconds(lifetime)! < accessKeyLifetimeSeconds(shortest)! ? lifetime : shortest
  ), null);
}

/** The current option with this effective duration; no unavailable value is added to the choices. */
export function offeredAccessKeyLifetime(choices: readonly string[], lifetime: string | null) {
  const seconds = accessKeyLifetimeSeconds(lifetime);
  return seconds === null ? null : choices.find((option) => accessKeyLifetimeSeconds(option) === seconds) ?? null;
}

/** The lifetime hint follows the chosen types' common options. */
export function accessKeyLifetimeHint(types: readonly AccessKeyType[], chosen: readonly string[]) {
  if (!chosen.length) return "Choose access to see its lifetime options.";
  if (!chosenAccessKeyTypes(types, chosen).length) return "Remove access that is no longer offered before choosing a lifetime.";
  if (!accessKeyLifetimeChoices(types, chosen).length) return "The chosen access types have no lifetime in common.";
  return "These lifetimes are offered by every chosen access type.";
}

export type AccessKeyDraft = { name: string; accessKeyTypes: string[]; lifetime: string | null; lifetimeManuallyChosen: boolean };
export type AccessKeyDraftField = "access" | "name" | "lifetime";
export type AccessKeyDraftIssue = { field: AccessKeyDraftField; message: string };

/** A fresh draft waits for the person to choose access before offering a lifetime. */
export function newAccessKeyDraft(): AccessKeyDraft {
  return { name: "", accessKeyTypes: [], lifetime: null, lifetimeManuallyChosen: false };
}

/** Keep a manual choice only while it is common; otherwise apply current configured defaults. */
export function reconcileAccessKeyLifetime(draft: AccessKeyDraft, types: readonly AccessKeyType[]): AccessKeyDraft {
  const manual = draft.lifetimeManuallyChosen ? offeredAccessKeyLifetime(accessKeyLifetimeChoices(types, draft.accessKeyTypes), draft.lifetime) : null;
  const lifetime = manual ?? defaultAccessKeyLifetime(types, draft.accessKeyTypes);
  const lifetimeManuallyChosen = manual !== null;
  return lifetime === draft.lifetime && lifetimeManuallyChosen === draft.lifetimeManuallyChosen
    ? draft
    : { ...draft, lifetime, lifetimeManuallyChosen };
}

export function toggleAccessKeyType(draft: AccessKeyDraft, id: string, checked: boolean, types: readonly AccessKeyType[]): AccessKeyDraft {
  const others = draft.accessKeyTypes.filter((value) => value !== id);
  return reconcileAccessKeyLifetime({ ...draft, accessKeyTypes: checked ? [...others, id] : others }, types);
}

/**
 * Chosen types no longer offered (after a refusal or a refresh), named as
 * they were last offered, so the form can show them for removal.
 */
export function unavailableChoices(draft: Pick<AccessKeyDraft, "accessKeyTypes">, offered: readonly AccessKeyType[], seen: ReadonlyMap<string, AccessKeyType>) {
  const offeredIds = new Set(offered.map((type) => type.id));
  return draft.accessKeyTypes.filter((id) => !offeredIds.has(id)).map((id) => ({ id, label: seen.get(id)?.displayName ?? id }));
}

/** The request body, or every issue in the order the form shows them. Nothing is trimmed away or chosen for the person. */
export function buildAccessKeyIssue(draft: Pick<AccessKeyDraft, "name" | "accessKeyTypes" | "lifetime">, offered: readonly AccessKeyType[]):
  | { valid: true; body: AccessKeyIssueBody }
  | { valid: false; issues: AccessKeyDraftIssue[] } {
  const issues: AccessKeyDraftIssue[] = [];
  const offeredIds = new Set(offered.map((type) => type.id));
  const chosen = draft.accessKeyTypes.filter((id) => offeredIds.has(id));
  const unavailable = draft.accessKeyTypes.filter((id) => !chosen.includes(id));
  if (unavailable.length) issues.push({ field: "access", message: "Remove access that is no longer offered." });
  else if (!chosen.length) issues.push({ field: "access", message: "Choose what this key gives access to." });
  else if (chosen.length > ACCESS_KEY_MAX_TYPES) issues.push({ field: "access", message: `Choose at most ${ACCESS_KEY_MAX_TYPES} kinds of access.` });
  const name = draft.name.trim();
  if (!name) issues.push({ field: "name", message: "Enter a key name." });
  else if (new TextEncoder().encode(name).length > ACCESS_KEY_NAME_MAX_BYTES) issues.push({ field: "name", message: `Shorten the key name to ${ACCESS_KEY_NAME_MAX_BYTES} bytes or fewer.` });
  const choices = accessKeyLifetimeChoices(offered, chosen);
  const lifetime = offeredAccessKeyLifetime(choices, draft.lifetime);
  if (chosen.length && !unavailable.length) {
    if (!choices.length) issues.push({ field: "lifetime", message: "The chosen access types have no lifetime in common." });
    else if (lifetime === null) issues.push({ field: "lifetime", message: "Choose an available lifetime." });
  }
  if (issues.length) return { valid: false, issues };
  return { valid: true, body: { name, accessKeyTypes: chosen, lifetime: lifetime! } };
}

/**
 * What an administrator may issue for an account: the configured types its
 * resolved policy allows, in the types list's order, and the ones it does not.
 */
export function administeredAccessKeyTypes(types: readonly AccessKeyType[], policy: AccessKeyTypePolicy | null | undefined) {
  const allowed = new Set((policy?.accessKeyTypes ?? []).filter((row) => row.allowed).map((row) => row.accessKeyType));
  return { offered: types.filter((type) => allowed.has(type.id)), notOffered: types.filter((type) => !allowed.has(type.id)) };
}

/**
 * What a person's own refused issue says beyond the account states above. A
 * person is told `access_key_type_not_eligible` for a type that is not
 * configured as well; only an administrator is told `access_key_type_unknown`.
 */
const OWN_ISSUE_REFUSALS: Record<string, string> = {
  access_key_type_not_self_service: "You can no longer issue one of the chosen types yourself. Reload the page and choose again.",
  access_key_type_not_eligible: "One of the chosen types is no longer allowed. Reload the page and choose again.",
  lifetime_not_offered: "The chosen lifetime is no longer offered by every access type. Choose an available lifetime.",
  session_required: "Sign in again in this browser to issue an access key."
};

/**
 * Why no key of an account can work, as an administrator reads it: what is
 * wrong and what to fix. The account detail's `accessKeyProblem` and an
 * administrator's refused issue carry the same codes.
 */
const ADMIN_ACCOUNT_REASONS: Record<AccessKeyAccountProblem, string> = {
  principal_disabled: "This account is disabled. Enable it before issuing access keys.",
  identity_access_paused: "This person’s identity access is paused. Resume it under Identity access on the Overview tab first.",
  identity_access_missing: "This person’s identity access record is missing, so their access keys cannot work. Ask the operator to check the managed store.",
  no_account_username: "This account has no username. Set one on the Overview tab first.",
  account_username_awaiting_confirmation: "This account’s username is waiting for confirmation. Confirm it on the Overview tab first.",
  account_username_reserved: "This account’s username is one the operator reserved. Set another on the Overview tab first.",
  group_limit_exceeded: "This account is in too many groups for access keys to work. Remove it from some groups on the Groups tab first."
};

/** What an administrator's refused issue for an account says. */
const ADMIN_REFUSALS: Record<string, string> = {
  ...ADMIN_ACCOUNT_REASONS,
  owner_kind: "This account cannot hold access keys.",
  access_key_type_unknown: "An access key type is no longer configured. Reload the page and choose again.",
  access_key_type_not_eligible: "One of the chosen types is no longer allowed. Reload the page and choose again.",
  lifetime_not_offered: "The chosen lifetime is no longer offered by every access type. Choose an available lifetime."
};

/** A refused mint's `details.refusal`, as one sentence; null for another failure. */
export function accessKeyRefusalMessage(refusal: unknown, personal: boolean) {
  if (typeof refusal !== "string") return null;
  if (personal) {
    if (Object.hasOwn(OWN_REASONS, refusal)) return OWN_REASONS[refusal as AccessKeyRefusal];
    return Object.hasOwn(OWN_ISSUE_REFUSALS, refusal) ? OWN_ISSUE_REFUSALS[refusal] : null;
  }
  return Object.hasOwn(ADMIN_REFUSALS, refusal) ? ADMIN_REFUSALS[refusal] : null;
}

/** The tab of the account where an administrator removes its access key problem, when the portal can. */
export type AccessKeyProblemFix = "overview" | "groups" | null;

/**
 * Why no access key of an account can work, from the account detail's
 * `accessKeyProblem`, as an administrator reads it: what is wrong with the
 * account and what to fix. Null when the server states no problem. The
 * username's state only words `no_account_username` when the name the email
 * gives belongs to someone else.
 */
export function accessKeyAccountProblem(account: Pick<PrincipalDetail, "kind" | "accessKeyProblem" | "accountUsername">): { text: string; fix: AccessKeyProblemFix } | null {
  const problem = account.accessKeyProblem ?? null;
  if (problem === null) return null;
  const serviceAccount = account.kind === "service_account";
  const reason = (fix: AccessKeyProblemFix) => ({ text: ADMIN_ACCOUNT_REASONS[problem], fix });
  switch (problem) {
    case "principal_disabled":
      return reason(null);
    case "identity_access_paused":
      return reason("overview");
    case "identity_access_missing":
      return reason(null);
    case "no_account_username":
      if (serviceAccount) return { text: "This service account’s ID cannot be used as a username. Issue keys for a service account whose ID can be.", fix: null };
      return account.accountUsername?.state === "conflict"
        ? { text: "This account has no username: the one its email gives belongs to someone else. Set one by hand on the Overview tab.", fix: "overview" }
        : reason("overview");
    case "account_username_awaiting_confirmation":
      return reason("overview");
    case "account_username_reserved":
      return serviceAccount
        ? { text: "This service account’s ID is a username the operator reserved. Ask the operator to change the username settings.", fix: null }
        : reason("overview");
    case "group_limit_exceeded":
      return reason("groups");
    default:
      // A cause this portal does not know still stops every key: offer nothing.
      return { text: "No access key of this account can work now.", fix: null };
  }
}

/**
 * Why an administrator cannot issue a key for an account whose access keys
 * can work, with the tab that fixes it: it is not a person or a service
 * account, which nothing changes, or it is allowed no type, which its
 * Overview changes. Null when the form can be offered.
 */
export function administeredIssueBlocker(input: { kind: string; offered: number }): { text: string; fix: AccessKeyProblemFix } | null {
  if (input.kind !== "user" && input.kind !== "service_account") return { text: "This account cannot hold access keys.", fix: null };
  if (input.offered === 0) return { text: "This account is not allowed any access key type. Allow one in Access key types on the Overview tab.", fix: "overview" };
  return null;
}

// ---------- usernames

export const USERNAME_STATE_BADGE: Record<AccountUsernameState, { label: string; tone: Tone }> = {
  usable: { label: "Working", tone: "success" },
  awaiting_confirmation: { label: "Awaiting confirmation", tone: "warning" },
  reserved: { label: "Reserved", tone: "warning" },
  conflict: { label: "Conflict", tone: "danger" },
  none: { label: "None", tone: "muted" }
};

/** The Username section's badge for the server's state; a state this portal does not know reads as a neutral Unknown. */
export function usernameStateBadge(state: AccountUsernameState) {
  return Object.hasOwn(USERNAME_STATE_BADGE, state) ? USERNAME_STATE_BADGE[state] : { label: "Unknown", tone: "neutral" as Tone };
}

/** Why the saved email gives no username, or why none is held, as the end of a sentence. */
export function usernameReasonText(reason: AccountUsernameReason | null | undefined, email: string | null | undefined) {
  const saved = email ? `The saved email, ${email},` : "The saved email";
  switch (reason) {
    case "no_email": return "The account has no saved email, so it gives no username.";
    case "email_unusable": return `${saved} cannot give a username.`;
    case "domain_not_listed": return `${saved} is not in a domain the operator lists for usernames, so it gives none.`;
    case "name_invalid": return `${saved} does not give a valid username.`;
    case "name_reserved": return `${saved} gives a name the operator reserved, so it gives none.`;
    case "name_taken": return `${saved} gives a name someone else holds.`;
    case "not_set": return "No username is set by hand.";
    case "not_yet_assigned": return "The saved email gives a free username, assigned at the person’s next sign-in or the next startup or reload.";
    case "id_unusable": return "This service account’s ID is not a valid username.";
    default: return "";
  }
}

/** The one line under **From email**: what the saved email gives, from the server. */
export function fromEmailExplanation(username: Pick<PrincipalAccountUsername, "email" | "name" | "fromEmail">) {
  const from = username.fromEmail;
  if (!from) return "";
  const held = username.name?.accountUsername ?? null;
  if (from.accountUsername !== null && from.accountUsername === held) return `Given by the saved email, ${username.email}.`;
  if (from.accountUsername !== null) return `The saved email, ${username.email}, gives ${from.accountUsername}.`;
  if (from.reason === "name_taken" && from.conflict) return `The saved email, ${username.email}, gives ${from.conflict.accountUsername}, which is taken.`;
  return usernameReasonText(from.reason, username.email);
}

/**
 * The statement before an email or mode change is saved: it may change the
 * username, and what follows if it does. `liveKeys` is the server's count.
 */
export function usernameChangeWarning(who: string, liveKeys: number) {
  return `This may change ${who}’s username. ${usernameChangeConsequence(liveKeys)}`;
}

/** The same statement before an email is saved for a person whose username follows it. */
export function emailChangeWarning(who: string, held: string | null | undefined, email: string, liveKeys: number) {
  return `${who}’s username${held ? `, ${held},` : ""} is set from email, so saving ${email || "no email"} may change it. ${usernameChangeConsequence(liveKeys)}`;
}

function usernameChangeConsequence(liveKeys: number) {
  const keys = liveKeys === 0 ? "any access keys they hold stop working" : `their ${liveKeys} active access ${liveKeys === 1 ? "key stops" : "keys stop"} working`;
  return `If it changes, ${keys} and their usage starts under the new username.`;
}

/** What the server says a saved change did to the username: old and new, and how many keys ended. */
export function usernameChangeSummary(change: AccountUsernameChange) {
  const before = change.before?.accountUsername ?? null;
  const after = change.after?.accountUsername ?? null;
  const ended = change.endedKeys === 0 ? "No access keys ended." : `${change.endedKeys} access ${change.endedKeys === 1 ? "key" : "keys"} ended.`;
  if (!change.renamed) return { changed: false, text: after ? `The username stayed ${after}. No access keys ended.` : "The account still has no username. No access keys ended." };
  if (after === null) {
    const why = change.reason === "name_taken" && change.conflict ? ` The name the email gives, ${change.conflict.accountUsername}, belongs to someone else.` : change.reason ? ` ${usernameReasonText(change.reason, null)}` : "";
    return { changed: true, text: `The username ${before ?? ""} was released; the account has no username now.${why} ${ended}`.replace("  ", " ") };
  }
  return { changed: true, text: before === null ? `The username is now ${after}. ${ended}` : before === after ? `The username ${after} was given again, so earlier keys no longer work. ${ended}` : `The username changed from ${before} to ${after}. ${ended}` };
}

// ---------- access key type settings

export type AccessKeyTypeChoice = "inherit" | "allow" | "deny";

export function principalAccessKeyTypeChoice(setting: PrincipalAccessKeyTypes, id: string): AccessKeyTypeChoice {
  return setting.allow.includes(id) ? "allow" : setting.deny.includes(id) ? "deny" : "inherit";
}

/** The complete setting with one type's choice replaced; the lists stay disjoint and sorted. */
export function setPrincipalAccessKeyTypeChoice(setting: PrincipalAccessKeyTypes, id: string, choice: AccessKeyTypeChoice): PrincipalAccessKeyTypes {
  const allow = setting.allow.filter((value) => value !== id);
  const deny = setting.deny.filter((value) => value !== id);
  if (choice === "allow") allow.push(id);
  if (choice === "deny") deny.push(id);
  return { allow: allow.sort(), deny: deny.sort() };
}

export function setGroupAccessKeyType(setting: GroupAccessKeyTypes, id: string, allowed: boolean): GroupAccessKeyTypes {
  const allow = setting.allow.filter((value) => value !== id);
  if (allowed) allow.push(id);
  return { allow: allow.sort() };
}

const sorted = (values: readonly string[]) => [...values].sort();

const namedTypes = (setting: PrincipalAccessKeyTypes | GroupAccessKeyTypes | undefined) => (setting ? [...setting.allow, ...("deny" in setting ? setting.deny : [])] : []);

/**
 * The types a settings draft names that are not configured, in ID order: a
 * type removed from the configuration after it was chosen. The broker refuses
 * a setting that names one, so the form shows each for removal. It refuses a
 * configuration without a type a saved setting names, so such a type is only
 * newer than the type list and is left out.
 */
export function unconfiguredAccessKeyTypes(value: PrincipalAccessKeyTypes | GroupAccessKeyTypes, saved: PrincipalAccessKeyTypes | GroupAccessKeyTypes | undefined, types: readonly AccessKeyType[]) {
  const known = new Set([...types.map((type) => type.id), ...namedTypes(saved)]);
  return sorted([...new Set(namedTypes(value))].filter((id) => !known.has(id)));
}

/** Why a settings draft cannot be saved yet: it names a type that is no longer configured. Null otherwise. */
export function accessKeyTypeSettingBlocker(value: PrincipalAccessKeyTypes | GroupAccessKeyTypes, saved: PrincipalAccessKeyTypes | GroupAccessKeyTypes | undefined, types: readonly AccessKeyType[]) {
  return unconfiguredAccessKeyTypes(value, saved, types).length ? "Remove access key types that are no longer configured." : null;
}

export function accessKeyTypesSettingEqual(a: PrincipalAccessKeyTypes | GroupAccessKeyTypes | undefined, b: PrincipalAccessKeyTypes | GroupAccessKeyTypes | undefined) {
  if (!a || !b) return a === b;
  const deny = (value: PrincipalAccessKeyTypes | GroupAccessKeyTypes) => ("deny" in value ? value.deny : []);
  return JSON.stringify([sorted(a.allow), sorted(deny(a))]) === JSON.stringify([sorted(b.allow), sorted(deny(b))]);
}

/** The RESULT column for one type: the server's decision, its source and allowing groups. */
export function accessKeyTypeResult(policy: AccessKeyTypePolicy | null | undefined, id: string, serviceAccount: boolean) {
  const row = policy?.accessKeyTypes.find((item) => item.accessKeyType === id);
  if (!row) return { label: "Unknown", tone: "muted" as Tone, detail: "the saved result is unavailable", groupIds: [] as string[] };
  if (row.source === "account") return row.allowed
    ? { label: "Allowed", tone: "success" as Tone, detail: "set on this account", groupIds: [] }
    : { label: "Denied", tone: "danger" as Tone, detail: "set on this account", groupIds: [] };
  if (row.allowed) return { label: "Allowed", tone: "success" as Tone, detail: row.groupIds.length === 1 ? "from group" : "from groups", groupIds: row.groupIds };
  return { label: "Not allowed", tone: "neutral" as Tone, detail: serviceAccount ? "none of its groups allows it" : "none of their groups allows it", groupIds: [] };
}
