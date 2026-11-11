// Registered applications: the consent page's wording and checks, and how one
// person's application access is described. Pure helpers, no JSX.
import { ApiError } from "../api";
import type { BadgeTone } from "../app-types";
import type { ApplicationAccess, RouteCatalog } from "../types";

/** A pending request's ID as the broker issues it: 43 unpadded base64url characters. */
const AUTHORIZATION_REQUEST_ID = /^[A-Za-z0-9_-]{43}$/;

export function validAuthorizationRequestId(value: string | undefined): value is string {
  return value !== undefined && AUTHORIZATION_REQUEST_ID.test(value);
}

/**
 * Whether the caller's runtime catalog lists the personal application routes.
 * The broker lists them only while an application is registered.
 */
export function catalogListsApplications(catalog: RouteCatalog) {
  return Array.isArray(catalog.routes) && catalog.routes.some((route) => route.operation === "applications.access.list");
}

/** The level a person's tokens have, in the words every application view uses. */
export function applicationLevelLabel(readOnly: boolean) {
  return readOnly ? "Read-only" : "Read and write";
}

/** What that level lets the application do, for the consent page. */
export function applicationLevelMeaning(readOnly: boolean) {
  return readOnly ? "It can read what you can read, and cannot make changes." : "It can read and make changes, as you can.";
}

const DENIAL_MESSAGES: Record<string, string> = {
  connecting_disabled: "Connecting this application is turned off on this broker.",
  access_disabled: "An administrator disabled your access for this application.",
  not_human: "Only a person’s account can connect an application, and this is a service account.",
  account_disabled: "Your broker account is disabled."
};

/** One plain sentence for why the signed-in account may not connect; unknown reasons get a general one. */
export function applicationDenialMessage(reason: string | null | undefined) {
  return (reason && Object.hasOwn(DENIAL_MESSAGES, reason) ? DENIAL_MESSAGES[reason] : undefined) ?? "The broker does not allow this account to connect the application.";
}

/** The reason carried by a refused approval (403 `application_access_denied`), else null. */
export function refusedApprovalReason(error: unknown) {
  if (!(error instanceof ApiError) || error.reasonCode !== "application_access_denied") return null;
  const reason = error.details?.denialReason;
  return typeof reason === "string" ? reason : "";
}

/** The request is unknown, already answered or expired (404 `application_authorization_invalid`). */
export function authorizationInvalid(error: unknown) {
  return error instanceof ApiError && error.reasonCode === "application_authorization_invalid";
}

/**
 * The application address a decision returns to, when it is an absolute web
 * address the browser may open as a page; anything else is refused.
 */
export function applicationRedirectTarget(redirectTo: unknown) {
  if (typeof redirectTo !== "string") return null;
  try {
    const url = new URL(redirectTo);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}

/** The application's name, or its ID while it is not registered. */
export function applicationAccessName(access: Pick<ApplicationAccess, "applicationName" | "applicationId">) {
  return access.applicationName ?? access.applicationId;
}

export type ApplicationAccessState = { label: string; tone: BadgeTone };

/**
 * The one state shown for an access. A person's own list holds only connected
 * rows; an administrator also sees a row that was disconnected and kept
 * because it carries a restriction.
 */
export function applicationAccessState(access: Pick<ApplicationAccess, "applicationAvailable" | "connect" | "enabled" | "connected">): ApplicationAccessState {
  if (!access.applicationAvailable) return { label: "Application unavailable", tone: "warning" };
  if (!access.connected) return { label: "Not connected", tone: "neutral" };
  if (!access.enabled) return { label: "Disabled by an administrator", tone: "warning" };
  if (access.connect === "none") return { label: "Connecting turned off", tone: "warning" };
  return { label: "Connected", tone: "success" };
}

/** The operator's level for the application, for the administrator's row. */
export function applicationLevelSummary(connect: ApplicationAccess["connect"]) {
  if (connect === "read_write") return "Level: read and write";
  if (connect === "read_only") return "Level: read-only";
  if (connect === "none") return "Level: none";
  return "Not registered";
}

export function liveTokenSummary(count: number) {
  return `${count} live ${count === 1 ? "token" : "tokens"}`;
}
