// Microsoft membership renewal: the status line under a principal's Microsoft
// sign-in method (administrators) and the signed-in person's own Microsoft
// groups line on Account, from `/v1/me`.
import { formatDateTime } from "../workbench";
import type { BadgeTone } from "../app-types";
import type { MicrosoftMembership, MicrosoftMembershipRenewal, MicrosoftMembershipRenewalFailureCode } from "../types";

export type MicrosoftMembershipLine = { tone: BadgeTone; text: string };

const FAILURE_REASONS: Record<MicrosoftMembershipRenewalFailureCode, string> = {
  groups_incomplete: "Microsoft reported an incomplete group list",
  client_rejected: "Microsoft rejected the Broker's client credentials",
  request_rejected: "Microsoft rejected the renewal request",
  invalid_response: "Microsoft returned a response the Broker could not accept",
  throttled: "Microsoft is throttling requests",
  unavailable: "Microsoft is unavailable"
};

function nextAttempt(renewal: MicrosoftMembershipRenewal) {
  return renewal.nextAttemptAfter ? ` (next attempt ${formatDateTime(renewal.nextAttemptAfter)})` : "";
}

function failureReason(renewal: MicrosoftMembershipRenewal) {
  return renewal.lastFailure ? `: ${FAILURE_REASONS[renewal.lastFailure.code]}` : "";
}

/**
 * The administrator's line for a Microsoft sign-in method's group renewal;
 * null when the method has no renewal record (renewal is off or the person
 * has not signed in with it on).
 */
export function microsoftRenewalStatus(renewal: MicrosoftMembershipRenewal | null | undefined): MicrosoftMembershipLine | null {
  if (!renewal) return null;
  switch (renewal.state) {
    case "active":
      return {
        tone: "success",
        text: renewal.lastRenewedAt
          ? `Groups renew automatically (last renewed ${formatDateTime(renewal.lastRenewedAt)})`
          : "Groups renew automatically (not renewed since sign-in)"
      };
    case "retrying":
      return { tone: "warning", text: `Renewal retrying${failureReason(renewal)}${nextAttempt(renewal)}` };
    case "blocked":
      return { tone: "danger", text: `Renewal blocked${failureReason(renewal)}${nextAttempt(renewal)}` };
    case "sign_in_required":
      return { tone: "warning", text: "Sign-in required to renew groups" };
    case "not_issued":
      return { tone: "neutral", text: "Not available: Microsoft returned no refresh token" };
    case "identity_mismatch":
      return { tone: "danger", text: "Sign-in required to renew groups: Microsoft returned a different identity" };
  }
}

/**
 * The signed-in person's own Microsoft groups line: whether they renew
 * automatically or need a new Microsoft sign-in, and how long the current
 * groups last.
 */
export function ownMicrosoftMembershipStatus(membership: MicrosoftMembership, now: number = Date.now()): MicrosoftMembershipLine {
  const window = !membership.validUntil
    ? "no current groups"
    : new Date(membership.validUntil).getTime() <= now
      ? `expired ${formatDateTime(membership.validUntil)}`
      : `valid until ${formatDateTime(membership.validUntil)}`;
  const renewal = membership.renewal;
  switch (renewal?.state) {
    case "active":
    case "retrying":
      return { tone: "success", text: `Renew automatically while you or your agents use the Broker; ${window}` };
    case "blocked":
      return { tone: "warning", text: `Automatic renewal is blocked; ask your administrator if group access is missing; ${window}` };
    case "sign_in_required":
    case "identity_mismatch":
      return { tone: "warning", text: `Sign in with Microsoft again to renew them; ${window}` };
    case "not_issued":
    case undefined:
      return { tone: "neutral", text: `Sign in with Microsoft again when they expire; ${window}` };
  }
}
