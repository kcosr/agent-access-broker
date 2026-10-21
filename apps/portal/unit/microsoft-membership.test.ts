import { describe, expect, test } from "vitest";
import { formatDateTime } from "../src/workbench";
import type { MicrosoftMembership, MicrosoftMembershipRenewal } from "../src/types";
import { microsoftRenewalStatus, ownMicrosoftMembershipStatus } from "../src/lib/microsoft-membership";

const RENEWED = "2026-10-21T08:00:00Z";
const NEXT = "2026-10-21T09:00:00Z";
const FAILED = "2026-10-21T08:30:00Z";
const VALID_UNTIL = "2026-10-21T16:00:00Z";
const NOW = Date.parse("2026-10-21T10:00:00Z");

function renewal(overrides: Partial<MicrosoftMembershipRenewal>): MicrosoftMembershipRenewal {
  return { state: "active", lastRenewedAt: null, nextAttemptAfter: null, lastFailure: null, ...overrides };
}

describe("administrator renewal status", () => {
  test("shows nothing without a renewal record", () => {
    expect(microsoftRenewalStatus(null)).toBeNull();
    expect(microsoftRenewalStatus(undefined)).toBeNull();
  });

  test("active renewal names the last renewal", () => {
    expect(microsoftRenewalStatus(renewal({ lastRenewedAt: RENEWED }))).toEqual({
      tone: "success",
      text: `Groups renew automatically (last renewed ${formatDateTime(RENEWED)})`
    });
    expect(microsoftRenewalStatus(renewal({}))).toEqual({
      tone: "success",
      text: "Groups renew automatically (not renewed since sign-in)"
    });
  });

  test("retrying renewal names the failure and the next attempt", () => {
    for (const [code, reason] of [
      ["unavailable", "Microsoft is unavailable"],
      ["throttled", "Microsoft is throttling requests"]
    ] as const) {
      expect(
        microsoftRenewalStatus(renewal({ state: "retrying", lastRenewedAt: RENEWED, nextAttemptAfter: NEXT, lastFailure: { code, at: FAILED } }))
      ).toEqual({ tone: "warning", text: `Renewal retrying: ${reason} (next attempt ${formatDateTime(NEXT)})` });
    }
  });

  test("blocked renewal names its reason and the hourly retry", () => {
    for (const [code, reason] of [
      ["groups_incomplete", "Microsoft reported an incomplete group list"],
      ["client_rejected", "Microsoft rejected the Broker's client credentials"],
      ["request_rejected", "Microsoft rejected the renewal request"],
      ["invalid_response", "Microsoft returned a response the Broker could not accept"]
    ] as const) {
      expect(microsoftRenewalStatus(renewal({ state: "blocked", nextAttemptAfter: NEXT, lastFailure: { code, at: FAILED } }))).toEqual({
        tone: "danger",
        text: `Renewal blocked: ${reason} (next attempt ${formatDateTime(NEXT)})`
      });
    }
  });

  test("ended renewals say what restores it", () => {
    expect(microsoftRenewalStatus(renewal({ state: "sign_in_required", lastRenewedAt: RENEWED }))).toEqual({
      tone: "warning",
      text: "Sign-in required to renew groups"
    });
    expect(microsoftRenewalStatus(renewal({ state: "not_issued" }))).toEqual({
      tone: "neutral",
      text: "Not available: Microsoft returned no refresh token"
    });
    expect(microsoftRenewalStatus(renewal({ state: "identity_mismatch" }))).toEqual({
      tone: "danger",
      text: "Sign-in required to renew groups: Microsoft returned a different identity"
    });
  });
});

describe("own Microsoft groups", () => {
  const membership = (state: MicrosoftMembershipRenewal["state"] | null, validUntil: string | null = VALID_UNTIL): MicrosoftMembership => ({
    validUntil,
    renewal: state === null ? null : renewal({ state })
  });
  const until = `valid until ${formatDateTime(VALID_UNTIL)}`;

  test("say groups renew automatically while renewal is active or retrying", () => {
    for (const state of ["active", "retrying"] as const) {
      expect(ownMicrosoftMembershipStatus(membership(state), NOW)).toEqual({
        tone: "success",
        text: `Renew automatically while you or your agents use the Broker; ${until}`
      });
    }
  });

  test("point a blocked renewal at the administrator", () => {
    expect(ownMicrosoftMembershipStatus(membership("blocked"), NOW)).toEqual({
      tone: "warning",
      text: `Automatic renewal is blocked; ask your administrator if group access is missing; ${until}`
    });
  });

  test("ask for a new sign-in when renewal ended", () => {
    for (const state of ["sign_in_required", "identity_mismatch"] as const) {
      expect(ownMicrosoftMembershipStatus(membership(state), NOW)).toEqual({
        tone: "warning",
        text: `Sign in with Microsoft again to renew them; ${until}`
      });
    }
  });

  test("ask for a sign-in at expiry without renewal", () => {
    for (const state of ["not_issued", null] as const) {
      expect(ownMicrosoftMembershipStatus(membership(state), NOW)).toEqual({
        tone: "neutral",
        text: `Sign in with Microsoft again when they expire; ${until}`
      });
    }
  });

  test("report expired and absent group evidence", () => {
    expect(ownMicrosoftMembershipStatus(membership("sign_in_required", "2026-10-21T09:00:00Z"), NOW).text).toBe(
      `Sign in with Microsoft again to renew them; expired ${formatDateTime("2026-10-21T09:00:00Z")}`
    );
    expect(ownMicrosoftMembershipStatus(membership(null, null), NOW).text).toBe("Sign in with Microsoft again when they expire; no current groups");
  });
});
