import { expect, test } from "vitest";
import { availabilityRequirementText } from "../src/lib/availability";
import { canGrantAction } from "../src/lib/grant-actions";
import type { AvailabilityRequirement, LocalAvailabilityReason } from "../src/types";

test("all local prerequisites describe local action and caller setup", () => {
  const reasons: LocalAvailabilityReason[] = [
    "managed_identity_required", "managed_policy_required", "credential_encryption_unavailable",
    "reference_identity_unsupported", "token_hashing_unavailable", "finite_token_ttl_required", "reference_output_required"
  ];
  for (const reason of reasons) {
    const requirement: AvailabilityRequirement = {
      kind: "local_runtime", reason,
      resolution: reason === "reference_identity_unsupported" ? "caller" : "administrator"
    };
    const rendered = availabilityRequirementText(requirement);
    expect(rendered.length).toBeGreaterThan(10);
    expect(rendered).not.toContain("Set up your");
  }
  expect(availabilityRequirementText({ kind: "local_runtime", reason: "reference_identity_unsupported", resolution: "caller" })).toContain("invocation credential");
});

test("credential setup distinguishes all three resolution owners", () => {
  const texts = ["user", "administrator", "caller"].map((resolution) =>
    availabilityRequirementText({ kind: "credential", reason: "credential_not_provisioned", credentialMode: "per_user", resolution } as AvailabilityRequirement));
  expect(texts[0]).toContain("Set up your");
  expect(texts[1]).toContain("administrator");
  expect(texts[2]).toContain("invocation credential");
});

test("local setup does not prevent granting an action, while unavailable imports stay blocked", () => {
  expect(canGrantAction({ action: "token.create", available: false, availabilityRequirements: [
    { kind: "local_runtime", reason: "reference_identity_unsupported", resolution: "caller" }
  ] })).toBe(true);
  expect(canGrantAction({ action: "retired", available: false })).toBe(false);
  expect(canGrantAction({ action: "missing_credential", available: false, availabilityRequirements: [
    { kind: "credential", reason: "credential_not_provisioned", credentialMode: "per_user", resolution: "user" }
  ] })).toBe(false);
});
