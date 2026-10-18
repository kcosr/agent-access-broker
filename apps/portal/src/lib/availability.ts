import type { AvailabilityRequirement, LocalAvailabilityReason } from "../types";

const LOCAL_REQUIREMENT: Record<LocalAvailabilityReason, string> = {
  managed_identity_required: "Managed identity is required.",
  managed_policy_required: "Managed policy is required.",
  credential_encryption_unavailable: "Managed encrypted secret storage is unavailable.",
  reference_identity_unsupported: "Use a supported invocation credential that can own temporary references.",
  token_hashing_unavailable: "The Broker token hashing key is unavailable.",
  finite_token_ttl_required: "Configure a finite administrator invocation-token lifetime.",
  reference_output_required: "Configure reference output mode to issue a Broker token."
};

/** Local prerequisites never lead to upstream credential setup. */
export function availabilityRequirementText(requirement: AvailabilityRequirement): string {
  if (requirement.kind === "local_runtime") return LOCAL_REQUIREMENT[requirement.reason];
  switch (requirement.resolution) {
    case "caller": return "Use a supported invocation credential.";
    case "administrator": return `An administrator must configure the ${requirement.credentialMode} credential.`;
    case "user": return `Set up your ${requirement.credentialMode} credential.`;
  }
}
