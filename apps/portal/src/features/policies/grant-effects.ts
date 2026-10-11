import type { PolicyCatalogResult, PolicyGrantRecord } from "../../types";
import { actionSelectionCounts } from "../../lib/grant-actions";
import { policyService } from "../../lib/helpers";

/** A grant is read-only only when every selected action was reviewed as a read. */
export function grantIsReadOnly(grant: Pick<PolicyGrantRecord, "service" | "actions">, catalog: PolicyCatalogResult | null) {
  const counts = actionSelectionCounts(policyService(catalog, grant.service)?.actions ?? [], grant.actions);
  return counts.readOnly > 0 && counts.writeCapable === 0;
}
