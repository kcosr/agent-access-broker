// A token's immutable boundary: services, contexts, and per-service restrictions.
import type { AgentTokenOptions, BrokerTokenRecord, ResourceCatalog } from "../../types";
import { tokenAllowedServiceItems, tokenAllowedServicesSummary, tokenExecutionContextsSummary, tokenStatus } from "../../lib/helpers";
import { serviceDisplayNames } from "../../lib/access";
import { ServiceLabel } from "../../components/service-label";
import { resourceSelectionLabels } from "../../lib/resource-labels";
import { useResourceTypes } from "../../lib/resource-types";
import { KeyValue } from "../../workbench";

/** `contexts={false}` when the surrounding view already shows the token's contexts. */
export function TokenBoundary({ record, options, contexts = true }: { record: BrokerTokenRecord; options?: AgentTokenOptions | ResourceCatalog | null; contexts?: boolean }) {
  const types = useResourceTypes();
  const restrictions = record.scopes.serviceRestrictions;
  // Display names from the token options (an admin's resource catalog has none: IDs stay).
  const names = serviceDisplayNames(options && "services" in options ? options : null);
  const name = (service: string) => names.get(service) ?? service;
  const allowed = tokenAllowedServiceItems(record);
  const summary = tokenAllowedServicesSummary(record);
  return (
    <div className="flex flex-col gap-3">
      <KeyValue
        items={[
          { label: "Services", value: allowed ? allowed.map(name).join(", ") : summary === "All configured" ? "All services its grants allow" : summary },
          contexts
            ? {
                label: "Contexts",
                value: <span className="wb-mono">{tokenExecutionContextsSummary(record, options && "executionContexts" in options ? options.executionContexts : undefined)}</span>
              }
            : null
        ]}
      />
      {!restrictions ? (
        <p className="pt-prose">All actions and resources allowed by current grants.</p>
      ) : (
        Object.entries(restrictions).map(([service, restriction]) => (
          <fieldset className="pt-fieldset" key={service}>
            <legend>
              <ServiceLabel service={service} name={names.get(service)} />
            </legend>
            <KeyValue
              items={[
                { label: "Actions", value: <span className="wb-mono">{restriction.actions.join(", ")}</span> },
                {
                  label: "Resources",
                  value:
                    restriction.resources === undefined
                      ? "Follow available grants"
                      : resourceSelectionLabels(types, restriction.resources, options).join(", ") || "No access currently"
                }
              ]}
            />
          </fieldset>
        ))
      )}
      <p className="pt-prose">
        {tokenStatus(record) === "Active"
          ? "The boundary cannot be edited. Current grants and resource-group membership are evaluated on every request."
          : `No access currently: this token is ${tokenStatus(record).toLowerCase()}.`}
      </p>
    </div>
  );
}
