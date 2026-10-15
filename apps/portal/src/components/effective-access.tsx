// Effective access: resource clauses as readable alternatives, and a preview
// that asks the broker what a grant or token boundary currently allows.
import { Fragment, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { brokerApi } from "../api";
import type { EffectiveAccessClause, EffectiveAccessResult, GrantEffectiveAccessBody, ResourceType, TokenEffectiveAccessBody } from "../types";
import { ACTION_GRANT_LABEL } from "../lib/helpers";
import { mergeEffectiveAccess } from "../lib/access";
import { ServiceLabel } from "./service-label";
import { clauseLabel } from "../lib/resource-labels";
import { useResourceTypes } from "../lib/resource-types";
import { portalQueryKeys } from "../lib/portal-queries";
import { useSession } from "../app/session";
import { EmptyState, ErrorState, Icon, SkeletonBlock } from "../workbench";

/** One clause: its inclusions minus exclusions, and whole-request conditions. */
export function AccessClause({ type, clause, alternative = false }: { type: ResourceType; clause: EffectiveAccessClause; alternative?: boolean }) {
  const types = useResourceTypes();
  return (
    <li>
      <span>
        {alternative ? "Or: " : ""}
        {clauseLabel(types, type, clause)}
      </span>
      {clause.excludedRequests?.map((boundary, index) => (
        <div className="pt-clause-note" key={index}>
          Does not apply when every requested resource is within: {clauseLabel(types, type, boundary)}.
        </div>
      ))}
    </li>
  );
}

/** Every alternative clause an action allows (or "Action grant" for actions without resources). */
export function AccessClauses({ type, clauses }: { type: ResourceType | null; clauses: EffectiveAccessClause[] }) {
  if (type === null) return <span>{ACTION_GRANT_LABEL}</span>;
  return (
    <>
      {clauses.length > 1 ? <div className="pt-clause-note">Every resource in a request must fit the same alternative.</div> : null}
      <ul className="pt-clauses">
        {clauses.map((clause, index) => (
          <AccessClause type={type} clause={clause} alternative={index > 0} key={index} />
        ))}
      </ul>
    </>
  );
}

/** An action name that line-breaks after its dots in a narrow column. */
function ActionName({ action }: { action: string }) {
  const parts = action.split(".");
  return (
    <>
      {parts.map((part, index) => (
        <Fragment key={index}>
          {part}
          {index < parts.length - 1 ? (
            <>
              .<wbr />
            </>
          ) : null}
        </Fragment>
      ))}
    </>
  );
}

/** Action names that wrap between names (and after dots within a long one). */
function ActionList({ actions }: { actions: string[] }) {
  return (
    <>
      {actions.map((action, index) => (
        <Fragment key={action}>
          {index > 0 ? ", " : null}
          <span>
            <ActionName action={action} />
          </span>
        </Fragment>
      ))}
    </>
  );
}

/**
 * What a grant or token allows now, as a compact table: one row per set of
 * actions and contexts with identical resources (see `mergeEffectiveAccess`),
 * grouped by service when there are several. `serviceNames` maps service IDs
 * to display names. `grantedActions` maps a service to the actions granted on
 * it (the grant's, or the principal's from the token options): a row covering
 * exactly those reads "All N granted actions", a disclosure that lists them.
 */
export function EffectiveAccessSummary({
  result,
  serviceNames,
  grantedActions
}: {
  result: EffectiveAccessResult;
  serviceNames?: ReadonlyMap<string, string> | undefined;
  grantedActions?: ReadonlyMap<string, readonly string[]> | undefined;
}) {
  const rows = mergeEffectiveAccess(result.access);
  const everyGrantedAction = (service: string, actions: string[]) => {
    const all = new Set(grantedActions?.get(service) ?? []);
    return all.size > 1 && actions.length === all.size && actions.every((action) => all.has(action));
  };
  const services = [...new Set(rows.map((row) => row.service))];
  return (
    <div className="flex flex-col gap-3">
      <p className="pt-prose">Current access at policy generation {result.policyGeneration}. Later policy changes apply to subsequent requests.</p>
      {rows.length === 0 ? (
        <EmptyState compact icon="ban" title="No access currently" />
      ) : (
        <table className="pt-access-table">
          <thead>
            <tr>
              <th scope="col">Actions</th>
              <th scope="col">Contexts</th>
              <th scope="col">Resources</th>
            </tr>
          </thead>
          {services.map((service) => (
            <tbody key={service}>
              {services.length > 1 ? (
                <tr className="pt-access-group">
                  <th scope="rowgroup" colSpan={3}>
                    <ServiceLabel service={service} name={serviceNames?.get(service)} />
                  </th>
                </tr>
              ) : null}
              {rows
                .filter((row) => row.service === service)
                .map((row) => (
                  <tr key={`${row.actions.join(",")}|${row.contexts.join(",")}`}>
                    <th scope="row" className="pt-access-actions">
                      {everyGrantedAction(row.service, row.actions) ? (
                        // Collapsed, but one keyboard-operable click away.
                        <details className="pt-access-all">
                          <summary>All {row.actions.length} granted actions</summary>
                          <ActionList actions={row.actions} />
                        </details>
                      ) : (
                        <ActionList actions={row.actions} />
                      )}
                    </th>
                    <td className="pt-access-contexts">
                      {row.contexts.map((context, index) => (
                        <Fragment key={context}>
                          {index > 0 ? ", " : null}
                          <span>{context}</span>
                        </Fragment>
                      ))}
                    </td>
                    <td>
                      <AccessClauses type={row.resourceType} clauses={row.clauses} />
                    </td>
                  </tr>
                ))}
            </tbody>
          ))}
        </table>
      )}
    </div>
  );
}

type PreviewInput = { grant: GrantEffectiveAccessBody; token?: undefined; principalId?: undefined } | { token: TokenEffectiveAccessBody; grant?: undefined; principalId?: string };

function useEffectiveAccess(input: PreviewInput, enabled: boolean) {
  const { session, runQuery } = useSession();
  return useQuery({
    queryKey: [...portalQueryKeys.effectiveAccessRoot, session.principal, input.principalId, input.grant ?? input.token],
    enabled,
    queryFn: () =>
      runQuery((current) =>
        input.grant ? brokerApi.grantEffectiveAccess(current, input.grant) : brokerApi.tokenEffectiveAccess(current, input.token, input.principalId)
      )
  });
}

type PreviewNames = {
  serviceNames?: ReadonlyMap<string, string> | undefined;
  grantedActions?: ReadonlyMap<string, readonly string[]> | undefined;
};

function PreviewBody({ input, enabled, serviceNames, grantedActions }: { input: PreviewInput; enabled: boolean } & PreviewNames) {
  const query = useEffectiveAccess(input, enabled);
  if (query.isPending) return <SkeletonBlock lines={3} label="Loading current access" />;
  if (query.isError) return <ErrorState compact error={query.error} title="Couldn’t load current access" onRetry={() => void query.refetch()} retrying={query.isFetching} />;
  return (
    <EffectiveAccessSummary
      result={query.data}
      serviceNames={serviceNames}
      grantedActions={input.grant ? new Map([[input.grant.service, input.grant.actions]]) : grantedActions}
    />
  );
}

/** Collapsed "Effective access" disclosure that loads when opened. */
export function EffectiveAccessDisclosure({
  summary = "Effective access",
  serviceNames,
  grantedActions,
  ...input
}: PreviewInput & { summary?: ReactNode } & PreviewNames) {
  const [open, setOpen] = useState(false);
  return (
    <details className="wb-disclosure" open={open} onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary>
        <Icon name="chevron-right" />
        {summary}
      </summary>
      {open ? <PreviewBody input={input} enabled={open} serviceNames={serviceNames} grantedActions={grantedActions} /> : null}
    </details>
  );
}

/** Always-on preview (drawers, the grant editor). */
export function EffectiveAccessPanel({ serviceNames, grantedActions, ...input }: PreviewInput & PreviewNames) {
  return <PreviewBody input={input} enabled serviceNames={serviceNames} grantedActions={grantedActions} />;
}
