// Account → Applications: the applications the signed-in person approved, and
// removing one. Self-service does not gate it. The section appears when the
// person has an application, or when the broker's catalog shows that
// applications are registered.
import { ApiError, brokerApi } from "../../api";
import { useModal } from "../../app/modal";
import { useSession } from "../../app/session";
import { useApplicationsRegistered, useOwnApplicationAccess } from "../../data/queries";
import { applicationAccessLevel, applicationAccessName, applicationAccessRestricted, applicationAccessState } from "../../lib/applications";
import type { ApplicationAccess } from "../../types";
import { Badge, Button, EmptyState, ErrorState, SettingsSection, SkeletonBlock, Time, useToast } from "../../workbench";

export function ApplicationsSection() {
  const { attempt } = useSession();
  const { confirm } = useModal();
  const toast = useToast();
  const registered = useApplicationsRegistered();
  const query = useOwnApplicationAccess();
  const access = query.data;
  // Nothing to show on a broker without applications, including while that is still unknown.
  if (!access?.length && registered.data !== true) return null;

  function remove(item: ApplicationAccess) {
    const name = applicationAccessName(item);
    confirm({
      title: "Remove application?",
      body: `Remove ${name}? This ends its access at once: every token it holds for you stops working, and it must ask for your approval again before it can act as you.${applicationAccessRestricted(item) ? " The restriction an administrator set stays in place if you connect it again." : ""}`,
      confirmLabel: "Remove application",
      onConfirm: async () => {
        try {
          await attempt((current) => brokerApi.removeApplicationAccess(current, item.accessId));
        } catch (failure) {
          // Already disconnected elsewhere: the list no longer holds it.
          if (!(failure instanceof ApiError && failure.reasonCode === "application_access_not_found")) throw failure;
        } finally {
          await query.refetch();
        }
        toast(`${name} removed`, { tone: "success" });
      }
    });
  }

  return (
    <SettingsSection title="Applications" description="Applications you approved to act as you through the broker. Each obtains its own short-lived tokens, which are not listed with your tokens.">
      {query.isError ? (
        <ErrorState compact title="Couldn’t load your applications" error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} />
      ) : !access ? (
        <SkeletonBlock lines={2} />
      ) : access.length === 0 ? (
        <EmptyState compact icon="link" title="No applications connected">
          An application asks for your approval the first time it needs the broker.
        </EmptyState>
      ) : (
        <ApplicationAccessTable access={access} busy={query.isFetching} onRemove={remove} />
      )}
    </SettingsSection>
  );
}

/** One row per application: when it was connected, level, state, last use, live tokens and Remove. */
export function ApplicationAccessTable({ access, busy, onRemove }: { access: ApplicationAccess[]; busy: boolean; onRemove: (access: ApplicationAccess) => void }) {
  return (
    <div className="wb-table-card overflow-x-auto">
      <table className="wb-table" aria-label="Applications">
        <thead>
          <tr>
            <th scope="col">Application</th>
            <th scope="col">Access level</th>
            <th scope="col">Status</th>
            <th scope="col">Last used</th>
            <th scope="col">Live tokens</th>
            <th scope="col">
              <span className="wb-sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {access.map((item) => {
            const name = applicationAccessName(item);
            const state = applicationAccessState(item);
            const level = applicationAccessLevel(item);
            return (
              <tr key={item.accessId}>
                <th scope="row" className="pt-identity-path">
                  <span className={item.applicationName === null ? "pt-identity-path-name wb-num" : "pt-identity-path-name"}>{name}</span>
                  <span className="wb-small wb-muted">
                    Connected <Time value={item.connectedAt} format="date" />
                  </span>
                </th>
                <td className="whitespace-nowrap">{level ?? <span className="wb-muted">Not available</span>}</td>
                <td>
                  <Badge tone={state.tone}>{state.label}</Badge>
                </td>
                <td className="whitespace-nowrap">
                  <Time value={item.lastUsedAt} fallback="Never" />
                </td>
                <td>{item.liveTokenCount}</td>
                <td className="wb-cell-actions">
                  <div className="flex justify-end gap-1">
                    <Button size="sm" variant="danger-ghost" disabled={busy} aria-label={`Remove ${name}`} onClick={() => onRemove(item)}>
                      Remove
                    </Button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
