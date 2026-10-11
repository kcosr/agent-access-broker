import { AdminIconButton, AdminButton } from "../../components/admin-access";
// User page › Limits: per-service invocation limits with managed-store
// overrides. Under TOML identity authority overrides live in broker config.
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { brokerApi } from "../../api";
import type { ServiceLimit, ServiceLimitInput } from "../../types";
import { errorMessage } from "../../lib/helpers";
import { formatServiceLimit, replaceServiceLimit, serviceLimitDraft, serviceLimitDraftIssues, serviceLimitInput, type ServiceLimitDraft } from "../../lib/service-limits";
import { portalQueryKeys, viewerKey } from "../../lib/portal-queries";
import { Badge, Banner, Button, EmptyState, ErrorState, Field, Input, Modal, SkeletonRows, useToast } from "../../workbench";
import { FormError } from "../../components/form";
import { useModal } from "../../app/modal";
import { useSession } from "../../app/session";
import { usePolicyCatalog, useServiceLimits } from "../../data/queries";

export function ServiceLimitsTab({ principalId, identityAuthority }: { principalId: string; identityAuthority: string }) {
  const managed = identityAuthority === "managed";
  const { session, attempt } = useSession();
  const queryClient = useQueryClient();
  const toast = useToast();
  const { confirm } = useModal();
  const query = useServiceLimits(principalId, managed);
  const catalog = usePolicyCatalog().data ?? null;
  const [editing, setEditing] = useState<ServiceLimit | null>(null);
  const key = portalQueryKeys.serviceLimits(viewerKey(session), principalId);
  const name = (service: string) => catalog?.services.find((item) => item.service === service)?.displayName ?? service;

  async function apply(service: string, input: ServiceLimitInput | null) {
    const result = await attempt((current) =>
      input ? brokerApi.adminSetServiceLimit(current, principalId, service, input) : brokerApi.adminClearServiceLimit(current, principalId, service)
    );
    queryClient.setQueryData<ServiceLimit[]>(key, (current) => replaceServiceLimit(current ?? [], result));
    toast(
      input
        ? `Override saved: ${result.service} is limited to ${formatServiceLimit(result)}.`
        : `Override removed: ${result.service} uses the default limit of ${formatServiceLimit(result)}.`,
      { tone: "success" }
    );
  }

  if (identityAuthority === "unknown") return <SkeletonRows rows={4} compact />;
  if (!managed) {
    return (
      <Banner tone="info" title="Limits are configured in the broker">
        Per-principal service limits are managed in the broker configuration (<code>limits.invocations.principal_overrides</code>) under {identityAuthority} identity
        authority.
      </Banner>
    );
  }
  if (query.isPending) return <SkeletonRows rows={4} compact />;
  if (query.isError) return <ErrorState title="Couldn’t load service limits" error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} />;
  if (query.data.length === 0) return <EmptyState icon="package" title="No services configured">Configure a service on the broker to manage its invocation limits.</EmptyState>;
  return (
    <>
      <p className="pt-prose">Invocations this principal may make to each service within a rolling window. An override replaces the service default for this principal only.</p>
      <div className="wb-table-card">
        <table className="wb-table service-limits">
          <thead>
            <tr>
              <th scope="col">Service</th>
              <th scope="col">Limit</th>
              <th scope="col">Source</th>
              <th scope="col" className="wb-cell-actions">
                <span className="wb-sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {query.data.map((limit) => (
              <tr key={limit.service}>
                <td className="wb-cell-strong">
                  {name(limit.service)} <span className="wb-num wb-muted">{limit.service}</span>
                </td>
                <td>{formatServiceLimit(limit)}</td>
                <td>
                  <Badge tone={limit.overridden ? "warning" : "neutral"}>{limit.overridden ? "Override" : "Default"}</Badge>
                </td>
                <td className="wb-cell-actions">
                  <div className="flex justify-end gap-1">
                    <AdminIconButton size="sm" icon="pencil" label={`Edit ${limit.service} limit`} onClick={() => setEditing(limit)} />
                    <AdminIconButton
                      size="sm"
                      icon="refresh"
                      label={`Reset ${limit.service} limit to default`}
                      disabled={!limit.overridden}
                      onClick={() =>
                        confirm({
                          title: "Reset to the default limit?",
                          body: `Remove the override for ${limit.service}? The service default applies to this principal's next invocations.`,
                          confirmLabel: "Reset limit",
                          onConfirm: () => apply(limit.service, null)
                        })
                      }
                    />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {editing ? <LimitEditor limit={editing} onClose={() => setEditing(null)} onSave={(input) => apply(editing.service, input)} /> : null}
    </>
  );
}

function LimitEditor({ limit, onClose, onSave }: { limit: ServiceLimit; onClose: () => void; onSave: (input: ServiceLimitInput) => Promise<void> }) {
  const [draft, setDraft] = useState<ServiceLimitDraft>(() => serviceLimitDraft(limit));
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const issues = serviceLimitDraftIssues(draft);
  const input = serviceLimitInput(draft);
  return (
    <Modal
      open
      size="sm"
      title={`Edit ${limit.service} limit`}
      onClose={onClose}
      dismissible={!pending}
      onSubmit={async () => {
        if (!input) return;
        setPending(true);
        setError(null);
        try {
          await onSave(input);
          onClose();
        } catch (failure) {
          setError(errorMessage(failure));
          setPending(false);
        }
      }}
      footer={
        <>
          <Button onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <AdminButton type="submit" variant="primary" disabled={!input} pending={pending}>
            Save override
          </AdminButton>
        </>
      }
    >
      <div className="pt-form">
        <div className="pt-form-row">
          <Field label="Requests" error={issues.requests}>
            <Input numeric inputMode="numeric" autoComplete="off" value={draft.requests} onChange={(event) => setDraft({ ...draft, requests: event.target.value })} autoFocus />
          </Field>
          <Field label="Window" error={issues.window}>
            <Input mono autoComplete="off" placeholder="1m" value={draft.window} onChange={(event) => setDraft({ ...draft, window: event.target.value })} />
          </Field>
        </div>
        <p className="pt-prose">From 1 to 1,000,000 requests per window. Windows use s, m, h, or d, from 1s to 1d: for example 30s, 1m, 2h, or 1d.</p>
        <FormError error={error} />
      </div>
    </Modal>
  );
}
