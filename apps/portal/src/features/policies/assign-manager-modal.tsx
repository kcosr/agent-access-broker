// Assign a service policy manager (global admins).
import { useState } from "react";
import { errorMessage, principalIdentityLabel } from "../../lib/helpers";
import { Banner, Button, Combobox, Field, Modal, Select } from "../../workbench";
import { FormError } from "../../components/form";
import { usePolicyCatalog, useAdminPrincipals } from "../../data/queries";
import { usePolicyActions } from "../../mutations/policy";

export function AssignManagerModal({ service: initialService, onClose }: { service?: string; onClose: () => void }) {
  const catalog = usePolicyCatalog().data ?? null;
  const policy = usePolicyActions();
  const services = catalog?.services ?? [];
  const [service, setService] = useState(initialService ?? "");
  const [principalId, setPrincipalId] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const target = service || services[0]?.service || "";
  const principals = useAdminPrincipals().data ?? [];
  const holders = principals.filter((principal) => principal.role === "service_policy_manager" && principal.status === "active")
    .map((principal) => ({ value: principal.principalId, label: principalIdentityLabel(principal.principalId, principal.displayName) }));
  return (
    <Modal
      open
      title="Assign service policy manager"
      onClose={onClose}
      dismissible={!pending}
      onSubmit={async () => {
        if (!target || !principalId) return;
        setPending(true);
        setError(null);
        try {
          await policy.assignManager(target, principalId);
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
          <Button type="submit" variant="primary" disabled={!target || !principalId} pending={pending}>
            Assign manager
          </Button>
        </>
      }
    >
      <div className="wb-form-stack">
        <Field label="Service">
          <Select
            value={target}
            onChange={(event) => setService(event.target.value)}
            disabled={Boolean(initialService)}
            options={services.map((item) => ({ value: item.service, label: `${item.displayName} (${item.service})` }))}
          />
        </Field>
        <Field label="Principal" hint="Choose an account with the Service policy manager role.">
          <Combobox value={principalId} onChange={setPrincipalId} options={holders} placeholder="Choose a principal…" />
        </Field>
        <Banner tone="warning" slim>
          {principalId ?? "The account"} will manage every grant for {target || "this service"}: granting access to themselves or anyone else, and authorizing
          configured service credentials without seeing the secrets.
        </Banner>
        <FormError error={error} />
      </div>
    </Modal>
  );
}
