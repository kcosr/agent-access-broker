// Issue an agent token: details, then (when restricted) services, actions and
// resources, then review. The wizard state lives in the app modal slot so it
// can follow refreshed token options.
import { useState } from "react";
import type { AgentTokenModal, ModalState } from "../../app-types";
import {
  agentTokenServiceHasResources,
  availableAgentTokenActions,
  availableAgentTokenServices,
  buildAgentTokenServiceRestrictions,
  errorMessage,
  reconcileAgentTokenModalOptions
} from "../../lib/helpers";
import { resourceSelectionLabels } from "../../lib/resource-labels";
import { grantedServiceActions, serviceDisplayNames } from "../../lib/access";
import { ServiceLabel } from "../../components/service-label";
import { useResourceTypes } from "../../lib/resource-types";
import { Banner, Button, Checkbox, Field, FilterInput, Input, KeyValue, Modal, Seg, Select } from "../../workbench";
import { EffectiveAccessDisclosure } from "../../components/effective-access";
import { ResourcePicker } from "../../components/resource-picker";
import { FieldGroup, FormError } from "../../components/form";

const STEPS = { edit: "Details", access: "Token access", review: "Review" } as const;

function accessComplete(modal: AgentTokenModal) {
  return (
    modal.selectedExecutionContexts.length > 0 &&
    modal.selectedServices.length > 0 &&
    modal.selectedServices.every((service) => (modal.selectedActions[service] ?? []).length > 0)
  );
}

export function IssueTokenModal({
  modal,
  setModal,
  onIssue
}: {
  modal: AgentTokenModal;
  setModal: (value: ModalState) => void;
  onIssue: (modal: AgentTokenModal) => Promise<void>;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const restricted = modal.accessMode === "restricted";
  const stepCount = restricted ? 3 : 1;
  const stepIndex = modal.screen === "edit" ? 1 : modal.screen === "access" ? 2 : 3;
  const detailsValid = Boolean(modal.name.trim() && modal.lifetime && modal.selectedExecutionContexts.length > 0);
  const update = (next: AgentTokenModal) => {
    setError(null);
    setModal(next);
  };

  async function issue() {
    setPending(true);
    setError(null);
    try {
      await onIssue(modal);
    } catch (failure) {
      setError(errorMessage(failure));
      setPending(false);
    }
  }

  function submit() {
    if (modal.screen === "edit") {
      if (!detailsValid) return;
      if (restricted) update({ ...modal, screen: "access" });
      else void issue();
    } else if (modal.screen === "access") {
      if (accessComplete(modal)) update({ ...modal, screen: "review" });
    } else if (accessComplete(modal)) {
      void issue();
    }
  }

  const boundary = {
    allowedExecutionContexts: modal.selectedExecutionContexts,
    ...(restricted
      ? {
          allowedServices: modal.selectedServices,
          serviceRestrictions: buildAgentTokenServiceRestrictions(modal.selectedServices, modal.selectedActions, modal.resourceSelections, modal.options)
        }
      : {})
  };

  return (
    <Modal
      open
      size="lg"
      title="Issue agent token"
      description={`${stepCount > 1 ? `Step ${stepIndex} of ${stepCount} · ${STEPS[modal.screen]} · ` : ""}Owner ${modal.targetPrincipalId}`}
      onClose={() => setModal(null)}
      dismissible={!pending}
      onSubmit={submit}
      footerNote={modal.screen === "review" ? "Restrictions cannot be edited after issuance." : undefined}
      footer={
        <>
          {modal.screen === "edit" ? (
            <Button onClick={() => setModal(null)} disabled={pending}>
              Cancel
            </Button>
          ) : (
            <Button onClick={() => update({ ...modal, screen: modal.screen === "review" ? "access" : "edit" })} disabled={pending}>
              Back
            </Button>
          )}
          {modal.screen === "edit" ? (
            <Button type="submit" variant="primary" disabled={!detailsValid} pending={pending}>
              {restricted ? "Continue" : "Issue token"}
            </Button>
          ) : modal.screen === "access" ? (
            <Button type="submit" variant="primary" disabled={!accessComplete(modal)}>
              Review
            </Button>
          ) : (
            <Button type="submit" variant="primary" disabled={!accessComplete(modal)} pending={pending}>
              Issue token
            </Button>
          )}
        </>
      }
    >
      <div className="pt-form">
        {modal.screen === "edit" ? <DetailsStep modal={modal} update={update} /> : null}
        {modal.screen === "access" ? <AccessStep modal={modal} update={update} /> : null}
        {modal.screen === "review" ? <ReviewStep modal={modal} /> : null}
        <EffectiveAccessDisclosure
          token={boundary}
          principalId={modal.administrative ? modal.targetPrincipalId : undefined}
          serviceNames={serviceDisplayNames(modal.options)}
          grantedActions={grantedServiceActions(modal.options)}
        />
        <FormError error={error} />
      </div>
    </Modal>
  );
}

function DetailsStep({ modal, update }: { modal: AgentTokenModal; update: (next: AgentTokenModal) => void }) {
  return (
    <>
      <Field label="Name" hint="Where the token runs, for example “laptop-cli” or “ci-nightly”.">
        <Input value={modal.name} onChange={(event) => update({ ...modal, name: event.target.value })} required autoFocus />
      </Field>
      <Field
        label="Lifetime"
        hint={`Choices are configured by the broker${modal.ttlPolicy.maxTtl ? `; the longest finite lifetime is ${modal.ttlPolicy.maxTtl}` : ""}.${modal.lifetime === "never" ? " This token stays active until it is revoked." : ""}`}
      >
        <Select
          value={modal.lifetime}
          onChange={(event) => update({ ...modal, lifetime: event.target.value })}
          options={modal.ttlPolicy.options.map((option) => ({ value: option, label: option === "never" ? "Never expires" : option }))}
        />
      </Field>
      <fieldset className="pt-fieldset">
        <legend>Execution contexts</legend>
        <div className="pt-checks">
          {modal.options.executionContexts.map((context) => (
            <Checkbox
              key={context}
              label={<span className="wb-mono">{context}</span>}
              aria-label={context}
              checked={modal.selectedExecutionContexts.includes(context)}
              onChange={(event) => {
                const selected = new Set(modal.selectedExecutionContexts);
                if (event.target.checked) selected.add(context);
                else selected.delete(context);
                update(reconcileAgentTokenModalOptions(modal, modal.options, modal.options.executionContexts.filter((item) => selected.has(item))));
              }}
            />
          ))}
        </div>
        <p className="pt-prose">
          Where the token may be used. This narrows access; it never grants it. Contexts added to your grants later are not added to the token.
        </p>
      </fieldset>
      <FieldGroup label="Access" hint={modal.accessMode === "restricted" ? "Choose services, actions, and resources next. Restrictions can only narrow current grants." : undefined}>
        <Seg
          label="Access"
          value={modal.accessMode}
          onChange={(accessMode) => update({ ...modal, accessMode })}
          options={[
            { value: "policy", label: "Follow current grants" },
            { value: "restricted", label: "Restrict to selected" }
          ]}
        />
      </FieldGroup>
      {modal.accessMode === "policy" ? (
        <Banner tone="info" slim>
          {modal.selectedExecutionContexts.length
            ? `The token can use everything ${modal.administrative ? "this principal is" : "you are"} granted in ${modal.selectedExecutionContexts.join(", ")}, including later grant changes in those contexts.`
            : "Select at least one execution context."}
        </Banner>
      ) : null}
    </>
  );
}

function AccessStep({ modal, update }: { modal: AgentTokenModal; update: (next: AgentTokenModal) => void }) {
  const [filters, setFilters] = useState<Record<string, string>>({});
  const services = [...new Set([...availableAgentTokenServices(modal.options, modal.selectedExecutionContexts), ...modal.selectedServices])];
  const names = serviceDisplayNames(modal.options);

  function toggleService(service: string, checked: boolean) {
    if (checked) {
      update({ ...modal, selectedServices: [...modal.selectedServices, service] });
      return;
    }
    const selectedActions = { ...modal.selectedActions };
    const resourceSelections = { ...modal.resourceSelections };
    delete selectedActions[service];
    delete resourceSelections[service];
    update({ ...modal, selectedServices: modal.selectedServices.filter((item) => item !== service), selectedActions, resourceSelections });
  }

  const setActions = (service: string, actions: string[]) => update({ ...modal, selectedActions: { ...modal.selectedActions, [service]: actions } });

  return (
    <>
      <fieldset className="pt-fieldset">
        <legend>Services</legend>
        <div className="flex flex-wrap gap-x-5 gap-y-2">
          {services.map((service) => (
            <Checkbox
              key={service}
              label={<ServiceLabel service={service} name={names.get(service)} />}
              aria-label={service}
              checked={modal.selectedServices.includes(service)}
              onChange={(event) => toggleService(service, event.target.checked)}
            />
          ))}
        </div>
        {services.length === 0 ? <span className="wb-small wb-muted">No services are available in the selected contexts.</span> : null}
      </fieldset>
      {modal.selectedServices.map((service) => {
        const available = availableAgentTokenActions(modal.options, service, modal.selectedExecutionContexts);
        const selected = modal.selectedActions[service] ?? [];
        const known = new Set(available.map((action) => action.action));
        const rows = [...available, ...selected.filter((action) => !known.has(action)).map((action) => ({ action, description: "Not available in the selected contexts" }))];
        const filter = (filters[service] ?? "").toLowerCase();
        const visible = rows.filter((action) => `${action.action} ${action.description}`.toLowerCase().includes(filter));
        const selection = agentTokenServiceHasResources(modal.options, service) ? modal.resourceSelections[service] : undefined;
        return (
          <fieldset className="pt-fieldset" key={service} aria-label={`${service} token access`}>
            <legend>
              <ServiceLabel service={service} name={names.get(service)} /> · {selected.length} selected
            </legend>
            <div className="flex flex-wrap items-center gap-2">
              <FilterInput
                className="flex-1"
                value={filters[service] ?? ""}
                onChange={(value) => setFilters({ ...filters, [service]: value })}
                placeholder="Filter actions…"
                label={`Filter ${service} actions`}
                hotkey={null}
              />
              <Button size="sm" onClick={() => setActions(service, available.map((action) => action.action))}>
                Select all
              </Button>
              <Button size="sm" onClick={() => setActions(service, [])} disabled={selected.length === 0}>
                Clear
              </Button>
            </div>
            <div className="pt-checks pt-checks--scroll">
              {visible.map((action) => (
                <Checkbox
                  key={action.action}
                  aria-label={action.action}
                  label={<span className="wb-mono">{action.action}</span>}
                  description={action.description || undefined}
                  checked={selected.includes(action.action)}
                  onChange={(event) => setActions(service, event.target.checked ? [...selected, action.action] : selected.filter((item) => item !== action.action))}
                />
              ))}
            </div>
            {selected.length === 0 ? <span className="pt-error">Select at least one action.</span> : null}
            {agentTokenServiceHasResources(modal.options, service) ? (
              <>
                <FieldGroup label="Resources" hint="Group membership stays live. Selections can only narrow current grants.">
                  <Seg
                    label={`${service} resources`}
                    value={selection === undefined ? "grants" : "selected"}
                    onChange={(value) =>
                      update({
                        ...modal,
                        resourceSelections: { ...modal.resourceSelections, [service]: value === "grants" ? undefined : { resourceIds: [], resourceGroupIds: [] } }
                      })
                    }
                    options={[
                      { value: "grants", label: "Follow available grants" },
                      { value: "selected", label: "Selected resources and groups" }
                    ]}
                  />
                </FieldGroup>
                {selection !== undefined ? (
                  <ResourcePicker
                    selection={selection}
                    catalog={modal.options}
                    onChange={(resources) => update({ ...modal, resourceSelections: { ...modal.resourceSelections, [service]: resources } })}
                  />
                ) : null}
              </>
            ) : (
              <p className="pt-prose">Access is controlled by action grants; this service has no resource selections.</p>
            )}
          </fieldset>
        );
      })}
    </>
  );
}

function ReviewStep({ modal }: { modal: AgentTokenModal }) {
  const types = useResourceTypes();
  return (
    <>
      <KeyValue
        items={[
          { label: "Owner", value: <span className="wb-num">{modal.targetPrincipalId}</span> },
          { label: "Name", value: modal.name },
          { label: "Lifetime", value: modal.lifetime === "never" ? "Never expires" : modal.lifetime },
          { label: "Contexts", value: <span className="wb-mono">{modal.selectedExecutionContexts.join(", ")}</span> }
        ]}
      />
      {modal.selectedServices.map((service) => {
        const actions = modal.selectedActions[service] ?? [];
        const selection = agentTokenServiceHasResources(modal.options, service) ? modal.resourceSelections[service] : undefined;
        return (
          <fieldset className="pt-fieldset" key={service}>
            <legend className="wb-mono">{service}</legend>
            <KeyValue
              items={[
                { label: "Actions", value: <span className="wb-mono">{actions.join(", ")}</span> },
                {
                  label: "Resources",
                  value: selection === undefined ? "Follow available grants" : resourceSelectionLabels(types, selection, modal.options).join(", ") || "No access currently"
                }
              ]}
            />
          </fieldset>
        );
      })}
      <Banner tone="info" slim>
        Issue a replacement token to change these restrictions. Current grants are still evaluated on every request.
      </Banner>
    </>
  );
}
