// A local token draft shares boundary validation between preview and issuance.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { useBlocker, useNavigate, useParams, useSearchParams } from "react-router";
import type { AgentTokenOptions, TokenTtlPolicy } from "../../types";
import { ACTION_GRANT_LABEL, agentTokenResourceSelection, agentTokenSelectedActions, agentTokenServiceHasResources, availableAgentTokenServices, errorMessage } from "../../lib/helpers";
import { canWriteSubject } from "../../lib/capabilities";
import { grantedServiceActions, serviceDisplayNames } from "../../lib/access";
import { resourceSelectionLabels } from "../../lib/resource-labels";
import { useResourceTypes } from "../../lib/resource-types";
import { buildAgentTokenBoundary, buildAgentTokenIssuance, createAgentTokenDraft, tokenActionChoices, type AgentTokenDraft } from "../../lib/token-draft";
import { Banner, Button, Card, Checkbox, ConfirmDialog, EmptyState, ErrorState, Field, Input, KeyValue, List, Main, PageHeader, Seg, Select, SkeletonBlock } from "../../workbench";
import { EffectiveAccessPanel } from "../../components/effective-access";
import { GrantActionSelector, WriteCapability } from "../../components/grant-actions";
import { ResourcePicker } from "../../components/resource-picker";
import { ServiceLabel } from "../../components/service-label";
import { FieldGroup, FormError } from "../../components/form";
import { type AccountSubject } from "../../app/active-route";
import { useModal } from "../../app/modal";
import { paths, portalReturnTo } from "../../app/paths";
import { useSession } from "../../app/session";
import { useTokenIssuance } from "../../app/token-issuance";
import { PortalPage } from "../../app/top-bar";
import { useAdminPrincipal, useAgentTokenOptions } from "../../data/queries";
import { usePortalInvalidation } from "../../data/invalidation";

const tokenListPath = (subject: AccountSubject, token?: string) => subject.administered ? paths.principalTokens(subject.principalId, token) : paths.tokens(token);

export function TokenEditorPage() {
  const { session } = useSession();
  const { principalId } = useParams();
  const [params] = useSearchParams();
  const subject: AccountSubject = { administered: principalId !== undefined, principalId: principalId ?? session.principal ?? "" };
  const initializedOwner = useRef<string | null>(null);
  const ownerKey = `${subject.administered}:${subject.principalId}:${params.toString()}`;
  const initialized = initializedOwner.current === ownerKey;
  const owner = useAdminPrincipal(subject.principalId, subject.administered);
  const ownerActive = !subject.administered || owner.data?.status === "active";
  const { query, options } = useAgentTokenOptions(subject, ownerActive);
  const ttlPolicy = subject.administered ? session.tokenIssuancePolicy?.administered?.agentInvoke : session.tokenIssuancePolicy?.selfAgentInvoke;
  const returnTo = portalReturnTo(params.get("returnTo")) ?? tokenListPath(subject);
  let state: ReactNode;
  if ((subject.administered && !owner.data && owner.isPending) || (ownerActive && !options && query.isPending)) {
    state = <SkeletonBlock lines={8} label="Loading token options" />;
  } else if ((subject.administered && !owner.data && owner.error) || (ownerActive && !options && query.error)) {
    state = <ErrorState title="Couldn’t load token options" error={owner.error ?? query.error} onRetry={() => { if (subject.administered) void owner.refetch(); void query.refetch(); }} />;
  } else if (!ownerActive) {
    state = <EmptyState icon="ban" title="This principal is disabled">Tokens cannot be issued for a disabled principal.</EmptyState>;
  } else if (!canWriteSubject(session, subject) || !subject.principalId) {
    state = <EmptyState icon="lock" title="Token issuance unavailable">You do not have permission to issue tokens here.</EmptyState>;
  } else if ((!ttlPolicy || ttlPolicy.options.length === 0) && !initialized) {
    state = <EmptyState icon="key" title="Token issuance unavailable">Token issuance policy is unavailable. Refresh the portal and try again.</EmptyState>;
  } else if (!options || (options.executionContexts.length === 0 && !initialized)) {
    state = <EmptyState icon="shield" title="No active grants">This principal needs an active policy grant before an execution-context-bound token can be issued.</EmptyState>;
  } else {
    initializedOwner.current = ownerKey;
    return <TokenEditor key={ownerKey} subject={subject} options={options} ttlPolicy={ttlPolicy ?? null} services={params.getAll("service")} returnTo={returnTo} optionsError={query.error} retryOptions={() => { void query.refetch(); }} />;
  }
  // A blocking state unmounts the editor, so its next initialization must
  // again require a complete issuance policy and initial grant options.
  initializedOwner.current = null;
  return <PortalPage><Main label="Issue agent token"><PageHeader title="Issue agent token" back={{ href: returnTo, label: "Back" }} meta={`Owner ${subject.principalId}`} /><List>{state}</List></Main></PortalPage>;
}

function TokenEditor({ subject, options, ttlPolicy, services, returnTo, optionsError, retryOptions }: {
  subject: AccountSubject;
  options: AgentTokenOptions;
  ttlPolicy: TokenTtlPolicy | null;
  services: string[];
  returnTo: string;
  optionsError: unknown;
  retryOptions: () => void;
}) {
  const [initial] = useState(() => createAgentTokenDraft(options, ttlPolicy!, services));
  const [draft, setDraft] = useState(initial);
  const [error, setError] = useState<string | null>(null);
  const saved = useRef(false);
  const submitting = useRef(false);
  const mounted = useRef(true);
  const { session, getSession } = useSession();
  const { setModal } = useModal();
  const issuance = useTokenIssuance();
  const invalidate = usePortalInvalidation();
  const navigate = useNavigate();
  const pending = issuance.pending(subject);
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  const boundary = buildAgentTokenBoundary(draft, options);
  const currentBlocker = !ttlPolicy || ttlPolicy.options.length === 0
    ? "Token issuance policy is unavailable. Refresh the portal and try again."
    : options.executionContexts.length === 0
      ? "This principal needs an active policy grant before a token can be issued."
      : null;
  const request = ttlPolicy ? buildAgentTokenIssuance(draft, options, ttlPolicy) : { valid: false as const, errors: [currentBlocker!] };
  const permitted = canWriteSubject(session, subject);
  const blocker = useBlocker(({ currentLocation, nextLocation }) => {
    // Session changes update the cache before React can unmount this draft.
    // Sign-out and required-password redirects must bypass draft navigation.
    const current = getSession();
    return current.authenticated && !current.passwordChangeRequired && current.principal === session.principal && !saved.current
      && (submitting.current || issuance.pending(subject) || dirty)
      && (currentLocation.pathname !== nextLocation.pathname || currentLocation.search !== nextLocation.search);
  });
  // A navigation attempt may occur after submission started.
  const latestBlocker = useRef(blocker);
  latestBlocker.current = blocker;
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { if (pending && blocker.state === "blocked") blocker.reset(); }, [pending, blocker]);
  useEffect(() => {
    if (!pending) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [pending]);

  function update(next: AgentTokenDraft) {
    if (pending || submitting.current) return;
    setError(null);
    setDraft(next);
  }

  async function issue() {
    if (submitting.current || pending || !permitted || currentBlocker || !request.valid) return;
    submitting.current = true;
    setError(null);
    const viewerPrincipal = getSession().principal;
    try {
      const issued = await issuance.issue(subject, request.body);
      saved.current = true;
      // The route may unmount after a session refresh. Reveal only to the same
      // current viewer, even when that viewer's capabilities have changed.
      const current = getSession();
      if (!viewerPrincipal || !current.authenticated || current.passwordChangeRequired || current.principal !== viewerPrincipal) return;
      setModal({ type: "reveal", token: issued.token, record: issued.record, principalId: subject.principalId, options, viewerPrincipal });
      if (mounted.current) latestBlocker.current.reset?.();
      invalidate.console();
      if (subject.administered) invalidate.admin();
      navigate(tokenListPath(subject, issued.record.tokenId), { replace: true });
    } catch (failure) {
      invalidate.agentTokenOptions();
      if (mounted.current) setError(errorMessage(failure));
    } finally {
      submitting.current = false;
    }
  }

  const footer = (
    <div className="wb-draftbar" role="region" aria-label="Issue token">
      <div className="pt-validation" role="status">{pending ? "Issuing token. Wait for issuance to finish before leaving this page." : currentBlocker ?? (request.valid ? "Ready to issue. Restrictions cannot be edited after issuance." : request.errors[0])}</div>
      <div className="wb-draftbar-actions">
        <Button onClick={() => navigate(returnTo)} disabled={pending}>Cancel</Button>
        <Button variant="primary" onClick={() => void issue()} pending={pending} disabled={pending || !permitted || Boolean(currentBlocker) || !request.valid}>Issue token</Button>
      </div>
    </div>
  );
  return (
    <PortalPage>
      <Main label="Issue agent token" footer={footer} tint>
        <PageHeader title="Issue agent token" back={{ href: returnTo, label: "Back" }} meta={`Owner ${subject.principalId}`} />
        <div className="pt-editor pt-token-editor">
          <div className="pt-editor-form">
            {optionsError ? <ErrorState compact title="Couldn’t refresh token options" error={optionsError} onRetry={retryOptions} /> : null}
            {currentBlocker ? <Banner tone="warning" slim>{currentBlocker}</Banner> : null}
            <TokenDetails subject={subject} draft={draft} options={options} ttlPolicy={ttlPolicy} disabled={pending} update={update} />
            <Card title="Access" subtitle="Follow current grants or narrow this token to selected services, actions, and resources.">
              <div className="pt-card-body">
                <FieldGroup label="Access"><Seg label="Access" value={draft.accessMode} onChange={(accessMode) => update({ ...draft, accessMode })} options={[{ value: "policy", label: "Follow current grants", disabled: pending }, { value: "restricted", label: "Restrict to selected", disabled: pending }]} /></FieldGroup>
                {draft.accessMode === "policy" ? <Banner tone="info" slim>{draft.selectedExecutionContexts.length ? `The token can use everything ${subject.administered ? "this principal is" : "you are"} granted in ${draft.selectedExecutionContexts.join(", ")}, including later grant changes in those contexts.` : "Select at least one execution context."}</Banner> : <TokenAccess draft={draft} options={options} disabled={pending} update={update} />}
              </div>
            </Card>
            <FormError error={error} />
          </div>
          <aside className="pt-editor-aside" aria-label="Token preview">
            <Card title="Boundary" subtitle="Fixed restrictions on this token. Current grants are evaluated on every request."><div className="pt-card-body"><BoundarySummary draft={draft} options={options} /></div></Card>
            <Card title="Effective access" subtitle="What this token would allow now."><div className="pt-card-body">{boundary.valid ? <EffectiveAccessPanel token={boundary.boundary} {...(subject.administered ? { principalId: subject.principalId } : {})} serviceNames={serviceDisplayNames(options)} grantedActions={grantedServiceActions(options)} /> : <p className="pt-prose">{boundary.errors.join(" ")} Complete the boundary to preview access.</p>}</div></Card>
          </aside>
        </div>
      </Main>
      <ConfirmDialog open={blocker.state === "blocked" && !pending} onClose={() => blocker.reset?.()} title="Discard changes?" confirmLabel="Discard changes" cancelLabel="Keep editing" onConfirm={() => blocker.proceed?.()}><p>Your token draft has not been issued.</p></ConfirmDialog>
    </PortalPage>
  );
}

function TokenDetails({ subject, draft, options, ttlPolicy, disabled, update }: {
  subject: AccountSubject; draft: AgentTokenDraft; options: AgentTokenOptions; ttlPolicy: TokenTtlPolicy | null; disabled: boolean; update: (next: AgentTokenDraft) => void;
}) {
  const lifetimes = ttlPolicy?.options ?? [];
  const lifetimeLabel = (lifetime: string) => lifetime === "never" ? "Never expires" : lifetime;
  const lifetimeOptions = [
    ...(!lifetimes.includes(draft.lifetime) ? [{
      value: draft.lifetime,
      label: draft.lifetime ? `${lifetimeLabel(draft.lifetime)} (no longer available)` : "Choose a lifetime",
      disabled: true,
    }] : []),
    ...lifetimes.map((lifetime) => ({ value: lifetime, label: lifetimeLabel(lifetime) })),
  ];
  return (
    <Card title="Details" subtitle="Name the token and choose where and how long it may be used.">
      <div className="pt-card-body">
        <KeyValue items={[{ label: "Owner", value: <span className="wb-mono">{subject.principalId}</span> }]} />
        <Field label="Name" hint="Where the token runs, for example “laptop-cli” or “ci-nightly”."><Input value={draft.name} onChange={(event) => update({ ...draft, name: event.target.value })} required disabled={disabled} autoFocus /></Field>
        <Field label="Lifetime" hint={`Choices are configured by the broker${ttlPolicy?.maxTtl ? `; the longest finite lifetime is ${ttlPolicy.maxTtl}` : ""}.${draft.lifetime === "never" ? " This token stays active until it is revoked." : ""}`}>
          <Select value={draft.lifetime} onChange={(event) => update({ ...draft, lifetime: event.target.value })} disabled={disabled} options={lifetimeOptions} />
        </Field>
        <fieldset className="pt-fieldset" disabled={disabled}>
          <legend>Execution contexts</legend>
          <div className="pt-checks">{[...new Set([...options.executionContexts, ...draft.selectedExecutionContexts])].map((context) => (
            <Checkbox key={context} label={<span className="wb-mono">{context}</span>} aria-label={context} description={options.executionContexts.includes(context) ? undefined : "Not currently granted"} checked={draft.selectedExecutionContexts.includes(context)} onChange={(event) => update({ ...draft, selectedExecutionContexts: event.target.checked ? [...draft.selectedExecutionContexts, context] : draft.selectedExecutionContexts.filter((value) => value !== context) })} />
          ))}</div>
          <p className="pt-prose">Where the token may be used. This narrows access; it never grants it. Contexts added to your grants later are not added to the token.</p>
        </fieldset>
      </div>
    </Card>
  );
}

function TokenAccess({ draft, options, disabled, update }: { draft: AgentTokenDraft; options: AgentTokenOptions; disabled: boolean; update: (next: AgentTokenDraft) => void }) {
  const services = [...new Set([...availableAgentTokenServices(options, draft.selectedExecutionContexts), ...draft.selectedServices])];
  const names = serviceDisplayNames(options);
  function toggleService(service: string, checked: boolean) {
    if (checked) { update({ ...draft, selectedServices: [...draft.selectedServices, service] }); return; }
    const selectedActions = { ...draft.selectedActions };
    const resourceSelections = { ...draft.resourceSelections };
    delete selectedActions[service];
    delete resourceSelections[service];
    update({ ...draft, selectedServices: draft.selectedServices.filter((item) => item !== service), selectedActions, resourceSelections });
  }
  return (
    <>
      <fieldset className="pt-fieldset" disabled={disabled}>
        <legend>Services</legend>
        <div className="flex flex-wrap gap-x-5 gap-y-2">{services.map((service) => <Checkbox key={service} label={<ServiceLabel service={service} name={names.get(service)} />} aria-label={service} checked={draft.selectedServices.includes(service)} onChange={(event) => toggleService(service, event.target.checked)} />)}</div>
        {services.length === 0 ? <span className="wb-small wb-muted">No services are available in the selected contexts.</span> : null}
      </fieldset>
      {draft.selectedServices.map((service) => {
        const selected = agentTokenSelectedActions(draft.selectedActions, service);
        const actions = tokenActionChoices(options, service, draft.selectedExecutionContexts, selected);
        const resourceScoped = agentTokenServiceHasResources(options, service, selected);
        const selection = resourceScoped ? agentTokenResourceSelection(draft.resourceSelections, service) : undefined;
        return (
          <fieldset className="pt-fieldset" key={service} aria-label={`${service} token access`} disabled={disabled}>
            <legend><ServiceLabel service={service} name={names.get(service)} /> · {selected.length} selected</legend>
            <div><WriteCapability available={actions} selected={selected} /></div>
            <GrantActionSelector available={actions} selected={selected} disabled={disabled} filterLabel={`Filter ${service} actions`} onChange={(selectedActions) => update({ ...draft, selectedActions: { ...draft.selectedActions, [service]: selectedActions } })} />
            {selected.length === 0 ? <span className="pt-error">Select at least one action.</span> : null}
            {resourceScoped ? (
              <>
                <FieldGroup label="Resources" hint="Group membership stays live. Selections can only narrow current grants.">
                  <Seg label={`${service} resources`} value={selection === undefined ? "grants" : "selected"} onChange={(value) => update({ ...draft, resourceSelections: { ...draft.resourceSelections, [service]: value === "grants" ? undefined : { resourceIds: [], resourceGroupIds: [] } } })} options={[{ value: "grants", label: "Follow available grants", disabled }, { value: "selected", label: "Selected resources and groups", disabled }]} />
                </FieldGroup>
                {selection !== undefined ? <ResourcePicker selection={selection} catalog={options} disabled={disabled} onChange={(resources) => update({ ...draft, resourceSelections: { ...draft.resourceSelections, [service]: resources } })} /> : null}
              </>
            ) : <p className="pt-prose">Access is controlled by action grants; this service has no resource selections.</p>}
          </fieldset>
        );
      })}
    </>
  );
}

function BoundarySummary({ draft, options }: { draft: AgentTokenDraft; options: AgentTokenOptions }) {
  const types = useResourceTypes();
  const names = serviceDisplayNames(options);
  return (
    <>
      <KeyValue items={[{ label: "Name", value: draft.name.trim() || "Not named yet" }, { label: "Lifetime", value: draft.lifetime === "never" ? "Never expires" : draft.lifetime || "Not selected" }, { label: "Contexts", value: draft.selectedExecutionContexts.join(", ") || "None selected" }, { label: "Access", value: draft.accessMode === "policy" ? "Follow current grants" : "Restrict to selected" }]} />
      {draft.accessMode === "restricted" ? draft.selectedServices.map((service) => {
        const actions = agentTokenSelectedActions(draft.selectedActions, service);
        const hasResources = agentTokenServiceHasResources(options, service, actions);
        const selection = hasResources ? agentTokenResourceSelection(draft.resourceSelections, service) : undefined;
        return <fieldset className="pt-fieldset" key={service}><legend><ServiceLabel service={service} name={names.get(service)} /></legend><KeyValue items={[{ label: "Actions", value: <span className="wb-mono">{actions.join(", ") || "None selected"}</span> }, { label: "Resources", value: !hasResources ? ACTION_GRANT_LABEL : selection === undefined ? "Follow available grants" : resourceSelectionLabels(types, selection, options).join(", ") || "No resources selected" }]} /></fieldset>;
      }) : <p className="pt-prose">All actions and resources allowed by current grants in the selected contexts.</p>}
      <p className="pt-prose">Issue a replacement token to change its restrictions.</p>
    </>
  );
}
