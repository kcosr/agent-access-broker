import { agentTokenIssuanceDescription, eligibleTokenContexts, isAgentTokenIssuancePolicy, selfTokenIssuanceContexts, tokenIssuanceBlocker, validTokenTtlPolicy } from "../../lib/token-issuance-policy";
import { TokenEffect, TokenReadOnlyControl } from "./token-effect";
// A local token draft shares boundary validation between preview and issuance.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { useBlocker, useNavigate, useParams, useSearchParams } from "react-router";
import type { AgentTokenOptions, ResourceType, TokenTtlPolicy } from "../../types";
import { agentTokenResourceSelection, agentTokenSelectedActions, agentTokenServiceHasResources, availableAgentTokenActions, availableAgentTokenServices, errorMessage } from "../../lib/helpers";
import { canWriteSubject } from "../../lib/capabilities";
import { grantedServiceActions, serviceDisplayNames } from "../../lib/access";
import { buildAgentTokenBoundary, buildAgentTokenIssuance, createAgentTokenDraft, lifetimeLabel, tokenActionChoices, type AgentTokenDraft, type AgentTokenDraftField } from "../../lib/token-draft";
import { Banner, Button, Card, Checkbox, EmptyState, ErrorState, Field, Icon, Input, KeyValue, List, Main, PageHeader, Seg, Select, SkeletonBlock } from "../../workbench";
import { DiscardChangesDialog } from "../../components/discard-changes-dialog";
import { EffectiveAccessPanel } from "../../components/effective-access";
import { ACTION_COLUMNS_HINT, GrantActionSelector } from "../../components/grant-actions";
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
/** The element an issue's footer link reveals; service sections are cards. */
const fieldElementId = (field: AgentTokenDraftField) => `token-${field.replace(":", "-")}`;
const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

export function TokenEditorPage() {
  const { session, refreshSession } = useSession();
  const { principalId } = useParams();
  const [params] = useSearchParams();
  const subject: AccountSubject = { administered: principalId !== undefined, principalId: principalId ?? session.principal ?? "" };

  const initializedOwner = useRef<string | null>(null);
  const ownerKey = `${subject.administered}:${subject.principalId}:${params.toString()}`;
  const initialized = initializedOwner.current === ownerKey;
  const [initialRefresh, setInitialRefresh] = useState<{ key: string; ready: boolean; error?: unknown }>({ key: "", ready: false });
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let active = true;
    setInitialRefresh({ key: ownerKey, ready: false });
    void refreshSession().then(() => { if (active) setInitialRefresh({ key: ownerKey, ready: true }); }, (error: unknown) => { if (active) setInitialRefresh({ key: ownerKey, ready: false, error }); });
    return () => { active = false; };
  }, [ownerKey, refreshSession, retry]);
  const owner = useAdminPrincipal(subject.principalId, subject.administered);
  const ownerActive = !subject.administered || owner.data?.status === "active";
  const { query, options } = useAgentTokenOptions(subject, ownerActive, true);
  const suppliedTtl = subject.administered ? session.tokenIssuancePolicy?.administered?.agentInvoke : session.tokenIssuancePolicy?.selfAgentInvoke;
  const ttlPolicy = validTokenTtlPolicy(suppliedTtl) ? suppliedTtl : null;
  const explicitReturn = portalReturnTo(params.get("returnTo"));
  const returnTo = explicitReturn ?? tokenListPath(subject);
  const back = { href: returnTo, label: explicitReturn ? "Back" : "Tokens" };
  const ownerName = owner.data?.displayName;
  const meta = subject.administered
    ? `For ${ownerName && ownerName !== subject.principalId ? `${ownerName} · ` : ""}${subject.principalId}`
    : "Agent tokens let a CLI or MCP client act for you, within the limits you set here.";
  const initialPolicyError = initialRefresh.error ?? query.error;
  const initialReady = initialRefresh.key === ownerKey && initialRefresh.ready && query.isFetchedAfterMount && !query.isFetching && !query.isPlaceholderData && query.isSuccess;
  let state: ReactNode;
  if (!canWriteSubject(session, subject) || !subject.principalId) {
    state = <EmptyState icon="lock" title="Token issuance unavailable">You do not have permission to issue tokens here.</EmptyState>;
  } else if (!initialized && initialPolicyError) {
    state = <ErrorState title="Couldn’t load token issuance policy" error={initialPolicyError} onRetry={() => { setRetry((value) => value + 1); void query.refetch(); }} />;
  } else if (!initialized && ownerActive && !initialReady) {
    state = <SkeletonBlock lines={8} label="Loading token options and issuance policy" />;
  } else if ((subject.administered && !owner.data && owner.isPending) || (ownerActive && !options && query.isPending)) {
    state = <SkeletonBlock lines={8} label="Loading token options" />;
  } else if ((subject.administered && !owner.data && owner.error) || (ownerActive && !options && query.error)) {
    state = <ErrorState title="Couldn’t load token options" error={owner.error ?? query.error} onRetry={() => { if (subject.administered) void owner.refetch(); void query.refetch(); }} />;
  } else if (!ownerActive) {
    state = <EmptyState icon="ban" title="This principal is disabled">Tokens cannot be issued for a disabled principal.</EmptyState>;
  } else if (!canWriteSubject(session, subject) || !subject.principalId) {
    state = <EmptyState icon="lock" title="Token issuance unavailable">You do not have permission to issue tokens here.</EmptyState>;
  } else if ((!ttlPolicy || ttlPolicy.options.length === 0) && !initialized) {
    state = <EmptyState icon="key" title="Token issuance unavailable">Token issuance policy is unavailable.</EmptyState>;
  } else if (!options || (options.executionContexts.length === 0 && !initialized)) {
    state = <EmptyState icon="shield" title="No active grants">{subject.administered ? "This principal needs" : "You need"} an active policy grant before an execution-context-bound token can be issued.</EmptyState>;
  } else if (!initialized && tokenIssuanceBlocker(session, subject.administered, options)) {
    state = <EmptyState icon="key" title="Token issuance unavailable">{tokenIssuanceBlocker(session, subject.administered, options)}</EmptyState>;
  } else {
    initializedOwner.current = ownerKey;
    return <TokenEditor key={ownerKey} subject={subject} options={options} ttlPolicy={ttlPolicy ?? null} services={params.getAll("service")} returnTo={returnTo} header={<PageHeader title="Issue agent token" back={back} meta={meta} />} optionsError={query.error} optionsRefreshing={query.isFetching} retryOptions={() => { void query.refetch(); }} />;
  }
  // A blocking state unmounts the editor, so its next initialization must
  // again require a complete issuance policy and initial grant options.
  initializedOwner.current = null;
  return <PortalPage><Main label="Issue agent token"><PageHeader title="Issue agent token" back={back} meta={meta} /><List>{state}</List></Main></PortalPage>;
}

function TokenEditor({ subject, options, ttlPolicy, services, returnTo, header, optionsError, optionsRefreshing, retryOptions }: {
  subject: AccountSubject;
  options: AgentTokenOptions;
  ttlPolicy: TokenTtlPolicy | null;
  services: string[];
  returnTo: string;
  header: ReactNode;
  optionsError: unknown;
  optionsRefreshing: boolean;
  retryOptions: () => void;
}) {
  const { session, getSession, sessionRefreshError, retryingSession, retrySession } = useSession();
  const [initial] = useState(() => createAgentTokenDraft(options, ttlPolicy!, services, eligibleTokenContexts(session, subject.administered, options)));
  const [draft, setDraft] = useState(initial);
  const [error, setError] = useState<string | null>(null);
  // Presentation only: collapsing a service never changes the draft.
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(() => new Set());
  const saved = useRef(false);
  const submitting = useRef(false);
  const mounted = useRef(true);
  const { setModal } = useModal();
  const issuance = useTokenIssuance();
  const invalidate = usePortalInvalidation();
  const navigate = useNavigate();
  const pending = issuance.pending(subject);
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  const boundary = buildAgentTokenBoundary(draft, options);
  const policyBlocker = tokenIssuanceBlocker(session, subject.administered, options);
  const eligibleContexts = eligibleTokenContexts(session, subject.administered, options);
  const contextModes = selfTokenIssuanceContexts(session, options);
  const readOnlyRequired = !subject.administered && draft.selectedExecutionContexts.some((context) => contextModes?.get(context) === "read_only");
  const staleContexts = draft.selectedExecutionContexts.some((context) => !eligibleContexts.includes(context));
  const currentBlocker = optionsError || sessionRefreshError
    ? "Token issuance policy could not be refreshed."
    : optionsRefreshing || retryingSession
      ? "Refreshing token issuance policy."
      : policyBlocker ?? (staleContexts ? "Remove execution contexts that are no longer granted or permitted for personal issuance." : null) ?? (readOnlyRequired && !draft.readOnly
        ? "Your account now requires read-only tokens. Apply the read-only restriction to continue."
        : options.executionContexts.length === 0
          ? `${subject.administered ? "This principal needs" : "You need"} an active policy grant before a token can be issued.`
          : null);
  const request = ttlPolicy ? buildAgentTokenIssuance(draft, options, ttlPolicy) : { valid: false as const, issues: [] };
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

  function setServiceOpen(service: string, open: boolean) {
    setCollapsed((current) => {
      const next = new Set(current);
      if (open) next.delete(service);
      else next.add(service);
      return next;
    });
  }

  /** Scrolls to an issue's section (expanding a collapsed service) and focuses its first control. */
  function reveal(field: AgentTokenDraftField) {
    if (field.startsWith("service:")) setServiceOpen(field.slice("service:".length), true);
    requestAnimationFrame(() => {
      const element = document.getElementById(fieldElementId(field));
      const service = field.startsWith("service:");
      // Fields stay in view with their card's heading; a service card starts at its own.
      element?.scrollIntoView({ block: service ? "start" : "center", behavior: "smooth" });
      // A service issue is about its actions: the first one, or the filter
      // when it hides them all.
      const actions = service ? document.getElementById(`${fieldElementId(field)}-body`)?.querySelector(".pt-action-selector") : null;
      const target = actions
        ? actions.querySelector<HTMLElement>(".pt-action-list input[type=checkbox]:not(:disabled)") ?? actions.querySelector<HTMLElement>("input[type=search]")
        : element?.querySelector<HTMLElement>("input:not(:disabled), select:not(:disabled), button:not(:disabled)");
      target?.focus({ preventScroll: true });
    });
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
      void invalidate.session();
      if (mounted.current) setError(errorMessage(failure));
    } finally {
      submitting.current = false;
    }
  }

  const issues = request.valid ? [] : request.issues;
  const status = pending ? (
    <span>Issuing token. Wait for issuance to finish before leaving this page.</span>
  ) : currentBlocker ? (
    <><Icon name="alert-circle" /><span>{currentBlocker}</span></>
  ) : issues.length ? (
    <>
      <Icon name="alert-circle" />
      <span><b>{plural(issues.length, "issue")}</b> · <button type="button" className="wb-link" onClick={() => reveal(issues[0]!.field)}>{issues[0]!.message}</button></span>
    </>
  ) : (
    <><Icon name="circle-check" /><span>Ready to issue. Restrictions cannot be edited after issuance.</span></>
  );
  // The warning tone is kept for problems to fix.
  const attention = !pending && (Boolean(currentBlocker) || issues.length > 0);
  const footer = (
    <div className={`wb-draftbar pt-token-draftbar${attention ? "" : " wb-draftbar--neutral"}`} role="region" aria-label="Issue token">
      <div className="pt-validation" role="status">{status}</div>
      <div className="wb-draftbar-actions">
        <Button onClick={() => navigate(returnTo)} disabled={pending}>Cancel</Button>
        <Button variant="primary" onClick={() => void issue()} pending={pending} disabled={pending || !permitted || Boolean(currentBlocker) || !request.valid}>Issue token</Button>
      </div>
    </div>
  );
  return (
    <PortalPage>
      <Main label="Issue agent token" footer={footer} tint>
        {header}
        <div className="pt-editor pt-token-editor">
          <div className="pt-token-form">
            {optionsError ? <ErrorState compact title="Couldn’t refresh token options" error={optionsError} onRetry={retryOptions} /> : null}
            {sessionRefreshError ? <ErrorState compact title="Couldn’t refresh token issuance policy" error={sessionRefreshError} onRetry={retrySession} /> : null}
            {currentBlocker ? <Banner tone="warning" slim>{currentBlocker}</Banner> : null}
            <TokenDetails draft={draft} fixedSingle={!subject.administered} eligibleContexts={eligibleContexts} options={options} ttlPolicy={ttlPolicy} disabled={pending} update={update} />
            <Card title="Token restriction">
              <div className="pt-card-body">
                <TokenReadOnlyControl readOnly={draft.readOnly} required={readOnlyRequired} disabled={pending || Boolean(policyBlocker)} onChange={(readOnly) => update({ ...draft, readOnly })} />
                {subject.administered ? <p className="pt-prose">{isAgentTokenIssuancePolicy(options.agentTokenIssuancePolicy) ? `Owner’s self-issuance policy: ${agentTokenIssuanceDescription(options.agentTokenIssuancePolicy)}.` : "Owner issuance policy unavailable."} Administrative issuance can choose either restriction.</p> : null}
              </div>
            </Card>
            <TokenAccess subject={subject} draft={draft} options={options} disabled={pending} update={update} collapsed={collapsed} setServiceOpen={setServiceOpen} />
            <FormError error={error} />
          </div>
          <aside className="pt-token-summary" aria-label="Token summary">
            <Card title="Summary"><TokenSummary draft={draft} options={options} reveal={reveal} /></Card>
          </aside>
          <div className="pt-token-preview">
            <Card title="Effective access" subtitle="What this token would allow now.">
              <div className="pt-card-body">
                {boundary.valid ? (
                  <EffectiveAccessPanel token={boundary.boundary} {...(subject.administered ? { principalId: subject.principalId } : {})} serviceNames={serviceDisplayNames(options)} grantedActions={grantedServiceActions(options)} />
                ) : (
                  <p className="pt-prose">Complete the boundary to preview access. {boundary.issues[0]!.message}</p>
                )}
              </div>
            </Card>
          </div>
        </div>
      </Main>
      <DiscardChangesDialog blocker={blocker} open={blocker.state === "blocked" && !pending}><p>Your token draft has not been issued.</p></DiscardChangesDialog>
    </PortalPage>
  );
}

function TokenDetails({ draft, options, eligibleContexts, fixedSingle, ttlPolicy, disabled, update }: {
  draft: AgentTokenDraft; options: AgentTokenOptions; eligibleContexts: string[]; fixedSingle: boolean; ttlPolicy: TokenTtlPolicy | null; disabled: boolean; update: (next: AgentTokenDraft) => void;
}) {
  const lifetimes = ttlPolicy?.options ?? [];
  const lifetimeOptions = [
    ...(!lifetimes.includes(draft.lifetime) ? [{
      value: draft.lifetime,
      label: draft.lifetime ? `${lifetimeLabel(draft.lifetime)} (no longer available)` : "Choose a lifetime",
      disabled: true,
    }] : []),
    ...lifetimes.map((lifetime) => ({ value: lifetime, label: lifetimeLabel(lifetime) })),
  ];
  return (
    <Card title="Details" subtitle="Name the token and choose how long and where it may be used.">
      <div className="pt-card-body">
        <div className="pt-token-details-row">
          <div id={fieldElementId("name")}>
            <Field label="Name" hint="Where the token runs, for example “laptop-cli” or “ci-nightly”."><Input value={draft.name} onChange={(event) => update({ ...draft, name: event.target.value })} required disabled={disabled} autoFocus /></Field>
          </div>
          <div id={fieldElementId("lifetime")}>
            <Field label="Lifetime" hint={`Set by the broker${ttlPolicy?.maxTtl ? `; the longest finite lifetime is ${lifetimeLabel(ttlPolicy.maxTtl)}` : ""}.${draft.lifetime === "never" ? " This token stays active until it is revoked." : ""}`}>
              <Select value={draft.lifetime} onChange={(event) => update({ ...draft, lifetime: event.target.value })} disabled={disabled} options={lifetimeOptions} />
            </Field>
          </div>
        </div>
        <fieldset className="pt-fieldset pt-fieldset--plain" id={fieldElementId("contexts")} disabled={disabled}>
          <legend>Execution contexts</legend>
          {fixedSingle && eligibleContexts.length === 1 && draft.selectedExecutionContexts.length === 1 && draft.selectedExecutionContexts[0] === eligibleContexts[0] ? <p className="wb-mono">{eligibleContexts[0]}</p> : <div className="pt-inline-checks">{[...new Set([...eligibleContexts, ...draft.selectedExecutionContexts])].map((context) => (
            <Checkbox key={context} label={<span className="wb-mono">{context}</span>} aria-label={context} description={!options.executionContexts.includes(context) ? "No longer granted" : !eligibleContexts.includes(context) ? "No longer permitted for personal issuance" : undefined} checked={draft.selectedExecutionContexts.includes(context)} onChange={(event) => update({ ...draft, selectedExecutionContexts: event.target.checked ? [...draft.selectedExecutionContexts, context] : draft.selectedExecutionContexts.filter((value) => value !== context) })} />
          ))}</div>}
          <p className="wb-field-hint">Where the token may be used. This narrows access and never grants it; contexts granted later are not added to the token.</p>
        </fieldset>
      </div>
    </Card>
  );
}

/** The resource types a service's actions use, or undefined when the service is no longer offered. */
function serviceResourceTypes(options: AgentTokenOptions, service: string): ResourceType[] | undefined {
  const option = options.services.find((item) => item.service === service);
  return option ? [...new Set(option.actions.flatMap((action) => action.resourceType === null ? [] : [action.resourceType]))] : undefined;
}

/** A selected service's action and resource counts for its card and the summary. */
function serviceSelection(draft: AgentTokenDraft, options: AgentTokenOptions, service: string) {
  const selected = agentTokenSelectedActions(draft.selectedActions, service);
  const actions = tokenActionChoices(options, service, draft.selectedExecutionContexts, selected, draft.readOnly);
  const resourceScoped = agentTokenServiceHasResources(options, service, selected);
  const selection = resourceScoped ? agentTokenResourceSelection(draft.resourceSelections, service) : undefined;
  const chosen = selection ? [selection.resourceIds.length ? plural(selection.resourceIds.length, "resource") : null, selection.resourceGroupIds.length ? plural(selection.resourceGroupIds.length, "group") : null].filter(Boolean).join(", ") : "";
  const resources = !resourceScoped ? "no resource selection" : selection === undefined ? "all granted resources" : chosen || "no resources selected";
  return { selected, actions, resourceScoped, selection, summary: `${selected.length} of ${plural(actions.length, "action")} · ${resources}` };
}

function TokenAccess({ subject, draft, options, disabled, update, collapsed, setServiceOpen }: {
  subject: AccountSubject;
  draft: AgentTokenDraft;
  options: AgentTokenOptions;
  disabled: boolean;
  update: (next: AgentTokenDraft) => void;
  collapsed: ReadonlySet<string>;
  setServiceOpen: (service: string, open: boolean) => void;
}) {
  const services = [...new Set([...availableAgentTokenServices(options, draft.selectedExecutionContexts), ...draft.selectedServices])];
  const names = serviceDisplayNames(options);
  function toggleService(service: string, checked: boolean) {
    if (checked) {
      setServiceOpen(service, true);
      update({ ...draft, selectedServices: [...draft.selectedServices, service] });
      return;
    }
    const selectedActions = { ...draft.selectedActions };
    const resourceSelections = { ...draft.resourceSelections };
    delete selectedActions[service];
    delete resourceSelections[service];
    update({ ...draft, selectedServices: draft.selectedServices.filter((item) => item !== service), selectedActions, resourceSelections });
  }
  return (
    <>
      <Card title="Access" subtitle="Follow current grants, or limit this token to selected services, actions, and resources.">
        <div className="pt-card-body">
          <Seg className="self-start" label="Access" value={draft.accessMode} onChange={(accessMode) => update({ ...draft, accessMode })} options={[{ value: "policy", label: "Follow current grants", disabled }, { value: "restricted", label: "Restrict to selected", disabled }]} />
          {draft.accessMode === "policy" ? (
            <p className="pt-prose">{draft.selectedExecutionContexts.length ? `The token can use ${draft.readOnly ? "read actions" : "everything"} ${subject.administered ? "this principal is" : "you are"} granted in ${draft.selectedExecutionContexts.join(", ")}, including later grant changes in those contexts.` : "Select at least one execution context."}</p>
          ) : (
            <fieldset className="pt-fieldset pt-fieldset--plain" id={fieldElementId("services")} disabled={disabled}>
              <legend>Services</legend>
              <div className="pt-token-services">{services.map((service) => {
                const name = names.get(service);
                const count = availableAgentTokenActions(options, service, draft.selectedExecutionContexts).length;
                return (
                  <Checkbox
                    key={service}
                    aria-label={service}
                    label={<span title={service}>{name && name !== service ? name : <span className="wb-mono">{service}</span>}</span>}
                    description={options.services.some((option) => option.service === service) ? plural(count, "action") : "Not currently granted"}
                    checked={draft.selectedServices.includes(service)}
                    onChange={(event) => toggleService(service, event.target.checked)}
                  />
                );
              })}</div>
              {services.length === 0 ? <span className="wb-small wb-muted">No services are available in the selected contexts.</span> : null}
              {draft.selectedServices.length ? <p className="wb-field-hint">{ACTION_COLUMNS_HINT}</p> : null}
            </fieldset>
          )}
        </div>
      </Card>
      {draft.accessMode === "restricted" ? draft.selectedServices.map((service) => (
        <TokenServiceCard key={service} service={service} name={names.get(service)} draft={draft} options={options} disabled={disabled} update={update} open={!collapsed.has(service)} setOpen={(open) => setServiceOpen(service, open)} />
      )) : null}
    </>
  );
}

function TokenServiceCard({ service, name, draft, options, disabled, update, open, setOpen }: {
  service: string;
  name: string | undefined;
  draft: AgentTokenDraft;
  options: AgentTokenOptions;
  disabled: boolean;
  update: (next: AgentTokenDraft) => void;
  open: boolean;
  setOpen: (open: boolean) => void;
}) {
  const bodyId = `${fieldElementId(`service:${service}`)}-body`;
  const { selected, actions, resourceScoped, selection, summary } = serviceSelection(draft, options, service);
  return (
    <Card
      id={fieldElementId(`service:${service}`)}
      className="pt-token-service"
      title={<ServiceLabel service={service} name={name} />}
      subtitle={summary}
      actions={
        <>
          <Button size="sm" variant="ghost" icon={open ? "chevron-up" : "chevron-down"} aria-expanded={open} aria-controls={bodyId} aria-label={`${open ? "Collapse" : "Expand"} ${name ?? service}`} onClick={() => setOpen(!open)}>{open ? "Collapse" : "Expand"}</Button>
        </>
      }
    >
      {open ? (
        <fieldset className="pt-fieldset--bare pt-card-body" id={bodyId} aria-label={`${service} token access`} disabled={disabled}>
          <GrantActionSelector available={actions} selected={selected} disabled={disabled} hint={false} filterLabel={`Filter ${service} actions`} onChange={(selectedActions) => update({ ...draft, selectedActions: { ...draft.selectedActions, [service]: selectedActions } })} />
          {selected.length === 0 ? <p className="wb-small wb-muted m-0">Select at least one action.</p> : null}
          {resourceScoped ? (
            <>
              <FieldGroup label="Resources" hint="Group membership stays live. Selections can only narrow current grants.">
                <Seg label={`${service} resources`} value={selection === undefined ? "grants" : "selected"} onChange={(value) => update({ ...draft, resourceSelections: { ...draft.resourceSelections, [service]: value === "grants" ? undefined : { resourceIds: [], resourceGroupIds: [] } } })} options={[{ value: "grants", label: "Follow available grants", disabled }, { value: "selected", label: "Selected resources and groups", disabled }]} />
              </FieldGroup>
              {selection !== undefined ? <ResourcePicker selection={selection} catalog={options} resourceTypes={serviceResourceTypes(options, service)} disabled={disabled} onChange={(resources) => update({ ...draft, resourceSelections: { ...draft.resourceSelections, [service]: resources } })} /> : null}
            </>
          ) : <p className="pt-prose">Access is controlled by action grants; this service has no resource selections.</p>}
        </fieldset>
      ) : null}
    </Card>
  );
}

function TokenSummary({ draft, options, reveal }: { draft: AgentTokenDraft; options: AgentTokenOptions; reveal: (field: AgentTokenDraftField) => void }) {
  const names = serviceDisplayNames(options);
  const restricted = draft.accessMode === "restricted";
  const muted = (text: string) => <span className="wb-muted">{text}</span>;
  return (
    <div className="pt-card-body">
      <KeyValue labelWidth={84} items={[
        { label: "Restriction", value: <TokenEffect readOnly={draft.readOnly} quiet /> },
        { label: "Name", value: draft.name.trim() || muted("Not named yet") },
        { label: "Lifetime", value: draft.lifetime ? lifetimeLabel(draft.lifetime) : muted("Not selected") },
        { label: "Contexts", value: draft.selectedExecutionContexts.length ? <span className="wb-mono">{draft.selectedExecutionContexts.join(", ")}</span> : muted("None selected") },
        { label: "Access", value: !restricted ? "Follows current grants" : draft.selectedServices.length ? plural(draft.selectedServices.length, "service") : muted("No services selected") },
      ]} />
      {restricted && draft.selectedServices.length ? (
        <ul className="pt-token-summary-services">
          {draft.selectedServices.map((service) => {
            const { selected, summary } = serviceSelection(draft, options, service);
            return (
              <li key={service}>
                <button type="button" className="pt-token-summary-service" onClick={() => reveal(`service:${service}`)}>
                  <span className="pt-token-summary-name">{names.get(service) ?? service}</span>
                  <Icon name="chevron-right" />
                  <span className={selected.length ? "pt-token-summary-detail" : "pt-token-summary-detail is-invalid"}>{summary}</span>
                </button>
              </li>
            );
          })}
        </ul>
      ) : null}
      <p className="pt-prose">Restrictions are fixed once issued; issue a replacement token to change them.</p>
    </div>
  );
}
