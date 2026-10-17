import { canWritePolicies } from "../../lib/capabilities";
// Admin › Policies › grant editor: a full page with a section index, live
// effective-access and JSON previews, and a sticky Save/Cancel bar with a
// validation summary. Handles create, edit, duplicate, and read-only inspect.
import { useDeferredValue, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { useBlocker, useNavigate, useParams, useSearchParams } from "react-router";
import type { PolicySubjectKind, PolicyGrantDraft } from "../../app-types";
import type { PolicyCatalogResult, PolicyValidationMessage } from "../../types";
import {
  buildPolicySubject,
  commonCredentialModes,
  commonSupportedCredentialModes,
  canGrantService,
  errorMessage,
  policyGrantBody,
  policyGrantDraft,
  policyGrantDraftForSubject,
  policyService,
  policyServiceLocked,
  policySubjectDisplayLabel,
  principalIdentityLabel,
  uniqueSortedOptions
} from "../../lib/helpers";
import {
  Banner,
  Button,
  Card,
  Checkbox,
  Chip,
  Combobox,
  EmptyState,
  ErrorState,
  Field,
  Icon,
  Input,
  List,
  Main,
  PageHeader,
  Seg,
  Select,
  Sidebar,
  SidebarItem,
  SidebarSection,
  SkeletonBlock,
  Textarea
} from "../../workbench";
import { FieldGroup, FormError } from "../../components/form";
import { DiscardChangesDialog } from "../../components/discard-changes-dialog";
import { EffectiveAccessPanel } from "../../components/effective-access";
import { GrantActionSelector, WriteCapability } from "../../components/grant-actions";
import { COMMAND_CHECK_CAVEAT } from "../../lib/import-command";
import { GrantResourcePicker } from "../../components/resource-picker";
import { paths, portalReturnTo } from "../../app/paths";
import { useSession } from "../../app/session";
import { PortalPage } from "../../app/top-bar";
import { usePolicyCatalog, usePolicyGrants, usePolicyStatus } from "../../data/queries";
import { usePolicyActions } from "../../mutations/policy";

type SectionId = "subjects" | "service" | "contexts" | "resources" | "settings";

const SECTIONS: { id: SectionId; label: string; icon: "users" | "package" | "globe" | "database" | "sliders" }[] = [
  { id: "subjects", label: "Subjects", icon: "users" },
  { id: "service", label: "Service and actions", icon: "package" },
  { id: "contexts", label: "Execution contexts", icon: "globe" },
  { id: "resources", label: "Resources", icon: "database" },
  { id: "settings", label: "Settings", icon: "sliders" }
];

const FIELD_SECTION: Record<string, SectionId> = {
  subjects: "subjects",
  service: "service",
  actions: "service",
  credentialMode: "service",
  executionContexts: "contexts",
  resources: "resources"
};

const sectionOf = (message: PolicyValidationMessage): SectionId => FIELD_SECTION[message.field] ?? "settings";
const sectionElementId = (id: SectionId) => `grant-${id}`;

export function GrantEditorPage() {
  const { session } = useSession();
  const { grantRef } = useParams();
  const [params] = useSearchParams();
  const catalogQuery = usePolicyCatalog();
  const grantsQuery = usePolicyGrants();
  const statusQuery = usePolicyStatus();
  const fromRef = params.get("from");
  const subject = params.get("subject");
  const returnTo = portalReturnTo(params.get("returnTo"));
  const loading = catalogQuery.isPending || grantsQuery.isPending || statusQuery.isPending;
  const error = catalogQuery.error ?? grantsQuery.error ?? statusQuery.error;
  const catalog = catalogQuery.data ?? null;
  const source = grantRef ?? fromRef;
  const grant = source ? grantsQuery.data?.find((item) => item.grantRef === source) ?? null : null;

  let body: ReactNode;
  if (loading) {
    body = (
      <Main label="Grant editor">
        <List>
          <SkeletonBlock lines={8} />
        </List>
      </Main>
    );
  } else if (error) {
    body = (
      <Main label="Grant editor">
        <List>
          <ErrorState error={error} onRetry={() => void Promise.all([catalogQuery.refetch(), grantsQuery.refetch(), statusQuery.refetch()])} />
        </List>
      </Main>
    );
  } else if (source && !grant) {
    body = (
      <Main label="Grant editor">
        <List>
          <EmptyState
            icon="shield"
            title="Grant not found"
            actions={
              <Button href={paths.policies()} icon="arrow-left">
                Back to Policies
              </Button>
            }
          >
            {source} does not exist or is outside the services you manage.
          </EmptyState>
        </List>
      </Main>
    );
  } else {
    const initial = grantRef && grant
      ? policyGrantDraft(catalog, grant.writable && canWritePolicies(session, grant.service) ? "edit" : "inspect", grant)
      : fromRef && grant
        ? policyGrantDraft(catalog, "duplicate", grant)
        : subject
          ? policyGrantDraftForSubject(catalog, subject)
          : policyGrantDraft(catalog, "create");
    return (
      <GrantEditor
        key={`${grantRef ?? ""}|${fromRef ?? ""}|${subject ?? ""}`}
        initial={initial}
        catalog={catalog}
        writableAuthority={Boolean(statusQuery.data?.writable)}
        policyAuthority={statusQuery.data?.policyAuthority ?? "unknown"}
        returnTo={returnTo}
      />
    );
  }
  return <PortalPage>{body}</PortalPage>;
}

function GrantEditor({
  initial,
  catalog,
  writableAuthority,
  policyAuthority,
  returnTo
}: {
  initial: PolicyGrantDraft;
  catalog: PolicyCatalogResult | null;
  writableAuthority: boolean;
  policyAuthority: string;
  returnTo: string | null;
}) {
  const { session } = useSession();
  const navigate = useNavigate();
  const policy = usePolicyActions();
  const [draft, setDraft] = useState(initial);
  const [serverMessages, setServerMessages] = useState<PolicyValidationMessage[]>([]);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  // A ref, so the navigation right after a save is never blocked by a stale blocker.
  const saved = useRef(false);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const current = useSectionSpy(scrollRef);
  const readonly = !canWritePolicies(session, draft.service) || draft.mode === "inspect" || !draft.writable || !writableAuthority;
  const lockService = policyServiceLocked(session, draft.mode);
  const service = policyService(catalog, draft.service);
  const { body, messages, preview } = policyGrantBody(draft, catalog);
  const shownMessages = serverMessages.length ? serverMessages : messages;
  const dirty = useMemo(() => JSON.stringify({ ...draft, validationMessages: [] }) !== JSON.stringify({ ...initial, validationMessages: [] }), [draft, initial]);
  const blocker = useBlocker(({ currentLocation, nextLocation }) => dirty && !saved.current && !readonly && currentLocation.pathname !== nextLocation.pathname);
  const title = draft.mode === "edit" ? "Edit grant" : draft.mode === "duplicate" ? "Duplicate grant" : draft.mode === "inspect" ? "Grant" : "Create grant";
  const exit = (grantRef?: string) => navigate(returnTo ?? (grantRef ? paths.grant(grantRef) : paths.policies()));

  function update(next: PolicyGrantDraft) {
    setServerMessages([]);
    setSaveError(null);
    setDraft(next);
  }

  async function save() {
    if (readonly) return;
    setSaving(true);
    setSaveError(null);
    try {
      const result = await policy.save(draft, catalog);
      if (!result.saved) {
        setServerMessages(result.messages);
        scrollTo(sectionOf(result.messages[0] ?? { field: "", code: "", message: "" }));
        return;
      }
      saved.current = true;
      exit(result.grantRef);
    } catch (failure) {
      setSaveError(errorMessage(failure));
    } finally {
      setSaving(false);
    }
  }

  const sidebar = (
    <Sidebar label="Grant sections">
      <SidebarSection title="Sections">
        {SECTIONS.filter((section) => section.id !== "resources" || !service || Object.keys(service.resourceScopes).length > 0).map((section) => {
          const issues = shownMessages.filter((message) => sectionOf(message) === section.id).length;
          return (
            <SidebarItem
              key={section.id}
              icon={section.icon}
              label={section.label}
              current={current === section.id}
              onClick={() => scrollTo(section.id)}
              trailing={issues > 0 ? <Icon name="alert-circle" title={`${issues} ${issues === 1 ? "issue" : "issues"}`} /> : undefined}
            />
          );
        })}
      </SidebarSection>
    </Sidebar>
  );

  // The warning tone is kept for problems to fix.
  const attention = !readonly && (shownMessages.length > 0 || Boolean(saveError));
  const footer = (
    <div className={attention ? "wb-draftbar" : "wb-draftbar wb-draftbar--neutral"} role="region" aria-label="Save grant">
      {readonly ? (
        <div className="pt-validation">
          <Icon name="lock" />
          <span>{draft.writable && !writableAuthority ? `Read-only while policy authority is ${policyAuthority}.` : "This grant is read-only."}</span>
        </div>
      ) : shownMessages.length ? (
        <div className="pt-validation" role="status">
          <Icon name="alert-circle" />
          <span>
            <b>
              {shownMessages.length} {shownMessages.length === 1 ? "issue" : "issues"}
            </b>{" "}
            · <button type="button" className="wb-link" onClick={() => scrollTo(sectionOf(shownMessages[0]!))}>{shownMessages[0]!.message}</button>
          </span>
        </div>
      ) : (
        <div className="pt-validation" role="status">
          <Icon name="circle-check" />
          <span>{dirty || draft.mode !== "edit" ? "Ready to save. The broker validates the grant again when you save." : "No changes."}</span>
        </div>
      )}
      <div className="wb-draftbar-actions">
        {saveError ? <span className="pt-error">{saveError}</span> : null}
        <Button onClick={() => exit(draft.grantRef)} disabled={saving}>
          {readonly ? "Back" : "Cancel"}
        </Button>
        {!readonly ? (
          <Button variant="primary" onClick={() => void save()} disabled={!body || (draft.mode === "edit" && !dirty)} pending={saving}>
            {draft.mode === "edit" ? "Save grant" : "Create grant"}
          </Button>
        ) : null}
      </div>
    </div>
  );

  return (
    <PortalPage sidebar={sidebar}>
      <Main label={title} footer={footer} scrollRef={scrollRef} tint>
        <PageHeader
          back={{ href: returnTo ?? paths.policies(), label: returnTo ? "Back" : "Policies" }}
          title={draft.mode === "edit" || draft.mode === "inspect" ? <span className="pt-title-mono">{draft.grantRef}</span> : title}
          meta={
            <>
              <span>{title}</span>
              {draft.grantRef ? (
                <>
                  <span className="wb-sep">·</span>
                  <span className="wb-num">version {draft.version ?? "read-only"}</span>
                </>
              ) : null}
              <span className="wb-sep">·</span>
              <span>policy authority {policyAuthority}</span>
            </>
          }
        />
        <div className="pt-editor">
          <div className="pt-editor-form">
            {readonly ? (
              <Banner tone="info" slim>
                {draft.writable && !writableAuthority
                  ? `Policy grants are read-only while policy authority is ${policyAuthority}.`
                  : "This grant comes from the broker configuration and cannot be edited here."}
              </Banner>
            ) : null}
            <SubjectsSection draft={draft} catalog={catalog} readonly={readonly} update={update} messages={shownMessages} />
            <ServiceSection draft={draft} catalog={catalog} readonly={readonly} lockService={lockService} update={update} messages={shownMessages} />
            <ContextsSection draft={draft} catalog={catalog} readonly={readonly} update={update} messages={shownMessages} />
            {!service || Object.keys(service.resourceScopes).length > 0 ? (
              <Card title="Resources" subtitle="Which resource entries and groups the actions may reach." id={sectionElementId("resources")}>
                <div className="pt-card-body">
                  <GrantResourcePicker
                    selection={draft.resources}
                    catalog={catalog ?? { resources: [], resourceGroups: [] }}
                    service={service}
                    executionContexts={draft.executionContexts}
                    onChange={(resources) => update({ ...draft, resources })}
                    disabled={readonly}
                  />
                  {service?.actions.some((action) => draft.actions.includes(action.action) && Object.keys(action.requiredScopes).length > 1) ? <p className="pt-prose">All required scopes must be covered by this one grant. Selecting several values of each resource type permits every combination within this grant. Use separate grants to restrict specific pairings.</p> : null}
                  <SectionMessages messages={shownMessages} section="resources" />
                </div>
              </Card>
            ) : null}
            <SettingsSection draft={draft} readonly={readonly} update={update} messages={shownMessages} />
          </div>
          <aside className="pt-editor-aside" aria-label="Preview">
            <Card title="Effective access" subtitle="What the grant allows now, as the broker evaluates it.">
              <LivePreview draft={draft} />
            </Card>
            <Card title="Request body" subtitle="Sent to the policy API on save.">
              <pre className="wb-code">{preview}</pre>
            </Card>
          </aside>
        </div>
      </Main>
      <DiscardChangesDialog blocker={blocker}>
        <p>Your changes to this grant have not been saved.</p>
      </DiscardChangesDialog>
    </PortalPage>
  );
}

function scrollTo(section: SectionId) {
  document.getElementById(sectionElementId(section))?.scrollIntoView({ block: "start", behavior: "smooth" });
}

/** The section whose top is nearest above the scroll region's upper third. */
function useSectionSpy(scrollRef: React.RefObject<HTMLDivElement | null>) {
  const [current, setCurrent] = useState<SectionId>("subjects");
  useEffect(() => {
    const root = scrollRef.current;
    if (!root) return;
    const update = () => {
      const limit = root.getBoundingClientRect().top + root.clientHeight / 3;
      let active: SectionId = "subjects";
      for (const section of SECTIONS) {
        const element = document.getElementById(sectionElementId(section.id));
        if (element && element.getBoundingClientRect().top <= limit) active = section.id;
      }
      setCurrent(active);
    };
    update();
    root.addEventListener("scroll", update, { passive: true });
    return () => root.removeEventListener("scroll", update);
  }, [scrollRef]);
  return current;
}

function SectionMessages({ messages, section }: { messages: PolicyValidationMessage[]; section: SectionId }) {
  const own = messages.filter((message) => sectionOf(message) === section);
  if (!own.length) return null;
  return (
    <div className="flex flex-col gap-1" role="alert">
      {own.map((message, index) => (
        <FormError key={`${message.field}-${message.code}-${index}`} error={message.message} />
      ))}
    </div>
  );
}

type SectionProps = {
  draft: PolicyGrantDraft;
  readonly: boolean;
  update: (draft: PolicyGrantDraft) => void;
  messages: PolicyValidationMessage[];
};

function SubjectsSection({ draft, catalog, readonly, update, messages }: SectionProps & { catalog: PolicyCatalogResult | null }) {
  const options = draft.subjectKind === "group" ? catalog?.subjects.groups ?? [] : draft.subjectKind === "user" ? catalog?.subjects.users ?? [] : [];
  const add = (kind: PolicySubjectKind, id: string) => {
    const subject = buildPolicySubject(kind, id);
    if (draft.subjects.includes(subject)) return;
    update({ ...draft, subjects: [...draft.subjects, subject], subjectId: "" });
  };
  return (
    <Card title="Subjects" subtitle="Users and groups the grant applies to." id={sectionElementId("subjects")}>
      <div className="pt-card-body">
        <div className="flex flex-wrap gap-2" aria-label="Grant subjects" role="list">
          {draft.subjects.length === 0 ? <span className="wb-small wb-muted">No subjects yet.</span> : null}
          {draft.subjects.map((subject) => (
            <span role="listitem" key={subject}>
              <Chip
                icon={subject.startsWith("group:") ? "users" : "user"}
                onRemove={readonly ? undefined : () => update({ ...draft, subjects: draft.subjects.filter((item) => item !== subject) })}
                removeLabel={`Remove ${subject}`}
              >
                {policySubjectDisplayLabel(subject, catalog)}
              </Chip>
            </span>
          ))}
        </div>
        {!readonly ? (
          <>
            <FieldGroup label="Add a subject">
              <Seg
                label="Subject type"
                value={draft.subjectKind}
                onChange={(subjectKind) => update({ ...draft, subjectKind, subjectId: "" })}
                options={[
                  { value: "group", label: "Group", icon: "users" },
                  { value: "user", label: "User", icon: "user" },
                  { value: "anonymousGroup", label: "Anonymous group" },
                  { value: "anonymousUser", label: "Anonymous user" }
                ]}
              />
            </FieldGroup>
            {draft.subjectKind === "group" || draft.subjectKind === "user" ? (
              <Field label={draft.subjectKind === "group" ? "Group" : "User"} hint="Choosing one adds it to the grant.">
                <Combobox
                  value={null}
                  onChange={(value) => {
                    if (value) add(draft.subjectKind, value);
                  }}
                  placeholder={draft.subjectKind === "group" ? "Find a group…" : "Find a user…"}
                  options={options.flatMap((option) => {
                    const id = draft.subjectKind === "group" ? option.groupId : option.principalId;
                    if (!id) return [];
                    const value = buildPolicySubject(draft.subjectKind, id);
                    return [
                      {
                        value: id,
                        label: `${principalIdentityLabel(id, option.displayName)}${option.status === "active" ? "" : ` (${option.status})`}`,
                        disabled: draft.subjects.includes(value)
                      }
                    ];
                  })}
                />
              </Field>
            ) : (
              <div>
                <Button icon="plus" onClick={() => add(draft.subjectKind, "")} disabled={draft.subjects.includes(buildPolicySubject(draft.subjectKind, ""))}>
                  Add {buildPolicySubject(draft.subjectKind, "")}
                </Button>
              </div>
            )}
          </>
        ) : null}
        <SectionMessages messages={messages} section="subjects" />
      </div>
    </Card>
  );
}

function ServiceSection({ draft, catalog, readonly, lockService, update, messages }: SectionProps & { catalog: PolicyCatalogResult | null; lockService: boolean }) {
  const service = policyService(catalog, draft.service);
  const credentialModes = commonCredentialModes(service, draft.actions);
  const supported = commonSupportedCredentialModes(service, draft.actions);
  const modeOptions = uniqueSortedOptions(draft.actions.length > 0 ? supported : credentialModes, draft.credentialMode);
  // A command import's actions that the command checks: grants pass to it as boundaries.
  const caveatId = useId();
  const commandChecked = Boolean(service?.actions.some((action) => action.resourcesCheckedBy === "command"));

  function changeService(serviceName: string) {
    const next = policyService(catalog, serviceName);
    update({
      ...draft,
      service: serviceName,
      actions: [],
      credentialMode: next?.configuredCredentialModes[0] ?? "",
      resources: next && Object.keys(next.resourceScopes).length === 0 ? { resourceIds: [], resourceGroupIds: [] } : draft.resources
    });
  }

  function setActions(actions: string[]) {
    const modes = commonCredentialModes(service, actions);
    const retained = draft.mode === "edit" && draft.service === draft.originalService && draft.credentialMode === draft.originalCredentialMode;
    update({ ...draft, actions, credentialMode: modes.includes(draft.credentialMode) || retained ? draft.credentialMode : modes[0] ?? "" });
  }

  return (
    <Card
      title="Service and actions"
      subtitle="The service, the actions granted on it, and the credential they use."
      id={sectionElementId("service")}
      actions={service ? <WriteCapability available={service.actions} selected={draft.actions} /> : undefined}
    >
      <div className="pt-card-body">
        <Field label="Service" hint={lockService ? "Service policy managers cannot move a grant to another service." : undefined}>
          <Select value={draft.service} onChange={(event) => changeService(event.target.value)} disabled={readonly || lockService}>
            <option value="">Choose a service</option>
            {draft.service && !service ? <option value={draft.service}>{draft.service} (not configured)</option> : null}
            {catalog?.services.map((item) => (
              <option value={item.service} key={item.service} disabled={!canGrantService(item) && item.service !== draft.service}>
                {item.displayName} ({item.service}){item.available === false ? " · unavailable" : ""}
              </option>
            ))}
          </Select>
        </Field>
        {service ? (
          <GrantActionSelector key={service.service} available={service.actions} selected={draft.actions} disabled={readonly} commandCaveatId={commandChecked ? caveatId : undefined} onChange={setActions} />
        ) : (
          <p className="pt-prose">Choose a service to select its actions.</p>
        )}
        {commandChecked ? (
          <p id={caveatId} className="pt-prose wb-small">
            <b>Resources checked by: Command.</b> {COMMAND_CHECK_CAVEAT}
          </p>
        ) : null}
        <Field label="Credential mode" hint="Whose upstream credential the actions use: each caller's own (per_user) or the service's shared one (service).">
          <Select
            value={draft.credentialMode}
            onChange={(event) => update({ ...draft, credentialMode: event.target.value })}
            disabled={readonly || modeOptions.length === 0}
          >
            <option value="">Choose</option>
            {modeOptions.map((mode) => (
              <option value={mode} key={mode} disabled={!credentialModes.includes(mode)}>
                {mode}
                {credentialModes.includes(mode) ? "" : " (not configured)"}
              </option>
            ))}
          </Select>
        </Field>
        <SectionMessages messages={messages} section="service" />
      </div>
    </Card>
  );
}

function ContextsSection({ draft, catalog, readonly, update, messages }: SectionProps & { catalog: PolicyCatalogResult | null }) {
  const configured = catalog?.executionContexts.allowedValues ?? [];
  const options = [...configured, ...draft.executionContexts.filter((context) => !configured.includes(context))];
  return (
    <Card title="Execution contexts" subtitle="Where requests may run. A request's context must match both the grant and any token restriction." id={sectionElementId("contexts")}>
      <div className="pt-card-body">
        <div className="pt-checks" role="group" aria-label="Execution contexts">
          {options.map((context) => (
            <Checkbox
              key={context}
              label={
                <span className="wb-mono">
                  {context}
                  {configured.includes(context) ? "" : " (not configured)"}
                </span>
              }
              aria-label={context}
              checked={draft.executionContexts.includes(context)}
              disabled={readonly}
              onChange={(event) => {
                const selected = new Set(draft.executionContexts);
                if (event.target.checked) selected.add(context);
                else selected.delete(context);
                update({ ...draft, executionContexts: options.filter((item) => selected.has(item)) });
              }}
            />
          ))}
          {options.length === 0 ? <span className="wb-small wb-muted">No execution contexts are configured.</span> : null}
        </div>
        <SectionMessages messages={messages} section="contexts" />
      </div>
    </Card>
  );
}

function SettingsSection({ draft, readonly, update, messages }: SectionProps) {
  return (
    <Card title="Settings" id={sectionElementId("settings")}>
      <div className="pt-card-body">
        {draft.mode !== "edit" && draft.mode !== "inspect" ? (
          <Field label="Grant ID" optional hint="A safe slug; leave empty to generate one. It cannot change later.">
            <Input mono value={draft.grantId} onChange={(event) => update({ ...draft, grantId: event.target.value })} placeholder="jira-read-platform" disabled={readonly} />
          </Field>
        ) : null}
        <FieldGroup label="Status" hint={draft.mode === "duplicate" ? "Duplicates start disabled so you can review them first." : undefined}>
          <Seg
            label="Status"
            value={draft.status === "disabled" ? "disabled" : "active"}
            onChange={(status) => !readonly && update({ ...draft, status })}
            options={[
              { value: "active", label: "Active", icon: "circle-check", tone: "success", disabled: readonly },
              { value: "disabled", label: "Disabled", icon: "pause", disabled: readonly }
            ]}
          />
        </FieldGroup>
        <Field label="Priority" optional hint="Higher priorities win when grants overlap. Leave empty for the default.">
          <Input numeric value={draft.priority} onChange={(event) => update({ ...draft, priority: event.target.value })} placeholder="default" disabled={readonly} inputMode="numeric" />
        </Field>
        <Field label="Description" optional>
          <Textarea value={draft.description} onChange={(event) => update({ ...draft, description: event.target.value })} rows={3} disabled={readonly} />
        </Field>
        <SectionMessages messages={messages} section="settings" />
      </div>
    </Card>
  );
}

/** Asks the broker what the draft would allow; waits for the draft to settle while typing. */
function LivePreview({ draft }: { draft: PolicyGrantDraft }) {
  const settled = useDeferredValue(draft);
  if (settled.status === "disabled") return <p className="pt-prose">No access currently: the grant is disabled.</p>;
  if (!settled.service || settled.actions.length === 0 || settled.executionContexts.length === 0) {
    return <p className="pt-prose">Choose a service, at least one action, and an execution context to preview access.</p>;
  }
  return (
    <EffectiveAccessPanel
      grant={{ service: settled.service, actions: settled.actions, executionContexts: settled.executionContexts, resources: settled.resources }}
    />
  );
}
