import { AGENT_TOKEN_ISSUANCE_LABELS, agentTokenIssuanceDescription, issuanceSettingBlocker } from "../../lib/token-issuance-policy";
import { AdminForm, AdminButton } from "../../components/admin-access";
import { canWriteAdmin, ROLE_LABELS } from "../../lib/capabilities";
import { AdminOnly } from "../../components/admin-access";
import { useAdminAccessKeyTypes, useAdminGroups, useAdminPrincipal, useConfigStatus, usePolicyCatalog, useServicePolicyManagers } from "../../data/queries";
import { usePolicyActions } from "../../mutations/policy";
import { useModal } from "../../app/modal";
import type { AccessKeyType, PrincipalAccessKeyTypes, PrincipalRecord, PrincipalRole } from "../../types";
import { AccountUsernameSection, UsernameChangeNotice, type UsernameNotice } from "./account-username";
import { PrincipalAccessKeyTypeTable } from "./access-key-type-settings";
import { accessKeyTypeSettingBlocker, accessKeyTypesSettingEqual, emailChangeWarning, usernameChangeSummary } from "../../lib/access-keys";
import { accessDraftPatch } from "../../lib/access-draft";
import { useAccessDraft } from "./use-access-draft";
import { AccessDraftConflict, TokenIssuanceControls, useIssuanceRegistry } from "./token-issuance-controls";
// User page › Overview: profile, status and role, sign-in methods, identity token.
import { LOCAL_SIGN_IN_EXPLANATION, LOCAL_SIGN_IN_ACKNOWLEDGMENT } from "./sign-in-methods";
import { useEffect, useState } from "react";
import type { LoginMethodRecord, PrincipalDetail } from "../../types";
import { errorMessage, identityDisplayName, microsoftLoginControl } from "../../lib/helpers";
import { microsoftRenewalStatus } from "../../lib/microsoft-membership";
import {
  Badge,
  Button,
  Checkbox,
  ErrorState,
  IconButton,
  Input,
  Modal,
  Select,
  KeyValue,
  SettingsPage,
  SettingsRow,
  SettingsSection,
  SkeletonBlock,
  StateCell,
  Time,
  useToast
} from "../../workbench";
import { FormError } from "../../components/form";
import { useActionRunner } from "../../app/actions";
import { useSession } from "../../app/session";
import { usePrincipalActions } from "../../mutations/principals";
import { MicrosoftEnrollmentControls } from "./microsoft-enrollment";
import { IdentityTokenSection } from "./identity-token";
import { IdentityAccessSection } from "./identity-access";

export function PrincipalOverview({
  principal,
  loginMethods,
  groupWritesEnabled
}: {
  principal: PrincipalDetail;
  loginMethods: LoginMethodRecord[];
  groupWritesEnabled: boolean;
}) {
  const serviceAccount = principal.kind === "service_account";
  // Access key type settings show while an access key type is configured. A
  // failed read shows its error, never editable rows from a stale list.
  const types = useAdminAccessKeyTypes(principal.kind !== "system");
  const keyTypes = types.isError ? [] : types.data ?? [];
  const keysShown = keyTypes.length > 0;
  // A refused save may name a type a reload elsewhere removed: reading the list again shows it for removal.
  const refreshTypes = () => void types.refetch();
  const [notice, setNotice] = useState<UsernameNotice>(null);
  // The email warning and its result read the account's own username, whatever the type list does.
  const username = principal.kind === "user" ? principal.accountUsername ?? null : null;
  // The Username section shows while a type is configured, when the type list could not be read, or
  // while the person holds a name or live keys.
  const usernameShown = Boolean(username) && (keysShown || types.isError || Boolean(username?.name) || (username?.liveKeys ?? 0) > 0);
  return (
    <SettingsPage>
      <ProfileSection principal={principal} username={username} notice={notice} onUsernameChange={setNotice} />
      {usernameShown ? <AccountUsernameSection key={`username:${principal.principalId}`} principal={principal} notice={notice} setNotice={setNotice} /> : null}
      {types.isError && principal.kind !== "system" ? (
        <SettingsSection title="Access key types">
          <ErrorState compact title="Couldn’t load access key types" error={types.error} onRetry={() => void types.refetch()} retrying={types.isFetching} />
        </SettingsSection>
      ) : null}
      {serviceAccount ? (
        <>
          <SettingsSection title="Sign-in" description="Service accounts are noninteractive.">
            <p className="pt-prose">
              Service accounts cannot use passwords, Microsoft sign-in, browser sessions, setup tokens, or admin tokens. Administrators assign grants,
              credentials, groups, and agent-token boundaries on the other tabs. Self-issuance is unavailable for service accounts.
            </p>
          </SettingsSection>
          {keysShown && principal.accessKeyTypes ? <ServiceAccountAccessKeyTypes key={`keys:${principal.principalId}`} principal={principal} types={keyTypes} refreshTypes={refreshTypes} /> : null}
        </>
      ) : (
        <>
          <RoleSection key={principal.principalId} principal={principal} keyTypes={principal.kind === "user" ? keyTypes : []} refreshTypes={refreshTypes} />
          {principal.role === "service_policy_manager" ? <ManagedServicesSection principal={principal} /> : null}
          <SignInSection principal={principal} loginMethods={loginMethods} groupWritesEnabled={groupWritesEnabled} />
          {principal.kind === "user" ? (
            <>
              <IdentityAccessSection key={`access:${principal.principalId}`} principalId={principal.principalId} principalActive={principal.status === "active"} />
              {/* Keyed: a revealed token, typed replacement, or pending reveal never carries over to another principal. */}
              <IdentityTokenSection key={principal.principalId} principalId={principal.principalId} />
            </>
          ) : null}
        </>
      )}
    </SettingsPage>
  );
}

function ProfileSection({ principal, username, notice, onUsernameChange }: { principal: PrincipalDetail; username: PrincipalDetail["accountUsername"]; notice: UsernameNotice; onUsernameChange: (notice: UsernameNotice) => void }) {
  const principals = usePrincipalActions();
  const { confirm } = useModal();
  const [displayName, setDisplayName] = useState(principal.displayName ?? "");
  const [email, setEmail] = useState(principal.email ?? "");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setDisplayName(principal.displayName ?? "");
    setEmail(principal.email ?? "");
  }, [principal.principalId, principal.displayName, principal.email]);
  const dirty = displayName !== (principal.displayName ?? "") || email !== (principal.email ?? "");
  return (
    <SettingsSection title="Profile">
      <AdminForm
        onSubmit={async (event) => {
          event.preventDefault();
          if (pending || !dirty) return;
          const save = async () => {
            setPending(true);
            setError(null);
            try {
              const saved = await principals.patch(principal.principalId, { displayName: displayName || null, email: email || null });
              // Every save replaces the notice: what the server says this save did to the
              // username when a name was involved, and no notice when there is nothing to report.
              const change = saved.accountUsernameChange;
              onUsernameChange(change && (change.before || change.after) ? { principalId: principal.principalId, source: "profile", ...usernameChangeSummary(change) } : null);
            } catch (failure) {
              setError(errorMessage(failure));
              throw failure;
            } finally {
              setPending(false);
            }
          };
          // A username that follows the email may change with it: say so before saving.
          // Only a held name or live keys can be ended; the account's own username data says which.
          if (username?.mode === "from_email" && (username.name || username.liveKeys > 0) && email !== (principal.email ?? "")) {
            const who = identityDisplayName(principal.displayName) || principal.principalId;
            const held = username.name?.accountUsername;
            confirm({
              title: "Change the email?",
              body: emailChangeWarning(who, held, email, username.liveKeys),
              confirmLabel: "Save email",
              onConfirm: save
            });
            return;
          }
          await save().catch(() => undefined);
        }}
      >
        <SettingsRow label="Principal ID" help="The stable identifier; it cannot change.">
          <span className="wb-num">{principal.principalId}</span>
        </SettingsRow>
        <SettingsRow label="Display name" help={principal.kind === "user" ? "Successful Microsoft sign-in refreshes this name from Microsoft and may replace administrator edits." : undefined}>
          <Input value={displayName} onChange={(event) => setDisplayName(event.target.value)} className="flex-1" />
        </SettingsRow>
        <SettingsRow label="Email" help={principal.microsoftEnrollment ? "Profile email is separate from the pending Microsoft match email. Editing this field does not change enrollment." : undefined}>
          <Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} className="flex-1" />
        </SettingsRow>
        <SettingsRow label="History">
          <KeyValue
            items={[
              { label: "Created", value: <><Time value={principal.createdAt} format="datetime" /> <span className="wb-muted">by {principal.createdBy}</span></> },
              { label: "Updated", value: <Time value={principal.updatedAt} format="datetime" /> }
            ]}
          />
        </SettingsRow>
        <UsernameChangeNotice notice={notice} principalId={principal.principalId} source="profile" onDismiss={() => onUsernameChange(null)} />
        <FormError error={error} />
        <div className="wb-settings-actions">
          <AdminButton type="submit" variant="primary" disabled={!dirty} pending={pending}>
            Save profile
          </AdminButton>
        </div>
      </AdminForm>
    </SettingsSection>
  );
}

function RoleSection({ principal, keyTypes, refreshTypes }: { principal: PrincipalDetail; keyTypes: AccessKeyType[]; refreshTypes: () => void }) {
  const principals = usePrincipalActions();
  const { session } = useSession();
  const { confirm } = useModal();
  const configQuery = useConfigStatus();
  const assignmentsAvailable = configQuery.data?.identityAuthority === "managed" && configQuery.data.policyAuthority === "managed";
  const assignmentsQuery = useServicePolicyManagers(assignmentsAvailable && principal.role === "service_policy_manager");
  const groups = useAdminGroups().data ?? [];
  const keysShown = keyTypes.length > 0 && Boolean(principal.accessKeyTypes);
  const fields = (value: PrincipalRecord) => ({ role: value.role, selfServiceEnabled: value.selfServiceEnabled, agentTokenIssuance: value.agentTokenIssuance, ...(keysShown && value.accessKeyTypes ? { accessKeyTypes: value.accessKeyTypes } : {}) });
  const draft = useAccessDraft(fields(principal));
  const { role, selfServiceEnabled, agentTokenIssuance } = draft.value;
  const accessKeyTypes = draft.value.accessKeyTypes as PrincipalAccessKeyTypes | undefined;
  const record = useAdminPrincipal(principal.principalId);
  const registry = useIssuanceRegistry();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const policyError = accessDraftPatch(draft).agentTokenIssuance ? issuanceSettingBlocker(agentTokenIssuance, registry.contexts) : null;
  const keyTypeError = keysShown && accessKeyTypes ? accessKeyTypeSettingBlocker(accessKeyTypes, principal.accessKeyTypes, keyTypes) : null;
  const self = principal.principalId === session.principal;
  const writable = canWriteAdmin(session);
  const roles = Object.entries(ROLE_LABELS).filter(([value]) => principal.kind !== "system" || value === "user" || value === "service_policy_manager");
  const changedRole = role !== principal.role;
  const leavingManager = changedRole && principal.role === "service_policy_manager";
  const scopePreviewReady = configQuery.isSuccess && (!assignmentsAvailable || assignmentsQuery.isSuccess);
  async function prepare() {
    const result = await record.refetch({ throwOnError: true });
    if (!result.data) throw new Error("Current account settings are unavailable.");
    const next = draft.refresh(fields(result.data));
    if (next.conflicts.length) throw new Error("Review the changed saved settings before saving.");
    return next;
  }
  const save = async () => {
    setPending(true); setError(null);
    try {
      const next = await prepare();
      const values = next.value;
      const roleChanged = values.role !== next.base.role;
      let scopeWarning = "";
      if (roleChanged && next.base.role === "service_policy_manager") {
        if (assignmentsAvailable) {
          const refreshed = await assignmentsQuery.refetch({ throwOnError: true });
          const scopes = (refreshed.data ?? []).filter((assignment) => assignment.principalId === principal.principalId).map((assignment) => assignment.service);
          scopeWarning = ` Direct management assignments will be removed: ${scopes.join(", ") || "none"}.`;
        } else scopeWarning = " Any stored direct management assignments will be removed. Assignment names are unavailable while policy is file-owned.";
      }
      confirm({
        title: "Update account access?",
        body: `${principal.principalId} will have the ${ROLE_LABELS[values.role]} role and self-service ${values.selfServiceEnabled ? "enabled" : "disabled"}, with agent token issuance set to ${AGENT_TOKEN_ISSUANCE_LABELS[values.agentTokenIssuance.mode]}${values.agentTokenIssuance.allowedExecutionContexts.length ? ` in ${values.agentTokenIssuance.allowedExecutionContexts.join(", ")}` : ""}. Existing token restrictions stay unchanged.${roleChanged ? " All administrative API tokens for this account will be revoked." : ""}${scopeWarning}${accessKeyTypesSettingEqual(values.accessKeyTypes, next.base.accessKeyTypes) ? "" : " Access key types change as chosen: a type this person may no longer hold stops working in their existing keys, which keep working for their other access."}`,
        confirmLabel: "Update access", tone: "primary",
        onConfirm: async () => {
          try {
            const current = await prepare();
            const patch = accessDraftPatch(current);
            if (!Object.keys(patch).length) return;
            const saved = await principals.setAccess(principal.principalId, patch);
            draft.committed(fields(saved));
          } catch (failure) {
            setError(errorMessage(failure));
            void registry.query.refetch();
            void record.refetch();
            if (keysShown) refreshTypes();
            throw failure;
          }
        }
      });
    } catch (failure) { setError(errorMessage(failure)); }
    finally { setPending(false); }
  };
  return (
    <SettingsSection title="Account access" description="One administrative role, with independent access to personal tokens, credentials and connections.">
      <SettingsRow label="Role" help={self ? "You cannot change your own role here." : undefined}>
        {writable ? <Select aria-label="Role" value={role} disabled={self} onChange={(event) => draft.edit({ ...draft.value, role: event.target.value as PrincipalRole })} options={roles.map(([value, label]) => ({ value, label }))} /> : <span>{ROLE_LABELS[principal.role]}</span>}
      </SettingsRow>
      <SettingsRow label="Self-service">
        {writable ? <Checkbox label="Self-service enabled" checked={selfServiceEnabled} onChange={(event) => draft.edit({ ...draft.value, selfServiceEnabled: event.target.checked })} /> : <span>{principal.selfServiceEnabled ? "Enabled" : "Disabled"}</span>}
      </SettingsRow>
      <SettingsRow label="Agent token issuance" alignTop>
        <div className="wb-form-stack">
          {writable ? <TokenIssuanceControls value={agentTokenIssuance} registry={registry} disabled={pending} onChange={(value) => draft.edit({ ...draft.value, agentTokenIssuance: value })} /> : <span>{AGENT_TOKEN_ISSUANCE_LABELS[principal.agentTokenIssuance.mode]}</span>}
          <p className="wb-field-hint">Current saved policy: {agentTokenIssuanceDescription(principal.agentTokenIssuancePolicy, groups)}</p>
          {agentTokenIssuance.mode === "inherit" && principal.agentTokenIssuance.mode !== "inherit" ? <p className="wb-field-hint">The inherited result appears after saving and refreshing.</p> : null}
        </div>
      </SettingsRow>
      {keysShown && accessKeyTypes ? (
        <div className="wb-settings-row wb-settings-row--top pt-key-setting">
          <div className="wb-form-stack">
            <h3 className="pt-key-setting-title">Access key types</h3>
            <p className="pt-prose">Which access key types this person may hold, chosen separately for each type. Inherit from groups allows a type when any of their groups allows it. Allow and Deny apply to this account alone and leave the other types inheriting.</p>
            <p className="pt-prose">Removing permission also stops this person’s existing keys giving that access; they keep working for their other access.</p>
            <PrincipalAccessKeyTypeTable types={keyTypes} value={accessKeyTypes} saved={principal.accessKeyTypes!} policy={principal.accessKeyTypePolicy} serviceAccount={false} writable={writable} disabled={pending} onChange={(value) => draft.edit({ ...draft.value, accessKeyTypes: value })} />
          </div>
        </div>
      ) : null}
      <AccessDraftConflict conflict={draft.conflicts.length > 0} kept={draft.kept} discard={() => { draft.discard(); setError(null); }} keep={() => { draft.keep(); setError(null); }} />
      {record.isError ? <ErrorState compact title="Couldn’t refresh saved account settings" error={record.error} onRetry={() => void record.refetch()} /> : null}
      <FormError error={error} />
      {leavingManager && configQuery.isError ? <ErrorState error={configQuery.error} onRetry={() => void configQuery.refetch()} retrying={configQuery.isFetching} /> : null}
      {leavingManager && assignmentsAvailable && assignmentsQuery.isError ? <ErrorState error={assignmentsQuery.error} onRetry={() => void assignmentsQuery.refetch()} retrying={assignmentsQuery.isFetching} /> : null}
      <AdminOnly><div className="wb-settings-actions"><AdminButton pending={pending} disabled={!draft.changed || draft.conflicts.length > 0 || Boolean(policyError) || Boolean(keyTypeError) || (leavingManager && !scopePreviewReady)} onClick={() => void save()}>Save access</AdminButton></div></AdminOnly>
    </SettingsSection>
  );
}

/** A service account's access key types: who issues its keys, and which types it may hold. */
function ServiceAccountAccessKeyTypes({ principal, types, refreshTypes }: { principal: PrincipalDetail; types: AccessKeyType[]; refreshTypes: () => void }) {
  const { session } = useSession();
  const principals = usePrincipalActions();
  const record = useAdminPrincipal(principal.principalId);
  const fields = (value: PrincipalRecord) => ({ agentTokenIssuance: value.agentTokenIssuance, accessKeyTypes: value.accessKeyTypes ?? { allow: [], deny: [] } });
  const draft = useAccessDraft(fields(principal));
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const writable = canWriteAdmin(session);
  const keyTypeError = accessKeyTypeSettingBlocker(draft.value.accessKeyTypes as PrincipalAccessKeyTypes, principal.accessKeyTypes, types);
  async function save() {
    setPending(true);
    setError(null);
    try {
      const result = await record.refetch({ throwOnError: true });
      if (!result.data) throw new Error("Current account settings are unavailable.");
      const next = draft.refresh(fields(result.data));
      if (next.conflicts.length) throw new Error("Review the changed saved settings before saving.");
      const patch = accessDraftPatch(next);
      if (patch.accessKeyTypes) {
        const saved = await principals.setAccess(principal.principalId, { accessKeyTypes: patch.accessKeyTypes as PrincipalAccessKeyTypes });
        draft.committed(fields(saved));
      }
    } catch (failure) {
      setError(errorMessage(failure));
      void record.refetch();
      refreshTypes();
    } finally {
      setPending(false);
    }
  }
  return (
    <SettingsSection title="Access key types" description="A service account does not issue its own keys: an administrator issues them on its Keys tab, for the types allowed here.">
      <p className="pt-prose">Which access key types this service account may hold, chosen separately for each type. Inherit from groups allows a type when any of its groups allows it. Allow and Deny apply to this account alone and leave the other types inheriting.</p>
      <p className="pt-prose">Removing permission also stops this service account’s existing keys giving that access; they keep working for their other access.</p>
      <PrincipalAccessKeyTypeTable types={types} value={draft.value.accessKeyTypes as PrincipalAccessKeyTypes} saved={principal.accessKeyTypes ?? { allow: [], deny: [] }} policy={principal.accessKeyTypePolicy} serviceAccount writable={writable} disabled={pending} onChange={(value) => draft.edit({ ...draft.value, accessKeyTypes: value })} />
      <AccessDraftConflict conflict={draft.conflicts.length > 0} kept={draft.kept} discard={() => { draft.discard(); setError(null); }} keep={() => { draft.keep(); setError(null); }} />
      <FormError error={error} />
      <AdminOnly><div className="wb-settings-actions"><AdminButton pending={pending} disabled={!draft.changed || draft.conflicts.length > 0 || Boolean(keyTypeError)} onClick={() => void save()}>Save access</AdminButton></div></AdminOnly>
    </SettingsSection>
  );
}

function ManagedServicesSection({ principal }: { principal: PrincipalDetail }) {
  const { session } = useSession();
  const config = useConfigStatus();
  const assignmentsAvailable = config.data?.identityAuthority === "managed" && config.data.policyAuthority === "managed";
  const catalog = usePolicyCatalog(assignmentsAvailable);
  const assignments = useServicePolicyManagers(assignmentsAvailable);
  const policy = usePolicyActions();
  const current = (assignments.data ?? []).filter((item) => item.principalId === principal.principalId).map((item) => item.service).sort();
  const key = JSON.stringify(current);
  const [selected, setSelected] = useState<string[]>(current);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  useEffect(() => { setSelected(JSON.parse(key) as string[]); }, [key]);
  const services = [...new Set([...(catalog.data?.services ?? []).map((item) => item.service), ...current])].sort();
  const writable = canWriteAdmin(session);
  if (!config.isSuccess || !assignmentsAvailable) return <SettingsSection title="Managed services">
    {config.isError ? <ErrorState error={config.error} onRetry={() => void config.refetch()} retrying={config.isFetching} /> : config.isPending ? <SkeletonBlock lines={2} /> : <p className="pt-prose">Service management assignments are available only when identity and policy are managed.</p>}
  </SettingsSection>;
  if (!catalog.isSuccess || !assignments.isSuccess) return <SettingsSection title="Managed services">
    {assignments.isError ? <ErrorState error={assignments.error} onRetry={() => void assignments.refetch()} retrying={assignments.isFetching} /> : catalog.isError ? <ErrorState error={catalog.error} onRetry={() => void catalog.refetch()} retrying={catalog.isFetching} /> : <SkeletonBlock lines={2} />}
  </SettingsSection>;
  return <SettingsSection title="Managed services" description="This account can manage every grant for the selected services. Group membership does not grant management authority.">
    {services.map((service) => <Checkbox key={service} label={catalog.data?.services.find((item) => item.service === service)?.displayName ?? service} checked={selected.includes(service)} disabled={!writable || pending} onChange={(event) => setSelected((values) => event.target.checked ? [...values, service] : values.filter((value) => value !== service))} />)}
    {!current.length ? <p className="pt-prose">No services assigned.</p> : null}
    <FormError error={error} />
    <AdminOnly><AdminButton disabled={assignments.isPending || catalog.isPending || JSON.stringify([...selected].sort()) === key} pending={pending} onClick={async () => {
      setPending(true); setError(null);
      try {
        for (const service of selected.filter((value) => !current.includes(value))) await policy.assignManager(service, principal.principalId);
        for (const service of current.filter((value) => !selected.includes(value))) await policy.revokeManager(service, principal.principalId);
      } catch (failure) { setError(errorMessage(failure)); } finally { setPending(false); }
    }}>Save managed services</AdminButton></AdminOnly>
  </SettingsSection>;
}

function SignInSection({ principal, loginMethods, groupWritesEnabled }: { principal: PrincipalDetail; loginMethods: LoginMethodRecord[]; groupWritesEnabled: boolean }) {
  const { session } = useSession();
  const principals = usePrincipalActions();
  const runner = useActionRunner();
  const toast = useToast();
  const localPassword = loginMethods.find((method) => method.method === "local_password");
  const microsoft = loginMethods.find((method) => method.method === "oidc" && method.oidc?.provider === "microsoft");
  const enrollment = principal.microsoftEnrollment;
  const control = microsoftLoginControl(microsoft?.status, Boolean(session.loginOptions?.microsoft?.enabled));
  const renewal = microsoftRenewalStatus(microsoft?.oidc?.membershipRenewal);
  const [objectId, setObjectId] = useState("");
  const [confirmId, setConfirmId] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [linkError, setLinkError] = useState<string | null>(null);
  const [linking, setLinking] = useState(false);
  const [enableOpen, setEnableOpen] = useState(false);
  const [enableAcknowledged, setEnableAcknowledged] = useState(false);
  const [enablePending, setEnablePending] = useState(false);
  const [enableError, setEnableError] = useState<string | null>(null);
  const localActive = localPassword?.status === "active";
  const enableLabel = localPassword ? "Re-enable local password sign-in" : "Enable local password sign-in";
  useEffect(() => {
    setObjectId("");
    setConfirmId("");
    setAcknowledged(false);
  }, [principal.principalId]);
  const canLink = !enrollment && groupWritesEnabled && objectId.trim() && confirmId === principal.principalId && acknowledged;
  return (
    <SettingsSection title="Sign-in methods" description="Enrollment is separate from user status and broker-wide sign-in availability.">
      {session.loginOptions?.localPassword?.enabled === false ? <p className="pt-prose">Local password sign-in is disabled for this broker. Enrolled methods are retained.</p> : null}
      {enableOpen ? (
        <Modal
          open
          title={enableLabel}
          onClose={() => setEnableOpen(false)}
          dismissible={!enablePending}
          onSubmit={async () => {
            if (!enableAcknowledged || enablePending) return;
            setEnablePending(true);
            setEnableError(null);
            try {
              await principals.enablePassword(principal.principalId);
              setEnableOpen(false);
            } catch (error) {
              setEnableError(errorMessage(error));
            } finally {
              setEnablePending(false);
            }
          }}
          footer={
            <>
              <Button disabled={enablePending} onClick={() => setEnableOpen(false)}>Cancel</Button>
              <AdminButton type="submit" variant="primary" disabled={!enableAcknowledged} pending={enablePending}>{enableLabel}</AdminButton>
            </>
          }
        >
          <p className="pt-prose">{LOCAL_SIGN_IN_EXPLANATION} A fresh temporary password is generated and must be changed at first local sign-in.</p>
          <Checkbox label={LOCAL_SIGN_IN_ACKNOWLEDGMENT} checked={enableAcknowledged} onChange={(event) => setEnableAcknowledged(event.target.checked)} disabled={enablePending} />
          <FormError error={enableError} />
        </Modal>
      ) : null}
      <SettingsRow
        label="Local password"
        help={
          localPassword?.mustChangePassword ? (
            "Must change it at next sign-in."
          ) : localPassword?.passwordSetAt ? (
            <>
              Set <Time value={localPassword.passwordSetAt} />
            </>
          ) : localPassword ? undefined : (
            "No local password sign-in is configured."
          )
        }
      >
        <Badge tone={localPassword?.status === "active" ? "success" : "neutral"}>{localPassword ? localPassword.status : "not configured"}</Badge>
        {localPassword?.locked && localPassword.lockedUntil ? (
          <span className="wb-small">
            Some sources locked until <Time value={localPassword.lockedUntil} format="datetime" />
          </span>
        ) : null}
        <span className="wb-spacer" />
        {localActive ? <>
          <AdminButton icon="key" onClick={() => principals.confirmResetPassword(principal.principalId)}>Reset local password</AdminButton>
          {localPassword?.locked ? <AdminButton pending={runner.isPending("unlock")} onClick={() => void runner.run("unlock", () => principals.updateLoginMethod(principal.principalId, "unlock"))}>Unlock local password</AdminButton> : null}
          <AdminButton variant="danger-ghost" onClick={() => principals.confirmDisablePassword(principal.principalId)}>Disable local password sign-in</AdminButton>
        </> : <AdminButton icon="key" onClick={() => { setEnableAcknowledged(false); setEnableError(null); setEnableOpen(true); }}>{enableLabel}</AdminButton>}

      </SettingsRow>
      <SettingsRow label="Microsoft" alignTop help={control === "disabled" ? "Microsoft sign-in is not enabled for this broker." : session.loginOptions?.microsoft?.available === false ? "Microsoft sign-in is temporarily unavailable. Enrolled methods are retained." : undefined}>
        <div className="flex flex-1 flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={microsoft?.status === "active" ? "success" : "neutral"}>{enrollment ? "Awaiting first Microsoft sign-in" : microsoft?.status ?? "not linked"}</Badge>
            {microsoft?.oidc ? (
              <>
                <span className="wb-small">
                  tenant <span className="wb-num">{microsoft.oidc.tenantId}</span>
                </span>
                <span className="wb-small">
                  object <span className="wb-num">{microsoft.oidc.userObjectId}</span>
                </span>
                <IconButton
                  size="sm"
                  icon="copy"
                  label="Copy Microsoft user Object ID"
                  onClick={() => void navigator.clipboard.writeText(microsoft.oidc!.userObjectId).then(() => toast("Object ID copied"))}
                />
              </>
            ) : null}
            {control === "unlink" ? (
              <>
                <span className="wb-spacer" />
                <AdminButton variant="danger-ghost" disabled={!groupWritesEnabled} onClick={() => principals.confirmUnlinkMicrosoft(principal.principalId)}>
                  Unlink Microsoft login
                </AdminButton>
              </>
            ) : null}
          </div>
          {renewal ? <StateCell label={renewal.text} tone={renewal.tone} /> : null}
          {!microsoft && principal.kind === "user" ? <MicrosoftEnrollmentControls principal={principal} /> : null}
          {control === "link" && !enrollment ? (
            <AdminForm
              className="wb-form-stack"
              onSubmit={async (event) => {
                event.preventDefault();
                if (!canLink) return;
                setLinking(true);
                setLinkError(null);
                try {
                  await principals.linkMicrosoft(principal.principalId, objectId.trim());
                  setObjectId("");
                  setConfirmId("");
                  setAcknowledged(false);
                } catch (failure) {
                  setLinkError(errorMessage(failure));
                } finally {
                  setLinking(false);
                }
              }}
            >
              {localActive ? <p className="pt-prose">Linking Microsoft keeps this user’s independent local password sign-in enabled.</p> : null}
              <div className="pt-form-row">
                <Input mono aria-label="Microsoft User Object ID" placeholder="00000000-0000-0000-0000-000000000000" value={objectId} onChange={(event) => setObjectId(event.target.value)} disabled={!groupWritesEnabled} />
                <Input mono aria-label="Confirm Principal ID" placeholder={principal.principalId} value={confirmId} onChange={(event) => setConfirmId(event.target.value)} disabled={!groupWritesEnabled} />
              </div>
              <Checkbox
                label={<>I understand this Microsoft account will be able to authenticate as {principal.principalId}.</>}
                checked={acknowledged}
                onChange={(event) => setAcknowledged(event.target.checked)}
                disabled={!groupWritesEnabled}
              />
              <FormError error={linkError} />
              <div>
                <AdminButton type="submit" disabled={!canLink} pending={linking}>
                  Link Microsoft login
                </AdminButton>
              </div>
            </AdminForm>
          ) : null}
        </div>
      </SettingsRow>
    </SettingsSection>
  );
}
